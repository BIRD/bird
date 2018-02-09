/*
 *	BIRD -- The Babel protocol
 *
 *	Copyright (c) 2015--2016 Toke Hoiland-Jorgensen
 * 	(c) 2016--2017 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2016--2017 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 *
 *	This file contains the main routines for handling and sending TLVs, as
 *	well as timers and interaction with the nest.
 */

/**
 * DOC: The Babel protocol
 *
 * Babel (RFC6126) is a loop-avoiding distance-vector routing protocol that is
 * robust and efficient both in ordinary wired networks and in wireless mesh
 * networks.
 *
 * The Babel protocol keeps state for each neighbour in a &babel_neighbor
 * struct, tracking received Hello and I Heard You (IHU) messages. A
 * &babel_interface struct keeps hello and update times for each interface, and
 * a separate hello seqno is maintained for each interface.
 *
 * For each prefix, Babel keeps track of both the possible routes (with next hop
 * and router IDs), as well as the feasibility distance for each prefix and
 * router id. The prefix itself is tracked in a &babel_entry struct, while the
 * possible routes for the prefix are tracked as &babel_route entries and the
 * feasibility distance is maintained through &babel_source structures.
 *
 * The main route selection is done in babel_select_route(). This is called when
 * an entry is updated by receiving updates from the network or when modified by
 * internal timers. The function selects from feasible and reachable routes the
 * one with the lowest metric to be announced to the core.
 */

#include <stdlib.h>
#include "babel.h"


/*
 * Is one number greater or equal than another mod 2^16? This is based on the
 * definition of serial number space in RFC 1982. Note that arguments are of
 * uint type to avoid integer promotion to signed integer.
 */
static inline int ge_mod64k(uint a, uint b)
{ return (u16)(a - b) < 0x8000; }

static void babel_expire_requests(struct babel_proto *p, struct babel_entry *e);
static void babel_select_route(struct babel_proto *p, struct babel_entry *e, struct babel_route *mod);
static inline void babel_announce_retraction(struct babel_proto *p, struct babel_entry *e);
static void babel_send_route_request(struct babel_proto *p, struct babel_entry *e, struct babel_neighbor *n);
static void babel_send_seqno_request(struct babel_proto *p, struct babel_entry *e, struct babel_seqno_request *sr);
static void babel_update_cost(struct babel_neighbor *n);
static inline void babel_kick_timer(struct babel_proto *p);
static inline void babel_iface_kick_timer(struct babel_iface *ifa);

static inline void babel_lock_neighbor(struct babel_neighbor *nbr)
{ if (nbr) nbr->uc++; }

static inline void babel_unlock_neighbor(struct babel_neighbor *nbr)
{ if (nbr && !--nbr->uc) mb_free(nbr); }


/*
 *	Functions to maintain data structures
 */

static void
babel_init_entry(void *E)
{
  struct babel_entry *e = E;

  e->updated = current_time();
  init_list(&e->requests);
  init_list(&e->sources);
  init_list(&e->routes);
}

static inline struct babel_entry *
babel_find_entry(struct babel_proto *p, const net_addr *n)
{
  struct fib *rtable = (n->type == NET_IP4) ? &p->ip4_rtable : &p->ip6_rtable;
  return fib_find(rtable, n);
}

static struct babel_entry *
babel_get_entry(struct babel_proto *p, const net_addr *n)
{
  struct fib *rtable = (n->type == NET_IP4) ? &p->ip4_rtable : &p->ip6_rtable;
  struct babel_entry *e = fib_get(rtable, n);
  return e;
}

static struct babel_source *
babel_find_source(struct babel_entry *e, u64 router_id)
{
  struct babel_source *s;

  WALK_LIST(s, e->sources)
    if (s->router_id == router_id)
      return s;

  return NULL;
}

static struct babel_source *
babel_get_source(struct babel_proto *p, struct babel_entry *e, u64 router_id)
{
  struct babel_source *s = babel_find_source(e, router_id);

  if (s)
    return s;

  s = sl_alloc(p->source_slab);
  s->router_id = router_id;
  s->expires = current_time() + BABEL_GARBAGE_INTERVAL;
  s->seqno = 0;
  s->metric = BABEL_INFINITY;
  add_tail(&e->sources, NODE s);

  return s;
}

static void
babel_expire_sources(struct babel_proto *p, struct babel_entry *e)
{
  struct babel_source *n, *nx;
  btime now_ = current_time();

  WALK_LIST_DELSAFE(n, nx, e->sources)
  {
    if (n->expires && n->expires <= now_)
    {
      rem_node(NODE n);
      sl_free(p->source_slab, n);
    }
  }
}

static struct babel_route *
babel_find_route(struct babel_entry *e, struct babel_neighbor *n)
{
  struct babel_route *r;

  WALK_LIST(r, e->routes)
    if (r->neigh == n)
      return r;

  return NULL;
}

static struct babel_route *
babel_get_route(struct babel_proto *p, struct babel_entry *e, struct babel_neighbor *nbr)
{
  struct babel_route *r = babel_find_route(e, nbr);

  if (r)
    return r;

  r = sl_alloc(p->route_slab);
  memset(r, 0, sizeof(*r));

  r->e = e;
  r->neigh = nbr;
  add_tail(&e->routes, NODE r);
  add_tail(&nbr->routes, NODE &r->neigh_route);

  return r;
}

static inline void
babel_retract_route(struct babel_proto *p, struct babel_route *r)
{
  r->metric = r->advert_metric = BABEL_INFINITY;

  if (r == r->e->selected)
    babel_select_route(p, r->e, r);
}

static void
babel_flush_route(struct babel_proto *p, struct babel_route *r)
{
  DBG("Babel: Flush route %N router_id %lR neigh %I\n",
      r->e->n.addr, r->router_id, r->neigh->addr);

  rem_node(NODE r);
  rem_node(&r->neigh_route);

  if (r->e->selected == r)
    r->e->selected = NULL;

  sl_free(p->route_slab, r);
}

static void
babel_expire_route(struct babel_proto *p, struct babel_route *r)
{
  struct babel_config *cf = (void *) p->p.cf;

  TRACE(D_EVENTS, "Route expiry timer for %N router-id %lR fired",
	r->e->n.addr, r->router_id);

  if (r->metric < BABEL_INFINITY)
  {
    r->metric = r->advert_metric = BABEL_INFINITY;
    r->expires = current_time() + cf->hold_time;
  }
  else
  {
    babel_flush_route(p, r);
  }
}

static void
babel_refresh_route(struct babel_proto *p, struct babel_route *r)
{
  if (r == r->e->selected)
    babel_send_route_request(p, r->e, r->neigh);

  r->refresh_time = 0;
}

static void
babel_expire_routes_(struct babel_proto *p, struct fib *rtable)
{
  struct babel_config *cf = (void *) p->p.cf;
  struct babel_route *r, *rx;
  struct fib_iterator fit;
  btime now_ = current_time();

  FIB_ITERATE_INIT(&fit, rtable);

loop:
  FIB_ITERATE_START(rtable, &fit, struct babel_entry, e)
  {
    int changed = 0;

    WALK_LIST_DELSAFE(r, rx, e->routes)
    {
      if (r->refresh_time && r->refresh_time <= now_)
	babel_refresh_route(p, r);

      if (r->expires && r->expires <= now_)
      {
	changed = changed || (r == e->selected);
	babel_expire_route(p, r);
      }
    }

    if (changed)
    {
      /*
       * We have to restart the iteration because there may be a cascade of
       * synchronous events babel_select_route() -> nest table change ->
       * babel_rt_notify() -> rtable change, invalidating hidden variables.
       */
      FIB_ITERATE_PUT(&fit);
      babel_select_route(p, e, NULL);
      goto loop;
    }

    /* Clean up stale entries */
    if ((e->valid == BABEL_ENTRY_STALE) && ((e->updated + cf->hold_time) <= now_))
      e->valid = BABEL_ENTRY_DUMMY;

    /* Clean up unreachable route */
    if (e->unreachable && (!e->valid || (e->router_id == p->router_id)))
    {
      FIB_ITERATE_PUT(&fit);
      babel_announce_retraction(p, e);
      goto loop;
    }

    babel_expire_sources(p, e);
    babel_expire_requests(p, e);

    /* Remove empty entries */
    if (!e->valid && EMPTY_LIST(e->routes) && EMPTY_LIST(e->sources) && EMPTY_LIST(e->requests))
    {
      FIB_ITERATE_PUT(&fit);
      fib_delete(rtable, e);
      goto loop;
    }
  }
  FIB_ITERATE_END;
}

static void
babel_expire_routes(struct babel_proto *p)
{
  babel_expire_routes_(p, &p->ip4_rtable);
  babel_expire_routes_(p, &p->ip6_rtable);
}

static inline int seqno_request_valid(struct babel_seqno_request *sr)
{ return !sr->nbr || sr->nbr->ifa; }

/*
 * Add seqno request to the table of pending requests (RFC 6216 3.2.6) and send
 * it to network. Do nothing if it is already in the table.
 */

static void
babel_add_seqno_request(struct babel_proto *p, struct babel_entry *e,
			u64 router_id, u16 seqno, u8 hop_count,
			struct babel_neighbor *nbr)
{
  struct babel_seqno_request *sr;

  WALK_LIST(sr, e->requests)
    if (sr->router_id == router_id)
    {
      /* Found matching or newer */
      if (ge_mod64k(sr->seqno, seqno) && seqno_request_valid(sr))
	return;

      /* Found older */
      babel_unlock_neighbor(sr->nbr);
      rem_node(NODE sr);
      goto found;
    }

  /* No entries found */
  sr = sl_alloc(p->seqno_slab);

found:
  sr->router_id = router_id;
  sr->seqno = seqno;
  sr->hop_count = hop_count;
  sr->count = 0;
  sr->expires = current_time() + BABEL_SEQNO_REQUEST_EXPIRY;
  babel_lock_neighbor(sr->nbr = nbr);
  add_tail(&e->requests, NODE sr);

  babel_send_seqno_request(p, e, sr);
}

static void
babel_remove_seqno_request(struct babel_proto *p, struct babel_seqno_request *sr)
{
  babel_unlock_neighbor(sr->nbr);
  rem_node(NODE sr);
  sl_free(p->seqno_slab, sr);
}

static int
babel_satisfy_seqno_request(struct babel_proto *p, struct babel_entry *e,
			   u64 router_id, u16 seqno)
{
  struct babel_seqno_request *sr;

  WALK_LIST(sr, e->requests)
    if ((sr->router_id == router_id) && ge_mod64k(seqno, sr->seqno))
    {
      /* Found the request, remove it */
      babel_remove_seqno_request(p, sr);
      return 1;
    }

  return 0;
}

static void
babel_expire_requests(struct babel_proto *p, struct babel_entry *e)
{
  struct babel_seqno_request *sr, *srx;
  btime now_ = current_time();

  WALK_LIST_DELSAFE(sr, srx, e->requests)
  {
    /* Remove seqno requests sent to dead neighbors */
    if (!seqno_request_valid(sr))
    {
      babel_remove_seqno_request(p, sr);
      continue;
    }

    /* Handle expired requests - resend or remove */
    if (sr->expires && sr->expires <= now_)
    {
      if (sr->count < BABEL_SEQNO_REQUEST_RETRY)
      {
	sr->count++;
	sr->expires += (BABEL_SEQNO_REQUEST_EXPIRY << sr->count);
	babel_send_seqno_request(p, e, sr);
      }
      else
      {
	TRACE(D_EVENTS, "Seqno request for %N router-id %lR expired",
	      e->n.addr, sr->router_id);

	babel_remove_seqno_request(p, sr);
	continue;
      }
    }
  }
}

static struct babel_neighbor *
babel_find_neighbor(struct babel_iface *ifa, ip_addr addr)
{
  struct babel_neighbor *nbr;

  WALK_LIST(nbr, ifa->neigh_list)
    if (ipa_equal(nbr->addr, addr))
      return nbr;

  return NULL;
}

static struct babel_neighbor *
babel_get_neighbor(struct babel_iface *ifa, ip_addr addr)
{
  struct babel_proto *p = ifa->proto;
  struct babel_neighbor *nbr = babel_find_neighbor(ifa, addr);

  if (nbr)
    return nbr;

  TRACE(D_EVENTS, "New neighbor %I on %s", addr, ifa->iface->name);

  nbr = mb_allocz(ifa->pool, sizeof(struct babel_neighbor));
  nbr->ifa = ifa;
  nbr->addr = addr;
  nbr->rxcost = BABEL_INFINITY;
  nbr->txcost = BABEL_INFINITY;
  nbr->cost = BABEL_INFINITY;
  init_list(&nbr->routes);
  babel_lock_neighbor(nbr);
  add_tail(&ifa->neigh_list, NODE nbr);

  return nbr;
}

static void
babel_flush_neighbor(struct babel_proto *p, struct babel_neighbor *nbr)
{
  struct babel_route *r;
  node *n;

  TRACE(D_EVENTS, "Removing neighbor %I on %s", nbr->addr, nbr->ifa->iface->name);

  WALK_LIST_FIRST(n, nbr->routes)
  {
    r = SKIP_BACK(struct babel_route, neigh_route, n);
    babel_retract_route(p, r);
    babel_flush_route(p, r);
  }

  nbr->ifa = NULL;
  rem_node(NODE nbr);
  babel_unlock_neighbor(nbr);
}

static void
babel_expire_ihu(struct babel_proto *p, struct babel_neighbor *nbr)
{
  TRACE(D_EVENTS, "IHU from nbr %I on %s expired", nbr->addr, nbr->ifa->iface->name);

  nbr->txcost = BABEL_INFINITY;
  nbr->ihu_expiry = 0;
  babel_update_cost(nbr);
}

static void
babel_expire_hello(struct babel_proto *p, struct babel_neighbor *nbr, btime now_)
{
again:
  nbr->hello_map <<= 1;

  if (nbr->hello_cnt < 16)
    nbr->hello_cnt++;

  nbr->hello_expiry += nbr->last_hello_int;

  /* We may expire multiple hellos if last_hello_int is too short */
  if (nbr->hello_map && nbr->hello_expiry <= now_)
    goto again;

  TRACE(D_EVENTS, "Hello from nbr %I on %s expired, %d left",
	nbr->addr, nbr->ifa->iface->name, u32_popcount(nbr->hello_map));

  if (nbr->hello_map)
    babel_update_cost(nbr);
  else
    babel_flush_neighbor(p, nbr);
}

static void
babel_expire_neighbors(struct babel_proto *p)
{
  struct babel_iface *ifa;
  struct babel_neighbor *nbr, *nbx;
  btime now_ = current_time();

  WALK_LIST(ifa, p->interfaces)
  {
    WALK_LIST_DELSAFE(nbr, nbx, ifa->neigh_list)
    {
      if (nbr->ihu_expiry && nbr->ihu_expiry <= now_)
        babel_expire_ihu(p, nbr);

      if (nbr->hello_expiry && nbr->hello_expiry <= now_)
        babel_expire_hello(p, nbr, now_);
    }
  }
}


/*
 *	Best route selection
 */

/*
 * From the RFC (section 3.5.1):
 *
 * a route advertisement carrying the quintuple (prefix, plen, router-id, seqno,
 * metric) is feasible if one of the following conditions holds:
 *
 * - metric is infinite; or
 *
 * - no entry exists in the source table indexed by (id, prefix, plen); or
 *
 * - an entry (prefix, plen, router-id, seqno', metric') exists in the source
 *   table, and either
 *   - seqno' < seqno or
 *   - seqno = seqno' and metric < metric'.
 */
static inline int
babel_is_feasible(struct babel_source *s, u16 seqno, u16 metric)
{
  return !s ||
    (metric == BABEL_INFINITY) ||
    (seqno > s->seqno) ||
    ((seqno == s->seqno) && (metric < s->metric));
}

/* Simple additive metric - Appendix 3.1 in the RFC */
static inline u16
babel_compute_metric(struct babel_neighbor *n, uint metric)
{
  return MIN(metric + n->cost, BABEL_INFINITY);
}

static void
babel_update_cost(struct babel_neighbor *nbr)
{
  struct babel_proto *p = nbr->ifa->proto;
  struct babel_iface_config *cf = nbr->ifa->cf;
  uint rcv = u32_popcount(nbr->hello_map); // number of bits set
  uint max = nbr->hello_cnt;
  uint rxcost = BABEL_INFINITY;	/* Cost to announce in IHU */
  uint txcost = BABEL_INFINITY;	/* Effective cost for route selection */

  if (!rcv || !nbr->ifa->up)
    goto done;

  switch (cf->type)
  {
  case BABEL_IFACE_TYPE_WIRED:
    /* k-out-of-j selection - Appendix 2.1 in the RFC. */

    /* Link is bad if less than cf->limit/16 of expected hellos were received */
    if (rcv * 16 < cf->limit * max)
      break;

    rxcost =  cf->rxcost;
    txcost = nbr->txcost;
    break;

  case BABEL_IFACE_TYPE_WIRELESS:
    /*
     * ETX - Appendix 2.2 in the RFC.
     *
     * alpha  = prob. of successful transmission estimated by the neighbor
     * beta   = prob. of successful transmission estimated by the router
     * rxcost = nominal rxcost of the router / beta
     * txcost = nominal rxcost of the neighbor / (alpha * beta)
     *        = received txcost / beta
     *
     * Note that received txcost is just neighbor's rxcost. Beta is rcv/max,
     * we use inverse values of beta (i.e. max/rcv) to stay in integers.
     */
    rxcost = MIN( cf->rxcost * max / rcv, BABEL_INFINITY);
    txcost = MIN(nbr->txcost * max / rcv, BABEL_INFINITY);
    break;
  }

done:
  /* If RX cost changed, send IHU with next Hello */
  if (rxcost != nbr->rxcost)
  {
    nbr->rxcost = rxcost;
    nbr->ihu_cnt = 0;
  }

  /* If link cost changed, run route selection */
  if (txcost != nbr->cost)
  {
    TRACE(D_EVENTS, "Cost of nbr %I on %s changed from %u to %u",
	  nbr->addr, nbr->ifa->iface->name, nbr->cost, txcost);

    nbr->cost = txcost;

    struct babel_route *r; node *n;
    WALK_LIST2(r, n, nbr->routes, neigh_route)
    {
      r->metric = babel_compute_metric(nbr, r->advert_metric);
      babel_select_route(p, r->e, r);
    }
  }
}

/**
 * babel_announce_rte - announce selected route to the core
 * @p: Babel protocol instance
 * @e: Babel route entry to announce
 *
 * This function announces a Babel entry to the core if it has a selected
 * incoming path, and retracts it otherwise. If there is no selected route but
 * the entry is valid and ours, the unreachable route is announced instead.
 */
static void
babel_announce_rte(struct babel_proto *p, struct babel_entry *e)
{
  struct babel_route *r = e->selected;
  struct channel *c = (e->n.addr->type == NET_IP4) ? p->ip4_channel : p->ip6_channel;

  if (r)
  {
    rta a0 = {
      .src = p->p.main_source,
      .source = RTS_BABEL,
      .scope = SCOPE_UNIVERSE,
      .dest = RTD_UNICAST,
      .from = r->neigh->addr,
      .nh.gw = r->next_hop,
      .nh.iface = r->neigh->ifa->iface,
    };

    rte rte = {
      .attrs = &a0,
      .u.babel = {
	  .seqno = r->seqno,
	  .metric = r->metric,
	  .router_id = r->router_id,
      },
      .pflags = 0,
    };

    e->unreachable = 0;
    rte_update2(c, e->n.addr, &rte, p->p.main_source);
  }
  else if (e->valid && (e->router_id != p->router_id))
  {
    /* Unreachable */
    rta a0 = {
      .src = p->p.main_source,
      .source = RTS_BABEL,
      .scope = SCOPE_UNIVERSE,
      .dest = RTD_UNREACHABLE,
    };

    rte rte = {
      .attrs = &a0,
      .u.babel = {},
      .pflags = 0,
      .pref = 1,
    };

    e->unreachable = 1;
    rte_update2(c, e->n.addr, &rte, p->p.main_source);
  }
  else
  {
    /* Retraction */
    e->unreachable = 0;
    rte_update2(c, e->n.addr, NULL, p->p.main_source);
  }
}

/* Special case of babel_announce_rte() just for retraction */
static inline void
babel_announce_retraction(struct babel_proto *p, struct babel_entry *e)
{
  struct channel *c = (e->n.addr->type == NET_IP4) ? p->ip4_channel : p->ip6_channel;
  e->unreachable = 0;
  rte_update2(c, e->n.addr, NULL, p->p.main_source);
}


/**
 * babel_select_route - select best route for given route entry
 * @p: Babel protocol instance
 * @e: Babel entry to select the best route for
 * @mod: Babel route that was modified or NULL if unspecified
 *
 * Select the best reachable and feasible route for a given prefix among the
 * routes received from peers, and propagate it to the nest. This just selects
 * the reachable and feasible route with the lowest metric, but keeps selected
 * the old one in case of tie.
 *
 * If no feasible route is available for a prefix that previously had a route
 * selected, a seqno request is sent to try to get a valid route. If the entry
 * is valid and not owned by us, the unreachable route is announced to the nest
 * (to blackhole packets going to it, as per section 2.8). It is later removed
 * by babel_expire_routes(). Otherwise, the route is just removed from the nest.
 *
 * Argument @mod is used to optimize best route calculation. When specified, the
 * function can assume that only the @mod route was modified to avoid full best
 * route selection and announcement when non-best route was modified in minor
 * way. The caller is advised to not call babel_select_route() when no change is
 * done (e.g. periodic route updates) to avoid unnecessary announcements of the
 * same best route. The caller is not required to call the function in case of a
 * retraction of a non-best route.
 *
 * Note that the function does not active triggered updates. That is done by
 * babel_rt_notify() when the change is propagated back to Babel.
 */
static void
babel_select_route(struct babel_proto *p, struct babel_entry *e, struct babel_route *mod)
{
  struct babel_route *r, *best = e->selected;

  /* Shortcut if only non-best was modified */
  if (mod && (mod != best))
  {
    /* Either select modified route, or keep old best route */
    if ((mod->metric < (best ? best->metric : BABEL_INFINITY)) && mod->feasible)
      best = mod;
    else
      return;
  }
  else
  {
    /* Selected route may be modified and no longer admissible */
    if (!best || (best->metric == BABEL_INFINITY) || !best->feasible)
      best = NULL;

    /* Find the best feasible route from all routes */
    WALK_LIST(r, e->routes)
      if ((r->metric < (best ? best->metric : BABEL_INFINITY)) && r->feasible)
	best = r;
  }

  if (best)
  {
    if (best != e->selected)
      TRACE(D_EVENTS, "Picked new route for prefix %N: router-id %lR metric %d",
	    e->n.addr, best->router_id, best->metric);
  }
  else if (e->selected)
  {
    /*
     * We have lost all feasible routes. We have to broadcast seqno request
     * (Section 3.8.2.1) and keep unreachable route for a while (section 2.8).
     * The later is done automatically by babel_announce_rte().
     */

    TRACE(D_EVENTS, "Lost feasible route for prefix %N", e->n.addr);
    if (e->valid && (e->selected->router_id == e->router_id))
      babel_add_seqno_request(p, e, e->selected->router_id, e->selected->seqno + 1, 0, NULL);
  }
  else
    return;

  e->selected = best;
  babel_announce_rte(p, e);
}

/*
 *	Functions to send replies
 */

static void
babel_send_ack(struct babel_iface *ifa, ip_addr dest, u16 nonce)
{
  struct babel_proto *p = ifa->proto;
  union babel_msg msg = {};

  TRACE(D_PACKETS, "Sending ACK to %I with nonce %d", dest, nonce);

  msg.type = BABEL_TLV_ACK;
  msg.ack.nonce = nonce;

  babel_send_unicast(&msg, ifa, dest);
}

static void
babel_build_ihu(union babel_msg *msg, struct babel_iface *ifa, struct babel_neighbor *n)
{
  struct babel_proto *p = ifa->proto;

  msg->type = BABEL_TLV_IHU;
  msg->ihu.addr = n->addr;
  msg->ihu.rxcost = n->rxcost;
  msg->ihu.interval = ifa->cf->ihu_interval;

  TRACE(D_PACKETS, "Sending IHU for %I with rxcost %d interval %t",
        msg->ihu.addr, msg->ihu.rxcost, (btime) msg->ihu.interval);
}

static void
babel_send_ihu(struct babel_iface *ifa, struct babel_neighbor *n)
{
  union babel_msg msg = {};
  babel_build_ihu(&msg, ifa, n);
  babel_send_unicast(&msg, ifa, n->addr);
  n->ihu_cnt = BABEL_IHU_INTERVAL_FACTOR;
}

static void
babel_send_ihus(struct babel_iface *ifa)
{
  struct babel_neighbor *n;
  WALK_LIST(n, ifa->neigh_list)
  {
    if (n->hello_cnt && (--n->ihu_cnt <= 0))
    {
      union babel_msg msg = {};
      babel_build_ihu(&msg, ifa, n);
      babel_enqueue(&msg, ifa);
      n->ihu_cnt = BABEL_IHU_INTERVAL_FACTOR;
    }
  }
}

static void
babel_send_hello(struct babel_iface *ifa)
{
  struct babel_proto *p = ifa->proto;
  union babel_msg msg = {};

  msg.type = BABEL_TLV_HELLO;
  msg.hello.seqno = ifa->hello_seqno++;
  msg.hello.interval = ifa->cf->hello_interval;

  TRACE(D_PACKETS, "Sending hello on %s with seqno %d interval %t",
	ifa->ifname, msg.hello.seqno, (btime) msg.hello.interval);

  babel_enqueue(&msg, ifa);

  babel_send_ihus(ifa);
}

static void
babel_send_route_request(struct babel_proto *p, struct babel_entry *e, struct babel_neighbor *n)
{
  union babel_msg msg = {};

  TRACE(D_PACKETS, "Sending route request for %N to %I",
        e->n.addr, n->addr);

  msg.type = BABEL_TLV_ROUTE_REQUEST;
  net_copy(&msg.route_request.net, e->n.addr);

  babel_send_unicast(&msg, n->ifa, n->addr);
}

static void
babel_send_wildcard_request(struct babel_iface *ifa)
{
  struct babel_proto *p = ifa->proto;
  union babel_msg msg = {};

  TRACE(D_PACKETS, "Sending wildcard route request on %s",
	ifa->ifname);

  msg.type = BABEL_TLV_ROUTE_REQUEST;
  msg.route_request.full = 1;

  babel_enqueue(&msg, ifa);
}

static void
babel_send_seqno_request(struct babel_proto *p, struct babel_entry *e, struct babel_seqno_request *sr)
{
  union babel_msg msg = {};

  msg.type = BABEL_TLV_SEQNO_REQUEST;
  msg.seqno_request.hop_count = sr->hop_count ?: BABEL_INITIAL_HOP_COUNT;
  msg.seqno_request.seqno = sr->seqno;
  msg.seqno_request.router_id = sr->router_id;
  net_copy(&msg.seqno_request.net, e->n.addr);

  if (sr->nbr)
  {
    TRACE(D_PACKETS, "Sending seqno request for %N router-id %lR seqno %d to %I on %s",
	  e->n.addr, sr->router_id, sr->seqno, sr->nbr->addr, sr->nbr->ifa->ifname);

    babel_send_unicast(&msg, sr->nbr->ifa, sr->nbr->addr);
  }
  else
  {
    TRACE(D_PACKETS, "Sending broadcast seqno request for %N router-id %lR seqno %d",
	  e->n.addr, sr->router_id, sr->seqno);

    struct babel_iface *ifa;
    WALK_LIST(ifa, p->interfaces)
      babel_enqueue(&msg, ifa);
  }
}

/**
 * babel_send_update - send route table updates
 * @ifa: Interface to transmit on
 * @changed: Only send entries changed since this time
 *
 * This function produces update TLVs for all entries changed since the time
 * indicated by the &changed parameter and queues them for transmission on the
 * selected interface. During the process, the feasibility distance for each
 * transmitted entry is updated.
 */
static void
babel_send_update_(struct babel_iface *ifa, btime changed, struct fib *rtable)
{
  struct babel_proto *p = ifa->proto;

  /* Update increase was requested */
  if (p->update_seqno_inc)
  {
    p->update_seqno++;
    p->update_seqno_inc = 0;
  }

  FIB_WALK(rtable, struct babel_entry, e)
  {
    if (!e->valid)
      continue;

    /* Our own seqno might have changed, in which case we update the routes we
       originate. */
    if ((e->router_id == p->router_id) && (e->seqno < p->update_seqno))
    {
      e->seqno = p->update_seqno;
      e->updated = current_time();
    }

    /* Skip routes that weren't updated since 'changed' time */
    if (e->updated < changed)
      continue;

    TRACE(D_PACKETS, "Sending update for %N router-id %lR seqno %d metric %d",
	  e->n.addr, e->router_id, e->seqno, e->metric);

    union babel_msg msg = {};
    msg.type = BABEL_TLV_UPDATE;
    msg.update.interval = ifa->cf->update_interval;
    msg.update.seqno = e->seqno;
    msg.update.metric = e->metric;
    msg.update.router_id = e->router_id;
    net_copy(&msg.update.net, e->n.addr);

    msg.update.next_hop = ((e->n.addr->type == NET_IP4) ?
			   ifa->next_hop_ip4 : ifa->next_hop_ip6);

    babel_enqueue(&msg, ifa);

    /* Update feasibility distance for redistributed routes */
    if (e->router_id != p->router_id)
    {
      struct babel_source *s = babel_get_source(p, e, e->router_id);
      s->expires = current_time() + BABEL_GARBAGE_INTERVAL;

      if ((msg.update.seqno > s->seqno) ||
	  ((msg.update.seqno == s->seqno) && (msg.update.metric < s->metric)))
      {
	s->seqno = msg.update.seqno;
	s->metric = msg.update.metric;
      }
    }
  }
  FIB_WALK_END;
}

static void
babel_send_update(struct babel_iface *ifa, btime changed)
{
  struct babel_proto *p = ifa->proto;

  babel_send_update_(ifa, changed, &p->ip4_rtable);
  babel_send_update_(ifa, changed, &p->ip6_rtable);
}

static void
babel_trigger_iface_update(struct babel_iface *ifa)
{
  struct babel_proto *p = ifa->proto;

  /* Interface not active or already scheduled */
  if (!ifa->up || ifa->want_triggered)
    return;

  TRACE(D_EVENTS, "Scheduling triggered updates for %s seqno %d",
	ifa->iface->name, p->update_seqno);

  ifa->want_triggered = current_time();
  babel_iface_kick_timer(ifa);
}

/* Sends and update on all interfaces. */
static void
babel_trigger_update(struct babel_proto *p)
{
  if (p->triggered)
    return;

  struct babel_iface *ifa;
  WALK_LIST(ifa, p->interfaces)
    babel_trigger_iface_update(ifa);

  p->triggered = 1;
}

/* A retraction is an update with an infinite metric */
static void
babel_send_retraction(struct babel_iface *ifa, net_addr *n)
{
  struct babel_proto *p = ifa->proto;
  union babel_msg msg = {};

  TRACE(D_PACKETS, "Sending retraction for %N seqno %d", n, p->update_seqno);

  msg.type = BABEL_TLV_UPDATE;
  msg.update.interval = ifa->cf->update_interval;
  msg.update.seqno = p->update_seqno;
  msg.update.metric = BABEL_INFINITY;
  msg.update.net = *n;

  babel_enqueue(&msg, ifa);
}

static void
babel_send_wildcard_retraction(struct babel_iface *ifa)
{
  struct babel_proto *p = ifa->proto;
  union babel_msg msg = {};

  TRACE(D_PACKETS, "Sending wildcard retraction on %s", ifa->ifname);

  msg.type = BABEL_TLV_UPDATE;
  msg.update.wildcard = 1;
  msg.update.interval = ifa->cf->update_interval;
  msg.update.seqno = p->update_seqno;
  msg.update.metric = BABEL_INFINITY;

  babel_enqueue(&msg, ifa);
}


/*
 *	TLV handler helpers
 */

/* Update hello history according to Appendix A1 of the RFC */
static void
babel_update_hello_history(struct babel_neighbor *n, u16 seqno, uint interval)
{
  /*
   * Compute the difference between expected and received seqno (modulo 2^16).
   * If the expected and received seqnos are within 16 of each other, the modular
   * difference is going to be less than 16 for one of the directions. Otherwise,
   * the values differ too much, so just reset the state.
   */

  u16 delta = ((uint) seqno - (uint) n->next_hello_seqno);

  if ((delta == 0) || (n->hello_cnt == 0))
  {
    /* Do nothing */
  }
  else if (delta <= 16)
  {
    /* Sending node decreased interval; fast-forward */
    n->hello_map <<= delta;
    n->hello_cnt = MIN(n->hello_cnt + delta, 16);
  }
  else if (delta >= 0xfff0)
  {
    u8 diff = (0xffff - delta);
    /* Sending node increased interval; undo history */
    n->hello_map >>= diff;
    n->hello_cnt = (diff < n->hello_cnt) ? n->hello_cnt - diff : 0;
  }
  else
  {
    /* Note state reset - flush entries */
    n->hello_map = n->hello_cnt = 0;
  }

  /* Current entry */
  n->hello_map = (n->hello_map << 1) | 1;
  n->next_hello_seqno = seqno+1;
  if (n->hello_cnt < 16) n->hello_cnt++;

  /* Update expiration */
  n->hello_expiry = current_time() + BABEL_HELLO_EXPIRY_FACTOR(interval);
  n->last_hello_int = interval;
}


/*
 *	TLV handlers
 */

void
babel_handle_ack_req(union babel_msg *m, struct babel_iface *ifa)
{
  struct babel_proto *p = ifa->proto;
  struct babel_msg_ack_req *msg = &m->ack_req;

  TRACE(D_PACKETS, "Handling ACK request nonce %d interval %t",
	msg->nonce, (btime) msg->interval);

  babel_send_ack(ifa, msg->sender, msg->nonce);
}

void
babel_handle_hello(union babel_msg *m, struct babel_iface *ifa)
{
  struct babel_proto *p = ifa->proto;
  struct babel_msg_hello *msg = &m->hello;

  TRACE(D_PACKETS, "Handling hello seqno %d interval %t",
	msg->seqno, (btime) msg->interval);

  struct babel_neighbor *n = babel_get_neighbor(ifa, msg->sender);
  int first_hello = !n->hello_cnt;

  babel_update_hello_history(n, msg->seqno, msg->interval);
  babel_update_cost(n);

  /* Speed up session establishment by sending IHU immediately */
  if (first_hello)
    babel_send_ihu(ifa, n);
}

void
babel_handle_ihu(union babel_msg *m, struct babel_iface *ifa)
{
  struct babel_proto *p = ifa->proto;
  struct babel_msg_ihu *msg = &m->ihu;

  /* Ignore IHUs that are not about us */
  if ((msg->ae != BABEL_AE_WILDCARD) && !ipa_equal(msg->addr, ifa->addr))
    return;

  TRACE(D_PACKETS, "Handling IHU rxcost %d interval %t",
	msg->rxcost, (btime) msg->interval);

  struct babel_neighbor *n = babel_get_neighbor(ifa, msg->sender);
  n->txcost = msg->rxcost;
  n->ihu_expiry = current_time() + BABEL_IHU_EXPIRY_FACTOR(msg->interval);
  babel_update_cost(n);
}

/**
 * babel_handle_update - handle incoming route updates
 * @m: Incoming update TLV
 * @ifa: Interface the update was received on
 *
 * This function is called as a handler for update TLVs and handles the updating
 * and maintenance of route entries in Babel's internal routing cache. The
 * handling follows the actions described in the Babel RFC, and at the end of
 * each update handling, babel_select_route() is called on the affected entry to
 * optionally update the selected routes and propagate them to the core.
 */
void
babel_handle_update(union babel_msg *m, struct babel_iface *ifa)
{
  struct babel_proto *p = ifa->proto;
  struct babel_msg_update *msg = &m->update;

  struct babel_neighbor *nbr;
  struct babel_entry *e;
  struct babel_source *s;
  struct babel_route *r, *best;
  node *n;
  int feasible, metric;

  if (msg->wildcard)
    TRACE(D_PACKETS, "Handling wildcard retraction", msg->seqno);
  else
    TRACE(D_PACKETS, "Handling update for %N with seqno %d metric %d",
	  &msg->net, msg->seqno, msg->metric);

  nbr = babel_find_neighbor(ifa, msg->sender);
  if (!nbr)
  {
    DBG("Babel: Haven't heard from neighbor %I; ignoring update.\n", msg->sender);
    return;
  }

  if (msg->router_id == p->router_id)
  {
    DBG("Babel: Ignoring update for our own router ID.\n");
    return;
  }

  struct channel *c = (msg->net.type == NET_IP4) ? p->ip4_channel : p->ip6_channel;
  if (!c || (c->channel_state != CS_UP))
  {
    DBG("Babel: Ignoring update for inactive address family.\n");
    return;
  }

  /* Retraction */
  if (msg->metric == BABEL_INFINITY)
  {
    if (msg->wildcard)
    {
      /*
       * Special case: This is a retraction of all prefixes announced by this
       * neighbour (see second-to-last paragraph of section 4.4.9 in the RFC).
       */
      WALK_LIST(n, nbr->routes)
      {
	r = SKIP_BACK(struct babel_route, neigh_route, n);
	babel_retract_route(p, r);
      }
    }
    else
    {
      e = babel_find_entry(p, &msg->net);

      if (!e)
	return;

      /* The route entry indexed by neighbour */
      r = babel_find_route(e, nbr);

      if (!r)
	return;

      /* Router-id, next-hop and seqno are ignored for retractions */
      babel_retract_route(p, r);
    }

    /* Done with retractions */
    return;
  }

  /* Regular update */
  e = babel_get_entry(p, &msg->net);
  r = babel_get_route(p, e, nbr); /* the route entry indexed by neighbour */
  s = babel_find_source(e, msg->router_id); /* for feasibility */
  feasible = babel_is_feasible(s, msg->seqno, msg->metric);
  metric = babel_compute_metric(nbr, msg->metric);
  best = e->selected;

  /* RFC section 3.8.2.2 - Dealing with unfeasible updates */
  if (!feasible && (metric != BABEL_INFINITY) &&
      (!best || (r == best) || (metric < best->metric)))
    babel_add_seqno_request(p, e, s->router_id, s->seqno + 1, 0, nbr);

  /* Special case - ignore unfeasible update to best route */
  if (r == best && !feasible && (msg->router_id == r->router_id))
    return;

  r->expires = current_time() + BABEL_ROUTE_EXPIRY_FACTOR(msg->interval);
  r->refresh_time = current_time() + BABEL_ROUTE_REFRESH_FACTOR(msg->interval);

  /* No further processing if there is no change */
  if ((r->feasible == feasible) && (r->seqno == msg->seqno) &&
      (r->metric == metric) && (r->advert_metric == msg->metric) &&
      (r->router_id == msg->router_id) && ipa_equal(r->next_hop, msg->next_hop))
    return;

  /* Last paragraph above - update the entry */
  r->feasible = feasible;
  r->seqno = msg->seqno;
  r->metric = metric;
  r->advert_metric = msg->metric;
  r->router_id = msg->router_id;
  r->next_hop = msg->next_hop;

  /* If received update satisfies seqno request, we send triggered updates */
  if (babel_satisfy_seqno_request(p, e, msg->router_id, msg->seqno))
  {
    babel_trigger_update(p);
    e->updated = current_time();
  }

  babel_select_route(p, e, r);
}

void
babel_handle_route_request(union babel_msg *m, struct babel_iface *ifa)
{
  struct babel_proto *p = ifa->proto;
  struct babel_msg_route_request *msg = &m->route_request;

  /* RFC 6126 3.8.1.1 */

  /* Wildcard request - full update on the interface */
  if (msg->full)
  {
    TRACE(D_PACKETS, "Handling wildcard route request");
    ifa->want_triggered = 1;
    return;
  }

  TRACE(D_PACKETS, "Handling route request for %N", &msg->net);

  /* Non-wildcard request - see if we have an entry for the route.
     If not, send a retraction, otherwise send an update. */
  struct babel_entry *e = babel_find_entry(p, &msg->net);
  if (!e)
  {
    babel_send_retraction(ifa, &msg->net);
  }
  else
  {
    babel_trigger_iface_update(ifa);
    e->updated = current_time();
  }
}

void
babel_handle_seqno_request(union babel_msg *m, struct babel_iface *ifa)
{
  struct babel_proto *p = ifa->proto;
  struct babel_msg_seqno_request *msg = &m->seqno_request;

  /* RFC 6126 3.8.1.2 */

  TRACE(D_PACKETS, "Handling seqno request for %N router-id %lR seqno %d hop count %d",
	&msg->net, msg->router_id, msg->seqno, msg->hop_count);

  /* Ignore if we have no such entry or entry has infinite metric */
  struct babel_entry *e = babel_find_entry(p, &msg->net);
  if (!e || !e->valid || (e->metric == BABEL_INFINITY))
    return;

  /* Trigger update on incoming interface if we have a selected route with
     different router id or seqno no smaller than requested */
  if ((e->router_id != msg->router_id) || ge_mod64k(e->seqno, msg->seqno))
  {
    babel_trigger_iface_update(ifa);
    e->updated = current_time();
    return;
  }

  /* Seqno is larger; check if we own the router id */
  if (msg->router_id == p->router_id)
  {
    /* Ours; seqno increase and trigger global update */
    p->update_seqno_inc = 1;
    babel_trigger_update(p);
  }
  else if (msg->hop_count > 1)
  {
    /* Not ours; forward if TTL allows it */

    /* Find best admissible route */
    struct babel_route *r, *best1 = NULL, *best2 = NULL;
    WALK_LIST(r, e->routes)
      if ((r->router_id == msg->router_id) && !ipa_equal(r->neigh->addr, msg->sender))
      {
	/* Find best feasible route */
	if ((!best1 || r->metric < best1->metric) && r->feasible)
	  best1 = r;

	/* Find best not necessary feasible route */
	if (!best2 || r->metric < best2->metric)
	  best2 = r;
      }

    /* If no route is found, do nothing */
    r = best1 ?: best2;
    if (!r)
      return;

    babel_add_seqno_request(p, e, msg->router_id, msg->seqno, msg->hop_count-1, r->neigh);
  }
}


/*
 *	Babel interfaces
 */

/**
 * babel_iface_timer - Babel interface timer handler
 * @t: Timer
 *
 * This function is called by the per-interface timer and triggers sending of
 * periodic Hello's and both triggered and periodic updates. Periodic Hello's
 * and updates are simply handled by setting the next_{hello,regular} variables
 * on the interface, and triggering an update (and resetting the variable)
 * whenever 'now' exceeds that value.
 *
 * For triggered updates, babel_trigger_iface_update() will set the
 * want_triggered field on the interface to a timestamp value. If this is set
 * (and the next_triggered time has passed; this is a rate limiting mechanism),
 * babel_send_update() will be called with this timestamp as the second
 * parameter. This causes updates to be send consisting of only the routes that
 * have changed since the time saved in want_triggered.
 *
 * Mostly when an update is triggered, the route being modified will be set to
 * the value of 'now' at the time of the trigger; the >= comparison for
 * selecting which routes to send in the update will make sure this is included.
 */
static void
babel_iface_timer(timer *t)
{
  struct babel_iface *ifa = t->data;
  struct babel_proto *p = ifa->proto;
  btime hello_period = ifa->cf->hello_interval;
  btime update_period = ifa->cf->update_interval;
  btime now_ = current_time();

  if (now_ >= ifa->next_hello)
  {
    babel_send_hello(ifa);
    ifa->next_hello += hello_period * (1 + (now_ - ifa->next_hello) / hello_period);
  }

  if (now_ >= ifa->next_regular)
  {
    TRACE(D_EVENTS, "Sending regular updates on %s", ifa->ifname);
    babel_send_update(ifa, 0);
    ifa->next_regular += update_period * (1 + (now_ - ifa->next_regular) / update_period);
    ifa->want_triggered = 0;
    p->triggered = 0;
  }
  else if (ifa->want_triggered && (now_ >= ifa->next_triggered))
  {
    TRACE(D_EVENTS, "Sending triggered updates on %s", ifa->ifname);
    babel_send_update(ifa, ifa->want_triggered);
    ifa->next_triggered = now_ + MIN(1 S, update_period / 2);
    ifa->want_triggered = 0;
    p->triggered = 0;
  }

  btime next_event = MIN(ifa->next_hello, ifa->next_regular);
  if (ifa->want_triggered) next_event = MIN(next_event, ifa->next_triggered);
  tm_set(ifa->timer, next_event);
}

static inline void
babel_iface_kick_timer(struct babel_iface *ifa)
{
  if (ifa->timer->expires > (current_time() + 100 MS))
    tm_start(ifa->timer, 100 MS);
}

static void
babel_iface_start(struct babel_iface *ifa)
{
  struct babel_proto *p = ifa->proto;

  TRACE(D_EVENTS, "Starting interface %s", ifa->ifname);

  ifa->next_hello = current_time() + (random() % ifa->cf->hello_interval);
  ifa->next_regular = current_time() + (random() % ifa->cf->update_interval);
  ifa->next_triggered = current_time() + MIN(1 S, ifa->cf->update_interval / 2);
  ifa->want_triggered = 0;	/* We send an immediate update (below) */
  tm_start(ifa->timer, 100 MS);
  ifa->up = 1;

  babel_send_hello(ifa);
  babel_send_wildcard_retraction(ifa);
  babel_send_wildcard_request(ifa);
  babel_send_update(ifa, 0);	/* Full update */
}

static void
babel_iface_stop(struct babel_iface *ifa)
{
  struct babel_proto *p = ifa->proto;
  struct babel_neighbor *nbr;
  struct babel_route *r;
  node *n;

  TRACE(D_EVENTS, "Stopping interface %s", ifa->ifname);

  /*
   * Rather than just flushing the neighbours, we set the metric of their routes
   * to infinity. This allows us to keep the neighbour hello state for when the
   * interface comes back up. The routes will also be kept until they expire.
   */
  WALK_LIST(nbr, ifa->neigh_list)
  {
    WALK_LIST(n, nbr->routes)
    {
      r = SKIP_BACK(struct babel_route, neigh_route, n);
      babel_retract_route(p, r);
    }
  }

  tm_stop(ifa->timer);
  ifa->up = 0;
}

static inline int
babel_iface_link_up(struct babel_iface *ifa)
{
  return !ifa->cf->check_link || (ifa->iface->flags & IF_LINK_UP);
}

static void
babel_iface_update_state(struct babel_iface *ifa)
{
  int up = ifa->sk && babel_iface_link_up(ifa);

  if (up == ifa->up)
    return;

  if (up)
    babel_iface_start(ifa);
  else
    babel_iface_stop(ifa);
}

static void
babel_iface_update_buffers(struct babel_iface *ifa)
{
  if (!ifa->sk)
    return;

  uint mtu = MAX(BABEL_MIN_MTU, ifa->iface->mtu);
  uint rbsize = ifa->cf->rx_buffer ?: mtu;
  uint tbsize = ifa->cf->tx_length ?: mtu;
  rbsize = MAX(rbsize, tbsize);

  sk_set_rbsize(ifa->sk, rbsize);
  sk_set_tbsize(ifa->sk, tbsize);

  ifa->tx_length = tbsize - BABEL_OVERHEAD;
}

static struct babel_iface*
babel_find_iface(struct babel_proto *p, struct iface *what)
{
  struct babel_iface *ifa;

  WALK_LIST (ifa, p->interfaces)
    if (ifa->iface == what)
      return ifa;

  return NULL;
}

static void
babel_iface_locked(struct object_lock *lock)
{
  struct babel_iface *ifa = lock->data;
  struct babel_proto *p = ifa->proto;

  if (!babel_open_socket(ifa))
  {
    log(L_ERR "%s: Cannot open socket for %s", p->p.name, ifa->iface->name);
    return;
  }

  babel_iface_update_buffers(ifa);
  babel_iface_update_state(ifa);
}

static void
babel_add_iface(struct babel_proto *p, struct iface *new, struct babel_iface_config *ic)
{
  struct babel_iface *ifa;

  TRACE(D_EVENTS, "Adding interface %s", new->name);

  pool *pool = rp_new(p->p.pool, new->name);

  ifa = mb_allocz(pool, sizeof(struct babel_iface));
  ifa->proto = p;
  ifa->iface = new;
  ifa->cf = ic;
  ifa->pool = pool;
  ifa->ifname = new->name;
  ifa->addr = new->llv6->ip;

  add_tail(&p->interfaces, NODE ifa);

  ip_addr addr4 = new->addr4 ? new->addr4->ip : IPA_NONE;
  ifa->next_hop_ip4 = ipa_nonzero(ic->next_hop_ip4) ? ic->next_hop_ip4 : addr4;
  ifa->next_hop_ip6 = ipa_nonzero(ic->next_hop_ip6) ? ic->next_hop_ip6 : ifa->addr;

  if (ipa_zero(ifa->next_hop_ip4) && p->ip4_channel)
    log(L_WARN "%s: Cannot find IPv4 next hop addr on %s", p->p.name, new->name);

  init_list(&ifa->neigh_list);
  ifa->hello_seqno = 1;

  ifa->timer = tm_new_init(ifa->pool, babel_iface_timer, ifa, 0, 0);

  init_list(&ifa->msg_queue);
  ifa->send_event = ev_new(ifa->pool);
  ifa->send_event->hook = babel_send_queue;
  ifa->send_event->data = ifa;

  struct object_lock *lock = olock_new(ifa->pool);
  lock->type = OBJLOCK_UDP;
  lock->addr = IP6_BABEL_ROUTERS;
  lock->port = ifa->cf->port;
  lock->iface = ifa->iface;
  lock->hook = babel_iface_locked;
  lock->data = ifa;

  olock_acquire(lock);
}

static void
babel_remove_iface(struct babel_proto *p, struct babel_iface *ifa)
{
  TRACE(D_EVENTS, "Removing interface %s", ifa->iface->name);

  struct babel_neighbor *n;
  WALK_LIST_FIRST(n, ifa->neigh_list)
    babel_flush_neighbor(p, n);

  rem_node(NODE ifa);

  rfree(ifa->pool); /* contains ifa itself, locks, socket, etc */
}

static void
babel_if_notify(struct proto *P, unsigned flags, struct iface *iface)
{
  struct babel_proto *p = (void *) P;
  struct babel_config *cf = (void *) P->cf;

  if (iface->flags & IF_IGNORE)
    return;

  if (flags & IF_CHANGE_UP)
  {
    struct babel_iface_config *ic = (void *) iface_patt_find(&cf->iface_list, iface, NULL);

    /* we only speak multicast */
    if (!(iface->flags & IF_MULTICAST))
      return;

    /* Ignore ifaces without link-local address */
    if (!iface->llv6)
      return;

    if (ic)
      babel_add_iface(p, iface, ic);

    return;
  }

  struct babel_iface *ifa = babel_find_iface(p, iface);

  if (!ifa)
    return;

  if (flags & IF_CHANGE_DOWN)
  {
    babel_remove_iface(p, ifa);
    return;
  }

  if (flags & IF_CHANGE_MTU)
    babel_iface_update_buffers(ifa);

  if (flags & IF_CHANGE_LINK)
    babel_iface_update_state(ifa);
}

static int
babel_reconfigure_iface(struct babel_proto *p, struct babel_iface *ifa, struct babel_iface_config *new)
{
  struct babel_iface_config *old = ifa->cf;

  /* Change of these options would require to reset the iface socket */
  if ((new->port != old->port) ||
      (new->tx_tos != old->tx_tos) ||
      (new->tx_priority != old->tx_priority))
    return 0;

  TRACE(D_EVENTS, "Reconfiguring interface %s", ifa->iface->name);

  ifa->cf = new;

  ip_addr addr4 = ifa->iface->addr4 ? ifa->iface->addr4->ip : IPA_NONE;
  ifa->next_hop_ip4 = ipa_nonzero(new->next_hop_ip4) ? new->next_hop_ip4 : addr4;
  ifa->next_hop_ip6 = ipa_nonzero(new->next_hop_ip6) ? new->next_hop_ip6 : ifa->addr;

  if (ipa_zero(ifa->next_hop_ip4) && p->ip4_channel)
    log(L_WARN "%s: Cannot find IPv4 next hop addr on %s", p->p.name, ifa->ifname);

  if (ifa->next_hello > (current_time() + new->hello_interval))
    ifa->next_hello = current_time() + (random() % new->hello_interval);

  if (ifa->next_regular > (current_time() + new->update_interval))
    ifa->next_regular = current_time() + (random() % new->update_interval);

  if ((new->tx_length != old->tx_length) || (new->rx_buffer != old->rx_buffer))
    babel_iface_update_buffers(ifa);

  if (new->check_link != old->check_link)
    babel_iface_update_state(ifa);

  if (ifa->up)
    babel_iface_kick_timer(ifa);

  return 1;
}

static void
babel_reconfigure_ifaces(struct babel_proto *p, struct babel_config *cf)
{
  struct iface *iface;

  WALK_LIST(iface, iface_list)
  {
    if (!(iface->flags & IF_UP))
      continue;

    /* Ignore non-multicast ifaces */
    if (!(iface->flags & IF_MULTICAST))
      continue;

    /* Ignore ifaces without link-local address */
    if (!iface->llv6)
      continue;

    struct babel_iface *ifa = babel_find_iface(p, iface);
    struct babel_iface_config *ic = (void *) iface_patt_find(&cf->iface_list, iface, NULL);

    if (ifa && ic)
    {
      if (babel_reconfigure_iface(p, ifa, ic))
	continue;

      /* Hard restart */
      log(L_INFO "%s: Restarting interface %s", p->p.name, ifa->iface->name);
      babel_remove_iface(p, ifa);
      babel_add_iface(p, iface, ic);
    }

    if (ifa && !ic)
      babel_remove_iface(p, ifa);

    if (!ifa && ic)
      babel_add_iface(p, iface, ic);
  }
}


/*
 *	Debugging and info output functions
 */

static void
babel_dump_source(struct babel_source *s)
{
  debug("Source router_id %lR seqno %d metric %d expires %t\n",
	s->router_id, s->seqno, s->metric,
	s->expires ? s->expires - current_time() : 0);
}

static void
babel_dump_route(struct babel_route *r)
{
  debug("Route neigh %I if %s seqno %d metric %d/%d router_id %lR expires %t\n",
	r->neigh->addr, r->neigh->ifa->ifname, r->seqno, r->advert_metric, r->metric,
	r->router_id, r->expires ? r->expires - current_time() : 0);
}

static void
babel_dump_entry(struct babel_entry *e)
{
  struct babel_source *s;
  struct babel_route *r;

  debug("Babel: Entry %N:\n", e->n.addr);

  WALK_LIST(s,e->sources)
  { debug(" "); babel_dump_source(s); }

  WALK_LIST(r,e->routes)
  {
    debug(" ");
    if (r == e->selected) debug("*");
    babel_dump_route(r);
  }
}

static void
babel_dump_neighbor(struct babel_neighbor *n)
{
  debug("Neighbor %I txcost %d hello_map %x next seqno %d expires %t/%t\n",
	n->addr, n->txcost, n->hello_map, n->next_hello_seqno,
	n->hello_expiry ? n->hello_expiry - current_time() : 0,
        n->ihu_expiry ? n->ihu_expiry - current_time() : 0);
}

static void
babel_dump_iface(struct babel_iface *ifa)
{
  struct babel_neighbor *n;

  debug("Babel: Interface %s addr %I rxcost %d type %d hello seqno %d intervals %t %t",
	ifa->ifname, ifa->addr, ifa->cf->rxcost, ifa->cf->type, ifa->hello_seqno,
	ifa->cf->hello_interval, ifa->cf->update_interval);
  debug(" next hop v4 %I next hop v6 %I\n", ifa->next_hop_ip4, ifa->next_hop_ip6);

  WALK_LIST(n, ifa->neigh_list)
  { debug(" "); babel_dump_neighbor(n); }
}

static void
babel_dump(struct proto *P)
{
  struct babel_proto *p = (struct babel_proto *) P;
  struct babel_iface *ifa;

  debug("Babel: router id %lR update seqno %d\n", p->router_id, p->update_seqno);

  WALK_LIST(ifa, p->interfaces)
    babel_dump_iface(ifa);

  FIB_WALK(&p->ip4_rtable, struct babel_entry, e)
  {
    babel_dump_entry(e);
  }
  FIB_WALK_END;
  FIB_WALK(&p->ip6_rtable, struct babel_entry, e)
  {
    babel_dump_entry(e);
  }
  FIB_WALK_END;
}

static void
babel_get_route_info(rte *rte, byte *buf, ea_list *attrs UNUSED)
{
  buf += bsprintf(buf, " (%d/%d) [%lR]", rte->pref, rte->u.babel.metric, rte->u.babel.router_id);
}

static int
babel_get_attr(eattr *a, byte *buf, int buflen UNUSED)
{
  switch (a->id)
  {
  case EA_BABEL_METRIC:
    bsprintf(buf, "metric: %d", a->u.data);
    return GA_FULL;

  case EA_BABEL_ROUTER_ID:
  {
    u64 rid = 0;
    memcpy(&rid, a->u.ptr->data, sizeof(u64));
    bsprintf(buf, "router_id: %lR", rid);
    return GA_FULL;
  }

  default:
    return GA_UNKNOWN;
  }
}

void
babel_show_interfaces(struct proto *P, char *iff)
{
  struct babel_proto *p = (void *) P;
  struct babel_iface *ifa = NULL;
  struct babel_neighbor *nbr = NULL;

  if (p->p.proto_state != PS_UP)
  {
    cli_msg(-1023, "%s: is not up", p->p.name);
    cli_msg(0, "");
    return;
  }

  cli_msg(-1023, "%s:", p->p.name);
  cli_msg(-1023, "%-10s %-6s %7s %6s %7s %-15s %s",
	  "Interface", "State", "RX cost", "Nbrs", "Timer",
	  "Next hop (v4)", "Next hop (v6)");

  WALK_LIST(ifa, p->interfaces)
  {
    if (iff && !patmatch(iff, ifa->iface->name))
      continue;

    int nbrs = 0;
    WALK_LIST(nbr, ifa->neigh_list)
	nbrs++;

    btime timer = MIN(ifa->next_regular, ifa->next_hello) - current_time();
    cli_msg(-1023, "%-10s %-6s %7u %6u %7t %-15I %I",
	    ifa->iface->name, (ifa->up ? "Up" : "Down"),
	    ifa->cf->rxcost, nbrs, MAX(timer, 0),
	    ifa->next_hop_ip4, ifa->next_hop_ip6);
  }

  cli_msg(0, "");
}

void
babel_show_neighbors(struct proto *P, char *iff)
{
  struct babel_proto *p = (void *) P;
  struct babel_iface *ifa = NULL;
  struct babel_neighbor *n = NULL;
  struct babel_route *r = NULL;

  if (p->p.proto_state != PS_UP)
  {
    cli_msg(-1024, "%s: is not up", p->p.name);
    cli_msg(0, "");
    return;
  }

  cli_msg(-1024, "%s:", p->p.name);
  cli_msg(-1024, "%-25s %-10s %6s %6s %6s %7s",
	  "IP address", "Interface", "Metric", "Routes", "Hellos", "Expires");

  WALK_LIST(ifa, p->interfaces)
  {
    if (iff && !patmatch(iff, ifa->iface->name))
      continue;

    WALK_LIST(n, ifa->neigh_list)
    {
      int rts = 0;
      WALK_LIST(r, n->routes)
        rts++;

      uint hellos = u32_popcount(n->hello_map);
      btime timer = n->hello_expiry - current_time();
      cli_msg(-1024, "%-25I %-10s %6u %6u %6u %7t",
	      n->addr, ifa->iface->name, n->cost, rts, hellos, MAX(timer, 0));
    }
  }

  cli_msg(0, "");
}

static void
babel_show_entries_(struct babel_proto *p UNUSED, struct fib *rtable)
{
  FIB_WALK(rtable, struct babel_entry, e)
  {
    struct babel_route *r = NULL;
    uint rts = 0, srcs = 0;
    node *n;

    WALK_LIST(n, e->routes)
      rts++;

    WALK_LIST(n, e->sources)
      srcs++;

    if (e->valid)
      cli_msg(-1025, "%-24N %-23lR %6u %5u %7u %7u",
	      e->n.addr, e->router_id, e->metric, e->seqno, rts, srcs);
    else if (r = e->selected)
      cli_msg(-1025, "%-24N %-23lR %6u %5u %7u %7u",
	      e->n.addr, r->router_id, r->metric, r->seqno, rts, srcs);
    else
      cli_msg(-1025, "%-24N %-23s %6s %5s %7u %7u",
	      e->n.addr, "<none>", "-", "-", rts, srcs);
  }
  FIB_WALK_END;
}

void
babel_show_entries(struct proto *P)
{
  struct babel_proto *p = (void *) P;

  if (p->p.proto_state != PS_UP)
  {
    cli_msg(-1025, "%s: is not up", p->p.name);
    cli_msg(0, "");
    return;
  }

  cli_msg(-1025, "%s:", p->p.name);
  cli_msg(-1025, "%-24s %-23s %6s %5s %7s %7s",
	  "Prefix", "Router ID", "Metric", "Seqno", "Routes", "Sources");

  babel_show_entries_(p, &p->ip4_rtable);
  babel_show_entries_(p, &p->ip6_rtable);

  cli_msg(0, "");
}

static void
babel_show_routes_(struct babel_proto *p UNUSED, struct fib *rtable)
{
  FIB_WALK(rtable, struct babel_entry, e)
  {
    struct babel_route *r;
    WALK_LIST(r, e->routes)
    {
      char c = (r == e->selected) ? '*' : (r->feasible ? '+' : ' ');
      btime time = r->expires ? r->expires - current_time() : 0;
      cli_msg(-1025, "%-24N %-25I %-10s %5u %c %5u %7t",
	      e->n.addr, r->next_hop, r->neigh->ifa->ifname,
	      r->metric, c, r->seqno, MAX(time, 0));
    }
  }
  FIB_WALK_END;
}

void
babel_show_routes(struct proto *P)
{
  struct babel_proto *p = (void *) P;

  if (p->p.proto_state != PS_UP)
  {
    cli_msg(-1025, "%s: is not up", p->p.name);
    cli_msg(0, "");
    return;
  }

  cli_msg(-1025, "%s:", p->p.name);
  cli_msg(-1025, "%-24s %-25s %-9s %6s F %5s %7s",
	  "Prefix", "Nexthop", "Interface", "Metric", "Seqno", "Expires");

  babel_show_routes_(p, &p->ip4_rtable);
  babel_show_routes_(p, &p->ip6_rtable);

  cli_msg(0, "");
}


/*
 *	Babel protocol glue
 */

/**
 * babel_timer - global timer hook
 * @t: Timer
 *
 * This function is called by the global protocol instance timer and handles
 * expiration of routes and neighbours as well as pruning of the seqno request
 * cache.
 */
static void
babel_timer(timer *t)
{
  struct babel_proto *p = t->data;

  babel_expire_routes(p);
  babel_expire_neighbors(p);
}

static inline void
babel_kick_timer(struct babel_proto *p)
{
  if (p->timer->expires > (current_time() + 100 MS))
    tm_start(p->timer, 100 MS);
}


static struct ea_list *
babel_prepare_attrs(struct linpool *pool, ea_list *next, uint metric, u64 router_id)
{
  struct ea_list *l = lp_alloc(pool, sizeof(struct ea_list) + 2*sizeof(eattr));
  struct adata *rid = lp_alloc(pool, sizeof(struct adata) + sizeof(u64));
  rid->length = sizeof(u64);
  memcpy(&rid->data, &router_id, sizeof(u64));

  l->next = next;
  l->flags = EALF_SORTED;
  l->count = 2;

  l->attrs[0].id = EA_BABEL_METRIC;
  l->attrs[0].flags = 0;
  l->attrs[0].type = EAF_TYPE_INT | EAF_TEMP;
  l->attrs[0].u.data = metric;

  l->attrs[1].id = EA_BABEL_ROUTER_ID;
  l->attrs[1].flags = 0;
  l->attrs[1].type = EAF_TYPE_OPAQUE | EAF_TEMP;
  l->attrs[1].u.ptr = rid;

  return l;
}


static int
babel_import_control(struct proto *P, struct rte **new, struct ea_list **attrs, struct linpool *pool)
{
  struct babel_proto *p = (void *) P;
  rte *rt = *new;

  /* Reject our own unreachable routes */
  if ((rt->attrs->dest == RTD_UNREACHABLE) && (rt->attrs->src->proto == P))
    return -1;


  /* Prepare attributes with initial values */
  if (rt->attrs->source != RTS_BABEL)
    *attrs = babel_prepare_attrs(pool, NULL, 0, p->router_id);

  return 0;
}

static struct ea_list *
babel_make_tmp_attrs(struct rte *rt, struct linpool *pool)
{
  return babel_prepare_attrs(pool, NULL, rt->u.babel.metric, rt->u.babel.router_id);
}

static void
babel_store_tmp_attrs(struct rte *rt, struct ea_list *attrs)
{
  rt->u.babel.metric = ea_get_int(attrs, EA_BABEL_METRIC, 0);
}

/*
 * babel_rt_notify - core tells us about new route (possibly our own),
 * so store it into our data structures.
 */
static void
babel_rt_notify(struct proto *P, struct channel *c UNUSED, struct network *net,
		struct rte *new, struct rte *old UNUSED, struct ea_list *attrs UNUSED)
{
  struct babel_proto *p = (void *) P;
  struct babel_entry *e;

  if (new)
  {
    /* Update */
    uint internal = (new->attrs->src->proto == P);
    uint rt_seqno = internal ? new->u.babel.seqno : p->update_seqno;
    uint rt_metric = ea_get_int(attrs, EA_BABEL_METRIC, 0);
    uint rt_router_id = internal ? new->u.babel.router_id : p->router_id;

    if (rt_metric > BABEL_INFINITY)
    {
      log(L_WARN "%s: Invalid babel_metric value %u for route %N",
	  p->p.name, rt_metric, net->n.addr);
      rt_metric = BABEL_INFINITY;
    }

    e = babel_get_entry(p, net->n.addr);

    /* Activate triggered updates */
    if ((e->valid |= BABEL_ENTRY_VALID) ||
	(e->router_id != rt_router_id))
    {
      babel_trigger_update(p);
      e->updated = current_time();
    }

    e->valid = BABEL_ENTRY_VALID;
    e->seqno = rt_seqno;
    e->metric = rt_metric;
    e->router_id = rt_router_id;
  }
  else
  {
    /* Withdraw */
    e = babel_find_entry(p, net->n.addr);

    if (!e || e->valid != BABEL_ENTRY_VALID)
      return;

    e->valid = BABEL_ENTRY_STALE;
    e->metric = BABEL_INFINITY;

    babel_trigger_update(p);
    e->updated = current_time();
  }
}

static int
babel_rte_better(struct rte *new, struct rte *old)
{
  return new->u.babel.metric < old->u.babel.metric;
}

static int
babel_rte_same(struct rte *new, struct rte *old)
{
  return ((new->u.babel.seqno == old->u.babel.seqno) &&
	  (new->u.babel.metric == old->u.babel.metric) &&
	  (new->u.babel.router_id == old->u.babel.router_id));
}


static struct proto *
babel_init(struct proto_config *CF)
{
  struct proto *P = proto_new(CF);
  struct babel_proto *p = (void *) P;

  proto_configure_channel(P, &p->ip4_channel, proto_cf_find_channel(CF, NET_IP4));
  proto_configure_channel(P, &p->ip6_channel, proto_cf_find_channel(CF, NET_IP6));

  P->if_notify = babel_if_notify;
  P->rt_notify = babel_rt_notify;
  P->import_control = babel_import_control;
  P->make_tmp_attrs = babel_make_tmp_attrs;
  P->store_tmp_attrs = babel_store_tmp_attrs;
  P->rte_better = babel_rte_better;
  P->rte_same = babel_rte_same;

  return P;
}

static int
babel_start(struct proto *P)
{
  struct babel_proto *p = (void *) P;
  struct babel_config *cf = (void *) P->cf;

  fib_init(&p->ip4_rtable, P->pool, NET_IP4, sizeof(struct babel_entry),
	   OFFSETOF(struct babel_entry, n), 0, babel_init_entry);
  fib_init(&p->ip6_rtable, P->pool, NET_IP6, sizeof(struct babel_entry),
	   OFFSETOF(struct babel_entry, n), 0, babel_init_entry);

  init_list(&p->interfaces);
  p->timer = tm_new_init(P->pool, babel_timer, p, 1 S, 0);
  tm_start(p->timer, 1 S);
  p->update_seqno = 1;
  p->router_id = proto_get_router_id(&cf->c);

  p->route_slab = sl_new(P->pool, sizeof(struct babel_route));
  p->source_slab = sl_new(P->pool, sizeof(struct babel_source));
  p->msg_slab = sl_new(P->pool, sizeof(struct babel_msg_node));
  p->seqno_slab = sl_new(P->pool, sizeof(struct babel_seqno_request));

  p->log_pkt_tbf = (struct tbf){ .rate = 1, .burst = 5 };

  return PS_UP;
}

static inline void
babel_iface_shutdown(struct babel_iface *ifa)
{
  if (ifa->sk)
  {
    babel_send_wildcard_retraction(ifa);
    babel_send_queue(ifa);
  }
}

static int
babel_shutdown(struct proto *P)
{
  struct babel_proto *p = (void *) P;
  struct babel_iface *ifa;

  TRACE(D_EVENTS, "Shutdown requested");

  WALK_LIST(ifa, p->interfaces)
    babel_iface_shutdown(ifa);

  return PS_DOWN;
}

static int
babel_reconfigure(struct proto *P, struct proto_config *CF)
{
  struct babel_proto *p = (void *) P;
  struct babel_config *new = (void *) CF;

  TRACE(D_EVENTS, "Reconfiguring");

  if (!proto_configure_channel(P, &p->ip4_channel, proto_cf_find_channel(CF, NET_IP4)) ||
      !proto_configure_channel(P, &p->ip6_channel, proto_cf_find_channel(CF, NET_IP6)))
    return 0;

  p->p.cf = CF;
  babel_reconfigure_ifaces(p, new);

  babel_trigger_update(p);
  babel_kick_timer(p);

  return 1;
}


struct protocol proto_babel = {
  .name =		"Babel",
  .template =		"babel%d",
  .attr_class =		EAP_BABEL,
  .preference =		DEF_PREF_BABEL,
  .channel_mask =	NB_IP,
  .proto_size =		sizeof(struct babel_proto),
  .config_size =	sizeof(struct babel_config),
  .init =		babel_init,
  .dump =		babel_dump,
  .start =		babel_start,
  .shutdown =		babel_shutdown,
  .reconfigure =	babel_reconfigure,
  .get_route_info =	babel_get_route_info,
  .get_attr =		babel_get_attr
};
