/*
 *	BIRD -- Routing Tables
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: Routing tables
 *
 * Routing tables are probably the most important structures BIRD uses. They
 * hold all the information about known networks, the associated routes and
 * their attributes.
 *
 * There are multiple routing tables (a primary one together with any
 * number of secondary ones if requested by the configuration). Each table
 * is basically a FIB containing entries describing the individual
 * destination networks. For each network (represented by structure &net),
 * there is a one-way linked list of route entries (&rte), the first entry
 * on the list being the best one (i.e., the one we currently use
 * for routing), the order of the other ones is undetermined.
 *
 * The &rte contains information specific to the route (preference, protocol
 * metrics, time of last modification etc.) and a pointer to a &rta structure
 * (see the route attribute module for a precise explanation) holding the
 * remaining route attributes which are expected to be shared by multiple
 * routes in order to conserve memory.
 */

#undef LOCAL_DEBUG

#include "nest/bird.h"
#include "nest/route.h"
#include "nest/protocol.h"
#include "nest/iface.h"
#include "lib/resource.h"
#include "lib/event.h"
#include "lib/string.h"
#include "conf/conf.h"
#include "filter/filter.h"
#include "lib/hash.h"
#include "lib/string.h"
#include "lib/alloca.h"

pool *rt_table_pool;

static slab *rte_slab;
static linpool *rte_update_pool;

static list routing_tables;

static void rt_free_hostcache(rtable *tab);
static void rt_notify_hostcache(rtable *tab, net *net);
static void rt_update_hostcache(rtable *tab);
static void rt_next_hop_update(rtable *tab);
static inline void rt_prune_table(rtable *tab);


/* Like fib_route(), but skips empty net entries */
static inline void *
net_route_ip4(rtable *t, net_addr_ip4 *n)
{
  net *r;

  while (r = net_find_valid(t, (net_addr *) n), (!r) && (n->pxlen > 0))
  {
    n->pxlen--;
    ip4_clrbit(&n->prefix, n->pxlen);
  }

  return r;
}

static inline void *
net_route_ip6(rtable *t, net_addr_ip6 *n)
{
  net *r;

  while (r = net_find_valid(t, (net_addr *) n), (!r) && (n->pxlen > 0))
  {
    n->pxlen--;
    ip6_clrbit(&n->prefix, n->pxlen);
  }

  return r;
}

static inline void *
net_route_ip6_sadr(rtable *t, net_addr_ip6_sadr *n)
{
  struct fib_node *fn;

  while (1)
  {
    net *best = NULL;
    int best_pxlen = 0;

    /* We need to do dst first matching. Since sadr addresses are hashed on dst
       prefix only, find the hash table chain and go through it to find the
       match with the smallest matching src prefix. */
    for (fn = fib_get_chain(&t->fib, (net_addr *) n); fn; fn = fn->next)
    {
      net_addr_ip6_sadr *a = (void *) fn->addr;

      if (net_equal_dst_ip6_sadr(n, a) &&
	  net_in_net_src_ip6_sadr(n, a) &&
	  (a->src_pxlen >= best_pxlen))
      {
	best = fib_node_to_user(&t->fib, fn);
	best_pxlen = a->src_pxlen;
      }
    }

    if (best)
      return best;

    if (!n->dst_pxlen)
      break;

    n->dst_pxlen--;
    ip6_clrbit(&n->dst_prefix, n->dst_pxlen);
  }

  return NULL;
}

void *
net_route(rtable *tab, const net_addr *n)
{
  ASSERT(tab->addr_type == n->type);

  net_addr *n0 = alloca(n->length);
  net_copy(n0, n);

  switch (n->type)
  {
  case NET_IP4:
  case NET_VPN4:
  case NET_ROA4:
    return net_route_ip4(tab, (net_addr_ip4 *) n0);

  case NET_IP6:
  case NET_VPN6:
  case NET_ROA6:
    return net_route_ip6(tab, (net_addr_ip6 *) n0);

  case NET_IP6_SADR:
    return net_route_ip6_sadr(tab, (net_addr_ip6_sadr *) n0);

  default:
    return NULL;
  }
}


static int
net_roa_check_ip4(rtable *tab, const net_addr_ip4 *px, u32 asn)
{
  struct net_addr_roa4 n = NET_ADDR_ROA4(px->prefix, px->pxlen, 0, 0);
  struct fib_node *fn;
  int anything = 0;

  while (1)
  {
    for (fn = fib_get_chain(&tab->fib, (net_addr *) &n); fn; fn = fn->next)
    {
      net_addr_roa4 *roa = (void *) fn->addr;
      net *r = fib_node_to_user(&tab->fib, fn);

      if (net_equal_prefix_roa4(roa, &n) && rte_is_valid(r->routes))
      {
	anything = 1;
	if (asn && (roa->asn == asn) && (roa->max_pxlen >= px->pxlen))
	  return ROA_VALID;
      }
    }

    if (n.pxlen == 0)
      break;

    n.pxlen--;
    ip4_clrbit(&n.prefix, n.pxlen);
  }

  return anything ? ROA_INVALID : ROA_UNKNOWN;
}

static int
net_roa_check_ip6(rtable *tab, const net_addr_ip6 *px, u32 asn)
{
  struct net_addr_roa6 n = NET_ADDR_ROA6(px->prefix, px->pxlen, 0, 0);
  struct fib_node *fn;
  int anything = 0;

  while (1)
  {
    for (fn = fib_get_chain(&tab->fib, (net_addr *) &n); fn; fn = fn->next)
    {
      net_addr_roa6 *roa = (void *) fn->addr;
      net *r = fib_node_to_user(&tab->fib, fn);

      if (net_equal_prefix_roa6(roa, &n) && rte_is_valid(r->routes))
      {
	anything = 1;
	if (asn && (roa->asn == asn) && (roa->max_pxlen >= px->pxlen))
	  return ROA_VALID;
      }
    }

    if (n.pxlen == 0)
      break;

    n.pxlen--;
    ip6_clrbit(&n.prefix, n.pxlen);
  }

  return anything ? ROA_INVALID : ROA_UNKNOWN;
}

/**
 * roa_check - check validity of route origination in a ROA table
 * @tab: ROA table
 * @n: network prefix to check
 * @asn: AS number of network prefix
 *
 * Implements RFC 6483 route validation for the given network prefix. The
 * procedure is to find all candidate ROAs - ROAs whose prefixes cover the given
 * network prefix. If there is no candidate ROA, return ROA_UNKNOWN. If there is
 * a candidate ROA with matching ASN and maxlen field greater than or equal to
 * the given prefix length, return ROA_VALID. Otherwise, return ROA_INVALID. If
 * caller cannot determine origin AS, 0 could be used (in that case ROA_VALID
 * cannot happen). Table @tab must have type NET_ROA4 or NET_ROA6, network @n
 * must have type NET_IP4 or NET_IP6, respectively.
 */
int
net_roa_check(rtable *tab, const net_addr *n, u32 asn)
{
  if ((tab->addr_type == NET_ROA4) && (n->type == NET_IP4))
    return net_roa_check_ip4(tab, (const net_addr_ip4 *) n, asn);
  else if ((tab->addr_type == NET_ROA6) && (n->type == NET_IP6))
    return net_roa_check_ip6(tab, (const net_addr_ip6 *) n, asn);
  else
    return ROA_UNKNOWN;	/* Should not happen */
}

/**
 * rte_find - find a route
 * @net: network node
 * @src: route source
 *
 * The rte_find() function returns a route for destination @net
 * which is from route source @src.
 */
rte *
rte_find(net *net, struct rte_src *src)
{
  rte *e = net->routes;

  while (e && e->attrs->src != src)
    e = e->next;
  return e;
}

/**
 * rte_get_temp - get a temporary &rte
 * @a: attributes to assign to the new route (a &rta; in case it's
 * un-cached, rte_update() will create a cached copy automatically)
 *
 * Create a temporary &rte and bind it with the attributes @a.
 * Also set route preference to the default preference set for
 * the protocol.
 */
rte *
rte_get_temp(rta *a)
{
  rte *e = sl_alloc(rte_slab);

  e->attrs = a;
  e->flags = 0;
  e->pref = 0;
  return e;
}

rte *
rte_do_cow(rte *r)
{
  rte *e = sl_alloc(rte_slab);

  memcpy(e, r, sizeof(rte));
  e->attrs = rta_clone(r->attrs);
  e->flags = 0;
  return e;
}

/**
 * rte_cow_rta - get a private writable copy of &rte with writable &rta
 * @r: a route entry to be copied
 * @lp: a linpool from which to allocate &rta
 *
 * rte_cow_rta() takes a &rte and prepares it and associated &rta for
 * modification. There are three possibilities: First, both &rte and &rta are
 * private copies, in that case they are returned unchanged.  Second, &rte is
 * private copy, but &rta is cached, in that case &rta is duplicated using
 * rta_do_cow(). Third, both &rte is shared and &rta is cached, in that case
 * both structures are duplicated by rte_do_cow() and rta_do_cow().
 *
 * Note that in the second case, cached &rta loses one reference, while private
 * copy created by rta_do_cow() is a shallow copy sharing indirect data (eattrs,
 * nexthops, ...) with it. To work properly, original shared &rta should have
 * another reference during the life of created private copy.
 *
 * Result: a pointer to the new writable &rte with writable &rta.
 */
rte *
rte_cow_rta(rte *r, linpool *lp)
{
  if (!rta_is_cached(r->attrs))
    return r;

  r = rte_cow(r);
  rta *a = rta_do_cow(r->attrs, lp);
  rta_free(r->attrs);
  r->attrs = a;
  return r;
}

static int				/* Actually better or at least as good as */
rte_better(rte *new, rte *old)
{
  int (*better)(rte *, rte *);

  if (!rte_is_valid(old))
    return 1;
  if (!rte_is_valid(new))
    return 0;

  if (new->pref > old->pref)
    return 1;
  if (new->pref < old->pref)
    return 0;
  if (new->attrs->src->proto->proto != old->attrs->src->proto->proto)
    {
      /*
       *  If the user has configured protocol preferences, so that two different protocols
       *  have the same preference, try to break the tie by comparing addresses. Not too
       *  useful, but keeps the ordering of routes unambiguous.
       */
      return new->attrs->src->proto->proto > old->attrs->src->proto->proto;
    }
  if (better = new->attrs->src->proto->rte_better)
    return better(new, old);
  return 0;
}

static int
rte_mergable(rte *pri, rte *sec)
{
  int (*mergable)(rte *, rte *);

  if (!rte_is_valid(pri) || !rte_is_valid(sec))
    return 0;

  if (pri->pref != sec->pref)
    return 0;

  if (pri->attrs->src->proto->proto != sec->attrs->src->proto->proto)
    return 0;

  if (mergable = pri->attrs->src->proto->rte_mergable)
    return mergable(pri, sec);

  return 0;
}

static void
rte_trace(struct proto *p, rte *e, int dir, char *msg)
{
  log(L_TRACE "%s %c %s %N %s", p->name, dir, msg, e->net->n.addr, rta_dest_name(e->attrs->dest));
}

static inline void
rte_trace_in(uint flag, struct proto *p, rte *e, char *msg)
{
  if (p->debug & flag)
    rte_trace(p, e, '>', msg);
}

static inline void
rte_trace_out(uint flag, struct proto *p, rte *e, char *msg)
{
  if (p->debug & flag)
    rte_trace(p, e, '<', msg);
}

static rte *
export_filter_(struct channel *c, rte *rt0, rte **rt_free, linpool *pool, int silent)
{
  struct proto *p = c->proto;
  struct filter *filter = c->out_filter;
  struct proto_stats *stats = &c->stats;
  rte *rt;
  int v;

  rt = rt0;
  *rt_free = NULL;

  rte_make_tmp_attrs(&rt, pool);

  v = p->import_control ? p->import_control(p, &rt, pool) : 0;
  if (v < 0)
    {
      if (silent)
	goto reject;

      stats->exp_updates_rejected++;
      if (v == RIC_REJECT)
	rte_trace_out(D_FILTERS, p, rt, "rejected by protocol");
      goto reject;
    }
  if (v > 0)
    {
      if (!silent)
	rte_trace_out(D_FILTERS, p, rt, "forced accept by protocol");
      goto accept;
    }

  v = filter && ((filter == FILTER_REJECT) ||
		 (f_run(filter, &rt, pool,
			(silent ? FF_SILENT : 0)) > F_ACCEPT));
  if (v)
    {
      if (silent)
	goto reject;

      stats->exp_updates_filtered++;
      rte_trace_out(D_FILTERS, p, rt, "filtered out");
      goto reject;
    }

 accept:
  if (rt != rt0)
    *rt_free = rt;
  return rt;

 reject:
  /* Discard temporary rte */
  if (rt != rt0)
    rte_free(rt);
  return NULL;
}

static inline rte *
export_filter(struct channel *c, rte *rt0, rte **rt_free, int silent)
{
  return export_filter_(c, rt0, rt_free, rte_update_pool, silent);
}

static void
do_rt_notify(struct channel *c, net *net, rte *new, rte *old, int refeed)
{
  struct proto *p = c->proto;
  struct proto_stats *stats = &c->stats;


  /*
   * First, apply export limit.
   *
   * Export route limits has several problems. Because exp_routes
   * counter is reset before refeed, we don't really know whether
   * limit is breached and whether the update is new or not. Therefore
   * the number of really exported routes may exceed the limit
   * temporarily (routes exported before and new routes in refeed).
   *
   * Minor advantage is that if the limit is decreased and refeed is
   * requested, the number of exported routes really decrease.
   *
   * Second problem is that with export limits, we don't know whether
   * old was really exported (it might be blocked by limit). When a
   * withdraw is exported, we announce it even when the previous
   * update was blocked. This is not a big issue, but the same problem
   * is in updating exp_routes counter. Therefore, to be consistent in
   * increases and decreases of exp_routes, we count exported routes
   * regardless of blocking by limits.
   *
   * Similar problem is in handling updates - when a new route is
   * received and blocking is active, the route would be blocked, but
   * when an update for the route will be received later, the update
   * would be propagated (as old != NULL). Therefore, we have to block
   * also non-new updates (contrary to import blocking).
   */

  struct channel_limit *l = &c->out_limit;
  if (l->action && new)
    {
      if ((!old || refeed) && (stats->exp_routes >= l->limit))
	channel_notify_limit(c, l, PLD_OUT, stats->exp_routes);

      if (l->state == PLS_BLOCKED)
	{
	  stats->exp_routes++;	/* see note above */
	  stats->exp_updates_rejected++;
	  rte_trace_out(D_FILTERS, p, new, "rejected [limit]");
	  new = NULL;

	  if (!old)
	    return;
	}
    }


  if (new)
    stats->exp_updates_accepted++;
  else
    stats->exp_withdraws_accepted++;

  /* Hack: We do not decrease exp_routes during refeed, we instead
     reset exp_routes at the start of refeed. */
  if (new)
    stats->exp_routes++;
  if (old && !refeed)
    stats->exp_routes--;

  if (p->debug & D_ROUTES)
    {
      if (new && old)
	rte_trace_out(D_ROUTES, p, new, "replaced");
      else if (new)
	rte_trace_out(D_ROUTES, p, new, "added");
      else if (old)
	rte_trace_out(D_ROUTES, p, old, "removed");
    }
  p->rt_notify(p, c, net, new, old);
}

static void
rt_notify_basic(struct channel *c, net *net, rte *new0, rte *old0, int refeed)
{
  struct proto *p = c->proto;

  rte *new = new0;
  rte *old = old0;
  rte *new_free = NULL;
  rte *old_free = NULL;

  if (new)
    c->stats.exp_updates_received++;
  else
    c->stats.exp_withdraws_received++;

  /*
   * This is a tricky part - we don't know whether route 'old' was exported to
   * protocol 'p' or was filtered by the export filter. We try to run the export
   * filter to know this to have a correct value in 'old' argument of rte_update
   * (and proper filter value).
   *
   * This is broken because 'configure soft' may change filters but keep routes.
   * Refeed cycle is expected to be called after change of the filters and with
   * old == new, therefore we do not even try to run the filter on an old route.
   * This may lead to 'spurious withdraws' but ensure that there are no 'missing
   * withdraws'.
   *
   * This is not completely safe as there is a window between reconfiguration
   * and the end of refeed - if a newly filtered route disappears during this
   * period, proper withdraw is not sent (because old would be also filtered)
   * and the route is not refeeded (because it disappeared before that).
   * Therefore, we also do not try to run the filter on old routes that are
   * older than the last filter change.
   */

  if (new)
    new = export_filter(c, new, &new_free, 0);

  log("XXX %N %p %p %u %t %t", net->n.addr, old, new, refeed, old ? old->lastmod : 0, c->last_tx_filter_change);
  if (old && !(refeed || (old->lastmod <= c->last_tx_filter_change)))
    old = export_filter(c, old, &old_free, 1);

  if (!new && !old)
  {
    /*
     * As mentioned above, 'old' value may be incorrect in some race conditions.
     * We generally ignore it with the exception of withdraw to pipe protocol.
     * In that case we rather propagate unfiltered withdraws regardless of
     * export filters to ensure that when a protocol is flushed, its routes are
     * removed from all tables. Possible spurious unfiltered withdraws are not
     * problem here as they are ignored if there is no corresponding route at
     * the other end of the pipe. We directly call rt_notify() hook instead of
     * do_rt_notify() to avoid logging and stat counters.
     */

#ifdef CONFIG_PIPE
    if ((p->proto == &proto_pipe) && !new0 && (p != old0->sender->proto))
      p->rt_notify(p, c, net, NULL, old0);
#endif

    return;
  }

  do_rt_notify(c, net, new, old, refeed);

  /* Discard temporary rte's */
  if (new_free)
    rte_free(new_free);
  if (old_free)
    rte_free(old_free);
}

static void
rt_notify_accepted(struct channel *c, net *net, rte *new_changed, rte *old_changed, rte *before_old, int feed)
{
  // struct proto *p = c->proto;

  rte *r;
  rte *new_best = NULL;
  rte *old_best = NULL;
  rte *new_free = NULL;
  rte *old_free = NULL;

  /* Used to track whether we met old_changed position. If before_old is NULL
     old_changed was the first and we met it implicitly before current best route. */
  int old_meet = old_changed && !before_old;

  /* Note that before_old is either NULL or valid (not rejected) route.
     If old_changed is valid, before_old have to be too. If old changed route
     was not valid, caller must use NULL for both old_changed and before_old. */

  if (new_changed)
    c->stats.exp_updates_received++;
  else
    c->stats.exp_withdraws_received++;

  /* First, find the new_best route - first accepted by filters */
  for (r=net->routes; rte_is_valid(r); r=r->next)
    {
      if (new_best = export_filter(c, r, &new_free, 0))
	break;

      /* Note if we walked around the position of old_changed route */
      if (r == before_old)
	old_meet = 1;
    }

  /*
   * Second, handle the feed case. That means we do not care for
   * old_best. It is NULL for feed, and the new_best for refeed.
   * For refeed, there is a hack similar to one in rt_notify_basic()
   * to ensure withdraws in case of changed filters
   */
  if (feed)
    {
      if (feed == 2)	/* refeed */
	old_best = new_best ? new_best :
	  (rte_is_valid(net->routes) ? net->routes : NULL);
      else
	old_best = NULL;

      if (!new_best && !old_best)
	return;

      goto found;
    }

  /*
   * Now, we find the old_best route. Generally, it is the same as the
   * new_best, unless new_best is the same as new_changed or
   * old_changed is accepted before new_best.
   *
   * There are four cases:
   *
   * - We would find and accept old_changed before new_best, therefore
   *   old_changed is old_best. In remaining cases we suppose this
   *   is not true.
   *
   * - We found no new_best, therefore there is also no old_best and
   *   we ignore this withdraw.
   *
   * - We found new_best different than new_changed, therefore
   *   old_best is the same as new_best and we ignore this update.
   *
   * - We found new_best the same as new_changed, therefore it cannot
   *   be old_best and we have to continue search for old_best.
   */

  /* First case */
  if (old_meet)
    if (old_best = export_filter(c, old_changed, &old_free, 1))
      goto found;

  /* Second case */
  if (!new_best)
    return;

  /* Third case, we use r instead of new_best, because export_filter() could change it */
  if (r != new_changed)
    {
      if (new_free)
	rte_free(new_free);
      return;
    }

  /* Fourth case */
  for (r=r->next; rte_is_valid(r); r=r->next)
    {
      if (old_best = export_filter(c, r, &old_free, 1))
	goto found;

      if (r == before_old)
	if (old_best = export_filter(c, old_changed, &old_free, 1))
	  goto found;
    }

  /* Implicitly, old_best is NULL and new_best is non-NULL */

 found:
  do_rt_notify(c, net, new_best, old_best, (feed == 2));

  /* Discard temporary rte's */
  if (new_free)
    rte_free(new_free);
  if (old_free)
    rte_free(old_free);
}


static struct nexthop *
nexthop_merge_rta(struct nexthop *nhs, rta *a, linpool *pool, int max)
{
  return nexthop_merge(nhs, &(a->nh), 1, 0, max, pool);
}

rte *
rt_export_merged(struct channel *c, net *net, rte **rt_free, linpool *pool, int silent)
{
  // struct proto *p = c->proto;
  struct nexthop *nhs = NULL;
  rte *best0, *best, *rt0, *rt, *tmp;

  best0 = net->routes;
  *rt_free = NULL;

  if (!rte_is_valid(best0))
    return NULL;

  best = export_filter_(c, best0, rt_free, pool, silent);

  if (!best || !rte_is_reachable(best))
    return best;

  for (rt0 = best0->next; rt0; rt0 = rt0->next)
  {
    if (!rte_mergable(best0, rt0))
      continue;

    rt = export_filter_(c, rt0, &tmp, pool, 1);

    if (!rt)
      continue;

    if (rte_is_reachable(rt))
      nhs = nexthop_merge_rta(nhs, rt->attrs, pool, c->merge_limit);

    if (tmp)
      rte_free(tmp);
  }

  if (nhs)
  {
    nhs = nexthop_merge_rta(nhs, best->attrs, pool, c->merge_limit);

    if (nhs->next)
    {
      best = rte_cow_rta(best, pool);
      nexthop_link(best->attrs, nhs);
    }
  }

  if (best != best0)
    *rt_free = best;

  return best;
}


static void
rt_notify_merged(struct channel *c, net *net, rte *new_changed, rte *old_changed,
		 rte *new_best, rte*old_best, int refeed)
{
  // struct proto *p = c->proto;

  rte *new_best_free = NULL;
  rte *old_best_free = NULL;
  rte *new_changed_free = NULL;
  rte *old_changed_free = NULL;

  /* We assume that all rte arguments are either NULL or rte_is_valid() */

  /* This check should be done by the caller */
  if (!new_best && !old_best)
    return;

  /* Check whether the change is relevant to the merged route */
  if ((new_best == old_best) && !refeed)
  {
    new_changed = rte_mergable(new_best, new_changed) ?
      export_filter(c, new_changed, &new_changed_free, 1) : NULL;

    old_changed = rte_mergable(old_best, old_changed) ?
      export_filter(c, old_changed, &old_changed_free, 1) : NULL;

    if (!new_changed && !old_changed)
      return;
  }

  if (new_best)
    c->stats.exp_updates_received++;
  else
    c->stats.exp_withdraws_received++;

  /* Prepare new merged route */
  if (new_best)
    new_best = rt_export_merged(c, net, &new_best_free, rte_update_pool, 0);

  /* Prepare old merged route (without proper merged next hops) */
  /* There are some issues with running filter on old route - see rt_notify_basic() */
  if (old_best && !refeed)
    old_best = export_filter(c, old_best, &old_best_free, 1);

  if (new_best || old_best)
    do_rt_notify(c, net, new_best, old_best, refeed);

  /* Discard temporary rte's */
  if (new_best_free)
    rte_free(new_best_free);
  if (old_best_free)
    rte_free(old_best_free);
  if (new_changed_free)
    rte_free(new_changed_free);
  if (old_changed_free)
    rte_free(old_changed_free);
}


/**
 * rte_announce - announce a routing table change
 * @tab: table the route has been added to
 * @type: type of route announcement (RA_OPTIMAL or RA_ANY)
 * @net: network in question
 * @new: the new route to be announced
 * @old: the previous route for the same network
 * @new_best: the new best route for the same network
 * @old_best: the previous best route for the same network
 * @before_old: The previous route before @old for the same network.
 *		If @before_old is NULL @old was the first.
 *
 * This function gets a routing table update and announces it
 * to all protocols that acccepts given type of route announcement
 * and are connected to the same table by their announcement hooks.
 *
 * Route announcement of type %RA_OPTIMAL si generated when optimal
 * route (in routing table @tab) changes. In that case @old stores the
 * old optimal route.
 *
 * Route announcement of type %RA_ANY si generated when any route (in
 * routing table @tab) changes In that case @old stores the old route
 * from the same protocol.
 *
 * For each appropriate protocol, we first call its import_control()
 * hook which performs basic checks on the route (each protocol has a
 * right to veto or force accept of the route before any filter is
 * asked) and adds default values of attributes specific to the new
 * protocol (metrics, tags etc.).  Then it consults the protocol's
 * export filter and if it accepts the route, the rt_notify() hook of
 * the protocol gets called.
 */
static void
rte_announce(rtable *tab, unsigned type, net *net, rte *new, rte *old,
	     rte *new_best, rte *old_best, rte *before_old)
{
  if (!rte_is_valid(new))
    new = NULL;

  if (!rte_is_valid(old))
    old = before_old = NULL;

  if (!rte_is_valid(new_best))
    new_best = NULL;

  if (!rte_is_valid(old_best))
    old_best = NULL;

  if (!old && !new)
    return;

  if ((type == RA_OPTIMAL) && tab->hostcache)
    rt_notify_hostcache(tab, net);

  struct channel *c; node *n;
  WALK_LIST2(c, n, tab->channels, table_node)
    {
      if (c->export_state == ES_DOWN)
	continue;

      if (c->ra_mode == type)
	if (type == RA_ACCEPTED)
	  rt_notify_accepted(c, net, new, old, before_old, 0);
	else if (type == RA_MERGED)
	  rt_notify_merged(c, net, new, old, new_best, old_best, 0);
	else
	  rt_notify_basic(c, net, new, old, 0);
    }
}

static inline int
rte_validate(rte *e)
{
  int c;
  net *n = e->net;

  if (!net_validate(n->n.addr))
  {
    log(L_WARN "Ignoring bogus prefix %N received via %s",
	n->n.addr, e->sender->proto->name);
    return 0;
  }

  /* FIXME: better handling different nettypes */
  c = !net_is_flow(n->n.addr) ?
    net_classify(n->n.addr): (IADDR_HOST | SCOPE_UNIVERSE);
  if ((c < 0) || !(c & IADDR_HOST) || ((c & IADDR_SCOPE_MASK) <= SCOPE_LINK))
  {
    log(L_WARN "Ignoring bogus route %N received via %s",
	n->n.addr, e->sender->proto->name);
    return 0;
  }

  if (net_type_match(n->n.addr, NB_DEST) == !e->attrs->dest)
  {
    log(L_WARN "Ignoring route %N with invalid dest %d received via %s",
	n->n.addr, e->attrs->dest, e->sender->proto->name);
    return 0;
  }

  if ((e->attrs->dest == RTD_UNICAST) && !nexthop_is_sorted(&(e->attrs->nh)))
  {
    log(L_WARN "Ignoring unsorted multipath route %N received via %s",
	n->n.addr, e->sender->proto->name);
    return 0;
  }

  return 1;
}

/**
 * rte_free - delete a &rte
 * @e: &rte to be deleted
 *
 * rte_free() deletes the given &rte from the routing table it's linked to.
 */
void
rte_free(rte *e)
{
  if (rta_is_cached(e->attrs))
    rta_free(e->attrs);
  sl_free(rte_slab, e);
}

static inline void
rte_free_quick(rte *e)
{
  rta_free(e->attrs);
  sl_free(rte_slab, e);
}

static int
rte_same(rte *x, rte *y)
{
  return
    x->attrs == y->attrs &&
    x->flags == y->flags &&
    x->pflags == y->pflags &&
    x->pref == y->pref &&
    (!x->attrs->src->proto->rte_same || x->attrs->src->proto->rte_same(x, y));
}

static inline int rte_is_ok(rte *e) { return e && !rte_is_filtered(e); }

static void
rte_recalculate(struct channel *c, net *net, rte *new, struct rte_src *src)
{
  struct proto *p = c->proto;
  struct rtable *table = c->table;
  struct proto_stats *stats = &c->stats;
  static struct tbf rl_pipe = TBF_DEFAULT_LOG_LIMITS;
  rte *before_old = NULL;
  rte *old_best = net->routes;
  rte *old = NULL;
  rte **k;

  k = &net->routes;			/* Find and remove original route from the same protocol */
  while (old = *k)
    {
      if (old->attrs->src == src)
	{
	  /* If there is the same route in the routing table but from
	   * a different sender, then there are two paths from the
	   * source protocol to this routing table through transparent
	   * pipes, which is not allowed.
	   *
	   * We log that and ignore the route. If it is withdraw, we
	   * ignore it completely (there might be 'spurious withdraws',
	   * see FIXME in do_rte_announce())
	   */
	  if (old->sender->proto != p)
	    {
	      if (new)
		{
		  log_rl(&rl_pipe, L_ERR "Pipe collision detected when sending %N to table %s",
		      net->n.addr, table->name);
		  rte_free_quick(new);
		}
	      return;
	    }

	  if (new && rte_same(old, new))
	    {
	      /* No changes, ignore the new route */

	      if (!rte_is_filtered(new))
		{
		  stats->imp_updates_ignored++;
		  rte_trace_in(D_ROUTES, p, new, "ignored");
		}

	      rte_free_quick(new);
	      return;
	    }
	  *k = old->next;
	  break;
	}
      k = &old->next;
      before_old = old;
    }

  if (!old)
    before_old = NULL;

  if (!old && !new)
    {
      stats->imp_withdraws_ignored++;
      return;
    }

  int new_ok = rte_is_ok(new);
  int old_ok = rte_is_ok(old);

  struct channel_limit *l = &c->rx_limit;
  if (l->action && !old && new)
    {
      u32 all_routes = stats->imp_routes + stats->filt_routes;

      if (all_routes >= l->limit)
	channel_notify_limit(c, l, PLD_RX, all_routes);

      if (l->state == PLS_BLOCKED)
	{
	  /* In receive limit the situation is simple, old is NULL so
	     we just free new and exit like nothing happened */

	  stats->imp_updates_ignored++;
	  rte_trace_in(D_FILTERS, p, new, "ignored [limit]");
	  rte_free_quick(new);
	  return;
	}
    }

  l = &c->in_limit;
  if (l->action && !old_ok && new_ok)
    {
      if (stats->imp_routes >= l->limit)
	channel_notify_limit(c, l, PLD_IN, stats->imp_routes);

      if (l->state == PLS_BLOCKED)
	{
	  /* In import limit the situation is more complicated. We
	     shouldn't just drop the route, we should handle it like
	     it was filtered. We also have to continue the route
	     processing if old or new is non-NULL, but we should exit
	     if both are NULL as this case is probably assumed to be
	     already handled. */

	  stats->imp_updates_ignored++;
	  rte_trace_in(D_FILTERS, p, new, "ignored [limit]");

	  if (c->in_keep_filtered)
	    new->flags |= REF_FILTERED;
	  else
	    { rte_free_quick(new); new = NULL; }

	  /* Note that old && !new could be possible when
	     c->in_keep_filtered changed in the recent past. */

	  if (!old && !new)
	    return;

	  new_ok = 0;
	  goto skip_stats1;
	}
    }

  if (new_ok)
    stats->imp_updates_accepted++;
  else if (old_ok)
    stats->imp_withdraws_accepted++;
  else
    stats->imp_withdraws_ignored++;

 skip_stats1:

  if (new)
    rte_is_filtered(new) ? stats->filt_routes++ : stats->imp_routes++;
  if (old)
    rte_is_filtered(old) ? stats->filt_routes-- : stats->imp_routes--;

  if (table->config->sorted)
    {
      /* If routes are sorted, just insert new route to appropriate position */
      if (new)
	{
	  if (before_old && !rte_better(new, before_old))
	    k = &before_old->next;
	  else
	    k = &net->routes;

	  for (; *k; k=&(*k)->next)
	    if (rte_better(new, *k))
	      break;

	  new->next = *k;
	  *k = new;
	}
    }
  else
    {
      /* If routes are not sorted, find the best route and move it on
	 the first position. There are several optimized cases. */

      if (src->proto->rte_recalculate && src->proto->rte_recalculate(table, net, new, old, old_best))
	goto do_recalculate;

      if (new && rte_better(new, old_best))
	{
	  /* The first case - the new route is cleary optimal,
	     we link it at the first position */

	  new->next = net->routes;
	  net->routes = new;
	}
      else if (old == old_best)
	{
	  /* The second case - the old best route disappeared, we add the
	     new route (if we have any) to the list (we don't care about
	     position) and then we elect the new optimal route and relink
	     that route at the first position and announce it. New optimal
	     route might be NULL if there is no more routes */

	do_recalculate:
	  /* Add the new route to the list */
	  if (new)
	    {
	      new->next = net->routes;
	      net->routes = new;
	    }

	  /* Find a new optimal route (if there is any) */
	  if (net->routes)
	    {
	      rte **bp = &net->routes;
	      for (k=&(*bp)->next; *k; k=&(*k)->next)
		if (rte_better(*k, *bp))
		  bp = k;

	      /* And relink it */
	      rte *best = *bp;
	      *bp = best->next;
	      best->next = net->routes;
	      net->routes = best;
	    }
	}
      else if (new)
	{
	  /* The third case - the new route is not better than the old
	     best route (therefore old_best != NULL) and the old best
	     route was not removed (therefore old_best == net->routes).
	     We just link the new route after the old best route. */

	  ASSERT(net->routes != NULL);
	  new->next = net->routes->next;
	  net->routes->next = new;
	}
      /* The fourth (empty) case - suboptimal route was removed, nothing to do */
    }

  if (new)
    new->lastmod = current_time();

  /* Log the route change */
  if (p->debug & D_ROUTES)
    {
      if (new_ok)
	rte_trace(p, new, '>', new == net->routes ? "added [best]" : "added");
      else if (old_ok)
	{
	  if (old != old_best)
	    rte_trace(p, old, '>', "removed");
	  else if (rte_is_ok(net->routes))
	    rte_trace(p, old, '>', "removed [replaced]");
	  else
	    rte_trace(p, old, '>', "removed [sole]");
	}
    }

  /* Propagate the route change */
  rte_announce(table, RA_ANY, net, new, old, NULL, NULL, NULL);
  if (net->routes != old_best)
    rte_announce(table, RA_OPTIMAL, net, net->routes, old_best, NULL, NULL, NULL);
  if (table->config->sorted)
    rte_announce(table, RA_ACCEPTED, net, new, old, NULL, NULL, before_old);
  rte_announce(table, RA_MERGED, net, new, old, net->routes, old_best, NULL);

  if (!net->routes &&
      (table->gc_counter++ >= table->config->gc_max_ops) &&
      (table->gc_time + table->config->gc_min_time <= current_time()))
    rt_schedule_prune(table);

  if (old_ok && p->rte_remove)
    p->rte_remove(net, old);
  if (new_ok && p->rte_insert)
    p->rte_insert(net, new);

  if (old)
    rte_free_quick(old);
}

static int rte_update_nest_cnt;		/* Nesting counter to allow recursive updates */

static inline void
rte_update_lock(void)
{
  rte_update_nest_cnt++;
}

static inline void
rte_update_unlock(void)
{
  if (!--rte_update_nest_cnt)
    lp_flush(rte_update_pool);
}

static inline void
rte_hide_dummy_routes(net *net, rte **dummy)
{
  if (net->routes && net->routes->attrs->source == RTS_DUMMY)
  {
    *dummy = net->routes;
    net->routes = (*dummy)->next;
  }
}

static inline void
rte_unhide_dummy_routes(net *net, rte **dummy)
{
  if (*dummy)
  {
    (*dummy)->next = net->routes;
    net->routes = *dummy;
  }
}

/**
 * rte_update - enter a new update to a routing table
 * @table: table to be updated
 * @c: channel doing the update
 * @net: network node
 * @p: protocol submitting the update
 * @src: protocol originating the update
 * @new: a &rte representing the new route or %NULL for route removal.
 *
 * This function is called by the routing protocols whenever they discover
 * a new route or wish to update/remove an existing route. The right announcement
 * sequence is to build route attributes first (either un-cached with @aflags set
 * to zero or a cached one using rta_lookup(); in this case please note that
 * you need to increase the use count of the attributes yourself by calling
 * rta_clone()), call rte_get_temp() to obtain a temporary &rte, fill in all
 * the appropriate data and finally submit the new &rte by calling rte_update().
 *
 * @src specifies the protocol that originally created the route and the meaning
 * of protocol-dependent data of @new. If @new is not %NULL, @src have to be the
 * same value as @new->attrs->proto. @p specifies the protocol that called
 * rte_update(). In most cases it is the same protocol as @src. rte_update()
 * stores @p in @new->sender;
 *
 * When rte_update() gets any route, it automatically validates it (checks,
 * whether the network and next hop address are valid IP addresses and also
 * whether a normal routing protocol doesn't try to smuggle a host or link
 * scope route to the table), converts all protocol dependent attributes stored
 * in the &rte to temporary extended attributes, consults import filters of the
 * protocol to see if the route should be accepted and/or its attributes modified,
 * stores the temporary attributes back to the &rte.
 *
 * Now, having a "public" version of the route, we
 * automatically find any old route defined by the protocol @src
 * for network @n, replace it by the new one (or removing it if @new is %NULL),
 * recalculate the optimal route for this destination and finally broadcast
 * the change (if any) to all routing protocols by calling rte_announce().
 *
 * All memory used for attribute lists and other temporary allocations is taken
 * from a special linear pool @rte_update_pool and freed when rte_update()
 * finishes.
 */

void
rte_update2(struct channel *c, const net_addr *n, rte *new, struct rte_src *src)
{
  struct proto *p = c->proto;
  struct proto_stats *stats = &c->stats;
  struct filter *filter = c->in_filter;
  rte *dummy = NULL;
  net *nn;

  ASSERT(c->channel_state == CS_UP);

  rte_update_lock();
  if (new)
    {
      nn = net_get(c->table, n);

      new->net = nn;
      new->sender = c;

      if (!new->pref)
	new->pref = c->preference;

      stats->imp_updates_received++;
      if (!rte_validate(new))
	{
	  rte_trace_in(D_FILTERS, p, new, "invalid");
	  stats->imp_updates_invalid++;
	  goto drop;
	}

      if (filter == FILTER_REJECT)
	{
	  stats->imp_updates_filtered++;
	  rte_trace_in(D_FILTERS, p, new, "filtered out");

	  if (! c->in_keep_filtered)
	    goto drop;

	  /* new is a private copy, i could modify it */
	  new->flags |= REF_FILTERED;
	}
      else
	{
	  rte_make_tmp_attrs(&new, rte_update_pool);
	  if (filter && (filter != FILTER_REJECT))
	    {
	      ea_list *oldea = new->attrs->eattrs;
	      int fr = f_run(filter, &new, rte_update_pool, 0);
	      if (fr > F_ACCEPT)
		{
		  stats->imp_updates_filtered++;
		  rte_trace_in(D_FILTERS, p, new, "filtered out");

		  if (! c->in_keep_filtered)
		    goto drop;

		  new->flags |= REF_FILTERED;
		}
	      if (new->attrs->eattrs != oldea && src->proto->store_tmp_attrs)
		src->proto->store_tmp_attrs(new);
	    }
	}
      if (!rta_is_cached(new->attrs)) /* Need to copy attributes */
	new->attrs = rta_lookup(new->attrs);
      new->flags |= REF_COW;
    }
  else
    {
      stats->imp_withdraws_received++;

      if (!(nn = net_find(c->table, n)) || !src)
	{
	  stats->imp_withdraws_ignored++;
	  rte_update_unlock();
	  return;
	}
    }

 recalc:
  rte_hide_dummy_routes(nn, &dummy);
  rte_recalculate(c, nn, new, src);
  rte_unhide_dummy_routes(nn, &dummy);
  rte_update_unlock();
  return;

 drop:
  rte_free(new);
  new = NULL;
  goto recalc;
}

/* Independent call to rte_announce(), used from next hop
   recalculation, outside of rte_update(). new must be non-NULL */
static inline void
rte_announce_i(rtable *tab, unsigned type, net *net, rte *new, rte *old,
	       rte *new_best, rte *old_best)
{
  rte_update_lock();
  rte_announce(tab, type, net, new, old, new_best, old_best, NULL);
  rte_update_unlock();
}

static inline void
rte_discard(rte *old)	/* Non-filtered route deletion, used during garbage collection */
{
  rte_update_lock();
  rte_recalculate(old->sender, old->net, NULL, old->attrs->src);
  rte_update_unlock();
}

/* Check rtable for best route to given net whether it would be exported do p */
int
rt_examine(rtable *t, net_addr *a, struct proto *p, struct filter *filter)
{
  net *n = net_find(t, a);
  rte *rt = n ? n->routes : NULL;

  if (!rte_is_valid(rt))
    return 0;

  rte_update_lock();

  /* Rest is stripped down export_filter() */
  rte_make_tmp_attrs(&rt, rte_update_pool);
  int v = p->import_control ? p->import_control(p, &rt, rte_update_pool) : 0;
  if (v == RIC_PROCESS)
    v = (f_run(filter, &rt, rte_update_pool, FF_SILENT) <= F_ACCEPT);

   /* Discard temporary rte */
  if (rt != n->routes)
    rte_free(rt);

  rte_update_unlock();

  return v > 0;
}


/**
 * rt_refresh_begin - start a refresh cycle
 * @t: related routing table
 * @c related channel
 *
 * This function starts a refresh cycle for given routing table and announce
 * hook. The refresh cycle is a sequence where the protocol sends all its valid
 * routes to the routing table (by rte_update()). After that, all protocol
 * routes (more precisely routes with @c as @sender) not sent during the
 * refresh cycle but still in the table from the past are pruned. This is
 * implemented by marking all related routes as stale by REF_STALE flag in
 * rt_refresh_begin(), then marking all related stale routes with REF_DISCARD
 * flag in rt_refresh_end() and then removing such routes in the prune loop.
 */
void
rt_refresh_begin(rtable *t, struct channel *c)
{
  FIB_WALK(&t->fib, net, n)
    {
      rte *e;
      for (e = n->routes; e; e = e->next)
	if (e->sender == c)
	  e->flags |= REF_STALE;
    }
  FIB_WALK_END;
}

/**
 * rt_refresh_end - end a refresh cycle
 * @t: related routing table
 * @c: related channel
 *
 * This function ends a refresh cycle for given routing table and announce
 * hook. See rt_refresh_begin() for description of refresh cycles.
 */
void
rt_refresh_end(rtable *t, struct channel *c)
{
  int prune = 0;

  FIB_WALK(&t->fib, net, n)
    {
      rte *e;
      for (e = n->routes; e; e = e->next)
	if ((e->sender == c) && (e->flags & REF_STALE))
	  {
	    e->flags |= REF_DISCARD;
	    prune = 1;
	  }
    }
  FIB_WALK_END;

  if (prune)
    rt_schedule_prune(t);
}


/**
 * rte_dump - dump a route
 * @e: &rte to be dumped
 *
 * This functions dumps contents of a &rte to debug output.
 */
void
rte_dump(rte *e)
{
  net *n = e->net;
  debug("%-1N ", n->n.addr);
  debug("KF=%02x PF=%02x pref=%d ", n->n.flags, e->pflags, e->pref);
  rta_dump(e->attrs);
  if (e->attrs->src->proto->proto->dump_attrs)
    e->attrs->src->proto->proto->dump_attrs(e);
  debug("\n");
}

/**
 * rt_dump - dump a routing table
 * @t: routing table to be dumped
 *
 * This function dumps contents of a given routing table to debug output.
 */
void
rt_dump(rtable *t)
{
  debug("Dump of routing table <%s>\n", t->name);
#ifdef DEBUGGING
  fib_check(&t->fib);
#endif
  FIB_WALK(&t->fib, net, n)
    {
      rte *e;
      for(e=n->routes; e; e=e->next)
	rte_dump(e);
    }
  FIB_WALK_END;
  debug("\n");
}

/**
 * rt_dump_all - dump all routing tables
 *
 * This function dumps contents of all routing tables to debug output.
 */
void
rt_dump_all(void)
{
  rtable *t;

  WALK_LIST(t, routing_tables)
    rt_dump(t);
}

static inline void
rt_schedule_hcu(rtable *tab)
{
  if (tab->hcu_scheduled)
    return;

  tab->hcu_scheduled = 1;
  ev_schedule(tab->rt_event);
}

static inline void
rt_schedule_nhu(rtable *tab)
{
  if (tab->nhu_state == NHU_CLEAN)
    ev_schedule(tab->rt_event);

  /* state change:
   *   NHU_CLEAN   -> NHU_SCHEDULED
   *   NHU_RUNNING -> NHU_DIRTY
   */
  tab->nhu_state |= NHU_SCHEDULED;
}

void
rt_schedule_prune(rtable *tab)
{
  if (tab->prune_state == 0)
    ev_schedule(tab->rt_event);

  /* state change 0->1, 2->3 */
  tab->prune_state |= 1;
}


static void
rt_event(void *ptr)
{
  rtable *tab = ptr;

  rt_lock_table(tab);

  if (tab->hcu_scheduled)
    rt_update_hostcache(tab);

  if (tab->nhu_state)
    rt_next_hop_update(tab);

  if (tab->prune_state)
    rt_prune_table(tab);

  rt_unlock_table(tab);
}

void
rt_setup(pool *p, rtable *t, struct rtable_config *cf)
{
  bzero(t, sizeof(*t));
  t->name = cf->name;
  t->config = cf;
  t->addr_type = cf->addr_type;
  fib_init(&t->fib, p, t->addr_type, sizeof(net), OFFSETOF(net, n), 0, NULL);
  init_list(&t->channels);

  t->rt_event = ev_new(p);
  t->rt_event->hook = rt_event;
  t->rt_event->data = t;
  t->gc_time = current_time();
}

/**
 * rt_init - initialize routing tables
 *
 * This function is called during BIRD startup. It initializes the
 * routing table module.
 */
void
rt_init(void)
{
  rta_init();
  rt_table_pool = rp_new(&root_pool, "Routing tables");
  rte_update_pool = lp_new_default(rt_table_pool);
  rte_slab = sl_new(rt_table_pool, sizeof(rte));
  init_list(&routing_tables);
}


/**
 * rt_prune_table - prune a routing table
 *
 * The prune loop scans routing tables and removes routes belonging to flushing
 * protocols, discarded routes and also stale network entries. It is called from
 * rt_event(). The event is rescheduled if the current iteration do not finish
 * the table. The pruning is directed by the prune state (@prune_state),
 * specifying whether the prune cycle is scheduled or running, and there
 * is also a persistent pruning iterator (@prune_fit).
 *
 * The prune loop is used also for channel flushing. For this purpose, the
 * channels to flush are marked before the iteration and notified after the
 * iteration.
 */
static void
rt_prune_table(rtable *tab)
{
  struct fib_iterator *fit = &tab->prune_fit;
  int limit = 512;

  struct channel *c;
  node *n, *x;

  DBG("Pruning route table %s\n", tab->name);
#ifdef DEBUGGING
  fib_check(&tab->fib);
#endif

  if (tab->prune_state == 0)
    return;

  if (tab->prune_state == 1)
  {
    /* Mark channels to flush */
    WALK_LIST2(c, n, tab->channels, table_node)
      if (c->channel_state == CS_FLUSHING)
	c->flush_active = 1;

    FIB_ITERATE_INIT(fit, &tab->fib);
    tab->prune_state = 2;
  }

again:
  FIB_ITERATE_START(&tab->fib, fit, net, n)
    {
      rte *e;

    rescan:
      for (e=n->routes; e; e=e->next)
	if (e->sender->flush_active || (e->flags & REF_DISCARD))
	  {
	    if (limit <= 0)
	      {
		FIB_ITERATE_PUT(fit);
		ev_schedule(tab->rt_event);
		return;
	      }

	    rte_discard(e);
	    limit--;

	    goto rescan;
	  }

      if (!n->routes)		/* Orphaned FIB entry */
	{
	  FIB_ITERATE_PUT(fit);
	  fib_delete(&tab->fib, n);
	  goto again;
	}
    }
  FIB_ITERATE_END;

#ifdef DEBUGGING
  fib_check(&tab->fib);
#endif

  tab->gc_counter = 0;
  tab->gc_time = current_time();

  /* state change 2->0, 3->1 */
  tab->prune_state &= 1;

  if (tab->prune_state > 0)
    ev_schedule(tab->rt_event);

  /* FIXME: This should be handled in a better way */
  rt_prune_sources();

  /* Close flushed channels */
  WALK_LIST2_DELSAFE(c, n, x, tab->channels, table_node)
    if (c->flush_active)
      {
	c->flush_active = 0;
	channel_set_state(c, CS_DOWN);
      }

  return;
}

void
rt_preconfig(struct config *c)
{
  init_list(&c->tables);

  rt_new_table(cf_get_symbol("master4"), NET_IP4);
  rt_new_table(cf_get_symbol("master6"), NET_IP6);
}


/*
 * Some functions for handing internal next hop updates
 * triggered by rt_schedule_nhu().
 */

static inline int
rta_next_hop_outdated(rta *a)
{
  struct hostentry *he = a->hostentry;

  if (!he)
    return 0;

  if (!he->src)
    return a->dest != RTD_UNREACHABLE;

  return (a->dest != he->dest) || (a->igp_metric != he->igp_metric) ||
    (!he->nexthop_linkable) || !nexthop_same(&(a->nh), &(he->src->nh));
}

void
rta_apply_hostentry(rta *a, struct hostentry *he, mpls_label_stack *mls)
{
  a->hostentry = he;
  a->dest = he->dest;
  a->igp_metric = he->igp_metric;

  if (a->dest != RTD_UNICAST)
  {
    /* No nexthop */
no_nexthop:
    a->nh = (struct nexthop) {};
    if (mls)
    { /* Store the label stack for later changes */
      a->nh.labels_orig = a->nh.labels = mls->len;
      memcpy(a->nh.label, mls->stack, mls->len * sizeof(u32));
    }
    return;
  }

  if (((!mls) || (!mls->len)) && he->nexthop_linkable)
  { /* Just link the nexthop chain, no label append happens. */
    memcpy(&(a->nh), &(he->src->nh), nexthop_size(&(he->src->nh)));
    return;
  }

  struct nexthop *nhp = NULL, *nhr = NULL;
  int skip_nexthop = 0;

  for (struct nexthop *nh = &(he->src->nh); nh; nh = nh->next)
  {
    if (skip_nexthop)
      skip_nexthop--;
    else
    {
      nhr = nhp;
      nhp = (nhp ? (nhp->next = lp_allocz(rte_update_pool, NEXTHOP_MAX_SIZE)) : &(a->nh));
    }

    nhp->iface = nh->iface;
    nhp->weight = nh->weight;
    if (mls)
    {
      nhp->labels = nh->labels + mls->len;
      nhp->labels_orig = mls->len;
      if (nhp->labels <= MPLS_MAX_LABEL_STACK)
      {
	memcpy(nhp->label, nh->label, nh->labels * sizeof(u32)); /* First the hostentry labels */
	memcpy(&(nhp->label[nh->labels]), mls->stack, mls->len * sizeof(u32)); /* Then the bottom labels */
      }
      else
      {
	log(L_WARN "Sum of label stack sizes %d + %d = %d exceedes allowed maximum (%d)",
	    nh->labels, mls->len, nhp->labels, MPLS_MAX_LABEL_STACK);
	skip_nexthop++;
	continue;
      }
    }
    if (ipa_nonzero(nh->gw))
    {
      nhp->gw = nh->gw;			/* Router nexthop */
      nhp->flags |= (nh->flags & RNF_ONLINK);
    }
    else if (ipa_nonzero(he->link))
      nhp->gw = he->link;		/* Device nexthop with link-local address known */
    else
      nhp->gw = he->addr;		/* Device nexthop with link-local address unknown */
  }

  if (skip_nexthop)
    if (nhr)
      nhr->next = NULL;
    else
    {
      a->dest = RTD_UNREACHABLE;
      log(L_WARN "No valid nexthop remaining, setting route unreachable");
      goto no_nexthop;
    }
}

static inline rte *
rt_next_hop_update_rte(rtable *tab UNUSED, rte *old)
{
  rta *a = alloca(RTA_MAX_SIZE);
  memcpy(a, old->attrs, rta_size(old->attrs));

  mpls_label_stack mls = { .len = a->nh.labels_orig };
  memcpy(mls.stack, &a->nh.label[a->nh.labels - mls.len], mls.len * sizeof(u32));

  rta_apply_hostentry(a, old->attrs->hostentry, &mls);
  a->aflags = 0;

  rte *e = sl_alloc(rte_slab);
  memcpy(e, old, sizeof(rte));
  e->attrs = rta_lookup(a);

  return e;
}

static inline int
rt_next_hop_update_net(rtable *tab, net *n)
{
  rte **k, *e, *new, *old_best, **new_best;
  int count = 0;
  int free_old_best = 0;

  old_best = n->routes;
  if (!old_best)
    return 0;

  for (k = &n->routes; e = *k; k = &e->next)
    if (rta_next_hop_outdated(e->attrs))
      {
	new = rt_next_hop_update_rte(tab, e);
	*k = new;

	rte_announce_i(tab, RA_ANY, n, new, e, NULL, NULL);
	rte_trace_in(D_ROUTES, new->sender->proto, new, "updated");

	/* Call a pre-comparison hook */
	/* Not really an efficient way to compute this */
	if (e->attrs->src->proto->rte_recalculate)
	  e->attrs->src->proto->rte_recalculate(tab, n, new, e, NULL);

	if (e != old_best)
	  rte_free_quick(e);
	else /* Freeing of the old best rte is postponed */
	  free_old_best = 1;

	e = new;
	count++;
      }

  if (!count)
    return 0;

  /* Find the new best route */
  new_best = NULL;
  for (k = &n->routes; e = *k; k = &e->next)
    {
      if (!new_best || rte_better(e, *new_best))
	new_best = k;
    }

  /* Relink the new best route to the first position */
  new = *new_best;
  if (new != n->routes)
    {
      *new_best = new->next;
      new->next = n->routes;
      n->routes = new;
    }

  /* Announce the new best route */
  if (new != old_best)
    {
      rte_announce_i(tab, RA_OPTIMAL, n, new, old_best, NULL, NULL);
      rte_trace_in(D_ROUTES, new->sender->proto, new, "updated [best]");
    }

  /* FIXME: Better announcement of merged routes */
  rte_announce_i(tab, RA_MERGED, n, new, old_best, new, old_best);

  if (free_old_best)
    rte_free_quick(old_best);

  return count;
}

static void
rt_next_hop_update(rtable *tab)
{
  struct fib_iterator *fit = &tab->nhu_fit;
  int max_feed = 32;

  if (tab->nhu_state == NHU_CLEAN)
    return;

  if (tab->nhu_state == NHU_SCHEDULED)
    {
      FIB_ITERATE_INIT(fit, &tab->fib);
      tab->nhu_state = NHU_RUNNING;
    }

  FIB_ITERATE_START(&tab->fib, fit, net, n)
    {
      if (max_feed <= 0)
	{
	  FIB_ITERATE_PUT(fit);
	  ev_schedule(tab->rt_event);
	  return;
	}
      max_feed -= rt_next_hop_update_net(tab, n);
    }
  FIB_ITERATE_END;

  /* State change:
   *   NHU_DIRTY   -> NHU_SCHEDULED
   *   NHU_RUNNING -> NHU_CLEAN
   */
  tab->nhu_state &= 1;

  if (tab->nhu_state != NHU_CLEAN)
    ev_schedule(tab->rt_event);
}


struct rtable_config *
rt_new_table(struct symbol *s, uint addr_type)
{
  /* Hack that allows to 'redefine' the master table */
  if ((s->class == SYM_TABLE) &&
      (s->def == new_config->def_tables[addr_type]) &&
      ((addr_type == NET_IP4) || (addr_type == NET_IP6)))
    return s->def;

  struct rtable_config *c = cfg_allocz(sizeof(struct rtable_config));

  cf_define_symbol(s, SYM_TABLE, c);
  c->name = s->name;
  c->addr_type = addr_type;
  c->gc_max_ops = 1000;
  c->gc_min_time = 5;

  add_tail(&new_config->tables, &c->n);

  /* First table of each type is kept as default */
  if (! new_config->def_tables[addr_type])
    new_config->def_tables[addr_type] = c;

  return c;
}

/**
 * rt_lock_table - lock a routing table
 * @r: routing table to be locked
 *
 * Lock a routing table, because it's in use by a protocol,
 * preventing it from being freed when it gets undefined in a new
 * configuration.
 */
void
rt_lock_table(rtable *r)
{
  r->use_count++;
}

/**
 * rt_unlock_table - unlock a routing table
 * @r: routing table to be unlocked
 *
 * Unlock a routing table formerly locked by rt_lock_table(),
 * that is decrease its use count and delete it if it's scheduled
 * for deletion by configuration changes.
 */
void
rt_unlock_table(rtable *r)
{
  if (!--r->use_count && r->deleted)
    {
      struct config *conf = r->deleted;
      DBG("Deleting routing table %s\n", r->name);
      r->config->table = NULL;
      if (r->hostcache)
	rt_free_hostcache(r);
      rem_node(&r->n);
      fib_free(&r->fib);
      rfree(r->rt_event);
      mb_free(r);
      config_del_obstacle(conf);
    }
}

static struct rtable_config *
rt_find_table_config(struct config *cf, char *name)
{
  struct symbol *sym = cf_find_symbol(cf, name);
  return (sym && (sym->class == SYM_TABLE)) ? sym->def : NULL;
}

/**
 * rt_commit - commit new routing table configuration
 * @new: new configuration
 * @old: original configuration or %NULL if it's boot time config
 *
 * Scan differences between @old and @new configuration and modify
 * the routing tables according to these changes. If @new defines a
 * previously unknown table, create it, if it omits a table existing
 * in @old, schedule it for deletion (it gets deleted when all protocols
 * disconnect from it by calling rt_unlock_table()), if it exists
 * in both configurations, leave it unchanged.
 */
void
rt_commit(struct config *new, struct config *old)
{
  struct rtable_config *o, *r;

  DBG("rt_commit:\n");
  if (old)
    {
      WALK_LIST(o, old->tables)
	{
	  rtable *ot = o->table;
	  if (!ot->deleted)
	    {
	      r = rt_find_table_config(new, o->name);
	      if (r && (r->addr_type == o->addr_type) && !new->shutdown)
		{
		  DBG("\t%s: same\n", o->name);
		  r->table = ot;
		  ot->name = r->name;
		  ot->config = r;
		  if (o->sorted != r->sorted)
		    log(L_WARN "Reconfiguration of rtable sorted flag not implemented");
		}
	      else
		{
		  DBG("\t%s: deleted\n", o->name);
		  ot->deleted = old;
		  config_add_obstacle(old);
		  rt_lock_table(ot);
		  rt_unlock_table(ot);
		}
	    }
	}
    }

  WALK_LIST(r, new->tables)
    if (!r->table)
      {
	rtable *t = mb_alloc(rt_table_pool, sizeof(struct rtable));
	DBG("\t%s: created\n", r->name);
	rt_setup(rt_table_pool, t, r);
	add_tail(&routing_tables, &t->n);
	r->table = t;
      }
  DBG("\tdone\n");
}

static inline void
do_feed_channel(struct channel *c, net *n, rte *e)
{
  rte_update_lock();
  if (c->ra_mode == RA_ACCEPTED)
    rt_notify_accepted(c, n, e, NULL, NULL, c->refeeding ? 2 : 1);
  else if (c->ra_mode == RA_MERGED)
    rt_notify_merged(c, n, NULL, NULL, e, c->refeeding ? e : NULL, c->refeeding);
  else /* RA_BASIC */
    rt_notify_basic(c, n, e, c->refeeding ? e : NULL, c->refeeding);
  rte_update_unlock();
}

/**
 * rt_feed_channel - advertise all routes to a channel
 * @c: channel to be fed
 *
 * This function performs one pass of advertisement of routes to a channel that
 * is in the ES_FEEDING state. It is called by the protocol code as long as it
 * has something to do. (We avoid transferring all the routes in single pass in
 * order not to monopolize CPU time.)
 */
int
rt_feed_channel(struct channel *c)
{
  struct fib_iterator *fit = &c->feed_fit;
  int max_feed = 256;

  ASSERT(c->export_state == ES_FEEDING);

  if (!c->feed_active)
    {
      FIB_ITERATE_INIT(fit, &c->table->fib);
      c->feed_active = 1;
    }

  FIB_ITERATE_START(&c->table->fib, fit, net, n)
    {
      rte *e = n->routes;
      if (max_feed <= 0)
	{
	  FIB_ITERATE_PUT(fit);
	  return 0;
	}

      /* FIXME: perhaps we should change feed for RA_ACCEPTED to not use 'new' */

      if ((c->ra_mode == RA_OPTIMAL) ||
	  (c->ra_mode == RA_ACCEPTED) ||
	  (c->ra_mode == RA_MERGED))
	if (rte_is_valid(e))
	  {
	    /* In the meantime, the protocol may fell down */
	    if (c->export_state != ES_FEEDING)
	      goto done;

	    do_feed_channel(c, n, e);
	    max_feed--;
	  }

      if (c->ra_mode == RA_ANY)
	for(e = n->routes; e; e = e->next)
	  {
	    /* In the meantime, the protocol may fell down */
	    if (c->export_state != ES_FEEDING)
	      goto done;

	    if (!rte_is_valid(e))
	      continue;

	    do_feed_channel(c, n, e);
	    max_feed--;
	  }
    }
  FIB_ITERATE_END;

done:
  c->feed_active = 0;
  return 1;
}

/**
 * rt_feed_baby_abort - abort protocol feeding
 * @c: channel
 *
 * This function is called by the protocol code when the protocol stops or
 * ceases to exist during the feeding.
 */
void
rt_feed_channel_abort(struct channel *c)
{
  if (c->feed_active)
    {
      /* Unlink the iterator */
      fit_get(&c->table->fib, &c->feed_fit);
      c->feed_active = 0;
    }
}

static inline u32
hc_hash(ip_addr a, rtable *dep)
{
  return ipa_hash(a) ^ ptr_hash(dep);
}

static inline void
hc_insert(struct hostcache *hc, struct hostentry *he)
{
  uint k = he->hash_key >> hc->hash_shift;
  he->next = hc->hash_table[k];
  hc->hash_table[k] = he;
}

static inline void
hc_remove(struct hostcache *hc, struct hostentry *he)
{
  struct hostentry **hep;
  uint k = he->hash_key >> hc->hash_shift;

  for (hep = &hc->hash_table[k]; *hep != he; hep = &(*hep)->next);
  *hep = he->next;
}

#define HC_DEF_ORDER 10
#define HC_HI_MARK *4
#define HC_HI_STEP 2
#define HC_HI_ORDER 16			/* Must be at most 16 */
#define HC_LO_MARK /5
#define HC_LO_STEP 2
#define HC_LO_ORDER 10

static void
hc_alloc_table(struct hostcache *hc, unsigned order)
{
  uint hsize = 1 << order;
  hc->hash_order = order;
  hc->hash_shift = 32 - order;
  hc->hash_max = (order >= HC_HI_ORDER) ? ~0U : (hsize HC_HI_MARK);
  hc->hash_min = (order <= HC_LO_ORDER) ?  0U : (hsize HC_LO_MARK);

  hc->hash_table = mb_allocz(rt_table_pool, hsize * sizeof(struct hostentry *));
}

static void
hc_resize(struct hostcache *hc, unsigned new_order)
{
  struct hostentry **old_table = hc->hash_table;
  struct hostentry *he, *hen;
  uint old_size = 1 << hc->hash_order;
  uint i;

  hc_alloc_table(hc, new_order);
  for (i = 0; i < old_size; i++)
    for (he = old_table[i]; he != NULL; he=hen)
      {
	hen = he->next;
	hc_insert(hc, he);
      }
  mb_free(old_table);
}

static struct hostentry *
hc_new_hostentry(struct hostcache *hc, ip_addr a, ip_addr ll, rtable *dep, unsigned k)
{
  struct hostentry *he = sl_alloc(hc->slab);

  *he = (struct hostentry) {
    .addr = a,
    .link = ll,
    .tab = dep,
    .hash_key = k,
  };

  add_tail(&hc->hostentries, &he->ln);
  hc_insert(hc, he);

  hc->hash_items++;
  if (hc->hash_items > hc->hash_max)
    hc_resize(hc, hc->hash_order + HC_HI_STEP);

  return he;
}

static void
hc_delete_hostentry(struct hostcache *hc, struct hostentry *he)
{
  rta_free(he->src);

  rem_node(&he->ln);
  hc_remove(hc, he);
  sl_free(hc->slab, he);

  hc->hash_items--;
  if (hc->hash_items < hc->hash_min)
    hc_resize(hc, hc->hash_order - HC_LO_STEP);
}

static void
rt_init_hostcache(rtable *tab)
{
  struct hostcache *hc = mb_allocz(rt_table_pool, sizeof(struct hostcache));
  init_list(&hc->hostentries);

  hc->hash_items = 0;
  hc_alloc_table(hc, HC_DEF_ORDER);
  hc->slab = sl_new(rt_table_pool, sizeof(struct hostentry));

  hc->lp = lp_new(rt_table_pool, LP_GOOD_SIZE(1024));
  hc->trie = f_new_trie(hc->lp, sizeof(struct f_trie_node));

  tab->hostcache = hc;
}

static void
rt_free_hostcache(rtable *tab)
{
  struct hostcache *hc = tab->hostcache;

  node *n;
  WALK_LIST(n, hc->hostentries)
    {
      struct hostentry *he = SKIP_BACK(struct hostentry, ln, n);
      rta_free(he->src);

      if (he->uc)
	log(L_ERR "Hostcache is not empty in table %s", tab->name);
    }

  rfree(hc->slab);
  rfree(hc->lp);
  mb_free(hc->hash_table);
  mb_free(hc);
}

static void
rt_notify_hostcache(rtable *tab, net *net)
{
  if (tab->hcu_scheduled)
    return;

  if (trie_match_net(tab->hostcache->trie, net->n.addr))
    rt_schedule_hcu(tab);
}

static int
if_local_addr(ip_addr a, struct iface *i)
{
  struct ifa *b;

  WALK_LIST(b, i->addrs)
    if (ipa_equal(a, b->ip))
      return 1;

  return 0;
}

static u32
rt_get_igp_metric(rte *rt)
{
  eattr *ea = ea_find(rt->attrs->eattrs, EA_GEN_IGP_METRIC);

  if (ea)
    return ea->u.data;

  rta *a = rt->attrs;

#ifdef CONFIG_OSPF
  if ((a->source == RTS_OSPF) ||
      (a->source == RTS_OSPF_IA) ||
      (a->source == RTS_OSPF_EXT1))
    return rt->u.ospf.metric1;
#endif

#ifdef CONFIG_RIP
  if (a->source == RTS_RIP)
    return rt->u.rip.metric;
#endif

  if (a->source == RTS_DEVICE)
    return 0;

  return IGP_METRIC_UNKNOWN;
}

static int
rt_update_hostentry(rtable *tab, struct hostentry *he)
{
  rta *old_src = he->src;
  int direct = 0;
  int pxlen = 0;

  /* Reset the hostentry */
  he->src = NULL;
  he->dest = RTD_UNREACHABLE;
  he->nexthop_linkable = 0;
  he->igp_metric = 0;

  net_addr he_addr;
  net_fill_ip_host(&he_addr, he->addr);
  net *n = net_route(tab, &he_addr);
  if (n)
    {
      rte *e = n->routes;
      rta *a = e->attrs;
      pxlen = n->n.addr->pxlen;

      if (a->hostentry)
	{
	  /* Recursive route should not depend on another recursive route */
	  log(L_WARN "Next hop address %I resolvable through recursive route for %N",
	      he->addr, n->n.addr);
	  goto done;
	}

      if (a->dest == RTD_UNICAST)
	{
	  for (struct nexthop *nh = &(a->nh); nh; nh = nh->next)
	    if (ipa_zero(nh->gw))
	      {
		if (if_local_addr(he->addr, nh->iface))
		  {
		    /* The host address is a local address, this is not valid */
		    log(L_WARN "Next hop address %I is a local address of iface %s",
			he->addr, nh->iface->name);
		    goto done;
		  }

		direct++;
	      }
	}

      he->src = rta_clone(a);
      he->dest = a->dest;
      he->nexthop_linkable = !direct;
      he->igp_metric = rt_get_igp_metric(e);
    }

done:
  /* Add a prefix range to the trie */
  trie_add_prefix(tab->hostcache->trie, &he_addr, pxlen, he_addr.pxlen);

  rta_free(old_src);
  return old_src != he->src;
}

static void
rt_update_hostcache(rtable *tab)
{
  struct hostcache *hc = tab->hostcache;
  struct hostentry *he;
  node *n, *x;

  /* Reset the trie */
  lp_flush(hc->lp);
  hc->trie = f_new_trie(hc->lp, sizeof(struct f_trie_node));

  WALK_LIST_DELSAFE(n, x, hc->hostentries)
    {
      he = SKIP_BACK(struct hostentry, ln, n);
      if (!he->uc)
	{
	  hc_delete_hostentry(hc, he);
	  continue;
	}

      if (rt_update_hostentry(tab, he))
	rt_schedule_nhu(he->tab);
    }

  tab->hcu_scheduled = 0;
}

struct hostentry *
rt_get_hostentry(rtable *tab, ip_addr a, ip_addr ll, rtable *dep)
{
  struct hostentry *he;

  if (!tab->hostcache)
    rt_init_hostcache(tab);

  u32 k = hc_hash(a, dep);
  struct hostcache *hc = tab->hostcache;
  for (he = hc->hash_table[k >> hc->hash_shift]; he != NULL; he = he->next)
    if (ipa_equal(he->addr, a) && (he->tab == dep))
      return he;

  he = hc_new_hostentry(hc, a, ipa_zero(ll) ? a : ll, dep, k);
  rt_update_hostentry(tab, he);
  return he;
}


/*
 *  Documentation for functions declared inline in route.h
 */
#if 0

/**
 * net_find - find a network entry
 * @tab: a routing table
 * @addr: address of the network
 *
 * net_find() looks up the given network in routing table @tab and
 * returns a pointer to its &net entry or %NULL if no such network
 * exists.
 */
static inline net *net_find(rtable *tab, net_addr *addr)
{ DUMMY; }

/**
 * net_get - obtain a network entry
 * @tab: a routing table
 * @addr: address of the network
 *
 * net_get() looks up the given network in routing table @tab and
 * returns a pointer to its &net entry. If no such entry exists, it's
 * created.
 */
static inline net *net_get(rtable *tab, net_addr *addr)
{ DUMMY; }

/**
 * rte_cow - copy a route for writing
 * @r: a route entry to be copied
 *
 * rte_cow() takes a &rte and prepares it for modification. The exact action
 * taken depends on the flags of the &rte -- if it's a temporary entry, it's
 * just returned unchanged, else a new temporary entry with the same contents
 * is created.
 *
 * The primary use of this function is inside the filter machinery -- when
 * a filter wants to modify &rte contents (to change the preference or to
 * attach another set of attributes), it must ensure that the &rte is not
 * shared with anyone else (and especially that it isn't stored in any routing
 * table).
 *
 * Result: a pointer to the new writable &rte.
 */
static inline rte * rte_cow(rte *r)
{ DUMMY; }

#endif
