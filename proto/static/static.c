/*
 *	BIRD -- Static Route Generator
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: Static
 *
 * The Static protocol is implemented in a straightforward way. It keeps a list
 * of static routes. Routes of dest RTD_UNICAST have associated sticky node in
 * the neighbor cache to be notified about gaining or losing the neighbor and
 * about interface-related events (e.g. link down). They may also have a BFD
 * request if associated with a BFD session. When a route is notified,
 * static_decide() is used to see whether the route activeness is changed. In
 * such case, the route is marked as dirty and scheduled to be announced or
 * withdrawn, which is done asynchronously from event hook. Routes of other
 * types (e.g. black holes) are announced all the time.
 *
 * Multipath routes are a bit tricky. To represent additional next hops, dummy
 * static_route nodes are used, which are chained using @mp_next field and link
 * to the master node by @mp_head field. Each next hop has a separate neighbor
 * entry and an activeness state, but the master node is used for most purposes.
 * Note that most functions DO NOT accept dummy nodes as arguments.
 *
 * The only other thing worth mentioning is that when asked for reconfiguration,
 * Static not only compares the two configurations, but it also calculates
 * difference between the lists of static routes and it just inserts the newly
 * added routes, removes the obsolete ones and reannounces changed ones.
 */

#undef LOCAL_DEBUG

#include <stdlib.h>

#include "nest/bird.h"
#include "nest/iface.h"
#include "nest/protocol.h"
#include "nest/route.h"
#include "nest/cli.h"
#include "conf/conf.h"
#include "filter/filter.h"
#include "lib/string.h"
#include "lib/alloca.h"

#include "static.h"

static linpool *static_lp;

static void
static_announce_rte(struct static_proto *p, struct static_route *r)
{
  rta *a = allocz(RTA_MAX_SIZE);
  a->src = p->p.main_source;
  a->source = RTS_STATIC;
  a->scope = SCOPE_UNIVERSE;
  a->dest = r->dest;

  if (r->dest == RTD_UNICAST)
  {
    struct static_route *r2;
    struct nexthop *nhs = NULL;

    for (r2 = r; r2; r2 = r2->mp_next)
    {
      if (!r2->active)
	continue;

      struct nexthop *nh = allocz(NEXTHOP_MAX_SIZE);
      nh->gw = r2->via;
      nh->iface = r2->neigh->iface;
      nh->flags = r2->onlink ? RNF_ONLINK : 0;
      nh->weight = r2->weight;
      if (r2->mls)
      {
	nh->labels = r2->mls->len;
	memcpy(nh->label, r2->mls->stack, r2->mls->len * sizeof(u32));
      }

      nexthop_insert(&nhs, nh);
    }

    if (!nhs)
      goto withdraw;

    nexthop_link(a, nhs);
  }

  if (r->dest == RTDX_RECURSIVE)
  {
    rtable *tab = ipa_is_ip4(r->via) ? p->igp_table_ip4 : p->igp_table_ip6;
    rta_set_recursive_next_hop(p->p.main_channel->table, a, tab, r->via, IPA_NONE, r->mls, static_lp);
  }

  /* Already announced */
  if (r->state == SRS_CLEAN)
    return;

  rte e = {
    .attrs = a,
    .pflags = 0
  };
  
  rte *ep = &e;

  if (r->cmds)
    f_eval_rte(r->cmds, &ep, static_lp);

  rte_update(&p->p, r->net, ep);
  r->state = SRS_CLEAN;

  if (r->cmds)
    lp_flush(static_lp);

  return;

withdraw:
  if (r->state == SRS_DOWN)
    return;

  rte_update(&p->p, r->net, NULL);
  r->state = SRS_DOWN;
}

static void
static_mark_rte(struct static_proto *p, struct static_route *r)
{
  if (r->state == SRS_DIRTY)
    return;

  r->state = SRS_DIRTY;
  BUFFER_PUSH(p->marked) = r;

  if (!ev_active(p->event))
    ev_schedule(p->event);
}

static void
static_announce_marked(void *P)
{
  struct static_proto *p = P;

  BUFFER_WALK(p->marked, r)
    static_announce_rte(P, r);

  BUFFER_FLUSH(p->marked);
}

static void
static_bfd_notify(struct bfd_request *req);

static void
static_update_bfd(struct static_proto *p, struct static_route *r)
{
  /* The @r is a RTD_UNICAST next hop, may be a dummy node */

  struct neighbor *nb = r->neigh;
  int bfd_up = (nb->scope > 0) && r->use_bfd;

  if (bfd_up && !r->bfd_req)
  {
    // ip_addr local = ipa_nonzero(r->local) ? r->local : nb->ifa->ip;
    r->bfd_req = bfd_request_session(p->p.pool, r->via, nb->ifa->ip, nb->iface,
				     static_bfd_notify, r);
  }

  if (!bfd_up && r->bfd_req)
  {
    rfree(r->bfd_req);
    r->bfd_req = NULL;
  }
}

static int
static_decide(struct static_proto *p, struct static_route *r)
{
  /* The @r is a RTD_UNICAST next hop, may be a dummy node */

  struct static_config *cf = (void *) p->p.cf;
  uint old_active = r->active;

  if (r->neigh->scope < 0)
    goto fail;

  if (cf->check_link && !(r->neigh->iface->flags & IF_LINK_UP))
    goto fail;

  if (r->bfd_req && (r->bfd_req->state != BFD_STATE_UP))
    goto fail;

  r->active = 1;
  return !old_active;

fail:
  r->active = 0;
  return old_active;
}

static void
static_add_rte(struct static_proto *p, struct static_route *r)
{
  if (r->dest == RTD_UNICAST)
  {
    struct static_route *r2;
    struct neighbor *n;

    for (r2 = r; r2; r2 = r2->mp_next)
    {
      n = ipa_nonzero(r2->via) ?
	neigh_find2(&p->p, &r2->via, r2->iface,
		    NEF_STICKY | (r2->onlink ? NEF_ONLINK : 0)) :
	neigh_find_iface(&p->p, r2->iface);

      if (!n)
      {
	log(L_WARN "Invalid next hop %I of static route %N", r2->via, r2->net);
	continue;
      }

      r2->neigh = n;
      r2->chain = n->data;
      n->data = r2;

      static_update_bfd(p, r2);
      static_decide(p, r2);
    }
  }

  static_announce_rte(p, r);
}

static void
static_reset_rte(struct static_proto *p UNUSED, struct static_route *r)
{
  struct static_route *r2;

  for (r2 = r; r2; r2 = r2->mp_next)
  {
    r2->neigh = NULL;
    r2->chain = NULL;

    r2->state = 0;
    r2->active = 0;

    rfree(r2->bfd_req);
    r2->bfd_req = NULL;
  }
}

static void
static_remove_rte(struct static_proto *p, struct static_route *r)
{
  if (r->state)
    rte_update(&p->p, r->net, NULL);

  static_reset_rte(p, r);
}


static inline int
static_same_dest(struct static_route *x, struct static_route *y)
{
  if (x->dest != y->dest)
    return 0;

  switch (x->dest)
  {
  case RTD_UNICAST:
    for (; x && y; x = x->mp_next, y = y->mp_next)
    {
      if (!ipa_equal(x->via, y->via) ||
	  (x->iface != y->iface) ||
	  (x->onlink != y->onlink) ||
	  (x->weight != y->weight) ||
	  (x->use_bfd != y->use_bfd) ||
	  (!x->mls != !y->mls) ||
	  ((x->mls) && (y->mls) && (x->mls->len != y->mls->len)))
	return 0;

      if (!x->mls)
	continue;

      for (uint i = 0; i < x->mls->len; i++)
	if (x->mls->stack[i] != y->mls->stack[i])
	  return 0;
    }
    return !x && !y;

  case RTDX_RECURSIVE:
    if (!ipa_equal(x->via, y->via) ||
	(!x->mls != !y->mls) ||
	((x->mls) && (y->mls) && (x->mls->len != y->mls->len)))
      return 0;

    if (!x->mls)
      return 1;

    for (uint i = 0; i < x->mls->len; i++)
      if (x->mls->stack[i] != y->mls->stack[i])
	return 0;

    return 1;

  default:
    return 1;
  }
}

static inline int
static_same_rte(struct static_route *or, struct static_route *nr)
{
  /* Note that i_same() requires arguments in (new, old) order */
  return static_same_dest(or, nr) && i_same(nr->cmds, or->cmds);
}

static void
static_reconfigure_rte(struct static_proto *p, struct static_route *or, struct static_route *nr)
{
  if ((or->state == SRS_CLEAN) && !static_same_rte(or, nr))
    nr->state = SRS_DIRTY;
  else
    nr->state = or->state;

  static_add_rte(p, nr);
  static_reset_rte(p, or);
}


static void
static_neigh_notify(struct neighbor *n)
{
  struct static_proto *p = (void *) n->proto;
  struct static_route *r;

  DBG("Static: neighbor notify for %I: iface %p\n", n->addr, n->iface);
  for (r = n->data; r; r = r->chain)
  {
    static_update_bfd(p, r);

    if (static_decide(p, r))
      static_mark_rte(p, r->mp_head);
  }
}

static void
static_bfd_notify(struct bfd_request *req)
{
  struct static_route *r = req->data;
  struct static_proto *p = (void *) r->neigh->proto;

  // if (req->down) TRACE(D_EVENTS, "BFD session down for nbr %I on %s", XXXX);

  if (static_decide(p, r))
    static_mark_rte(p, r->mp_head);
}

static int
static_rte_mergable(rte *pri UNUSED, rte *sec UNUSED)
{
  return 1;
}


static void
static_postconfig(struct proto_config *CF)
{
  struct static_config *cf = (void *) CF;
  struct static_route *r;

  if (EMPTY_LIST(CF->channels))
    cf_error("Channel not specified");

  struct channel_config *cc = proto_cf_main_channel(CF);

  if (!cf->igp_table_ip4)
    cf->igp_table_ip4 = (cc->table->addr_type == NET_IP4) ?
      cc->table : cf->c.global->def_tables[NET_IP4];

  if (!cf->igp_table_ip6)
    cf->igp_table_ip6 = (cc->table->addr_type == NET_IP6) ?
      cc->table : cf->c.global->def_tables[NET_IP6];

  WALK_LIST(r, cf->routes)
    if (r->net && (r->net->type != CF->net_type))
      cf_error("Route %N incompatible with channel type", r->net);
}

static struct proto *
static_init(struct proto_config *CF)
{
  struct proto *P = proto_new(CF);
  struct static_proto *p = (void *) P;
  struct static_config *cf = (void *) CF;

  P->main_channel = proto_add_channel(P, proto_cf_main_channel(CF));

  P->neigh_notify = static_neigh_notify;
  P->rte_mergable = static_rte_mergable;

  if (cf->igp_table_ip4)
    p->igp_table_ip4 = cf->igp_table_ip4->table;

  if (cf->igp_table_ip6)
    p->igp_table_ip6 = cf->igp_table_ip6->table;

  return P;
}

static int
static_start(struct proto *P)
{
  struct static_proto *p = (void *) P;
  struct static_config *cf = (void *) P->cf;
  struct static_route *r;

  if (!static_lp)
    static_lp = lp_new(&root_pool, LP_GOOD_SIZE(1024));

  if (p->igp_table_ip4)
    rt_lock_table(p->igp_table_ip4);

  if (p->igp_table_ip6)
    rt_lock_table(p->igp_table_ip6);

  p->event = ev_new(p->p.pool);
  p->event->hook = static_announce_marked;
  p->event->data = p;

  BUFFER_INIT(p->marked, p->p.pool, 4);

  /* We have to go UP before routes could be installed */
  proto_notify_state(P, PS_UP);

  WALK_LIST(r, cf->routes)
    static_add_rte(p, r);

  return PS_UP;
}

static int
static_shutdown(struct proto *P)
{
  struct static_proto *p = (void *) P;
  struct static_config *cf = (void *) P->cf;
  struct static_route *r;

  /* Just reset the flag, the routes will be flushed by the nest */
  WALK_LIST(r, cf->routes)
    static_reset_rte(p, r);

  return PS_DOWN;
}

static void
static_cleanup(struct proto *P)
{
  struct static_proto *p = (void *) P;

  if (p->igp_table_ip4)
    rt_unlock_table(p->igp_table_ip4);

  if (p->igp_table_ip6)
    rt_unlock_table(p->igp_table_ip6);
}

static void
static_dump_rte(struct static_route *r)
{
  debug("%-1N: ", r->net);
  if (r->dest == RTD_UNICAST)
    if (r->iface && ipa_zero(r->via))
      debug("dev %s\n", r->iface->name);
    else
      debug("via %I%J\n", r->via, r->iface);
  else
    debug("rtd %d\n", r->dest);
}

static void
static_dump(struct proto *P)
{
  struct static_config *c = (void *) P->cf;
  struct static_route *r;

  debug("Static routes:\n");
  WALK_LIST(r, c->routes)
    static_dump_rte(r);
}

#define IGP_TABLE(cf, sym) ((cf)->igp_table_##sym ? (cf)->igp_table_##sym ->table : NULL )

static inline int
static_cmp_rte(const void *X, const void *Y)
{
  struct static_route *x = *(void **)X, *y = *(void **)Y;
  return net_compare(x->net, y->net);
}

static int
static_reconfigure(struct proto *P, struct proto_config *CF)
{
  struct static_proto *p = (void *) P;
  struct static_config *o = (void *) P->cf;
  struct static_config *n = (void *) CF;
  struct static_route *r, *r2, *or, *nr;

  /* Check change in IGP tables */
  if ((IGP_TABLE(o, ip4) != IGP_TABLE(n, ip4)) ||
      (IGP_TABLE(o, ip6) != IGP_TABLE(n, ip6)))
    return 0;

  if (!proto_configure_channel(P, &P->main_channel, proto_cf_main_channel(CF)))
    return 0;

  p->p.cf = CF;

  /* Reset route lists in neighbor entries */
  WALK_LIST(r, o->routes)
    for (r2 = r; r2; r2 = r2->mp_next)
      if (r2->neigh)
	r2->neigh->data = NULL;

  /* Reconfigure initial matching sequence */
  for (or = HEAD(o->routes), nr = HEAD(n->routes);
       NODE_VALID(or) && NODE_VALID(nr) && net_equal(or->net, nr->net);
       or = NODE_NEXT(or), nr = NODE_NEXT(nr))
    static_reconfigure_rte(p, or, nr);

  if (!NODE_VALID(or) && !NODE_VALID(nr))
    return 1;

  /* Reconfigure remaining routes, sort them to find matching pairs */
  struct static_route *or2, *nr2, **orbuf, **nrbuf;
  uint ornum = 0, nrnum = 0, orpos = 0, nrpos = 0, i;

  for (or2 = or; NODE_VALID(or2); or2 = NODE_NEXT(or2))
    ornum++;

  for (nr2 = nr; NODE_VALID(nr2); nr2 = NODE_NEXT(nr2))
    nrnum++;

  orbuf = xmalloc(ornum * sizeof(void *));
  nrbuf = xmalloc(nrnum * sizeof(void *));

  for (i = 0, or2 = or; i < ornum; i++, or2 = NODE_NEXT(or2))
    orbuf[i] = or2;

  for (i = 0, nr2 = nr; i < nrnum; i++, nr2 = NODE_NEXT(nr2))
    nrbuf[i] = nr2;

  qsort(orbuf, ornum, sizeof(struct static_route *), static_cmp_rte);
  qsort(nrbuf, nrnum, sizeof(struct static_route *), static_cmp_rte);

  while ((orpos < ornum) && (nrpos < nrnum))
  {
    int x = net_compare(orbuf[orpos]->net, nrbuf[nrpos]->net);
    if (x < 0)
      static_remove_rte(p, orbuf[orpos++]);
    else if (x > 0)
      static_add_rte(p, nrbuf[nrpos++]);
    else
      static_reconfigure_rte(p, orbuf[orpos++], nrbuf[nrpos++]);
  }

  while (orpos < ornum)
    static_remove_rte(p, orbuf[orpos++]);

  while (nrpos < nrnum)
    static_add_rte(p, nrbuf[nrpos++]);

  xfree(orbuf);
  xfree(nrbuf);

  return 1;
}

static void
static_copy_config(struct proto_config *dest, struct proto_config *src)
{
  struct static_config *d = (struct static_config *) dest;
  struct static_config *s = (struct static_config *) src;

  struct static_route *srt, *snh;

  /* Copy route list */
  init_list(&d->routes);
  WALK_LIST(srt, s->routes)
  {
    struct static_route *drt = NULL, *dnh = NULL, **dnp = &drt;

    for (snh = srt; snh; snh = snh->mp_next)
    {
      dnh = cfg_alloc(sizeof(struct static_route));
      memcpy(dnh, snh, sizeof(struct static_route));

      if (!drt)
	add_tail(&d->routes, &(dnh->n));

      *dnp = dnh;
      dnp = &(dnh->mp_next);

      if (snh->mp_head)
	dnh->mp_head = drt;
    }
  }
}

static void
static_show_rt(struct static_route *r)
{
  switch (r->dest)
  {
  case RTD_UNICAST:
  {
    struct static_route *r2;

    cli_msg(-1009, "%N", r->net);
    for (r2 = r; r2; r2 = r2->mp_next)
    {
      if (r2->iface && ipa_zero(r2->via))
	cli_msg(-1009, "\tdev %s%s", r2->iface->name,
		r2->active ? "" : " (dormant)");
      else
	cli_msg(-1009, "\tvia %I%J%s%s%s", r2->via, r2->iface,
		r2->onlink ? " onlink" : "",
		r2->bfd_req ? " (bfd)" : "",
		r2->active ? "" : " (dormant)");
    }
    break;
  }

  case RTD_NONE:
  case RTD_BLACKHOLE:
  case RTD_UNREACHABLE:
  case RTD_PROHIBIT:
    cli_msg(-1009, "%N\t%s", r->net, rta_dest_names[r->dest]);
    break;

  case RTDX_RECURSIVE:
    cli_msg(-1009, "%N\trecursive %I", r->net, r->via);
    break;
  }
}

void
static_show(struct proto *P)
{
  struct static_config *c = (void *) P->cf;
  struct static_route *r;

  WALK_LIST(r, c->routes)
    static_show_rt(r);
  cli_msg(0, "");
}


struct protocol proto_static = {
  .name =		"Static",
  .template =		"static%d",
  .preference =		DEF_PREF_STATIC,
  .channel_mask =	NB_ANY,
  .proto_size =		sizeof(struct static_proto),
  .config_size =	sizeof(struct static_config),
  .postconfig =		static_postconfig,
  .init =		static_init,
  .dump =		static_dump,
  .start =		static_start,
  .shutdown =		static_shutdown,
  .cleanup =		static_cleanup,
  .reconfigure =	static_reconfigure,
  .copy_config =	static_copy_config
};
