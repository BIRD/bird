/*
 *	BIRD -- Router Advertisement
 *
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */


#include <stdlib.h>
#include "radv.h"

/**
 * DOC: Router Advertisements
 *
 * The RAdv protocol is implemented in two files: |radv.c| containing
 * the interface with BIRD core and the protocol logic and |packets.c|
 * handling low level protocol stuff (RX, TX and packet formats).
 * The protocol does not export any routes.
 *
 * The RAdv is structured in the usual way - for each handled interface
 * there is a structure &radv_iface that contains a state related to
 * that interface together with its resources (a socket, a timer).
 * There is also a prepared RA stored in a TX buffer of the socket
 * associated with an iface. These iface structures are created
 * and removed according to iface events from BIRD core handled by
 * radv_if_notify() callback.
 *
 * The main logic of RAdv consists of two functions:
 * radv_iface_notify(), which processes asynchronous events (specified
 * by RA_EV_* codes), and radv_timer(), which triggers sending RAs and
 * computes the next timeout.
 *
 * The RAdv protocol could receive routes (through
 * radv_import_control() and radv_rt_notify()), but only the
 * configured trigger route is tracked (in &active var).  When a radv
 * protocol is reconfigured, the connected routing table is examined
 * (in radv_check_active()) to have proper &active value in case of
 * the specified trigger prefix was changed.
 *
 * Supported standards:
 * - RFC 4861 - main RA standard
 * - RFC 6106 - DNS extensions (RDDNS, DNSSL)
 * - RFC 4191 (partial) - Default Router Preference
 */

static void
radv_timer(timer *tm)
{
  struct radv_iface *ifa = tm->data;
  struct radv_proto *p = ifa->ra;

  RADV_TRACE(D_EVENTS, "Timer fired on %s", ifa->iface->name);

  /*
   * If some dead prefixes expired, regenerate the prefix list and the packet.
   * We do so by pretending there was a change on the interface.
   *
   * This sets the timer, but we replace it just at the end of this function
   * (replacing a timer is fine).
   */
  if (ifa->prefix_expires && (ifa->prefix_expires <= now))
    radv_iface_notify(ifa, RA_EV_GC);

  radv_send_ra(ifa, 0);

  /* Update timer */
  ifa->last = now;
  unsigned after = ifa->cf->min_ra_int;
  after += random() % (ifa->cf->max_ra_int - ifa->cf->min_ra_int + 1);

  if (ifa->initial)
    ifa->initial--;

  if (ifa->initial)
    after = MIN(after, MAX_INITIAL_RTR_ADVERT_INTERVAL);

  tm_start(ifa->timer, after);
}

static struct radv_prefix_config default_prefix = {
  .onlink = 1,
  .autonomous = 1,
  .valid_lifetime = DEFAULT_VALID_LIFETIME,
  .preferred_lifetime = DEFAULT_PREFERRED_LIFETIME
};

static struct radv_prefix_config dead_prefix = {
};

/* Find a corresponding config for the given prefix */
static struct radv_prefix_config *
radv_prefix_match(struct radv_iface *ifa, struct ifa *a)
{
  struct radv_proto *p = ifa->ra;
  struct radv_config *cf = (struct radv_config *) (p->p.cf);
  struct radv_prefix_config *pc;

  if (a->scope <= SCOPE_LINK)
    return NULL;

  WALK_LIST(pc, ifa->cf->pref_list)
    if ((a->pxlen >= pc->pxlen) && ipa_in_net(a->prefix, pc->prefix, pc->pxlen))
      return pc;

  WALK_LIST(pc, cf->pref_list)
    if ((a->pxlen >= pc->pxlen) && ipa_in_net(a->prefix, pc->prefix, pc->pxlen))
      return pc;

  return &default_prefix;
}

/*
 * Go through the list of prefixes, compare them with configs and decide if we
 * want them or not.
 */
static void
radv_prepare_prefixes(struct radv_iface *ifa)
{
  struct radv_proto *p = ifa->ra;
  struct radv_iface_config *cf = ifa->cf;
  struct radv_prefix *pfx;

  /* First mark all the prefixes as unused */
  WALK_LIST(pfx, ifa->prefixes)
    pfx->mark = 0;

  /* Find all the prefixes we want to use and make sure they are in the list. */
  struct ifa *addr;
  WALK_LIST(addr, ifa->iface->addrs)
  {
    struct radv_prefix_config *pc = radv_prefix_match(ifa, addr);

    if (!pc || pc->skip)
      continue;

    /* Do we have it already? */
    struct radv_prefix *existing = NULL;
    WALK_LIST(pfx, ifa->prefixes)
      if ((pfx->len == addr->pxlen) && ipa_equal(pfx->prefix, addr->prefix))
      {
	existing = pfx;
	break;
      }

    if (!existing)
    {
      RADV_TRACE(D_EVENTS, "Adding new prefix %I/%d on %s",
		 addr->prefix, addr->pxlen, ifa->iface->name);

      existing = mb_allocz(ifa->pool, sizeof *existing);
      existing->prefix = addr->prefix;
      existing->len = addr->pxlen;
      add_tail(&ifa->prefixes, NODE existing);
    }

    /*
     * Update the information (it may have changed, or even bring a prefix back
     * to life).
     */
    existing->alive = 1;
    existing->mark = 1;
    existing->cf = pc;
  }

  /*
   * Garbage-collect the prefixes. If something isn't used, it dies (but isn't
   * dropped just yet). If something is dead and rots there for long enough,
   * clean it up.
   */
  bird_clock_t expires = now + cf->linger_time;
  bird_clock_t expires_min = 0;
  struct radv_prefix *next;
  WALK_LIST_DELSAFE(pfx, next, ifa->prefixes)
  {
    if (pfx->alive && !pfx->mark)
    {
      RADV_TRACE(D_EVENTS, "Marking prefix %I/$d on %s as dead",
		 pfx->prefix, pfx->len, ifa->iface->name);

      pfx->alive = 0;
      pfx->expires = expires;
      pfx->cf = &dead_prefix;
    }

    if (!pfx->alive)
    {
      if (pfx->expires <= now)
      {
	RADV_TRACE(D_EVENTS, "Removing prefix %I/%d on %s",
		   pfx->prefix, pfx->len, ifa->iface->name);

	rem_node(NODE pfx);
	mb_free(pfx);
      }
      else
      {
	/* Find minimum expiration time */
	if (!expires_min || (pfx->expires < expires_min))
	  expires_min = pfx->expires;
      }
    }
  }

  ifa->prefix_expires = expires_min;
}

static char* ev_name[] = { NULL, "Init", "Change", "RS", "Garbage collect" };

void
radv_iface_notify(struct radv_iface *ifa, int event)
{
  struct radv_proto *p = ifa->ra;

  if (!ifa->sk)
    return;

  RADV_TRACE(D_EVENTS, "Event %s on %s", ev_name[event], ifa->iface->name);

  switch (event)
  {
  case RA_EV_CHANGE:
  case RA_EV_GC:
    ifa->plen = 0;
  case RA_EV_INIT:
    ifa->initial = MAX_INITIAL_RTR_ADVERTISEMENTS;
    break;

  case RA_EV_RS:
    break;
  }

  radv_prepare_prefixes(ifa);

  /* Update timer */
  unsigned delta = now - ifa->last;
  unsigned after = 0;

  if (delta < ifa->cf->min_delay)
    after = ifa->cf->min_delay - delta;

  tm_start(ifa->timer, after);
}

static void
radv_iface_notify_all(struct radv_proto *p, int event)
{
  struct radv_iface *ifa;

  WALK_LIST(ifa, p->iface_list)
    radv_iface_notify(ifa, event);
}


static struct radv_iface *
radv_iface_find(struct radv_proto *p, struct iface *what)
{
  struct radv_iface *ifa;

  WALK_LIST(ifa, p->iface_list)
    if (ifa->iface == what)
      return ifa;

  return NULL;
}

static void
radv_iface_add(struct object_lock *lock)
{
  struct radv_iface *ifa = lock->data;
  struct radv_proto *p = ifa->ra;

  if (! radv_sk_open(ifa))
  {
    log(L_ERR "%s: Socket open failed on interface %s", p->p.name, ifa->iface->name);
    return;
  }

  radv_iface_notify(ifa, RA_EV_INIT);
}

static inline struct ifa *
find_lladdr(struct iface *iface)
{
  struct ifa *a;
  WALK_LIST(a, iface->addrs)
    if (a->scope == SCOPE_LINK)
      return a;

  return NULL;
}

static void
radv_iface_new(struct radv_proto *p, struct iface *iface, struct radv_iface_config *cf)
{
  struct radv_iface *ifa;

  RADV_TRACE(D_EVENTS, "Adding interface %s", iface->name);

  pool *pool = rp_new(p->p.pool, iface->name);
  ifa = mb_allocz(pool, sizeof(struct radv_iface));
  ifa->pool = pool;
  ifa->ra = p;
  ifa->cf = cf;
  ifa->iface = iface;
  init_list(&ifa->prefixes);

  add_tail(&p->iface_list, NODE ifa);

  ifa->addr = find_lladdr(iface);
  if (!ifa->addr)
  {
    log(L_ERR "%s: Missing link-local address on interface %s", p->p.name, iface->name);
    return;
  }

  timer *tm = tm_new(pool);
  tm->hook = radv_timer;
  tm->data = ifa;
  tm->randomize = 0;
  tm->recurrent = 0;
  ifa->timer = tm;

  struct object_lock *lock = olock_new(pool);
  lock->addr = IPA_NONE;
  lock->type = OBJLOCK_IP;
  lock->port = ICMPV6_PROTO;
  lock->iface = iface;
  lock->data = ifa;
  lock->hook = radv_iface_add;
  ifa->lock = lock;

  olock_acquire(lock);
}

static void
radv_iface_remove(struct radv_iface *ifa)
{
  struct radv_proto *p = ifa->ra;
  RADV_TRACE(D_EVENTS, "Removing interface %s", ifa->iface->name);

  rem_node(NODE ifa);

  rfree(ifa->pool);
}

static void
radv_if_notify(struct proto *P, unsigned flags, struct iface *iface)
{
  struct radv_proto *p = (struct radv_proto *) P;
  struct radv_config *cf = (struct radv_config *) (P->cf);

  if (iface->flags & IF_IGNORE)
    return;

  if (flags & IF_CHANGE_UP)
  {
    struct radv_iface_config *ic = (struct radv_iface_config *)
      iface_patt_find(&cf->patt_list, iface, NULL);

    if (ic)
      radv_iface_new(p, iface, ic);

    return;
  }

  struct radv_iface *ifa = radv_iface_find(p, iface);
  if (!ifa)
    return;

  if (flags & IF_CHANGE_DOWN)
  {
    radv_iface_remove(ifa);
    return;
  }

  if ((flags & IF_CHANGE_LINK) && (iface->flags & IF_LINK_UP))
    radv_iface_notify(ifa, RA_EV_INIT);
}

static void
radv_ifa_notify(struct proto *P, unsigned flags UNUSED, struct ifa *a)
{
  struct radv_proto *p = (struct radv_proto *) P;

  if (a->flags & IA_SECONDARY)
    return;

  if (a->scope <= SCOPE_LINK)
    return;

  struct radv_iface *ifa = radv_iface_find(p, a->iface);

  if (ifa)
    radv_iface_notify(ifa, RA_EV_CHANGE);
}

static inline int radv_net_match_trigger(struct radv_config *cf, net *n)
{
  return cf->trigger_valid &&
    (n->n.pxlen == cf->trigger_pxlen) &&
    ipa_equal(n->n.prefix, cf->trigger_prefix);
}

int
radv_import_control(struct proto *P, rte **new, ea_list **attrs UNUSED, struct linpool *pool UNUSED)
{
  // struct radv_proto *p = (struct radv_proto *) P;
  struct radv_config *cf = (struct radv_config *) (P->cf);

  if (radv_net_match_trigger(cf, (*new)->net))
    return RIC_PROCESS;

  if (cf->propagate_specific)
    return RIC_PROCESS;
  else
    return RIC_DROP;
}

/*
 * Cleans up all the dead routes that expired and schedules itself to be run
 * again if there are more routes waiting for expiration.
 *
 * Invoked as a timer callback (radv_proto::gc_timer).
 */
static void
radv_routes_gc(timer *tm)
{
  struct radv_proto *p = (void *) tm->data;
  struct radv_config *cf = (void *) p->p.cf;
  /* In case of race conditions after turning it off */
  if (!cf->propagate_specific)
    return;
  RADV_TRACE(D_EVENTS, "Route GC running");
  /* 0 -> no expiration scheduled */
  bird_clock_t nearest_expire = 0;
  uint count = p->route_cache.hash_size;
  /*
   * Allocate dynamically. We expect to have very few routes, but we can't be
   * *sure* of that. So we don't risk overflowing the stack with huge array.
   */
  struct radv_cache_node **condemned = mb_alloc(p->p.pool,
						count * sizeof *condemned);
  uint condemned_count = 0;
  FIB_WALK(&p->route_cache, node)
  {
    struct radv_cache_node *cnode = (void *) node;
    if (cnode->alive)
      continue;
    if (cnode->expires <= now)
      /* Can't delete right away when iterating */
      condemned[condemned_count ++] = cnode;
    else if (!nearest_expire || cnode->expires < nearest_expire)
      nearest_expire = cnode->expires;
  }
  FIB_WALK_END;

  for (uint i = 0; i < condemned_count; i ++)
    fib_delete(&p->route_cache, condemned[i]);

  mb_free(condemned);

  if (nearest_expire)
    tm_start(p->gc_timer, nearest_expire - now);

  radv_iface_notify_all(p, RA_EV_CHANGE);
}

static void
radv_rt_notify(struct proto *P, rtable *tbl UNUSED, net *n, rte *new, rte *old UNUSED, ea_list *attrs UNUSED)
{
  struct radv_proto *p = (struct radv_proto *) P;
  struct radv_config *cf = (struct radv_config *) (P->cf);

  if (radv_net_match_trigger(cf, n))
  {
    u8 old_active = p->active;
    p->active = !!new;

    if (p->active == old_active)
      return;

    if (p->active)
      RADV_TRACE(D_EVENTS, "Triggered");
    else
      RADV_TRACE(D_EVENTS, "Suppressed");

    radv_iface_notify_all(p, RA_EV_CHANGE);
  }
  else if (cf->propagate_specific)
  {
    /*
     * Some other route we want to send (or stop sending). Update the cache -
     * remove old if there was one first, and then insert a new one, if we got
     * it.
     *
     * And yes, we exclude the trigger route on purpose from the cache.
     */

    struct radv_cache_node *node = fib_find(&p->route_cache, &n->n.prefix,
					    n->n.pxlen);
    if (node && !new && node->alive) {
      node->alive = 0;
      node->expires = now + cf->specific_linger_time;
      if (!tm_active(p->gc_timer) ||
	  cf->specific_linger_time < tm_remains(p->gc_timer))
	tm_start(p->gc_timer, cf->specific_linger_time);
    }

    if (new) {
      if (!node)
	node = fib_get(&p->route_cache, &n->n.prefix, n->n.pxlen);
      node->alive = 1;
      ea_list *ea = new->attrs->eattrs;
      node->preference =
	ea_get_int(ea, EA_CODE(EAP_RADV, RA_PREF), PREF_MEDIUM);
      int lifetime =
	ea_get_int(ea, EA_CODE(EAP_RADV, RA_LIFE), -1);
      if (lifetime == -1) {
	node->lifetime_set = 0;
      } else {
	node->lifetime_set = 1;
	node->lifetime = lifetime;
      }
    }

    /* Schedule sending of the changes out. */
    /*
     * FIXME This is a bit drastic approach. For one, we should check that
     * something meaningful actually changed, compare the new and old.
     *
     * For another, there might be a better way to send out the update than just
     * invalidating all our state around interfaces.
     *
     * But this is the first shot.
     */
    radv_iface_notify_all(p, RA_EV_CHANGE);
  }
}

static int
radv_check_active(struct radv_proto *p)
{
  struct radv_config *cf = (struct radv_config *) (p->p.cf);

  if (! cf->trigger_valid)
    return 1;

  return rt_examine(p->p.table, cf->trigger_prefix, cf->trigger_pxlen,
		    &(p->p), p->p.cf->out_filter);
}

static struct proto *
radv_init(struct proto_config *c)
{
  struct proto *P = proto_new(c, sizeof(struct radv_proto));

  P->accept_ra_types = RA_OPTIMAL;
  P->import_control = radv_import_control;
  P->rt_notify = radv_rt_notify;
  P->if_notify = radv_if_notify;
  P->ifa_notify = radv_ifa_notify;

  return P;
}

static void
radv_set_propagate(struct radv_proto *p, u8 old, u8 new)
{
  if (old == new)
    return;

  if (new) {
    RADV_TRACE(D_EVENTS, "Creating a route cache");
    fib_init(&p->route_cache, p->p.pool, sizeof(struct radv_cache_node), 0,
	     NULL);
  } else {
    RADV_TRACE(D_EVENTS, "Getting rid of a route cache");
    fib_free(&p->route_cache);
    tm_stop(p->gc_timer);
  }

  /*
   * The propagate_specific option has an influence on what routes we allow to
   * reach the filters. Therefore, we need to re-request them and decide based
   * on the new configuration. But preferably *after* we switch the
   * configuration, so we use the new one O:-).
   */
  ev_schedule(p->refeed_request);
}

static void
radv_request_refeed(void *data)
{
  struct radv_proto *p = data;
  RADV_TRACE(D_EVENTS, "Asking for re-feeding of routes");
  proto_request_feeding(&p->p);
}

static int
radv_start(struct proto *P)
{
  struct radv_proto *p = (struct radv_proto *) P;
  struct radv_config *cf = (struct radv_config *) (P->cf);

  init_list(&(p->iface_list));
  p->active = !cf->trigger_valid;
  p->refeed_request = ev_new(P->pool);
  p->refeed_request->hook = radv_request_refeed;
  p->refeed_request->data = p;

  timer *tm = tm_new(P->pool);
  tm->hook = radv_routes_gc;
  tm->data = p;
  tm->randomize = 0;
  tm->recurrent = 0;
  p->gc_timer = tm;

  radv_set_propagate(p, 0, cf->propagate_specific);

  return PS_UP;
}

static inline void
radv_iface_shutdown(struct radv_iface *ifa)
{
  if (ifa->sk)
    radv_send_ra(ifa, 1);
}

static int
radv_shutdown(struct proto *P)
{
  struct radv_proto *p = (struct radv_proto *) P;
  struct radv_config *cf = (struct radv_config *) (P->cf);

  radv_set_propagate(p, cf->propagate_specific, 0);

  struct radv_iface *ifa;
  WALK_LIST(ifa, p->iface_list)
    radv_iface_shutdown(ifa);

  return PS_DOWN;
}

static int
radv_reconfigure(struct proto *P, struct proto_config *c)
{
  struct radv_proto *p = (struct radv_proto *) P;
  struct radv_config *old = (struct radv_config *) (P->cf);
  struct radv_config *new = (struct radv_config *) c;

  /*
   * The question is why there is a reconfigure function for RAdv if
   * it has almost none internal state so restarting the protocol
   * would probably suffice. One small reason is that restarting the
   * protocol would lead to sending a RA with Router Lifetime 0
   * causing nodes to temporary remove their default routes.
   */

  P->cf = c; /* radv_check_active() requires proper P->cf */
  p->active = radv_check_active(p);

  radv_set_propagate(p, old->propagate_specific, new->propagate_specific);

  struct iface *iface;
  WALK_LIST(iface, iface_list)
  {
    struct radv_iface *ifa = radv_iface_find(p, iface);
    struct radv_iface_config *ic = (struct radv_iface_config *)
      iface_patt_find(&new->patt_list, iface, NULL);

    if (ifa && ic)
    {
      ifa->cf = ic;

      /* We cheat here - always notify the change even if there isn't
	 any. That would leads just to a few unnecessary RAs. */
      radv_iface_notify(ifa, RA_EV_CHANGE);
    }

    if (ifa && !ic)
    {
      radv_iface_shutdown(ifa);
      radv_iface_remove(ifa);
    }

    if (!ifa && ic)
      radv_iface_new(p, iface, ic);
  }

  return 1;
}

static void
radv_copy_config(struct proto_config *dest, struct proto_config *src)
{
  struct radv_config *d = (struct radv_config *) dest;
  struct radv_config *s = (struct radv_config *) src;

  /* We clean up patt_list, ifaces are non-sharable */
  init_list(&d->patt_list);

  /* We copy pref_list, shallow copy suffices */
  cfg_copy_list(&d->pref_list, &s->pref_list, sizeof(struct radv_prefix_config));
}

static void
radv_get_status(struct proto *P, byte *buf)
{
  struct radv_proto *p = (struct radv_proto *) P;

  if (!p->active)
    strcpy(buf, "Suppressed");
}

static const char *
radv_pref_str(u32 pref)
{
  switch (pref)
  {
    case RA_PREF_LOW:
      return "low";
    case RA_PREF_MEDIUM:
      return "medium";
    case RA_PREF_HIGH:
      return "high";
    default:
      return "??";
  }
}

/* The buffer has some minimal size */
static int
radv_get_attr(eattr *a, byte *buf, int buflen UNUSED)
{
  switch (EA_ID(a->id))
  {
  case RA_PREF:
    bsprintf(buf, "preference: %s", radv_pref_str(a->u.data));
    return GA_FULL;
  case RA_LIFE:
    bsprintf(buf, "lifetime");
    return GA_NAME;
  default:
    return GA_UNKNOWN;
  }
}

struct protocol proto_radv = {
  .name =		"RAdv",
  .template =		"radv%d",
  .attr_class =		EAP_RADV,
  .config_size =	sizeof(struct radv_config),
  .init =		radv_init,
  .start =		radv_start,
  .shutdown =		radv_shutdown,
  .reconfigure =	radv_reconfigure,
  .copy_config =	radv_copy_config,
  .get_status =		radv_get_status,
  .get_attr =		radv_get_attr
};
