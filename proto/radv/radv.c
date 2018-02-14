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
 * The RAdv protocol is implemented in two files: |radv.c| containing the
 * interface with BIRD core and the protocol logic and |packets.c| handling low
 * level protocol stuff (RX, TX and packet formats). The protocol does not
 * export any routes.
 *
 * The RAdv is structured in the usual way - for each handled interface there is
 * a structure &radv_iface that contains a state related to that interface
 * together with its resources (a socket, a timer). There is also a prepared RA
 * stored in a TX buffer of the socket associated with an iface. These iface
 * structures are created and removed according to iface events from BIRD core
 * handled by radv_if_notify() callback.
 *
 * The main logic of RAdv consists of two functions: radv_iface_notify(), which
 * processes asynchronous events (specified by RA_EV_* codes), and radv_timer(),
 * which triggers sending RAs and computes the next timeout.
 *
 * The RAdv protocol could receive routes (through radv_preexport() and
 * radv_rt_notify()), but only the configured trigger route is tracked (in
 * &active var).  When a radv protocol is reconfigured, the connected routing
 * table is examined (in radv_check_active()) to have proper &active value in
 * case of the specified trigger prefix was changed.
 *
 * Supported standards:
 * - RFC 4861 - main RA standard
 * - RFC 4191 - Default Router Preferences and More-Specific Routes
 * - RFC 6106 - DNS extensions (RDDNS, DNSSL)
 */

static void radv_prune_prefixes(struct radv_iface *ifa);
static void radv_prune_routes(struct radv_proto *p);

/* Invalidate cached RA packet */
static inline void radv_invalidate(struct radv_iface *ifa)
{ ifa->plen = 0; }

static void
radv_timer(timer *tm)
{
  struct radv_iface *ifa = tm->data;
  struct radv_proto *p = ifa->ra;
  btime now = current_time();

  RADV_TRACE(D_EVENTS, "Timer fired on %s", ifa->iface->name);

  if (ifa->valid_time <= now)
    radv_invalidate(ifa);

  if (ifa->prune_time <= now)
    radv_prune_prefixes(ifa);

  if (p->prune_time <= now)
    radv_prune_routes(p);

  radv_send_ra(ifa);

  /* Update timer */
  ifa->last = now;
  btime t = ifa->cf->min_ra_int S;
  btime r = (ifa->cf->max_ra_int - ifa->cf->min_ra_int) S;
  t += random() % (r + 1);

  if (ifa->initial)
  {
    t = MIN(t, MAX_INITIAL_RTR_ADVERT_INTERVAL);
    ifa->initial--;
  }

  tm_start(ifa->timer, t);
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
radv_prefix_match(struct radv_iface *ifa, net_addr_ip6 *px)
{
  struct radv_proto *p = ifa->ra;
  struct radv_config *cf = (struct radv_config *) (p->p.cf);
  struct radv_prefix_config *pc;

  WALK_LIST(pc, ifa->cf->pref_list)
    if (net_in_net_ip6(px, &pc->prefix))
      return pc;

  WALK_LIST(pc, cf->pref_list)
    if (net_in_net_ip6(px, &pc->prefix))
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
  struct radv_prefix *pfx, *next;
  btime now = current_time();

  /* First mark all the prefixes as unused */
  WALK_LIST(pfx, ifa->prefixes)
    pfx->mark = 0;

  /* Find all the prefixes we want to use and make sure they are in the list. */
  struct ifa *addr;
  WALK_LIST(addr, ifa->iface->addrs)
  {
    if ((addr->prefix.type != NET_IP6) ||
	(addr->scope <= SCOPE_LINK))
      continue;

    net_addr_ip6 *prefix = (void *) &addr->prefix;
    struct radv_prefix_config *pc = radv_prefix_match(ifa, prefix);

    if (!pc || pc->skip)
      continue;

    /* Do we have it already? */
    struct radv_prefix *existing = NULL;
    WALK_LIST(pfx, ifa->prefixes)
      if (net_equal_ip6(&pfx->prefix, prefix))
      {
	existing = pfx;
	break;
      }

    if (!existing)
    {
      RADV_TRACE(D_EVENTS, "Adding new prefix %N on %s",
		 prefix, ifa->iface->name);

      existing = mb_allocz(ifa->pool, sizeof *existing);
      net_copy_ip6(&existing->prefix, prefix);
      add_tail(&ifa->prefixes, NODE existing);
    }

    /*
     * Update the information (it may have changed, or even bring a prefix back
     * to life).
     */
    existing->valid = 1;
    existing->changed = now;
    existing->mark = 1;
    existing->cf = pc;
  }

  WALK_LIST_DELSAFE(pfx, next, ifa->prefixes)
  {
    if (pfx->valid && !pfx->mark)
    {
      RADV_TRACE(D_EVENTS, "Invalidating prefix %N on %s",
		 pfx->prefix, ifa->iface->name);

      pfx->valid = 0;
      pfx->changed = now;
      pfx->cf = &dead_prefix;
    }
  }
}

static void
radv_prune_prefixes(struct radv_iface *ifa)
{
  struct radv_proto *p = ifa->ra;
  btime now = current_time();
  btime next = TIME_INFINITY;
  btime expires = 0;

  struct radv_prefix *px, *pxn;
  WALK_LIST_DELSAFE(px, pxn, ifa->prefixes)
  {
    if (!px->valid)
    {
      expires = px->changed + ifa->cf->prefix_linger_time S;

      if (expires <= now)
      {
	RADV_TRACE(D_EVENTS, "Removing prefix %N on %s",
		   px->prefix, ifa->iface->name);

	rem_node(NODE px);
	mb_free(px);
      }
      else
	next = MIN(next, expires);
    }
  }

  ifa->prune_time = next;
}

static char* ev_name[] = { NULL, "Init", "Change", "RS" };

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
    radv_invalidate(ifa);
  case RA_EV_INIT:
    ifa->initial = MAX_INITIAL_RTR_ADVERTISEMENTS;
    radv_prepare_prefixes(ifa);
    radv_prune_prefixes(ifa);
    break;

  case RA_EV_RS:
    break;
  }

  /* Update timer */
  btime t = ifa->last + ifa->cf->min_delay S - current_time();
  tm_start(ifa->timer, t);
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
  ifa->addr = iface->llv6;
  init_list(&ifa->prefixes);
  ifa->prune_time = TIME_INFINITY;

  add_tail(&p->iface_list, NODE ifa);

  ifa->timer = tm_new_init(pool, radv_timer, ifa, 0, 0);

  struct object_lock *lock = olock_new(pool);
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
    struct radv_iface_config *ic = (void *) iface_patt_find(&cf->patt_list, iface, NULL);

    /* Ignore non-multicast ifaces */
    if (!(iface->flags & IF_MULTICAST))
      return;

    /* Ignore ifaces without link-local address */
    if (!iface->llv6)
      return;

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

static inline int
radv_trigger_valid(struct radv_config *cf)
{
  return cf->trigger.type != 0;
}

static inline int
radv_net_match_trigger(struct radv_config *cf, net *n)
{
  return radv_trigger_valid(cf) && net_equal(n->n.addr, &cf->trigger);
}

int
radv_preexport(struct proto *P, rte **new, ea_list **attrs UNUSED, struct linpool *pool UNUSED)
{
  // struct radv_proto *p = (struct radv_proto *) P;
  struct radv_config *cf = (struct radv_config *) (P->cf);

  if (radv_net_match_trigger(cf, (*new)->net))
    return RIC_PROCESS;

  if (cf->propagate_routes)
    return RIC_PROCESS;
  else
    return RIC_DROP;
}

static void
radv_rt_notify(struct proto *P, struct channel *ch UNUSED, net *n, rte *new, rte *old UNUSED, ea_list *attrs)
{
  struct radv_proto *p = (struct radv_proto *) P;
  struct radv_config *cf = (struct radv_config *) (P->cf);
  struct radv_route *rt;
  eattr *ea;

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
    return;
  }

  if (!cf->propagate_routes)
    return;

  /*
   * Some other route we want to send (or stop sending). Update the cache,
   * with marking a removed one as dead or creating a new one as needed.
   *
   * And yes, we exclude the trigger route on purpose.
   */

  if (new)
  {
    /* Update */

    ea = ea_find(attrs, EA_RA_PREFERENCE);
    uint preference = ea ? ea->u.data : RA_PREF_MEDIUM;
    uint preference_set = !!ea;

    ea = ea_find(attrs, EA_RA_LIFETIME);
    uint lifetime = ea ? ea->u.data : 0;
    uint lifetime_set = !!ea;

    if ((preference != RA_PREF_LOW) &&
	(preference != RA_PREF_MEDIUM) &&
	(preference != RA_PREF_HIGH))
    {
      log(L_WARN "%s: Invalid ra_preference value %u on route %N",
	  p->p.name, preference, n->n.addr);
      preference = RA_PREF_MEDIUM;
      preference_set = 1;
      lifetime = 0;
      lifetime_set = 1;
    }

    rt = fib_get(&p->routes, n->n.addr);

    /* Ignore update if nothing changed */
    if (rt->valid &&
	(rt->preference == preference) &&
	(rt->preference_set == preference_set) &&
	(rt->lifetime == lifetime) &&
	(rt->lifetime_set == lifetime_set))
      return;

    if (p->routes.entries == 18)
      log(L_WARN "%s: More than 17 routes exported to RAdv", p->p.name);

    rt->valid = 1;
    rt->changed = current_time();
    rt->preference = preference;
    rt->preference_set = preference_set;
    rt->lifetime = lifetime;
    rt->lifetime_set = lifetime_set;
  }
  else
  {
    /* Withdraw */
    rt = fib_find(&p->routes, n->n.addr);

    if (!rt || !rt->valid)
      return;

    /* Invalidate the route */
    rt->valid = 0;
    rt->changed = current_time();

    /* Invalidated route will be pruned eventually */
    btime expires = rt->changed + cf->max_linger_time S;
    p->prune_time = MIN(p->prune_time, expires);
  }

  radv_iface_notify_all(p, RA_EV_CHANGE);
}

/*
 * Cleans up all the dead routes that expired and schedules itself to be run
 * again if there are more routes waiting for expiration.
 */
static void
radv_prune_routes(struct radv_proto *p)
{
  struct radv_config *cf = (struct radv_config *) (p->p.cf);
  btime now = current_time();
  btime next = TIME_INFINITY;
  btime expires = 0;

  /* Should not happen */
  if (!p->fib_up)
    return;

  struct fib_iterator fit;
  FIB_ITERATE_INIT(&fit, &p->routes);

again:
  FIB_ITERATE_START(&p->routes, &fit, struct radv_route, rt)
  {
    if (!rt->valid)
    {
      expires = rt->changed + cf->max_linger_time S;

      /* Delete expired nodes */
      if (expires <= now)
      {
	FIB_ITERATE_PUT(&fit);
	fib_delete(&p->routes, rt);
	goto again;
      }
      else
	next = MIN(next, expires);
    }
  }
  FIB_ITERATE_END;

  p->prune_time = next;
}

static int
radv_check_active(struct radv_proto *p)
{
  struct radv_config *cf = (struct radv_config *) (p->p.cf);

  if (!radv_trigger_valid(cf))
    return 1;

  struct channel *c = p->p.main_channel;
  struct linpool *lp = lp_new(p->p.pool, 1024);
  return rt_examine(c->table, &cf->trigger, &p->p, c->out_filter, lp);
  rfree(lp);
}

static void
radv_postconfig(struct proto_config *CF)
{
  // struct radv_config *cf = (void *) CF;

  /* Define default channel */
  if (EMPTY_LIST(CF->channels))
    channel_config_new(NULL, net_label[NET_IP6], NET_IP6, CF);
}

static struct proto *
radv_init(struct proto_config *CF)
{
  struct proto *P = proto_new(CF);

  P->main_channel = proto_add_channel(P, proto_cf_main_channel(CF));

  P->preexport = radv_preexport;
  P->rt_notify = radv_rt_notify;
  P->if_notify = radv_if_notify;
  P->ifa_notify = radv_ifa_notify;

  return P;
}

static void
radv_set_fib(struct radv_proto *p, int up)
{
  if (up == p->fib_up)
    return;

  if (up)
    fib_init(&p->routes, p->p.pool, NET_IP6, sizeof(struct radv_route),
	     OFFSETOF(struct radv_route, n), 4, NULL);
  else
    fib_free(&p->routes);

  p->fib_up = up;
  p->prune_time = TIME_INFINITY;
}

static int
radv_start(struct proto *P)
{
  struct radv_proto *p = (struct radv_proto *) P;
  struct radv_config *cf = (struct radv_config *) (P->cf);

  init_list(&(p->iface_list));
  p->valid = 1;
  p->active = !radv_trigger_valid(cf);

  p->fib_up = 0;
  radv_set_fib(p, cf->propagate_routes);
  p->prune_time = TIME_INFINITY;

  return PS_UP;
}

static inline void
radv_iface_shutdown(struct radv_iface *ifa)
{
  if (ifa->sk)
  {
    radv_invalidate(ifa);
    radv_send_ra(ifa);
  }
}

static int
radv_shutdown(struct proto *P)
{
  struct radv_proto *p = (struct radv_proto *) P;

  p->valid = 0;

  struct radv_iface *ifa;
  WALK_LIST(ifa, p->iface_list)
    radv_iface_shutdown(ifa);

  return PS_DOWN;
}

static int
radv_reconfigure(struct proto *P, struct proto_config *CF)
{
  struct radv_proto *p = (struct radv_proto *) P;
  struct radv_config *old = (struct radv_config *) (P->cf);
  struct radv_config *new = (struct radv_config *) CF;

  if (!proto_configure_channel(P, &P->main_channel, proto_cf_main_channel(CF)))
    return 0;

  P->cf = CF; /* radv_check_active() requires proper P->cf */
  p->active = radv_check_active(p);

  /* Allocate or free FIB */
  radv_set_fib(p, new->propagate_routes);

  /* We started to accept routes so we need to refeed them */
  if (!old->propagate_routes && new->propagate_routes)
    channel_request_feeding(p->p.main_channel);

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
  switch (a->id)
  {
  case EA_RA_PREFERENCE:
    bsprintf(buf, "preference: %s", radv_pref_str(a->u.data));
    return GA_FULL;
  case EA_RA_LIFETIME:
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
  .channel_mask =	NB_IP6,
  .proto_size =		sizeof(struct radv_proto),
  .config_size =	sizeof(struct radv_config),
  .postconfig =		radv_postconfig,
  .init =		radv_init,
  .start =		radv_start,
  .shutdown =		radv_shutdown,
  .reconfigure =	radv_reconfigure,
  .copy_config =	radv_copy_config,
  .get_status =		radv_get_status,
  .get_attr =		radv_get_attr
};
