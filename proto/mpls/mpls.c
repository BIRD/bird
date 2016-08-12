/*
 *	BIRD -- MPLS central hub
 *
 *	(c) 2016 Jan Moskyto Matejka <mq@ucw.cz>
 *	(c) 2016 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: MPLS
 *
 * This protocol is a governor over its MPLS table. It maintains the MPLS
 * routes in that table to match the MPLS enabled IP routing tables.
 *
 * This protocol is the authority that assigns the MPLS labels. It also
 * maintains route labelling according to neighbors' LIBs.
 *
 * Route labelling (neighbor labels):
 * a) the protocol may import a route with a full neighbor's MPLS stack. This
 *    may happen e.g. for single hop labeled BGP. Nothing more is needed to do.
 * b) the protocol may import a route with a recursive nexthop and partial MPLS
 *    stack (according to that nexthop). The route gets resolved via hostentry
 *    and prepended the appropriate MPLS stack for the neighbor. This may
 *    happen e.g. for multihop labeled BGP.
 * c) the protocol may be MPLS unaware at all. Then the MPLS labeling pipeline
 *    is activated and the route gets its libentry. The MPLS labels may then
 *    change even when no route change appears. This may happen e.g. for OSPF
 *    which is then labeled by e.g. LDP.
 *
 * Note: Recursive routes (nexthops) cannot be labeled externally. The only
 * source of label stack in recursive nexthop is the importing protocol itself.
 *
 * Label assignments (local labels):
 * a) the protocol may ignore label assignments at all. Then the MPLS protocol
 *    assigns a label to every route, one label per destination
 * b) the protocol may request a label and then import a MPLS route specifying
 *    what to do with that label
 *
 */

#undef LOCAL_DEBUG

#include "nest/bird.h"
#include "nest/protocol.h"
#include "nest/route.h"

#include "mpls.h"

static void
mpls_rt_notify(struct proto *P, struct channel *ch, net *n, rte *new, rte *old UNUSED, ea_list *ea)
{
}

static void mpls_postconfig(struct proto_config *CF)
{
  struct mpls_config *c = (struct mpls_config *) CF;
  if (!c->mpls_channel)
    cf_error("MPLS channel must be configured in MPLS protocol.");
}

static struct proto *mpls_init(struct proto_config *CF)
{
  struct proto *P = proto_new(CF);
  struct mpls_proto *p = (struct mpls_proto *) P;

  struct channel_config *cc;
  WALK_LIST(cc, CF->channels)
    if (cc->net_type == NET_MPLS)
      p->mpls_channel = proto_add_channel(P, cc);
    else
      proto_add_channel(P, cc);

  P->rt_notify = mpls_rt_notify;

  return P;
}

static int mpls_start(struct proto *P)
{
  struct mpls_proto *p = (struct mpls_proto *) P;

  struct channel *ch;
  WALK_LIST(ch, p->p.channels)
    if (ch->table->mpls_flags & RT_MPLS_LABELED)
    {
      log(L_ERR "%s: Cannot start MPLS protocol: Table %s already labeled by another instance", p->p.name, ch->table->name);
      return PS_START;
    }

  WALK_LIST(ch, p->p.channels)
    ch->table->mpls_flags |= RT_MPLS_LABELED;

  return PS_UP;
}

static int mpls_shutdown(struct proto *P)
{
  struct channel *ch;
  WALK_LIST(ch, P->channels)
    ch->table->mpls_flags &= ~RT_MPLS_LABELED;

  return PS_DOWN;
}

static int mpls_reconfigure(struct proto *p, struct proto_config *c)
{
  return 1;
}

struct protocol proto_mpls = {
  .name =		"MPLS",
  .template =		"mpls%d",
  .preference =		DEF_PREF_MPLS,
  .channel_mask =	NB_IP | NB_MPLS,
  .proto_size =		sizeof(struct mpls_proto),
  .config_size =	sizeof(struct mpls_config),
  .postconfig =		mpls_postconfig,
  .init =		mpls_init,
  .start =		mpls_start,
  .shutdown =		mpls_shutdown,
  .reconfigure =	mpls_reconfigure,
};


