/*
 *	BIRD -- Table-to-Table Routing Protocol a.k.a Pipe
 *
 *	(c) 1999--2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: Pipe
 *
 * The Pipe protocol is very simple. It just connects to two routing tables
 * using proto_add_announce_hook() and whenever it receives a rt_notify()
 * about a change in one of the tables, it converts it to a rte_update()
 * in the other one.
 *
 * To avoid pipe loops, Pipe keeps a `being updated' flag in each routing
 * table.
 *
 * A pipe has two announce hooks, the first connected to the main
 * table, the second connected to the peer table. When a new route is
 * announced on the main table, it gets checked by an export filter in
 * ahook 1, and, after that, it is announced to the peer table via
 * rte_update(), an import filter in ahook 2 is called. When a new
 * route is announced in the peer table, an export filter in ahook2
 * and an import filter in ahook 1 are used. Oviously, there is no
 * need in filtering the same route twice, so both import filters are
 * set to accept, while user configured 'import' and 'export' filters
 * are used as export filters in ahooks 2 and 1. Route limits are
 * handled similarly, but on the import side of ahooks.
 */

#undef LOCAL_DEBUG

#include "nest/bird.h"
#include "nest/iface.h"
#include "nest/protocol.h"
#include "nest/route.h"
#include "nest/cli.h"
#include "conf/conf.h"
#include "filter/filter.h"
#include "lib/string.h"

#include "pipe.h"

static void
pipe_rt_notify(struct proto *P, struct channel *src_ch, net *n, rte *new, rte *old, ea_list *attrs)
{
  struct pipe_proto *p = (void *) P;
  struct channel *dst = (src_ch == p->pri) ? p->sec : p->pri;
  struct rte_src *src;

  rte *e;
  rta *a;

  if (!new && !old)
    return;

  if (dst->table->pipe_busy)
    {
      log(L_ERR "Pipe loop detected when sending %N to table %s",
	  n->n.addr, dst->table->name);
      return;
    }

  if (new)
    {
      a = alloca(rta_size(new->attrs));
      memcpy(a, new->attrs, rta_size(new->attrs));

      a->aflags = 0;
      a->eattrs = attrs;
      a->hostentry = NULL;
      e = rte_get_temp(a);
      e->pflags = 0;

      /* Copy protocol specific embedded attributes. */
      memcpy(&(e->u), &(new->u), sizeof(e->u));
      e->pref = new->pref;
      e->pflags = new->pflags;

      src = a->src;
    }
  else
    {
      e = NULL;
      src = old->attrs->src;
    }

  src_ch->table->pipe_busy = 1;
  rte_update2(dst, n->n.addr, e, src);
  src_ch->table->pipe_busy = 0;
}

static int
pipe_import_control(struct proto *P, rte **ee, ea_list **ea UNUSED, struct linpool *p UNUSED)
{
  struct proto *pp = (*ee)->sender->proto;

  if (pp == P)
    return -1;	/* Avoid local loops automatically */

  return 0;
}

static void
pipe_reload_routes(struct channel *C)
{
  struct pipe_proto *p = (void *) C->proto;

  /* Route reload on one channel is just refeed on the other */
  channel_request_feeding((C == p->pri) ? p->sec : p->pri);
}


static void
pipe_postconfig(struct proto_config *CF)
{
  struct pipe_config *cf = (void *) CF;
  struct channel_config *cc = proto_cf_main_channel(CF);

  if (!cc->table)
    cf_error("Primary routing table not specified");

  if (!cf->peer)
    cf_error("Secondary routing table not specified");

  if (cc->table == cf->peer)
    cf_error("Primary table and peer table must be different");

  if (cc->table->addr_type != cf->peer->addr_type)
    cf_error("Primary table and peer table must have the same type");

  if (cc->rx_limit.action)
    cf_error("Pipe protocol does not support receive limits");

  if (cc->in_keep_filtered)
    cf_error("Pipe protocol prohibits keeping filtered routes");
}

static int
pipe_configure_channels(struct pipe_proto *p, struct pipe_config *cf)
{
  struct channel_config *cc = proto_cf_main_channel(&cf->c);

  struct channel_config pri_cf = {
    .name = "pri",
    .channel = cc->channel,
    .table = cc->table,
    .out_filter = cc->out_filter,
    .in_limit = cc->in_limit,
    .ra_mode = RA_ANY
  };

  struct channel_config sec_cf = {
    .name = "sec",
    .channel = cc->channel,
    .table = cf->peer,
    .out_filter = cc->in_filter,
    .in_limit = cc->out_limit,
    .ra_mode = RA_ANY
  };

  return
    proto_configure_channel(&p->p, &p->pri, &pri_cf) &&
    proto_configure_channel(&p->p, &p->sec, &sec_cf);
}

static struct proto *
pipe_init(struct proto_config *CF)
{
  struct proto *P = proto_new(CF);
  struct pipe_proto *p = (void *) P;
  struct pipe_config *cf = (void *) CF;

  P->rt_notify = pipe_rt_notify;
  P->import_control = pipe_import_control;
  P->reload_routes = pipe_reload_routes;

  pipe_configure_channels(p, cf);

  return P;
}

static int
pipe_reconfigure(struct proto *P, struct proto_config *CF)
{
  struct pipe_proto *p = (void *) P;
  struct pipe_config *cf = (void *) CF;

  return pipe_configure_channels(p, cf);
}

static void
pipe_copy_config(struct proto_config *dest UNUSED, struct proto_config *src UNUSED)
{
  /* Just a shallow copy, not many items here */
}

static const char *pipe_channel_left_state[] = { [ES_DOWN] = "--", [ES_FEEDING] = "<<", [ES_READY] = "==" };
static const char *pipe_channel_right_state[] = { [ES_DOWN] = "--", [ES_FEEDING] = ">>", [ES_READY] = "==" };

static void
pipe_get_status(struct proto *P, byte *buf)
{
  struct pipe_proto *p = (void *) P;
  bsprintf(buf, "%s  %s%s  %s",
      p->pri->table->name, pipe_channel_left_state[p->sec->export_state],
      pipe_channel_right_state[p->pri->export_state], p->sec->table->name);
}

static void
pipe_show_stats(struct pipe_proto *p)
{
  struct proto_stats *s1 = &p->pri->stats;
  struct proto_stats *s2 = &p->sec->stats;

  /*
   * Pipe stats (as anything related to pipes) are a bit tricky. There
   * are two sets of stats - s1 for ahook to the primary routing and
   * s2 for the ahook to the secondary routing table. The user point
   * of view is that routes going from the primary routing table to
   * the secondary routing table are 'exported', while routes going in
   * the other direction are 'imported'.
   *
   * Each route going through a pipe is, technically, first exported
   * to the pipe and then imported from that pipe and such operations
   * are counted in one set of stats according to the direction of the
   * route propagation. Filtering is done just in the first part
   * (export). Therefore, we compose stats for one directon for one
   * user direction from both import and export stats, skipping
   * immediate and irrelevant steps (exp_updates_accepted,
   * imp_updates_received, imp_updates_filtered, ...).
   *
   * Rule of thumb is that stats s1 have the correct 'polarity'
   * (imp/exp), while stats s2 have switched 'polarity'.
   */

  cli_msg(-1006, "  Routes:         %u imported, %u exported",
	  s1->imp_routes, s2->imp_routes);
  cli_msg(-1006, "  Route change stats:     received   rejected   filtered    ignored   accepted");
  cli_msg(-1006, "    Import updates:     %10u %10u %10u %10u %10u",
	  s2->exp_updates_received, s2->exp_updates_rejected + s1->imp_updates_invalid,
	  s2->exp_updates_filtered, s1->imp_updates_ignored, s1->imp_updates_accepted);
  cli_msg(-1006, "    Import withdraws:   %10u %10u        --- %10u %10u",
	  s2->exp_withdraws_received, s1->imp_withdraws_invalid,
	  s1->imp_withdraws_ignored, s1->imp_withdraws_accepted);
  cli_msg(-1006, "    Export updates:     %10u %10u %10u %10u %10u",
	  s1->exp_updates_received, s1->exp_updates_rejected + s2->imp_updates_invalid,
	  s1->exp_updates_filtered, s2->imp_updates_ignored, s2->imp_updates_accepted);
  cli_msg(-1006, "    Export withdraws:   %10u %10u        --- %10u %10u",
	  s1->exp_withdraws_received, s2->imp_withdraws_invalid,
	  s2->imp_withdraws_ignored, s2->imp_withdraws_accepted);
}

static void
pipe_show_proto_info(struct proto *P)
{
  struct pipe_proto *p = (void *) P;

  cli_msg(-1006, "  Channel %s", "main");
  cli_msg(-1006, "    Table:          %s", p->pri->table->name);
  cli_msg(-1006, "    Peer table:     %s", p->sec->table->name);
  cli_msg(-1006, "    Import filter:  %s", filter_name(p->sec->out_filter));
  cli_msg(-1006, "    Export filter:  %s", filter_name(p->pri->out_filter));

  channel_show_limit(&p->pri->in_limit, "Import limit:");
  channel_show_limit(&p->sec->in_limit, "Export limit:");

  if (P->proto_state != PS_DOWN)
    pipe_show_stats(p);
}


struct protocol proto_pipe = {
  .name =		"Pipe",
  .template =		"pipe%d",
  .proto_size =		sizeof(struct pipe_proto),
  .config_size =	sizeof(struct pipe_config),
  .postconfig =		pipe_postconfig,
  .init =		pipe_init,
  .reconfigure =	pipe_reconfigure,
  .copy_config = 	pipe_copy_config,
  .get_status = 	pipe_get_status,
  .show_proto_info = 	pipe_show_proto_info
};
