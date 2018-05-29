/*
 *	BIRD -- Route Display Routines
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *	(c) 2017       Jan Moskyto Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#undef LOCAL_DEBUG

#include "nest/bird.h"
#include "nest/route.h"
#include "nest/protocol.h"
#include "nest/cli.h"
#include "nest/iface.h"
#include "filter/filter.h"

static void
rt_show_table(struct cli *c, struct rt_show_data *d)
{
  /* No table blocks in 'show route count' */
  if (d->stats == 2)
    return;

  if (d->last_table) cli_printf(c, -1007, "");
  cli_printf(c, -1007, "Table %s:", d->tab->table->name);
  d->last_table = d->tab;
}

static void
rt_show_rte(struct cli *c, byte *ia, rte *e, struct rt_show_data *d)
{
  byte from[IPA_MAX_TEXT_LENGTH+8];
  byte tm[TM_DATETIME_BUFFER_SIZE], info[256];
  rta *a = e->attrs;
  int primary = (e->net->routes == e);
  int sync_error = (e->net->n.flags & KRF_SYNC_ERROR);
  void (*get_route_info)(struct rte *, byte *buf);
  struct nexthop *nh;

  tm_format_time(tm, &config->tf_route, e->lastmod);
  if (ipa_nonzero(a->from) && !ipa_equal(a->from, a->nh.gw))
    bsprintf(from, " from %I", a->from);
  else
    from[0] = 0;

  get_route_info = a->src->proto->proto->get_route_info;
  /* Need to normalize the extended attributes */
  if ((get_route_info || d->verbose) && !rta_is_cached(a))
    ea_normalize(a->eattrs);
  if (get_route_info)
    get_route_info(e, info);
  else
    bsprintf(info, " (%d)", e->pref);

  if (d->last_table != d->tab)
    rt_show_table(c, d);

  cli_printf(c, -1007, "%-20s %s [%s %s%s]%s%s", ia, rta_dest_name(a->dest),
	     a->src->proto->name, tm, from, primary ? (sync_error ? " !" : " *") : "", info);

  if (a->dest == RTD_UNICAST)
    for (nh = &(a->nh); nh; nh = nh->next)
    {
      char mpls[MPLS_MAX_LABEL_STACK*12 + 5], *lsp = mpls;
      char *onlink = (nh->flags & RNF_ONLINK) ? " onlink" : "";
      char weight[16] = "";

      if (nh->labels)
	{
	  lsp += bsprintf(lsp, " mpls %d", nh->label[0]);
	  for (int i=1;i<nh->labels; i++)
	    lsp += bsprintf(lsp, "/%d", nh->label[i]);
	}
      *lsp = '\0';

      if (a->nh.next)
	bsprintf(weight, " weight %d", nh->weight + 1);

      if (ipa_nonzero(nh->gw))
	cli_printf(c, -1007, "\tvia %I on %s%s%s%s",
		   nh->gw, nh->iface->name, mpls, onlink, weight);
      else
	cli_printf(c, -1007, "\tdev %s%s%s",
		   nh->iface->name, mpls,  onlink, weight);
    }

  if (d->verbose)
    rta_show(c, a);
}

static void
rt_show_net(struct cli *c, net *n, struct rt_show_data *d)
{
  rte *e, *ee;
  byte ia[NET_MAX_TEXT_LENGTH+1];
  struct channel *ec = d->tab->export_channel;
  int first = 1;
  int pass = 0;

  bsnprintf(ia, sizeof(ia), "%N", n->n.addr);

  for (e = n->routes; e; e = e->next)
    {
      if (rte_is_filtered(e) != d->filtered)
	continue;

      d->rt_counter++;
      d->net_counter += first;
      first = 0;

      if (pass)
	continue;

      ee = e;
      rte_make_tmp_attrs(&e, c->show_pool);

      /* Export channel is down, do not try to export routes to it */
      if (ec && (ec->export_state == ES_DOWN))
	goto skip;

      /* Special case for merged export */
      if ((d->export_mode == RSEM_EXPORT) && (ec->ra_mode == RA_MERGED))
	{
	  rte *rt_free;
	  e = rt_export_merged(ec, n, &rt_free, c->show_pool, 1);
	  pass = 1;

	  if (!e)
	  { e = ee; goto skip; }
	}
      else if (d->export_mode)
	{
	  struct proto *ep = ec->proto;
	  int ic = ep->import_control ? ep->import_control(ep, &e, c->show_pool) : 0;

	  if (ec->ra_mode == RA_OPTIMAL || ec->ra_mode == RA_MERGED)
	    pass = 1;

	  if (ic < 0)
	    goto skip;

	  if (d->export_mode > RSEM_PREEXPORT)
	    {
	      /*
	       * FIXME - This shows what should be exported according to current
	       * filters, but not what was really exported. 'configure soft'
	       * command may change the export filter and do not update routes.
	       */
	      int do_export = (ic > 0) ||
		(f_run(ec->out_filter, &e, c->show_pool, FF_SILENT) <= F_ACCEPT);

	      if (do_export != (d->export_mode == RSEM_EXPORT))
		goto skip;

	      if ((d->export_mode == RSEM_EXPORT) && (ec->ra_mode == RA_ACCEPTED))
		pass = 1;
	    }
	}

      if (d->show_protocol && (d->show_protocol != e->attrs->src->proto))
	goto skip;

      if (f_run(d->filter, &e, c->show_pool, 0) > F_ACCEPT)
	goto skip;

      if (d->stats < 2)
	rt_show_rte(c, ia, e, d);

      d->show_counter++;
      ia[0] = 0;

    skip:
      if (e != ee)
      {
	rte_free(e);
	e = ee;
      }
      lp_flush(c->show_pool);

      if (d->primary_only)
	break;
    }
}

static void
rt_show_cleanup(struct cli *c)
{
  struct rt_show_data *d = c->rover;
  struct rt_show_data_rtable *tab;

  /* Unlink the iterator */
  if (d->table_open)
    fit_get(&d->tab->table->fib, &d->fit);

  /* Unlock referenced tables */
  WALK_LIST(tab, d->tables)
    rt_unlock_table(tab->table);
}

static void
rt_show_cont(struct cli *c)
{
  struct rt_show_data *d = c->rover;
#ifdef DEBUGGING
  unsigned max = 4;
#else
  unsigned max = 64;
#endif
  struct fib *fib = &d->tab->table->fib;
  struct fib_iterator *it = &d->fit;

  if (d->running_on_config && (d->running_on_config != config))
  {
    cli_printf(c, 8004, "Stopped due to reconfiguration");
    goto done;
  }

  if (!d->table_open)
  {
    FIB_ITERATE_INIT(&d->fit, &d->tab->table->fib);
    d->table_open = 1;
    d->table_counter++;

    d->show_counter_last = d->show_counter;
    d->rt_counter_last   = d->rt_counter;
    d->net_counter_last  = d->net_counter;

    if (d->tables_defined_by & RSD_TDB_SET)
      rt_show_table(c, d);
  }

  FIB_ITERATE_START(fib, it, net, n)
  {
    if (!max--)
    {
      FIB_ITERATE_PUT(it);
      return;
    }
    rt_show_net(c, n, d);
  }
  FIB_ITERATE_END;

  if (d->stats)
  {
    if (d->last_table != d->tab)
      rt_show_table(c, d);

    cli_printf(c, -1007, "%d of %d routes for %d networks in table %s",
	       d->show_counter - d->show_counter_last, d->rt_counter - d->rt_counter_last,
	       d->net_counter - d->net_counter_last, d->tab->table->name);
  }

  d->table_open = 0;
  d->tab = NODE_NEXT(d->tab);

  if (NODE_VALID(d->tab))
    return;

  if (d->stats && (d->table_counter > 1))
  {
    if (d->last_table) cli_printf(c, -1007, "");
    cli_printf(c, 14, "Total: %d of %d routes for %d networks in %d tables",
	       d->show_counter, d->rt_counter, d->net_counter, d->table_counter);
  }
  else
    cli_printf(c, 0, "");

done:
  rt_show_cleanup(c);
  c->cont = c->cleanup = NULL;
}

struct rt_show_data_rtable *
rt_show_add_table(struct rt_show_data *d, rtable *t)
{
  struct rt_show_data_rtable *tab = cfg_allocz(sizeof(struct rt_show_data_rtable));
  tab->table = t;
  add_tail(&(d->tables), &(tab->n));
  return tab;
}

static inline void
rt_show_get_default_tables(struct rt_show_data *d)
{
  struct channel *c;
  struct rt_show_data_rtable *tab;

  if (d->export_channel)
  {
    c = d->export_channel;
    tab = rt_show_add_table(d, c->table);
    tab->export_channel = c;
    return;
  }

  if (d->export_protocol)
  {
    WALK_LIST(c, d->export_protocol->channels)
    {
      if (c->export_state == ES_DOWN)
	continue;

      tab = rt_show_add_table(d, c->table);
      tab->export_channel = c;
    }
    return;
  }

  if (d->show_protocol)
  {
    WALK_LIST(c, d->show_protocol->channels)
      rt_show_add_table(d, c->table);
    return;
  }

  for (int i=1; i<NET_MAX; i++)
    if (config->def_tables[i])
      rt_show_add_table(d, config->def_tables[i]->table);
}

static inline void
rt_show_prepare_tables(struct rt_show_data *d)
{
  struct rt_show_data_rtable *tab, *tabx;

  /* Add implicit tables if no table is specified */
  if (EMPTY_LIST(d->tables))
    rt_show_get_default_tables(d);

  WALK_LIST_DELSAFE(tab, tabx, d->tables)
  {
    /* Ensure there is defined export_channel for each table */
    if (d->export_mode)
    {
      if (!tab->export_channel && d->export_channel &&
	  (tab->table == d->export_channel->table))
	tab->export_channel = d->export_channel;

      if (!tab->export_channel && d->export_protocol)
	tab->export_channel = proto_find_channel_by_table(d->export_protocol, tab->table);

      if (!tab->export_channel)
      {
	if (d->tables_defined_by & RSD_TDB_NMN)
	  cf_error("No export channel for table %s", tab->table->name);

	rem_node(&(tab->n));
	continue;
      }
    }

    /* Ensure specified network is compatible with each table */
    if (d->addr && (tab->table->addr_type != d->addr->type))
    {
      if (d->tables_defined_by & RSD_TDB_NMN)
	cf_error("Incompatible type of prefix/ip for table %s", tab->table->name);

      rem_node(&(tab->n));
      continue;
    }
  }

  /* Ensure there is at least one table */
  if (EMPTY_LIST(d->tables))
    cf_error("No valid tables");
}

void
rt_show(struct rt_show_data *d)
{
  struct rt_show_data_rtable *tab;
  net *n;

  /* Filtered routes are neither exported nor have sensible ordering */
  if (d->filtered && (d->export_mode || d->primary_only))
    cf_error("Incompatible show route options");

  rt_show_prepare_tables(d);

  if (!d->addr)
  {
    WALK_LIST(tab, d->tables)
      rt_lock_table(tab->table);

    /* There is at least one table */
    d->tab = HEAD(d->tables);
    this_cli->cont = rt_show_cont;
    this_cli->cleanup = rt_show_cleanup;
    this_cli->rover = d;
  }
  else
  {
    WALK_LIST(tab, d->tables)
    {
      d->tab = tab;

      if (d->show_for)
	n = net_route(tab->table, d->addr);
      else
	n = net_find(tab->table, d->addr);

      if (n)
	rt_show_net(this_cli, n, d);
    }

    if (d->rt_counter)
      cli_msg(0, "");
    else
      cli_msg(8001, "Network not found");
  }
}
