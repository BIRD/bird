/*
 *	Rest in pieces - RIP protocol
 *
 *	Copyright (c) 1998, 1999 Pavel Machek <pavel@ucw.cz>
 *	              2004       Ondrej Filip <feela@network.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 *
 	FIXME: IPv6 support: packet size
	FIXME: (nonurgent) IPv6 support: receive "route using" blocks
	FIXME: (nonurgent) IPv6 support: generate "nexthop" blocks
		next hops are only advisory, and they are pretty ugly in IPv6.
		I suggest just forgetting about them.

	FIXME: (nonurgent): fold rip_connection into rip_interface?
 */

/**
 * DOC: Routing Information Protocol
 *
 * RIP is a pretty simple protocol, so about a half of its code is interface
 * with the core.
 *
 * We maintain our own linked list of &rip_entry structures -- it serves
 * as our small routing table. RIP never adds to this linked list upon
 * packet reception; instead, it lets the core know about data from the packet
 * and waits for the core to call rip_rt_notify().
 *
 * Within rip_tx(), the list is
 * walked and a packet is generated using rip_tx_prepare(). This gets
 * tricky because we may need to send more than one packet to one
 * destination. Struct &rip_connection is used to hold context information such as how
 * many of &rip_entry's we have already sent and it's also used to protect
 * against two concurrent sends to one destination. Each &rip_interface has
 * at most one &rip_connection.
 *
 * We are not going to honor requests for sending part of
 * routing table. That would need to turn split horizon off etc.  
 *
 * About triggered updates, RFC says: when a triggered update was sent,
 * don't send a new one for something between 1 and 5 seconds (and send one
 * after that). We do something else: each 5 seconds,
 * we look for any changed routes and broadcast them.
 */

#undef LOCAL_DEBUG
#define LOCAL_DEBUG 1

#include "nest/bird.h"
#include "nest/iface.h"
#include "nest/protocol.h"
#include "nest/route.h"
#include "lib/socket.h"
#include "lib/resource.h"
#include "lib/lists.h"
#include "lib/timer.h"
#include "lib/string.h"

#include "rip.h"

#undef TRACE
#define TRACE(level, msg, args...) do { if (p->p.debug & level) { log(L_TRACE "%s: " msg, p->p.name , ## args); } } while(0)

static struct rip_iface *new_iface(struct rip_proto *p, struct iface *new, unsigned long flags, struct iface_patt *patt);
static void rip_dump(struct proto *P);

/*
 * Output processing
 *
 * This part is responsible for getting packets out to the network.
 */

static void
rip_tx_err(sock *s, int err)
{
  struct rip_connection *conn = ((struct rip_iface *) (s->data))->busy;
  struct proto *P = conn->proto;
  log(L_ERR "%s: Unexpected error at rip transmit: %M", P->name, err);
}

/*
 * rip_tx_prepare:
 * @e: rip entry that needs to be translated to form suitable for network
 * @b: block to be filled
 *
 * Fill one rip block with info that needs to go to the network. Handle
 * nexthop and split horizont correctly. (Next hop is ignored for IPv6,
 * that could be fixed but it is not real problem).
 */
static int
rip_tx_prepare(struct rip_proto *p, struct rip_block *block, struct rip_entry *entry, struct rip_iface *rif, int pos)
{
  int metric;
  struct rip_config *cf = (struct rip_config *) p->p.cf;

  DBG(".");
  block->tag = htons(entry->tag);
  block->network = entry->n.prefix;
  metric = entry->metric;
  if (neigh_connected_to(&p->p, &entry->who_told_me, rif->iface))
  {
    DBG("(split horizon)");
    metric = cf->infinity;
  }
#ifndef IPV6
  block->family = htons(2); /* AF_INET */
  block->netmask = ipa_mkmask(entry->n.pxlen);
  ipa_hton(block->netmask);

  if (neigh_connected_to(&p->p, &entry->next_hop, rif->iface))
    block->next_hop = entry->next_hop;
  else
    block->next_hop = IPA_NONE;
  ipa_hton(block->next_hop);
  block->metric = htonl(metric);
#else
  block->pxlen = entry->n.pxlen;
  block->metric = metric; /* it is u8 */
#endif

  ipa_hton(block->network);

  return pos + 1;
}

static void
rip_set_up_packet(struct rip_packet *packet)
{
  packet->heading.command = RIPCMD_RESPONSE;
#ifndef IPV6
  packet->heading.version = RIP_V2;
#else
  packet->heading.version = RIP_NG;
#endif
  packet->heading.unused = 0;
}

static int
rip_get_max_rip_entries(int auth_type, unsigned mtu)
{
#ifndef IPV6
  switch (auth_type)
  {
    case AUTH_PLAINTEXT:
      return MAX_RTEs_IN_PACKET_WITH_PLAIN_TEXT_AUTH;
    case AUTH_MD5:
      return MAX_RTEs_IN_PACKET_WITH_MD5_AUTH;
    default:
      return MAX_RTEs_IN_PACKET_WITHOUT_AUTH;
  }
#endif
  /**
   * http://tools.ietf.org/html/rfc2080
   *
   *               +-                                                   -+
   *               | MTU - sizeof(IPv6_hdrs) - UDP_hdrlen - RIPng_hdrlen |
   *   #RTEs = INT | --------------------------------------------------- |
   *               |                      RTE_size                       |
   *               +-                                                   -+
   **/
  return ((mtu - IPV6_HEADER_SIZE - UDP_HEADER_SIZE - RIP_NG_HEADER_SIZE) / RIP_RTE_SIZE);
}

/*
 * rip_tx - send one rip packet to the network
 */
static void
rip_tx(sock *sock)
{
  struct rip_iface *rif = sock->data;
  struct rip_connection *conn = rif->busy;
  struct rip_proto *p = (struct rip_proto *) conn->proto;
  struct rip_config *cf = (struct rip_config *) p->p.cf;
  struct rip_packet *packet = (void *) sock->tbuf;
  int packet_len;
  int max_rte_entries, used_rte_entries = 0;
  int nothing_to_update = 1;

  DBG("Sending to %I\n", sock->daddr);
  do
  {
    if (conn->done)
      goto done;

    DBG("Preparing packet to send: ");
    rip_set_up_packet(packet);
    max_rte_entries = rip_get_max_rip_entries(cf->auth_type, sock->iface->mtu);

    FIB_ITERATE_START(&p->rtable, &conn->iter, z)
    {
      struct rip_entry *entry = (struct rip_entry *) z;

      if (!rif->triggered || (entry->changed >= now - 2))
      {
	/* FIXME: Should be probably 1 or some different algorithm */
	nothing_to_update = 0;
	used_rte_entries = rip_tx_prepare(p, packet->block + used_rte_entries, entry, rif, used_rte_entries);
	if (used_rte_entries >= max_rte_entries)
	{
	  FIB_ITERATE_PUT(&conn->iter, z);
	  goto break_loop;
	}
      }
    } FIB_ITERATE_END(z);
    conn->done = 1;

    break_loop:

    packet_len = rip_outgoing_authentication(cf, (void *) &packet->block[0], packet, used_rte_entries);

    DBG(", sending %d blocks, ", used_rte_entries);
    if (nothing_to_update)
    {
      DBG("not sending NULL update\n");
      conn->done = 1;
      goto done;
    }
    if (ipa_nonzero(conn->daddr))
      used_rte_entries = sk_send_to(sock, packet_len, conn->daddr, conn->dport);
    else
      used_rte_entries = sk_send(sock, packet_len);

    DBG("it wants more\n");
  } while (used_rte_entries > 0);

  if (used_rte_entries < 0)
    rip_tx_err(sock, used_rte_entries);
  DBG("blocked\n");
  return;

  done:
  DBG("Looks like I'm");
  conn->rif->busy = NULL;
  rem_node(NODE conn);
  mb_free(conn);
  DBG(" done\n");
  return;
}

static struct rip_connection *
rip_get_connection(struct rip_proto *p, ip_addr daddr, int dport, struct rip_iface *rif)
{
  struct rip_connection *conn;
  static int num = 0;

  conn = mb_alloc(p->p.pool, sizeof(struct rip_connection));
  rif->busy = conn;

  conn->addr = daddr;
  conn->proto = &p->p;
  conn->num = num++;
  conn->rif = rif;

  conn->dport = dport;
  conn->daddr = daddr;
  if (conn->rif->sock->data != rif)
    bug("not enough send magic");

  conn->done = 0;
  return conn;
}

/* 
 * rip_sendto - send whole routing table to selected destination
 * @rif: interface to use. Notice that we lock interface so that at
 * most one send to one interface is done.
 */
static void
rip_sendto(struct rip_proto *p, ip_addr daddr, int dport, struct rip_iface *rif)
{
  struct iface *iface = rif->iface;
  struct rip_connection *conn;

  if (rif->busy)
  {
    log(L_WARN "%s: Interface %s is much too slow, dropping request", p->p.name, iface->name);
    return;
  }

  conn = rip_get_connection(p, daddr, dport, rif);

  FIB_ITERATE_INIT(&conn->iter, &p->rtable);
  add_head(&p->connections, NODE conn);
  if (ipa_nonzero(daddr))
    TRACE(D_PACKETS, "Sending my routing table to %I:%d on %s", daddr, dport, rif->iface->name);
  else
    TRACE(D_PACKETS, "Broadcasting routing table to %s", rif->iface->name);

  rip_tx(conn->rif->sock);
}

static struct rip_iface*
find_interface(struct rip_proto *p, struct iface *what)
{
  struct rip_iface *i;

  WALK_LIST (i, p->interfaces)
    if (i->iface == what)
      return i;
  return NULL;
}

static int
rip_get_metric_with_interface(struct rip_proto *p, struct rip_block *block, struct rip_iface *rif)
{
  int metric;
  struct rip_config *cf = (struct rip_config *) p->p.cf;

  int rif_metric;
  if (rif == NULL)
    rif_metric = 0;
  else
    rif_metric = rif->metric;

#ifndef IPV6
  metric = ntohl(block->metric) + rif_metric;
#else
  metric = block->metric + rif_metric;
#endif

  if (metric > cf->infinity)
    metric = cf->infinity;
  return metric;
}

static int
rip_get_metric(struct rip_proto *p, struct rip_block *block)
{
  return rip_get_metric_with_interface(p, block, NULL);
}

static int
rip_get_pxlen(struct rip_block *block)
{
#ifndef IPV6
  return ipa_mklen(block->netmask);
#else
  return block->pxlen;
#endif
}

static int
rip_shloud_we_advertise_entry(struct rip_proto *p, struct rip_block *block, ip_addr who_told_me, int pxlen, ip_addr gw,
			      neighbor *neighbor)
{
  /* No need to look if destination looks valid - ie not net 0 or 127 -- core will do for us. */
  if (!neighbor)
  {
    log(L_REMOTE "%s: %I asked me to route %I/%d using not-neighbor %I.", p->p.name, who_told_me, block->network, pxlen, gw);
    return FAIL;
  }
  if (neighbor->scope == SCOPE_HOST)
  {
    DBG("Self-destined route, ignoring.\n");
    return FAIL;
  }
  if (pxlen == -1)
  {
    log(L_REMOTE "%s: %I gave me invalid pxlen/netmask for %I.", p->p.name, who_told_me, block->network);
    return FAIL;
  }

  return OK;
}

/*
 * Input processing
 *
 * This part is responsible for any updates that come from network 
 */

static int
rip_route_update_arrived(struct rip_entry *entry, int metric, ip_addr who_told_me)
{
  return (!entry || (entry->metric > metric) || (ipa_equal(who_told_me, entry->who_told_me) && (metric != entry->metric)));
}

static rta
rip_create_rta(struct rip_proto *p, ip_addr gw, ip_addr who_told_me, neighbor *neighbor)
{
  rta A;
  bzero(&A, sizeof(A));
  A.src = p->p.main_source;
  A.source = RTS_RIP;
  A.scope = SCOPE_UNIVERSE;
  A.cast = RTC_UNICAST;
  A.dest = RTD_ROUTER;
  A.flags = 0;
  A.gw = gw;
  A.from = who_told_me;
  A.iface = neighbor->iface;

  return A;
}

static void
rip_add_route(struct rip_proto *p, struct rip_block *block, struct rip_entry *entry, rta *A)
{
  net *n = net_get(p->p.table, block->network, entry->n.pxlen);
  rta *a = rta_lookup(A);
  rte *r = rte_get_temp(a);

  r->u.rip.metric = entry->metric;

  r->u.rip.tag = ntohl(block->tag);
  r->net = n;
  r->pflags = 0; /* Here go my flags */

  add_head(&p->garbage, NODE &entry->gb);

  rte_update(&p->p, n, r);
  DBG("New route %I/%d from %I met=%d\n", block->network, entry->n.pxlen, entry->who_told_me, entry->metric);
}

static ip_addr
rip_get_gateway(struct rip_block *block, ip_addr who_told_me)
{
#ifndef IPV6
  return ipa_nonzero(block->next_hop) ? block->next_hop : who_told_me;
#endif
  /* FIXME: next hop is in other packet for v6 */
  return who_told_me;
}

static struct rip_entry *
rip_get_entry(struct rip_proto *p, struct rip_block *block, ip_addr who_told_me, int metric)
{
  struct rip_entry *entry;
  int pxlen;
  ip_addr gw;

  gw = rip_get_gateway(block, who_told_me);
  pxlen = rip_get_pxlen(block);

  entry = fib_get(&p->rtable, &block->network, pxlen);
  entry->next_hop = gw;
  entry->metric = metric;
  entry->who_told_me = who_told_me;
  entry->tag = ntohl(block->tag);

  entry->updated = entry->changed = now;
  entry->flags = 0;

  return entry;
}

/*
 * advertise_entry - let main routing table know about our new entry
 * @b: entry in network format
 *
 * This basically translates @b to format used by bird core and feeds
 * bird core with this route.
 */
static void
advertise_entry(struct rip_proto *p, struct rip_block *block, ip_addr who_told_me, struct iface *iface)
{
  neighbor *neighbor;
  struct rip_iface *rif;
  int pxlen, metric;
  ip_addr gw;
  struct rip_entry *entry;

  gw = rip_get_gateway(block, who_told_me);
  pxlen = rip_get_pxlen(block);

  neighbor = neigh_find2(&p->p, &gw, iface, 0);

  if (!rip_shloud_we_advertise_entry(p, block, who_told_me, pxlen, gw, neighbor))
    return;

  if (!(rif = neighbor->data))
  {
    rif = neighbor->data = find_interface(p, neighbor->iface);
  }
  if (!rif)
    bug("Route packet using unknown interface? No.");

  metric = rip_get_metric_with_interface(p, block, rif);

  /* set to: interface of nexthop */
  entry = fib_find(&p->rtable, &block->network, pxlen);

  if (rip_route_update_arrived(entry, metric, who_told_me))
  {
    rta A = rip_create_rta(p, gw, who_told_me, neighbor);

    if (entry)
      rem_node(NODE &entry->gb);

    entry = rip_get_entry(p, block, who_told_me, metric);
    rip_add_route(p, block, entry, &A);
  }
  else
  {
    if ((ipa_equal(who_told_me, entry->who_told_me) && (metric == entry->metric)))
    {
      entry->updated = now; /* Renew */
      DBG("Route renewed %I/%d from %I met=%d\n", block->network, pxlen, who_told_me, metric);
    }
  }
  DBG("done\n");
}

/*
 * process_block - do some basic check and pass block to advertise_entry
 */
static void
process_block(struct rip_proto *p, struct rip_block *block, ip_addr who_told_me, struct iface *iface)
{
  int metric, pxlen;
  struct rip_config *cf = (struct rip_config *) p->p.cf;

  metric = rip_get_metric(p, block);
  pxlen  = rip_get_pxlen(block);

  ip_addr network = block->network;

  CHK_MAGIC;

  TRACE(D_ROUTES, "block: %I tells me: %I/%d available, metric %d... ", who_told_me, network, pxlen, metric);

  if ((!metric) || (metric > cf->infinity))
  {
#ifdef IPV6
    if (metric == 0xff)
    {
      /* Someone is sending us nexthop and we are ignoring it */
      DBG("IPv6 nexthop ignored");
      return;
    }
#endif
    log(L_WARN "%s: Got metric %d from %I", p->p.name, metric, who_told_me);
    return;
  }

  advertise_entry(p, block, who_told_me, iface);
}

static int
rip_process_packet_request(struct rip_proto *p, ip_addr who_told_me, int port, struct iface *iface)
{
  struct rip_config *cf = (struct rip_config *) p->p.cf;
  DBG("Asked to send my routing table\n");
  if (cf->honor == HONOR_NEVER)
    BAD("They asked me to send routing table, but I was told not to do it");
  if ((cf->honor == HONOR_NEIGHBOR) && (!neigh_find2(&p->p, &who_told_me, iface, 0)))
    BAD("They asked me to send routing table, but he is not my neighbor");
  rip_sendto(p, who_told_me, port, HEAD(p->interfaces)); /* no broadcast */

  return 0;
}

static int
rip_process_packet_response(struct rip_proto *p, struct rip_packet *packet, int num_blocks, ip_addr who_told_me, int port,
			    struct iface *iface)
{
  int i;
  neighbor *neighbor;
  int authenticated = 0;
  struct rip_config *cf = (struct rip_config *) p->p.cf;

  DBG("*** Rtable from %I\n", who_told_me);
  if (port != cf->port)
  {
    log(L_REMOTE "%s: %I send me routing info from port %d", p->p.name, who_told_me, port);
    return 1;
  }

  if (!(neighbor = neigh_find2(&p->p, &who_told_me, iface, 0)) || neighbor->scope == SCOPE_HOST)
  {
    log(L_REMOTE "%s: %I send me routing info but he is not my neighbor", p->p.name, who_told_me);
    return 0;
  }

  for (i = 0; i < num_blocks; i++)
  {
    struct rip_block *block = &packet->block[i];

#ifndef IPV6
    /* Authentication is not defined for v6 */
    if (block->family == 0xffff)
    {
      if (i)
	continue; /* md5 tail has this family */
      if (rip_incoming_authentication(p, (void *) block, packet, num_blocks, who_told_me))
	BAD("Authentication failed");
      authenticated = 1;
      continue;
    }
#endif
    if ((!authenticated) && (cf->auth_type != AUTH_NONE))
      BAD("Packet is not authenticated and it should be");

    ipa_ntoh(block->network);
#ifndef IPV6
    ipa_ntoh(block->netmask);
    ipa_ntoh(block->next_hop);
    if (packet->heading.version == RIP_V1) /* FIXME (nonurgent): switch to disable this? */
      block->netmask = ipa_class_mask(block->network);
#endif
    process_block(p, block, who_told_me, iface);
  }
  return 0;
}
/*
 * rip_process_packet - this is main routine for incoming packets.
 */
static int
rip_process_packet(struct rip_proto *p, struct rip_packet *packet, int num_blocks, ip_addr who_told_me, int port,
		   struct iface *iface)
{
  switch (packet->heading.version)
  {
    case RIP_V1:
      DBG("Rip1: ");
      break;
    case RIP_V2:
      DBG("Rip2: ");
      break;
    default:
      BAD("Unknown version");
  }

  switch (packet->heading.command)
  {
    case RIPCMD_REQUEST:
      return rip_process_packet_request(p, who_told_me, port, iface);
    case RIPCMD_RESPONSE:
      return rip_process_packet_response(p, packet, num_blocks, who_told_me, port, iface);
    case RIPCMD_TRACEON:
    case RIPCMD_TRACEOFF:
      BAD("I was asked for traceon/traceoff");
    case RIPCMD_SUN_EXT:
      BAD("Some Sun extension around here");
    default:
      BAD("Unknown command");
  }

  return 0;
}

/*
 * rip_rx - Receive hook: do basic checks and pass packet to rip_process_packet
 */
static int
rip_rx(sock *sock, int size)
{
  struct rip_iface *rif = sock->data;
  struct rip_proto *p = (struct rip_proto *) rif->proto;
  struct iface *iface = NULL;
  int num_blocks;

  /* In non-listening mode, just ignore packet */
  if (rif->mode & IM_NOLISTEN)
    return 1;

#ifdef IPV6
  if (! rif->iface || sock->lifindex != rif->iface->index)
  return 1;

  iface = rif->iface;
#endif

  if (rif->check_ttl && (sock->rcv_ttl < 255))
  {
    log(L_REMOTE "%s: Discarding packet with TTL %d (< 255) from %I on %sock", p->p.name, sock->rcv_ttl, sock->faddr,
	rif->iface->name);
    return 1;
  }

  CHK_MAGIC;
  DBG("RIP: message came: %d bytes from %I via %sock\n", size, sock->faddr, rif->iface ? rif->iface->name : "(dummy)");
  size -= sizeof(struct rip_packet_heading);
  if (size < 0)
    BAD("Too small packet");
  if (size % sizeof(struct rip_block))
    BAD("Odd sized packet");
  num_blocks = size / sizeof(struct rip_block);

#ifndef IPV6
  if (num_blocks > MAX_RTEs_IN_PACKET_WITHOUT_AUTH)
    BAD("Too many blocks");
#endif

  if (ipa_equal(rif->iface->addr->ip, sock->faddr))
  {
    DBG("My own packet\n");
    return 1;
  }

  rip_process_packet(p, (struct rip_packet *) sock->rbuf, num_blocks, sock->faddr, sock->fport, iface);
  return 1;
}

/*
 * Interface to BIRD core
 */

static void
rip_dump_entry(struct rip_entry *entry)
{
  debug("%I told me %d/%d ago: to %I/%d go via %I, metric %d ", entry->who_told_me, entry->updated - now,
	entry->changed - now, entry->n.prefix, entry->n.pxlen, entry->next_hop, entry->metric);
  debug("\n");
}

/**
 * rip_timer
 * @t: timer
 *
 * Broadcast routing tables periodically (using rip_tx) and kill
 * routes that are too old. RIP keeps a list of its own entries present
 * in the core table by a linked list (functions rip_rte_insert() and
 * rip_rte_delete() are responsible for that), it walks this list in the timer
 * and in case an entry is too old, it is discarded.
 */

static void
rip_timer(timer *timer)
{
  struct rip_proto *p = (struct rip_proto *) timer->data;
  struct rip_config *cf = (struct rip_config *) p->p.cf;
  struct fib_node *node_i, *node_next;

  CHK_MAGIC;
  DBG("RIP: tick tock\n");

  WALK_LIST_DELSAFE(node_i, node_next, p->garbage)
  {
    rte *rte = NULL;
    net *net;
    struct rip_entry *entry;
    entry = SKIP_BACK(struct rip_entry, gb, node_i);

    net = net_find(p->p.table, entry->n.prefix, entry->n.pxlen);
    if (net)
      rte = rte_find(net, p->p.main_source);

    CHK_MAGIC;

    //DBG("Garbage: (%p)", rte); rte_dump(rte);

    if (entry->changed && (now - entry->updated > cf->timeout_time))
    {
      TRACE(D_EVENTS, "entry is old: %I", entry->n.prefix);
      entry->metric = cf->infinity;
      if (rte)
	rte_discard(p->p.table, rte);
    }

    if (entry->changed && (now - entry->updated > cf->garbage_time))
    {
      TRACE(D_EVENTS, "entry is too old: %I", entry->n.prefix);
      if (rte)
	rte_discard(p->p.table, rte);
      rem_node(NODE &entry->gb);
      fib_delete(&p->rtable, entry);
    }
  }

  DBG("RIP: Broadcasting routing tables\n");
  {
    struct rip_iface *rif;

    if ( cf->period > 2)
    { /* Bring some randomness into sending times */
      if (!(p->tx_count % cf->period))
	p->rnd_count = random_u32() % 2;
    }
    else
      p->rnd_count = p->tx_count % cf->period;

    WALK_LIST(rif, p->interfaces)
    {
      struct iface *iface = rif->iface;

      if (!iface)
	continue;
      if (rif->mode & IM_QUIET)
	continue;
      if (!(iface->flags & IF_UP))
	continue;
      rif->triggered = p->rnd_count;

      rip_sendto(p, IPA_NONE, 0, rif);
    }
    p->tx_count++;
    p->rnd_count--;
  }

  DBG("RIP: tick tock done\n");
}

/*
 * rip_start - initialize instance of rip
 */
static int
rip_start(struct proto *P)
{
  struct rip_iface *rif;
  struct rip_proto *p = (struct rip_proto *) P;
  DBG("RIP: starting instance...\n");

  ASSERT(sizeof(struct rip_packet_heading) == 4);
  ASSERT(sizeof(struct rip_block) == 20);
  ASSERT(sizeof(struct rip_block_auth) == 20);

#ifdef LOCAL_DEBUG
  p->magic = RIP_MAGIC;
#endif
  fib_init(&p->rtable, P->pool, sizeof(struct rip_entry), 0, NULL);
  init_list(&p->connections);
  init_list(&p->garbage);
  init_list(&p->interfaces);
  p->timer = tm_new(P->pool);
  p->timer->data = P;
  p->timer->recurrent = 1;
  p->timer->hook = rip_timer;
  tm_start(p->timer, 2);
  rif = new_iface(p, NULL, 0, NULL); /* Initialize dummy interface */
  add_head(&p->interfaces, NODE rif);
  CHK_MAGIC;

  rip_init_instance(P);

  DBG("RIP: ...done\n");
  return PS_UP;
}

static struct proto *
rip_init(struct proto_config *cfg)
{
  struct proto *P = proto_new(cfg, sizeof(struct rip_proto));

  return P;
}

static void
rip_dump(struct proto *P)
{
  int i;
  node *w;	// rename!
  struct rip_iface *rif;
  struct rip_proto *p = (struct rip_proto *) P;

  CHK_MAGIC;
  WALK_LIST(w, p->connections)
  {
    struct rip_connection *conn = (void *) w;
    debug("RIP: connection #%d: %I\n", conn->num, conn->addr);
  }
  i = 0;
  FIB_WALK(&p->rtable, e)
  {
    debug("RIP: entry #%d: ", i++);
    rip_dump_entry((struct rip_entry *) e);
  } FIB_WALK_END;
  i = 0;
  WALK_LIST(rif, p->interfaces)
  {
    debug("RIP: interface #%d: %s, %I, busy = %x\n", i++, rif->iface ? rif->iface->name : "(dummy)", rif->sock->daddr,
	  rif->busy);
  }
}

static void
rip_get_route_info(rte *rte, byte *buf, ea_list *attrs)
{
  eattr *metric = ea_find(attrs, EA_RIP_METRIC);
  eattr *tag = ea_find(attrs, EA_RIP_TAG);

  buf += bsprintf(buf, " (%d/%d)", rte->pref, metric ? metric->u.data : 0);
  if (tag && tag->u.data)
    bsprintf(buf, " t%04x", tag->u.data);
}

static void
kill_iface(struct rip_iface *i)
{
  DBG("RIP: Interface %s disappeared\n", i->iface->name);
  rfree(i->sock);
  mb_free(i);
}

/**
 * new_iface
 * @p: myself
 * @new: interface to be created or %NULL if we are creating a magic
 * socket. The magic socket is used for listening and also for
 * sending requested responses.
 * @flags: interface flags
 * @patt: pattern this interface matched, used for access to config options
 *
 * Create an interface structure and start listening on the interface.
 */
static struct rip_iface *
new_iface(struct rip_proto *p, struct iface *new, unsigned long flags, struct iface_patt *patt)
{
  struct rip_config *cf = (struct rip_config *) p->p.cf;
  struct rip_iface *rif;
  struct rip_patt *PATT = (struct rip_patt *) patt;

  rif = mb_allocz(p->p.pool, sizeof(struct rip_iface));
  rif->iface = new;
  rif->proto = &p->p;
  rif->busy = NULL;
  if (PATT)
  {
    rif->mode = PATT->mode;
    rif->metric = PATT->metric;
    rif->multicast = (!(PATT->mode & IM_BROADCAST)) && (flags & IF_MULTICAST);
    rif->check_ttl = (PATT->ttl_security == 1);
  }
  /* lookup multicasts over unnumbered links - no: rip is not defined over unnumbered links */

  if (rif->multicast)
    DBG("Doing multicasts!\n");

  rif->sock = sk_new(p->p.pool);
  rif->sock->type = SK_UDP;
  rif->sock->sport = cf->port;
  rif->sock->rx_hook = rip_rx;
  rif->sock->data = rif;
  rif->sock->rbsize = 10240;
  rif->sock->iface = new; /* Automatically works for dummy interface */
  rif->sock->tbuf = mb_alloc(p->p.pool, sizeof(struct rip_packet));
  rif->sock->tx_hook = rip_tx;
  rif->sock->err_hook = rip_tx_err;
  rif->sock->daddr = IPA_NONE;
  rif->sock->dport = cf->port;
  if (new)
  {
    rif->sock->tos = PATT->tx_tos;
    rif->sock->priority = PATT->tx_priority;
    rif->sock->ttl = PATT->ttl_security ? 255 : 1;
    rif->sock->flags = SKF_LADDR_RX | (rif->check_ttl ? SKF_TTL_RX : 0);
  }

  if (new)
  {
    if (new->addr->flags & IA_PEER)
      log(L_WARN "%s: rip is not defined over unnumbered links", p->p.name);
    if (rif->multicast)
    {
#ifndef IPV6
      rif->sock->daddr = ipa_from_u32(0xe0000009);	// 0xe0000009, WTF?
#else
      rif->sock->daddr = ipa_build(0xff020000, 0, 0, 9); // '0xff020000, 0, 0, 9' WTF?
#endif
    }
    else
    {
      rif->sock->daddr = new->addr->brd;
    }
  }

  if (!ipa_nonzero(rif->sock->daddr))
  {
    if (rif->iface)
      log(L_WARN "%s: interface %s is too strange for me", p->p.name, rif->iface->name);
  }
  else
  {
    if (sk_open(rif->sock) < 0)
      goto err;

    if (rif->multicast)
    {
      if (sk_setup_multicast(rif->sock) < 0)
	goto err;
      if (sk_join_group(rif->sock, rif->sock->daddr) < 0)
	goto err;
    }
    else
    {
      if (sk_setup_broadcast(rif->sock) < 0)
	goto err;
    }
  }

  TRACE(D_EVENTS, "Listening on %s, port %d, mode %s (%I)", rif->iface ? rif->iface->name : "(dummy)", cf->port,
	rif->multicast ? "multicast" : "broadcast", rif->sock->daddr);

  return rif;

  err: sk_log_error(rif->sock, p->p.name);
  log(L_ERR "%s: Cannot open socket for %s", p->p.name, rif->iface ? rif->iface->name : "(dummy)");
  if (rif->iface)
  {
    rfree(rif->sock);
    mb_free(rif);
    return NULL;
  }
  /* On dummy, we just return non-working socket, so that user gets error every time anyone requests table */
  return rif;
}

static void
rip_real_if_add(struct object_lock *lock)
{
  struct iface *iface = lock->iface;
  struct rip_proto *p = (struct rip_proto *) lock->data;
  struct rip_config *cf = (struct rip_config *) p->p.cf;
  struct rip_iface *rif;
  struct iface_patt *k = iface_patt_find(&cf->iface_list, iface, iface->addr);

  if (!k)
    bug("This can not happen! It existed few seconds ago!");
  DBG("adding interface %s\n", iface->name);
  rif = new_iface(p, iface, iface->flags, k);
  if (rif)
  {
    add_head(&p->interfaces, NODE rif);
    DBG("Adding object lock of %p for %p\n", lock, rif);
    rif->lock = lock;
  }
  else
  {
    rfree(lock);
  }
}

static void
rip_if_notify(struct proto *P, unsigned flags, struct iface *iface)
{
  struct rip_proto *p = (struct rip_proto *) P;
  struct rip_config *cf = (struct rip_config *) P->cf;

  DBG("RIP: if notify\n");
  if (iface->flags & IF_IGNORE)
    return;
  if (flags & IF_CHANGE_DOWN)
  {
    struct rip_iface *i;
    i = find_interface(p, iface);
    if (i)
    {
      rem_node(NODE i);
      rfree(i->lock);
      kill_iface(i);
    }
  }
  if (flags & IF_CHANGE_UP)
  {
    struct iface_patt *k = iface_patt_find(&cf->iface_list, iface, iface->addr);
    struct object_lock *lock;
    struct rip_patt *PATT = (struct rip_patt *) k;

    if (!k)
      return; /* We are not interested in this interface */

    lock = olock_new(P->pool);
    if (!(PATT->mode & IM_BROADCAST) && (iface->flags & IF_MULTICAST))
    {
#ifndef IPV6
      lock->addr = ipa_from_u32(0xe0000009);
#else
      ip_pton("FF02::9", &lock->addr);
#endif
    }
    else
      lock->addr = iface->addr->brd;
    lock->port = cf->port;
    lock->iface = iface;
    lock->hook = rip_real_if_add;
    lock->data = P;
    lock->type = OBJLOCK_UDP;
    olock_acquire(lock);
  }
}

static struct ea_list *
rip_gen_attrs(struct linpool *pool, int metric, u16 tag)
{
  struct ea_list *list = lp_alloc(pool, sizeof(struct ea_list) + 2 * sizeof(eattr));

  list->next = NULL;
  list->flags = EALF_SORTED;
  list->count = 2;
  list->attrs[0].id = EA_RIP_TAG;
  list->attrs[0].flags = 0;
  list->attrs[0].type = EAF_TYPE_INT | EAF_TEMP;
  list->attrs[0].u.data = tag;
  list->attrs[1].id = EA_RIP_METRIC;
  list->attrs[1].flags = 0;
  list->attrs[1].type = EAF_TYPE_INT | EAF_TEMP;
  list->attrs[1].u.data = metric;
  return list;
}

static int
rip_import_control(struct proto *P, struct rte **rt, struct ea_list **attrs, struct linpool *pool)
{
  if ((*rt)->attrs->src->proto == P) /* Ignore my own routes */
    return -1;

  if ((*rt)->attrs->source != RTS_RIP)
  {
    struct ea_list *new = rip_gen_attrs(pool, 1, 0);
    new->next = *attrs;
    *attrs = new;
  }
  return 0;
}

static struct ea_list *
rip_make_tmp_attrs(struct rte *rt, struct linpool *pool)
{
  return rip_gen_attrs(pool, rt->u.rip.metric, rt->u.rip.tag);
}

static void
rip_store_tmp_attrs(struct rte *rt, struct ea_list *attrs)
{
  rt->u.rip.tag = ea_get_int(attrs, EA_RIP_TAG, 0);
  rt->u.rip.metric = ea_get_int(attrs, EA_RIP_METRIC, 1);
}

/*
 * rip_rt_notify - core tells us about new route (possibly our
 * own), so store it into our data structures. 
 */
static void
rip_rt_notify(struct proto *P, struct rtable *table UNUSED, struct network *net, struct rte *new,
	      struct rte *old UNUSED, struct ea_list *attrs)
{
  struct rip_proto *p = (struct rip_proto *) P;
  struct rip_config *cf = (struct rip_config *) p->p.cf;
  CHK_MAGIC;
  struct rip_entry *entry;

  entry = fib_find(&p->rtable, &net->n.prefix, net->n.pxlen);
  if (new)
  {
    /* FIXME: Text is the current rip_entry is not better! */
    if (entry)
    {
      rem_node(NODE &entry->gb);
      fib_delete(&p->rtable, entry);
    }

    entry = fib_get(&p->rtable, &net->n.prefix, net->n.pxlen);

    entry->next_hop = new->attrs->gw;
    entry->metric = 0;
    entry->who_told_me = IPA_NONE;

    entry->tag = ea_get_int(attrs, EA_RIP_TAG, 0);
    entry->metric = ea_get_int(attrs, EA_RIP_METRIC, 1);
    if (entry->metric > cf->infinity)
      entry->metric = cf->infinity;

    if (new->attrs->src->proto == P)
      entry->who_told_me = new->attrs->from;

    if (!entry->metric) /* That's okay: this way user can set his own value for external routes in rip. */
      entry->metric = 5;

    entry->updated = entry->changed = 0; /* External routes do not age */
    entry->flags = 0;

    add_head(&p->garbage, NODE &entry->gb);
  }
  else
  {
    if (entry)
    {
      entry->metric = cf->infinity; /* Will be removed soon */
      entry->updated = entry->changed = now - cf->timeout_time; /* Allow aging */
    }
  }
}

static int
rip_rte_same(struct rte *new, struct rte *old)
{
  /* new->attrs == old->attrs always */
  return new->u.rip.metric == old->u.rip.metric;
}

static int
rip_rte_better(struct rte *new, struct rte *old)
{
  struct rip_config *cf = (struct rip_config *) new->attrs->src->proto->cf;

  if (ipa_equal(old->attrs->from, new->attrs->from))
    return 1;

  if (old->u.rip.metric < new->u.rip.metric)
    return 0;

  if (old->u.rip.metric > new->u.rip.metric)
    return 1;

  if (old->attrs->src->proto == new->attrs->src->proto) /* This does not make much sense for different protocols */
    if ((old->u.rip.metric == new->u.rip.metric) && ((now - old->lastmod) > (cf->timeout_time / 2)))
      return 1;

  return 0;
}

void
rip_init_instance(struct proto *P)
{
  P->accept_ra_types = RA_OPTIMAL;
  P->if_notify = rip_if_notify;
  P->rt_notify = rip_rt_notify;
  P->import_control = rip_import_control;
  P->make_tmp_attrs = rip_make_tmp_attrs;
  P->store_tmp_attrs = rip_store_tmp_attrs;
  P->rte_better = rip_rte_better;
  P->rte_same = rip_rte_same;
}

void
rip_init_config(struct rip_config *cf)
{
  init_list(&cf->iface_list);
  cf->infinity = 16;
  cf->port = RIP_PORT;
  cf->period = 30;
  cf->garbage_time = 120 + 180;
  cf->timeout_time = 120;
  cf->passwords = NULL;
  cf->auth_type = AUTH_NONE;
}

static int
rip_get_attr(eattr *a, byte *buf, int buflen UNUSED)
{
  switch (a->id)
  {
    case EA_RIP_METRIC:
      bsprintf(buf, "metric: %d", a->u.data);
      return GA_FULL;
    case EA_RIP_TAG:
      bsprintf(buf, "tag: %d", a->u.data);
      return GA_FULL;
    default:
      return GA_UNKNOWN;
  }
}

static int
rip_pat_compare(struct rip_patt *a, struct rip_patt *b)
{
  return ((a->metric == b->metric) &&
	  (a->mode == b->mode) &&
	  (a->tx_tos == b->tx_tos) &&
	  (a->tx_priority == b->tx_priority));
}

static int
rip_reconfigure(struct proto *P, struct proto_config *cf)
{
  struct rip_config *cf_old = (struct rip_config *) P->cf;
  struct rip_config *cf_new = (struct rip_config *) cf;
  int generic = sizeof(struct proto_config) + sizeof(list) /* + sizeof(struct password_item *) */;

  if (!iface_patts_equal(&cf_old->iface_list, &cf_new->iface_list, (void *) rip_pat_compare))
    return 0;
  return !memcmp(((byte *) cf_old) + generic, ((byte *) cf_new) + generic, sizeof(struct rip_config) - generic);
}

static void
rip_copy_config(struct proto_config *dest, struct proto_config *src)
{
  /* Shallow copy of everything */
  proto_copy_rest(dest, src, sizeof(struct rip_config));

  /* We clean up iface_list, ifaces are non-sharable */
  init_list(&((struct rip_config *) dest)->iface_list);

  /* Copy of passwords is OK, it just will be replaced in dest when used */
}


struct protocol proto_rip = {
  name: "RIP",
  template: "rip%d",
  attr_class: EAP_RIP,
  preference: DEF_PREF_RIP,
  get_route_info: rip_get_route_info,
  get_attr: rip_get_attr,

  init: rip_init,
  dump: rip_dump,
  start: rip_start,
  reconfigure: rip_reconfigure,
  copy_config: rip_copy_config
};
