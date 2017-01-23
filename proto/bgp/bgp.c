/*
 *	BIRD -- The Border Gateway Protocol
 *
 *	(c) 2000 Martin Mares <mj@ucw.cz>
 *	(c) 2008--2016 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2008--2016 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: Border Gateway Protocol
 *
 * The BGP protocol is implemented in three parts: |bgp.c| which takes care of
 * the connection and most of the interface with BIRD core, |packets.c| handling
 * both incoming and outgoing BGP packets and |attrs.c| containing functions for
 * manipulation with BGP attribute lists.
 *
 * As opposed to the other existing routing daemons, BIRD has a sophisticated
 * core architecture which is able to keep all the information needed by BGP in
 * the primary routing table, therefore no complex data structures like a
 * central BGP table are needed. This increases memory footprint of a BGP router
 * with many connections, but not too much and, which is more important, it
 * makes BGP much easier to implement.
 *
 * Each instance of BGP (corresponding to a single BGP peer) is described by a
 * &bgp_proto structure to which are attached individual connections represented
 * by &bgp_connection (usually, there exists only one connection, but during BGP
 * session setup, there can be more of them). The connections are handled
 * according to the BGP state machine defined in the RFC with all the timers and
 * all the parameters configurable.
 *
 * In incoming direction, we listen on the connection's socket and each time we
 * receive some input, we pass it to bgp_rx(). It decodes packet headers and the
 * markers and passes complete packets to bgp_rx_packet() which distributes the
 * packet according to its type.
 *
 * In outgoing direction, we gather all the routing updates and sort them to
 * buckets (&bgp_bucket) according to their attributes (we keep a hash table for
 * fast comparison of &rta's and a &fib which helps us to find if we already
 * have another route for the same destination queued for sending, so that we
 * can replace it with the new one immediately instead of sending both
 * updates). There also exists a special bucket holding all the route
 * withdrawals which cannot be queued anywhere else as they don't have any
 * attributes. If we have any packet to send (due to either new routes or the
 * connection tracking code wanting to send a Open, Keepalive or Notification
 * message), we call bgp_schedule_packet() which sets the corresponding bit in a
 * @packet_to_send bit field in &bgp_conn and as soon as the transmit socket
 * buffer becomes empty, we call bgp_fire_tx(). It inspects state of all the
 * packet type bits and calls the corresponding bgp_create_xx() functions,
 * eventually rescheduling the same packet type if we have more data of the same
 * type to send.
 *
 * The processing of attributes consists of two functions: bgp_decode_attrs()
 * for checking of the attribute blocks and translating them to the language of
 * BIRD's extended attributes and bgp_encode_attrs() which does the
 * converse. Both functions are built around a @bgp_attr_table array describing
 * all important characteristics of all known attributes.  Unknown transitive
 * attributes are attached to the route as %EAF_TYPE_OPAQUE byte streams.
 *
 * BGP protocol implements graceful restart in both restarting (local restart)
 * and receiving (neighbor restart) roles. The first is handled mostly by the
 * graceful restart code in the nest, BGP protocol just handles capabilities,
 * sets @gr_wait and locks graceful restart until end-of-RIB mark is received.
 * The second is implemented by internal restart of the BGP state to %BS_IDLE
 * and protocol state to %PS_START, but keeping the protocol up from the core
 * point of view and therefore maintaining received routes. Routing table
 * refresh cycle (rt_refresh_begin(), rt_refresh_end()) is used for removing
 * stale routes after reestablishment of BGP session during graceful restart.
 */

#undef LOCAL_DEBUG

#include "nest/bird.h"
#include "nest/iface.h"
#include "nest/protocol.h"
#include "nest/route.h"
#include "nest/cli.h"
#include "nest/locks.h"
#include "conf/conf.h"
#include "lib/socket.h"
#include "lib/resource.h"
#include "lib/string.h"

#include "bgp.h"


struct linpool *bgp_linpool;		/* Global temporary pool */
static list bgp_sockets;		/* Global list of listening sockets */


static void bgp_connect(struct bgp_proto *p);
static void bgp_active(struct bgp_proto *p);
static void bgp_update_bfd(struct bgp_proto *p, int use_bfd);

static int bgp_incoming_connection(sock *sk, uint dummy UNUSED);
static void bgp_listen_sock_err(sock *sk UNUSED, int err);

/**
 * bgp_open - open a BGP instance
 * @p: BGP instance
 *
 * This function allocates and configures shared BGP resources, mainly listening
 * sockets. Should be called as the last step during initialization (when lock
 * is acquired and neighbor is ready). When error, caller should change state to
 * PS_DOWN and return immediately.
 */
static int
bgp_open(struct bgp_proto *p)
{
  struct bgp_socket *bs = NULL;
  struct iface *ifa = p->cf->strict_bind ? p->cf->iface : NULL;
  ip_addr addr = p->cf->strict_bind ? p->cf->local_ip :
    (ipa_is_ip4(p->cf->remote_ip) ? IPA_NONE4 : IPA_NONE6);
  uint port = p->cf->local_port;

  /* FIXME: Add some global init? */
  if (!bgp_linpool)
    init_list(&bgp_sockets);

  /* We assume that cf->iface is defined iff cf->local_ip is link-local */

  WALK_LIST(bs, bgp_sockets)
    if (ipa_equal(bs->sk->saddr, addr) && (bs->sk->iface == ifa) && (bs->sk->sport == port))
    {
      bs->uc++;
      p->sock = bs;
      return 0;
    }

  sock *sk = sk_new(proto_pool);
  sk->type = SK_TCP_PASSIVE;
  sk->ttl = 255;
  sk->saddr = addr;
  sk->sport = port;
  sk->flags = 0;
  sk->tos = IP_PREC_INTERNET_CONTROL;
  sk->rbsize = BGP_RX_BUFFER_SIZE;
  sk->tbsize = BGP_TX_BUFFER_SIZE;
  sk->rx_hook = bgp_incoming_connection;
  sk->err_hook = bgp_listen_sock_err;

  if (sk_open(sk) < 0)
    goto err;

  bs = mb_allocz(proto_pool, sizeof(struct bgp_socket));
  bs->sk = sk;
  bs->uc = 1;
  p->sock = bs;

  add_tail(&bgp_sockets, &bs->n);

  if (!bgp_linpool)
    bgp_linpool = lp_new(proto_pool, 4080);

  return 0;

err:
  sk_log_error(sk, p->p.name);
  log(L_ERR "%s: Cannot open listening socket", p->p.name);
  rfree(sk);
  return -1;
}

/**
 * bgp_close - close a BGP instance
 * @p: BGP instance
 *
 * This function frees and deconfigures shared BGP resources.
 */
static void
bgp_close(struct bgp_proto *p)
{
  struct bgp_socket *bs = p->sock;

  ASSERT(bs && bs->uc);

  if (--bs->uc)
    return;

  rfree(bs->sk);
  rem_node(&bs->n);
  mb_free(bs);

  if (!EMPTY_LIST(bgp_sockets))
    return;

  rfree(bgp_linpool);
  bgp_linpool = NULL;
}

static inline int
bgp_setup_auth(struct bgp_proto *p, int enable)
{
  if (p->cf->password)
  {
    int rv = sk_set_md5_auth(p->sock->sk,
			     p->cf->local_ip, p->cf->remote_ip, p->cf->iface,
			     enable ? p->cf->password : NULL, p->cf->setkey);

    if (rv < 0)
      sk_log_error(p->sock->sk, p->p.name);

    return rv;
  }
  else
    return 0;
}

static inline struct bgp_channel *
bgp_find_channel(struct bgp_proto *p, u32 afi)
{
  struct bgp_channel *c;
  WALK_LIST(c, p->p.channels)
    if (c->afi == afi)
      return c;

  return NULL;
}

static void
bgp_startup(struct bgp_proto *p)
{
  BGP_TRACE(D_EVENTS, "Started");
  p->start_state = BSS_CONNECT;

  if (!p->cf->passive)
    bgp_active(p);
}

static void
bgp_startup_timeout(timer *t)
{
  bgp_startup(t->data);
}


static void
bgp_initiate(struct bgp_proto *p)
{
  int err_val;

  if (bgp_open(p) < 0)
  { err_val = BEM_NO_SOCKET; goto err1; }

  if (bgp_setup_auth(p, 1) < 0)
  { err_val = BEM_INVALID_MD5; goto err2; }

  if (p->cf->bfd)
    bgp_update_bfd(p, p->cf->bfd);

  if (p->startup_delay)
  {
    p->start_state = BSS_DELAY;
    BGP_TRACE(D_EVENTS, "Startup delayed by %d seconds due to errors", p->startup_delay);
    bgp_start_timer(p->startup_timer, p->startup_delay);
  }
  else
    bgp_startup(p);

  return;

err2:
  bgp_close(p);
err1:
  p->p.disabled = 1;
  bgp_store_error(p, NULL, BE_MISC, err_val);
  proto_notify_state(&p->p, PS_DOWN);

  return;
}

/**
 * bgp_start_timer - start a BGP timer
 * @t: timer
 * @value: time to fire (0 to disable the timer)
 *
 * This functions calls tm_start() on @t with time @value and the amount of
 * randomization suggested by the BGP standard. Please use it for all BGP
 * timers.
 */
void
bgp_start_timer(timer *t, int value)
{
  if (value)
  {
    /* The randomization procedure is specified in RFC 1771: 9.2.3.3 */
    t->randomize = value / 4;
    tm_start(t, value - t->randomize);
  }
  else
    tm_stop(t);
}

/**
 * bgp_close_conn - close a BGP connection
 * @conn: connection to close
 *
 * This function takes a connection described by the &bgp_conn structure, closes
 * its socket and frees all resources associated with it.
 */
void
bgp_close_conn(struct bgp_conn *conn)
{
  // struct bgp_proto *p = conn->bgp;

  DBG("BGP: Closing connection\n");
  conn->packets_to_send = 0;
  conn->channels_to_send = 0;
  rfree(conn->connect_timer);
  conn->connect_timer = NULL;
  rfree(conn->keepalive_timer);
  conn->keepalive_timer = NULL;
  rfree(conn->hold_timer);
  conn->hold_timer = NULL;
  rfree(conn->tx_ev);
  conn->tx_ev = NULL;
  rfree(conn->sk);
  conn->sk = NULL;

  mb_free(conn->local_caps);
  conn->local_caps = NULL;
  mb_free(conn->remote_caps);
  conn->remote_caps = NULL;
}


/**
 * bgp_update_startup_delay - update a startup delay
 * @p: BGP instance
 *
 * This function updates a startup delay that is used to postpone next BGP
 * connect. It also handles disable_after_error and might stop BGP instance
 * when error happened and disable_after_error is on.
 *
 * It should be called when BGP protocol error happened.
 */
void
bgp_update_startup_delay(struct bgp_proto *p)
{
  struct bgp_config *cf = p->cf;

  DBG("BGP: Updating startup delay\n");

  if (p->last_proto_error && ((now - p->last_proto_error) >= (int) cf->error_amnesia_time))
    p->startup_delay = 0;

  p->last_proto_error = now;

  if (cf->disable_after_error)
  {
    p->startup_delay = 0;
    p->p.disabled = 1;
    return;
  }

  if (!p->startup_delay)
    p->startup_delay = cf->error_delay_time_min;
  else
    p->startup_delay = MIN(2 * p->startup_delay, cf->error_delay_time_max);
}

static void
bgp_graceful_close_conn(struct bgp_conn *conn, uint subcode)
{
  switch (conn->state)
  {
  case BS_IDLE:
  case BS_CLOSE:
    return;

  case BS_CONNECT:
  case BS_ACTIVE:
    bgp_conn_enter_idle_state(conn);
    return;

  case BS_OPENSENT:
  case BS_OPENCONFIRM:
  case BS_ESTABLISHED:
    bgp_error(conn, 6, subcode, NULL, 0);
    return;

  default:
    bug("bgp_graceful_close_conn: Unknown state %d", conn->state);
  }
}

static void
bgp_down(struct bgp_proto *p)
{
  if (p->start_state > BSS_PREPARE)
  {
    bgp_setup_auth(p, 0);
    bgp_close(p);
  }

  BGP_TRACE(D_EVENTS, "Down");
  proto_notify_state(&p->p, PS_DOWN);
}

static void
bgp_decision(void *vp)
{
  struct bgp_proto *p = vp;

  DBG("BGP: Decision start\n");
  if ((p->p.proto_state == PS_START) &&
      (p->outgoing_conn.state == BS_IDLE) &&
      (p->incoming_conn.state != BS_OPENCONFIRM) &&
      !p->cf->passive)
    bgp_active(p);

  if ((p->p.proto_state == PS_STOP) &&
      (p->outgoing_conn.state == BS_IDLE) &&
      (p->incoming_conn.state == BS_IDLE))
    bgp_down(p);
}

void
bgp_stop(struct bgp_proto *p, uint subcode)
{
  proto_notify_state(&p->p, PS_STOP);
  bgp_graceful_close_conn(&p->outgoing_conn, subcode);
  bgp_graceful_close_conn(&p->incoming_conn, subcode);
  ev_schedule(p->event);
}

static inline void
bgp_conn_set_state(struct bgp_conn *conn, uint new_state)
{
  if (conn->bgp->p.mrtdump & MD_STATES)
    mrt_dump_bgp_state_change(conn, conn->state, new_state);

  conn->state = new_state;
}

void
bgp_conn_enter_openconfirm_state(struct bgp_conn *conn)
{
  /* Really, most of the work is done in bgp_rx_open(). */
  bgp_conn_set_state(conn, BS_OPENCONFIRM);
}

static const struct bgp_af_caps dummy_af_caps = { };

void
bgp_conn_enter_established_state(struct bgp_conn *conn)
{
  struct bgp_proto *p = conn->bgp;
  struct bgp_caps *local = conn->local_caps;
  struct bgp_caps *peer = conn->remote_caps;
  struct bgp_channel *c;

  BGP_TRACE(D_EVENTS, "BGP session established");

  /* For multi-hop BGP sessions */
  if (ipa_zero(p->source_addr))
    p->source_addr = conn->sk->saddr;

  conn->sk->fast_rx = 0;

  p->conn = conn;
  p->last_error_class = 0;
  p->last_error_code = 0;

  p->as4_session = conn->as4_session;

  p->route_refresh = peer->route_refresh;
  p->enhanced_refresh = local->enhanced_refresh && peer->enhanced_refresh;

  /* Whether we may handle possible GR of peer (it has some AF GR-able) */
  p->gr_ready = 0;	/* Updated later */

  /* Whether peer is ready to handle our GR recovery */
  int peer_gr_ready = peer->gr_aware && !(peer->gr_flags & BGP_GRF_RESTART);

  if (p->gr_active_num)
    tm_stop(p->gr_timer);

  /* Number of active channels */
  int num = 0;

  WALK_LIST(c, p->p.channels)
  {
    const struct bgp_af_caps *loc = bgp_find_af_caps(local, c->afi);
    const struct bgp_af_caps *rem = bgp_find_af_caps(peer,  c->afi);

    /* Ignore AFIs that were not announced in multiprotocol capability */
    if (!loc || !loc->ready)
      loc = &dummy_af_caps;

    if (!rem || !rem->ready)
      rem = &dummy_af_caps;

    int active = loc->ready && rem->ready;
    c->c.disabled = !active;
    c->c.reloadable = p->route_refresh;

    c->index = active ? num++ : 0;

    c->feed_state = BFS_NONE;
    c->load_state = BFS_NONE;

    /* Channels where peer may do GR */
    c->gr_ready = active && local->gr_aware && rem->gr_able;
    p->gr_ready = p->gr_ready || c->gr_ready;

    /* Channels not able to recover gracefully */
    if (p->p.gr_recovery && (!active || !peer_gr_ready))
      channel_graceful_restart_unlock(&c->c);

    /* Channels waiting for local convergence */
    if (p->p.gr_recovery && loc->gr_able && peer_gr_ready)
      c->c.gr_wait = 1;

    /* Channels where peer is not able to recover gracefully */
    if (c->gr_active && ! (c->gr_ready && (rem->gr_af_flags & BGP_GRF_FORWARDING)))
      bgp_graceful_restart_done(c);

    /* GR capability implies that neighbor will send End-of-RIB */
    if (peer->gr_aware)
      c->load_state = BFS_LOADING;

    c->add_path_rx = (loc->add_path & BGP_ADD_PATH_RX) && (rem->add_path & BGP_ADD_PATH_TX);
    c->add_path_tx = (loc->add_path & BGP_ADD_PATH_TX) && (rem->add_path & BGP_ADD_PATH_RX);

    // XXXX reset back to non-ANY?
    if (c->add_path_tx)
      c->c.ra_mode = RA_ANY;
  }

  p->afi_map = mb_alloc(p->p.pool, num * sizeof(u32));
  p->channel_map = mb_alloc(p->p.pool, num * sizeof(void *));
  p->channel_count = num;

  WALK_LIST(c, p->p.channels)
  {
    if (c->c.disabled)
      continue;

    p->afi_map[c->index] = c->afi;
    p->channel_map[c->index] = c;
  }

  /* proto_notify_state() will likely call bgp_feed_begin(), setting c->feed_state */

  bgp_conn_set_state(conn, BS_ESTABLISHED);
  proto_notify_state(&p->p, PS_UP);
}

static void
bgp_conn_leave_established_state(struct bgp_proto *p)
{
  BGP_TRACE(D_EVENTS, "BGP session closed");
  p->conn = NULL;

  if (p->p.proto_state == PS_UP)
    bgp_stop(p, 0);
}

void
bgp_conn_enter_close_state(struct bgp_conn *conn)
{
  struct bgp_proto *p = conn->bgp;
  int os = conn->state;

  bgp_conn_set_state(conn, BS_CLOSE);
  tm_stop(conn->keepalive_timer);
  conn->sk->rx_hook = NULL;

  /* Timeout for CLOSE state, if we cannot send notification soon then we just hangup */
  bgp_start_timer(conn->hold_timer, 10);

  if (os == BS_ESTABLISHED)
    bgp_conn_leave_established_state(p);
}

void
bgp_conn_enter_idle_state(struct bgp_conn *conn)
{
  struct bgp_proto *p = conn->bgp;
  int os = conn->state;

  bgp_close_conn(conn);
  bgp_conn_set_state(conn, BS_IDLE);
  ev_schedule(p->event);

  if (os == BS_ESTABLISHED)
    bgp_conn_leave_established_state(p);
}

/**
 * bgp_handle_graceful_restart - handle detected BGP graceful restart
 * @p: BGP instance
 *
 * This function is called when a BGP graceful restart of the neighbor is
 * detected (when the TCP connection fails or when a new TCP connection
 * appears). The function activates processing of the restart - starts routing
 * table refresh cycle and activates BGP restart timer. The protocol state goes
 * back to %PS_START, but changing BGP state back to %BS_IDLE is left for the
 * caller.
 */
void
bgp_handle_graceful_restart(struct bgp_proto *p)
{
  ASSERT(p->conn && (p->conn->state == BS_ESTABLISHED) && p->gr_ready);

  BGP_TRACE(D_EVENTS, "Neighbor graceful restart detected%s",
	    p->gr_active_num ? " - already pending" : "");

  p->gr_active_num = 0;

  struct bgp_channel *c;
  WALK_LIST(c, p->p.channels)
  {
    if (c->gr_ready)
    {
      if (c->gr_active)
	rt_refresh_end(c->c.table, &c->c);

      c->gr_active = 1;
      p->gr_active_num++;
      rt_refresh_begin(c->c.table, &c->c);
    }
    else
    {
      /* Just flush the routes */
      rt_refresh_begin(c->c.table, &c->c);
      rt_refresh_end(c->c.table, &c->c);
    }
  }

  proto_notify_state(&p->p, PS_START);
  bgp_start_timer(p->gr_timer, p->conn->local_caps->gr_time);
}

/**
 * bgp_graceful_restart_done - finish active BGP graceful restart
 * @c: BGP channel
 *
 * This function is called when the active BGP graceful restart of the neighbor
 * should be finished for channel @c - either successfully (the neighbor sends
 * all paths and reports end-of-RIB for given AFI/SAFI on the new session) or
 * unsuccessfully (the neighbor does not support BGP graceful restart on the new
 * session). The function ends the routing table refresh cycle.
 */
void
bgp_graceful_restart_done(struct bgp_channel *c)
{
  struct bgp_proto *p = (void *) c->c.proto;

  ASSERT(c->gr_active);
  c->gr_active = 0;
  p->gr_active_num--;

  if (!p->gr_active_num)
    BGP_TRACE(D_EVENTS, "Neighbor graceful restart done");

  rt_refresh_end(c->c.table, &c->c);
}

/**
 * bgp_graceful_restart_timeout - timeout of graceful restart 'restart timer'
 * @t: timer
 *
 * This function is a timeout hook for @gr_timer, implementing BGP restart time
 * limit for reestablisment of the BGP session after the graceful restart. When
 * fired, we just proceed with the usual protocol restart.
 */

static void
bgp_graceful_restart_timeout(timer *t)
{
  struct bgp_proto *p = t->data;

  BGP_TRACE(D_EVENTS, "Neighbor graceful restart timeout");
  bgp_stop(p, 0);
}


/**
 * bgp_refresh_begin - start incoming enhanced route refresh sequence
 * @c: BGP channel
 *
 * This function is called when an incoming enhanced route refresh sequence is
 * started by the neighbor, demarcated by the BoRR packet. The function updates
 * the load state and starts the routing table refresh cycle. Note that graceful
 * restart also uses routing table refresh cycle, but RFC 7313 and load states
 * ensure that these two sequences do not overlap.
 */
void
bgp_refresh_begin(struct bgp_channel *c)
{
  struct bgp_proto *p = (void *) c->c.proto;

  if (c->load_state == BFS_LOADING)
  { log(L_WARN "%s: BEGIN-OF-RR received before END-OF-RIB, ignoring", p->p.name); return; }

  c->load_state = BFS_REFRESHING;
  rt_refresh_begin(c->c.table, &c->c);
}

/**
 * bgp_refresh_end - finish incoming enhanced route refresh sequence
 * @c: BGP channel
 *
 * This function is called when an incoming enhanced route refresh sequence is
 * finished by the neighbor, demarcated by the EoRR packet. The function updates
 * the load state and ends the routing table refresh cycle. Routes not received
 * during the sequence are removed by the nest.
 */
void
bgp_refresh_end(struct bgp_channel *c)
{
  struct bgp_proto *p = (void *) c->c.proto;

  if (c->load_state != BFS_REFRESHING)
  { log(L_WARN "%s: END-OF-RR received without prior BEGIN-OF-RR, ignoring", p->p.name); return; }

  c->load_state = BFS_NONE;
  rt_refresh_end(c->c.table, &c->c);
}


static void
bgp_send_open(struct bgp_conn *conn)
{
  DBG("BGP: Sending open\n");
  conn->sk->rx_hook = bgp_rx;
  conn->sk->tx_hook = bgp_tx;
  tm_stop(conn->connect_timer);
  bgp_schedule_packet(conn, NULL, PKT_OPEN);
  bgp_conn_set_state(conn, BS_OPENSENT);
  bgp_start_timer(conn->hold_timer, conn->bgp->cf->initial_hold_time);
}

static void
bgp_connected(sock *sk)
{
  struct bgp_conn *conn = sk->data;
  struct bgp_proto *p = conn->bgp;

  BGP_TRACE(D_EVENTS, "Connected");
  bgp_send_open(conn);
}

static void
bgp_connect_timeout(timer *t)
{
  struct bgp_conn *conn = t->data;
  struct bgp_proto *p = conn->bgp;

  DBG("BGP: connect_timeout\n");
  if (p->p.proto_state == PS_START)
  {
    bgp_close_conn(conn);
    bgp_connect(p);
  }
  else
    bgp_conn_enter_idle_state(conn);
}

static void
bgp_sock_err(sock *sk, int err)
{
  struct bgp_conn *conn = sk->data;
  struct bgp_proto *p = conn->bgp;

  /*
   * This error hook may be called either asynchronously from main
   * loop, or synchronously from sk_send().  But sk_send() is called
   * only from bgp_tx() and bgp_kick_tx(), which are both called
   * asynchronously from main loop. Moreover, they end if err hook is
   * called. Therefore, we could suppose that it is always called
   * asynchronously.
   */

  bgp_store_error(p, conn, BE_SOCKET, err);

  if (err)
    BGP_TRACE(D_EVENTS, "Connection lost (%M)", err);
  else
    BGP_TRACE(D_EVENTS, "Connection closed");

  if ((conn->state == BS_ESTABLISHED) && p->gr_ready)
    bgp_handle_graceful_restart(p);

  bgp_conn_enter_idle_state(conn);
}

static void
bgp_hold_timeout(timer *t)
{
  struct bgp_conn *conn = t->data;
  struct bgp_proto *p = conn->bgp;

  DBG("BGP: Hold timeout\n");

  /* We are already closing the connection - just do hangup */
  if (conn->state == BS_CLOSE)
  {
    BGP_TRACE(D_EVENTS, "Connection stalled");
    bgp_conn_enter_idle_state(conn);
    return;
  }

  /* If there is something in input queue, we are probably congested
     and perhaps just not processed BGP packets in time. */

  if (sk_rx_ready(conn->sk) > 0)
    bgp_start_timer(conn->hold_timer, 10);
  else
    bgp_error(conn, 4, 0, NULL, 0);
}

static void
bgp_keepalive_timeout(timer *t)
{
  struct bgp_conn *conn = t->data;

  DBG("BGP: Keepalive timer\n");
  bgp_schedule_packet(conn, NULL, PKT_KEEPALIVE);

  /* Kick TX a bit faster */
  if (ev_active(conn->tx_ev))
    ev_run(conn->tx_ev);
}

static void
bgp_setup_conn(struct bgp_proto *p, struct bgp_conn *conn)
{
  conn->sk = NULL;
  conn->bgp = p;

  conn->packets_to_send = 0;
  conn->channels_to_send = 0;
  conn->last_channel = 0;
  conn->last_channel_count = 0;

  conn->connect_timer	= tm_new_set(p->p.pool, bgp_connect_timeout,	conn, 0, 0);
  conn->hold_timer 	= tm_new_set(p->p.pool, bgp_hold_timeout,	conn, 0, 0);
  conn->keepalive_timer	= tm_new_set(p->p.pool, bgp_keepalive_timeout,	conn, 0, 0);

  conn->tx_ev = ev_new(p->p.pool);
  conn->tx_ev->hook = bgp_kick_tx;
  conn->tx_ev->data = conn;
}

static void
bgp_setup_sk(struct bgp_conn *conn, sock *s)
{
  s->data = conn;
  s->err_hook = bgp_sock_err;
  s->fast_rx = 1;
  conn->sk = s;
}

static void
bgp_active(struct bgp_proto *p)
{
  int delay = MAX(1, p->cf->connect_delay_time);
  struct bgp_conn *conn = &p->outgoing_conn;

  BGP_TRACE(D_EVENTS, "Connect delayed by %d seconds", delay);
  bgp_setup_conn(p, conn);
  bgp_conn_set_state(conn, BS_ACTIVE);
  bgp_start_timer(conn->connect_timer, delay);
}

/**
 * bgp_connect - initiate an outgoing connection
 * @p: BGP instance
 *
 * The bgp_connect() function creates a new &bgp_conn and initiates
 * a TCP connection to the peer. The rest of connection setup is governed
 * by the BGP state machine as described in the standard.
 */
static void
bgp_connect(struct bgp_proto *p)	/* Enter Connect state and start establishing connection */
{
  struct bgp_conn *conn = &p->outgoing_conn;
  int hops = p->cf->multihop ? : 1;

  DBG("BGP: Connecting\n");
  sock *s = sk_new(p->p.pool);
  s->type = SK_TCP_ACTIVE;
  s->saddr = p->source_addr;
  s->daddr = p->cf->remote_ip;
  s->dport = p->cf->remote_port;
  s->iface = p->neigh ? p->neigh->iface : NULL;
  s->ttl = p->cf->ttl_security ? 255 : hops;
  s->rbsize = p->cf->enable_extended_messages ? BGP_RX_BUFFER_EXT_SIZE : BGP_RX_BUFFER_SIZE;
  s->tbsize = p->cf->enable_extended_messages ? BGP_TX_BUFFER_EXT_SIZE : BGP_TX_BUFFER_SIZE;
  s->tos = IP_PREC_INTERNET_CONTROL;
  s->password = p->cf->password;
  s->tx_hook = bgp_connected;
  BGP_TRACE(D_EVENTS, "Connecting to %I%J from local address %I%J", s->daddr, p->cf->iface,
	    s->saddr, ipa_is_link_local(s->saddr) ? s->iface : NULL);
  bgp_setup_conn(p, conn);
  bgp_setup_sk(conn, s);
  bgp_conn_set_state(conn, BS_CONNECT);

  if (sk_open(s) < 0)
    goto err;

  /* Set minimal receive TTL if needed */
  if (p->cf->ttl_security)
    if (sk_set_min_ttl(s, 256 - hops) < 0)
      goto err;

  DBG("BGP: Waiting for connect success\n");
  bgp_start_timer(conn->connect_timer, p->cf->connect_retry_time);
  return;

err:
  sk_log_error(s, p->p.name);
  bgp_sock_err(s, 0);
  return;
}

/**
 * bgp_find_proto - find existing proto for incoming connection
 * @sk: TCP socket
 *
 */
static struct bgp_proto *
bgp_find_proto(sock *sk)
{
  struct bgp_proto *p;

  WALK_LIST(p, proto_list)
    if ((p->p.proto == &proto_bgp) &&
	ipa_equal(p->cf->remote_ip, sk->daddr) &&
	(!ipa_is_link_local(sk->daddr) || (p->cf->iface == sk->iface)) &&
	(ipa_zero(p->cf->local_ip) || ipa_equal(p->cf->local_ip, sk->saddr)) &&
	(p->cf->local_port == sk->sport))
      return p;

  return NULL;
}

/**
 * bgp_incoming_connection - handle an incoming connection
 * @sk: TCP socket
 * @dummy: unused
 *
 * This function serves as a socket hook for accepting of new BGP
 * connections. It searches a BGP instance corresponding to the peer
 * which has connected and if such an instance exists, it creates a
 * &bgp_conn structure, attaches it to the instance and either sends
 * an Open message or (if there already is an active connection) it
 * closes the new connection by sending a Notification message.
 */
static int
bgp_incoming_connection(sock *sk, uint dummy UNUSED)
{
  struct bgp_proto *p;
  int acc, hops;

  DBG("BGP: Incoming connection from %I port %d\n", sk->daddr, sk->dport);
  p = bgp_find_proto(sk);
  if (!p)
  {
    log(L_WARN "BGP: Unexpected connect from unknown address %I%J (port %d)",
	sk->daddr, ipa_is_link_local(sk->daddr) ? sk->iface : NULL, sk->dport);
    rfree(sk);
    return 0;
  }

  /*
   * BIRD should keep multiple incoming connections in OpenSent state (for
   * details RFC 4271 8.2.1 par 3), but it keeps just one. Duplicate incoming
   * connections are rejected istead. The exception is the case where an
   * incoming connection triggers a graceful restart.
   */

  acc = (p->p.proto_state == PS_START || p->p.proto_state == PS_UP) &&
    (p->start_state >= BSS_CONNECT) && (!p->incoming_conn.sk);

  if (p->conn && (p->conn->state == BS_ESTABLISHED) && p->gr_ready)
  {
    bgp_store_error(p, NULL, BE_MISC, BEM_GRACEFUL_RESTART);
    bgp_handle_graceful_restart(p);
    bgp_conn_enter_idle_state(p->conn);
    acc = 1;

    /* There might be separate incoming connection in OpenSent state */
    if (p->incoming_conn.state > BS_ACTIVE)
      bgp_close_conn(&p->incoming_conn);
  }

  BGP_TRACE(D_EVENTS, "Incoming connection from %I%J (port %d) %s",
	    sk->daddr, ipa_is_link_local(sk->daddr) ? sk->iface : NULL,
	    sk->dport, acc ? "accepted" : "rejected");

  if (!acc)
  {
    rfree(sk);
    return 0;
  }

  hops = p->cf->multihop ? : 1;

  if (sk_set_ttl(sk, p->cf->ttl_security ? 255 : hops) < 0)
    goto err;

  if (p->cf->ttl_security)
    if (sk_set_min_ttl(sk, 256 - hops) < 0)
      goto err;

  if (p->cf->enable_extended_messages)
  {
    sk->rbsize = BGP_RX_BUFFER_EXT_SIZE;
    sk->tbsize = BGP_TX_BUFFER_EXT_SIZE;
    sk_reallocate(sk);
  }

  bgp_setup_conn(p, &p->incoming_conn);
  bgp_setup_sk(&p->incoming_conn, sk);
  bgp_send_open(&p->incoming_conn);
  return 0;

err:
  sk_log_error(sk, p->p.name);
  log(L_ERR "%s: Incoming connection aborted", p->p.name);
  rfree(sk);
  return 0;
}

static void
bgp_listen_sock_err(sock *sk UNUSED, int err)
{
  if (err == ECONNABORTED)
    log(L_WARN "BGP: Incoming connection aborted");
  else
    log(L_ERR "BGP: Error on listening socket: %M", err);
}

static void
bgp_start_neighbor(struct bgp_proto *p)
{
  /* Called only for single-hop BGP sessions */

  if (ipa_zero(p->source_addr))
    p->source_addr = p->neigh->ifa->ip;

  if (ipa_is_link_local(p->source_addr))
    p->link_addr = p->source_addr;
  else
  {
    /* Find some link-local address for given iface */
    struct ifa *a;
    p->link_addr = IPA_NONE;
    WALK_LIST(a, p->neigh->iface->addrs)
      if (a->scope == SCOPE_LINK)
      {
	p->link_addr = a->ip;
	break;
      }

    DBG("%s: Selected link-local address %I\n", p->p.name, p->link_addr);
  }

  bgp_initiate(p);
}

static void
bgp_neigh_notify(neighbor *n)
{
  struct bgp_proto *p = (struct bgp_proto *) n->proto;
  int ps = p->p.proto_state;

  if (n != p->neigh)
    return;

  if ((ps == PS_DOWN) || (ps == PS_STOP))
    return;

  int prepare = (ps == PS_START) && (p->start_state == BSS_PREPARE);

  if (n->scope <= 0)
  {
    if (!prepare)
    {
      BGP_TRACE(D_EVENTS, "Neighbor lost");
      bgp_store_error(p, NULL, BE_MISC, BEM_NEIGHBOR_LOST);
      /* Perhaps also run bgp_update_startup_delay(p)? */
      bgp_stop(p, 0);
    }
  }
  else if (p->cf->check_link && !(n->iface->flags & IF_LINK_UP))
  {
    if (!prepare)
    {
      BGP_TRACE(D_EVENTS, "Link down");
      bgp_store_error(p, NULL, BE_MISC, BEM_LINK_DOWN);
      if (ps == PS_UP)
	bgp_update_startup_delay(p);
      bgp_stop(p, 0);
    }
  }
  else
  {
    if (prepare)
    {
      BGP_TRACE(D_EVENTS, "Neighbor ready");
      bgp_start_neighbor(p);
    }
  }
}

static void
bgp_bfd_notify(struct bfd_request *req)
{
  struct bgp_proto *p = req->data;
  int ps = p->p.proto_state;

  if (req->down && ((ps == PS_START) || (ps == PS_UP)))
  {
    BGP_TRACE(D_EVENTS, "BFD session down");
    bgp_store_error(p, NULL, BE_MISC, BEM_BFD_DOWN);
    if (ps == PS_UP)
      bgp_update_startup_delay(p);
    bgp_stop(p, 0);
  }
}

static void
bgp_update_bfd(struct bgp_proto *p, int use_bfd)
{
  if (use_bfd && !p->bfd_req)
    p->bfd_req = bfd_request_session(p->p.pool, p->cf->remote_ip, p->source_addr,
				     p->cf->multihop ? NULL : p->neigh->iface,
				     bgp_bfd_notify, p);

  if (!use_bfd && p->bfd_req)
  {
    rfree(p->bfd_req);
    p->bfd_req = NULL;
  }
}

static void
bgp_reload_routes(struct channel *C)
{
  struct bgp_proto *p = (void *) C->proto;
  struct bgp_channel *c = (void *) C;

  ASSERT(p->conn && p->route_refresh);

  bgp_schedule_packet(p->conn, c, PKT_ROUTE_REFRESH);
}

static void
bgp_feed_begin(struct channel *C, int initial)
{
  struct bgp_proto *p = (void *) C->proto;
  struct bgp_channel *c = (void *) C;

  /* This should not happen */
  if (!p->conn)
    return;

  if (initial && p->cf->gr_mode)
    c->feed_state = BFS_LOADING;

  /* It is refeed and both sides support enhanced route refresh */
  if (!initial && p->enhanced_refresh)
  {
    /* BoRR must not be sent before End-of-RIB */
    if (c->feed_state == BFS_LOADING || c->feed_state == BFS_LOADED)
      return;

    c->feed_state = BFS_REFRESHING;
    bgp_schedule_packet(p->conn, c, PKT_BEGIN_REFRESH);
  }
}

static void
bgp_feed_end(struct channel *C)
{
  struct bgp_proto *p = (void *) C->proto;
  struct bgp_channel *c = (void *) C;

  /* This should not happen */
  if (!p->conn)
    return;

  /* Non-demarcated feed ended, nothing to do */
  if (c->feed_state == BFS_NONE)
    return;

  /* Schedule End-of-RIB packet */
  if (c->feed_state == BFS_LOADING)
    c->feed_state = BFS_LOADED;

  /* Schedule EoRR packet */
  if (c->feed_state == BFS_REFRESHING)
    c->feed_state = BFS_REFRESHED;

  /* Kick TX hook */
  bgp_schedule_packet(p->conn, c, PKT_UPDATE);
}


static void
bgp_start_locked(struct object_lock *lock)
{
  struct bgp_proto *p = lock->data;
  struct bgp_config *cf = p->cf;

  if (p->p.proto_state != PS_START)
  {
    DBG("BGP: Got lock in different state %d\n", p->p.proto_state);
    return;
  }

  DBG("BGP: Got lock\n");

  if (cf->multihop)
  {
    /* Multi-hop sessions do not use neighbor entries */
    bgp_initiate(p);
    return;
  }

  neighbor *n = neigh_find2(&p->p, &cf->remote_ip, cf->iface, NEF_STICKY);
  if (!n)
  {
    log(L_ERR "%s: Invalid remote address %I%J", p->p.name, cf->remote_ip, cf->iface);
    /* As we do not start yet, we can just disable protocol */
    p->p.disabled = 1;
    bgp_store_error(p, NULL, BE_MISC, BEM_INVALID_NEXT_HOP);
    proto_notify_state(&p->p, PS_DOWN);
    return;
  }

  p->neigh = n;

  if (n->scope <= 0)
    BGP_TRACE(D_EVENTS, "Waiting for %I%J to become my neighbor", cf->remote_ip, cf->iface);
  else if (p->cf->check_link && !(n->iface->flags & IF_LINK_UP))
    BGP_TRACE(D_EVENTS, "Waiting for link on %s", n->iface->name);
  else
    bgp_start_neighbor(p);
}

static int
bgp_start(struct proto *P)
{
  struct bgp_proto *p = (struct bgp_proto *) P;
  struct object_lock *lock;

  DBG("BGP: Startup.\n");
  p->start_state = BSS_PREPARE;
  p->outgoing_conn.state = BS_IDLE;
  p->incoming_conn.state = BS_IDLE;
  p->neigh = NULL;
  p->bfd_req = NULL;
  p->gr_ready = 0;
  p->gr_active_num = 0;

  p->event = ev_new(p->p.pool);
  p->event->hook = bgp_decision;
  p->event->data = p;

  p->startup_timer = tm_new(p->p.pool);
  p->startup_timer->hook = bgp_startup_timeout;
  p->startup_timer->data = p;

  p->gr_timer = tm_new(p->p.pool);
  p->gr_timer->hook = bgp_graceful_restart_timeout;
  p->gr_timer->data = p;

  p->local_id = proto_get_router_id(P->cf);
  if (p->rr_client)
    p->rr_cluster_id = p->cf->rr_cluster_id ? p->cf->rr_cluster_id : p->local_id;

  p->remote_id = 0;
  p->source_addr = p->cf->local_ip;

  /* XXXX */
  if (p->p.gr_recovery && p->cf->gr_mode)
  {
    struct bgp_channel *c;
    WALK_LIST(c, p->p.channels)
      channel_graceful_restart_lock(&c->c);
  }

  /*
   * Before attempting to create the connection, we need to lock the port,
   * so that we are the only instance attempting to talk with that neighbor.
   */

  lock = p->lock = olock_new(P->pool);
  lock->addr = p->cf->remote_ip;
  lock->port = p->cf->remote_port;
  lock->iface = p->cf->iface;
  lock->type = OBJLOCK_TCP;
  lock->hook = bgp_start_locked;
  lock->data = p;
  olock_acquire(lock);

  return PS_START;
}

extern int proto_restart;

static int
bgp_shutdown(struct proto *P)
{
  struct bgp_proto *p = (struct bgp_proto *) P;
  uint subcode = 0;

  BGP_TRACE(D_EVENTS, "Shutdown requested");

  switch (P->down_code)
  {
  case PDC_CF_REMOVE:
  case PDC_CF_DISABLE:
    subcode = 3; // Errcode 6, 3 - peer de-configured
    break;

  case PDC_CF_RESTART:
    subcode = 6; // Errcode 6, 6 - other configuration change
    break;

  case PDC_CMD_DISABLE:
  case PDC_CMD_SHUTDOWN:
    subcode = 2; // Errcode 6, 2 - administrative shutdown
    break;

  case PDC_CMD_RESTART:
    subcode = 4; // Errcode 6, 4 - administrative reset
    break;

  case PDC_RX_LIMIT_HIT:
  case PDC_IN_LIMIT_HIT:
    subcode = 1; // Errcode 6, 1 - max number of prefixes reached
    /* log message for compatibility */
    log(L_WARN "%s: Route limit exceeded, shutting down", p->p.name);
    goto limit;

  case PDC_OUT_LIMIT_HIT:
    subcode = proto_restart ? 4 : 2; // Administrative reset or shutdown

  limit:
    bgp_store_error(p, NULL, BE_AUTO_DOWN, BEA_ROUTE_LIMIT_EXCEEDED);
    if (proto_restart)
      bgp_update_startup_delay(p);
    else
      p->startup_delay = 0;
    goto done;
  }

  bgp_store_error(p, NULL, BE_MAN_DOWN, 0);
  p->startup_delay = 0;

done:
  bgp_stop(p, subcode);
  return p->p.proto_state;
}

static struct proto *
bgp_init(struct proto_config *CF)
{
  struct proto *P = proto_new(CF);
  struct bgp_proto *p = (struct bgp_proto *) P;
  struct bgp_config *cf = (struct bgp_config *) CF;

  P->rt_notify = bgp_rt_notify;
  P->import_control = bgp_import_control;
  P->neigh_notify = bgp_neigh_notify;
  P->reload_routes = bgp_reload_routes;
  P->feed_begin = bgp_feed_begin;
  P->feed_end = bgp_feed_end;
  P->rte_better = bgp_rte_better;
  P->rte_mergable = bgp_rte_mergable;
  P->rte_recalculate = cf->deterministic_med ? bgp_rte_recalculate : NULL;

  p->cf = cf;
  p->local_as = cf->local_as;
  p->remote_as = cf->remote_as;
  p->public_as = cf->local_as;
  p->is_internal = (cf->local_as == cf->remote_as);
  p->is_interior = p->is_internal || cf->confederation_member;
  p->rs_client = cf->rs_client;
  p->rr_client = cf->rr_client;

  /* Confederation ID is used for truly external peers */
  if (cf->confederation && !p->is_interior)
    p->public_as = cf->confederation;

  /* Add all channels */
  struct bgp_channel_config *cc;
  WALK_LIST(cc, CF->channels)
    proto_add_channel(P, &cc->c);

  return P;
}

static inline rtable *
get_igp_table(struct bgp_channel_config *cf)
{
  return cf->igp_table ? cf->igp_table->table : cf->c.table->table;
}

static void
bgp_channel_init(struct channel *C, struct channel_config *CF)
{
  struct bgp_channel *c = (void *) C;
  struct bgp_channel_config *cf = (void *) CF;

  C->ra_mode = cf->secondary ? RA_ACCEPTED : RA_OPTIMAL;

  c->cf = cf;
  c->afi = cf->afi;
  c->desc = bgp_get_af_desc(c->afi);
  c->igp_table = get_igp_table(cf);
}

static int
bgp_channel_start(struct channel *C)
{
  struct bgp_proto *p = (void *) C->proto;
  struct bgp_channel *c = (void *) C;
  ip_addr src = p->source_addr;

  rt_lock_table(c->igp_table);

  c->pool = p->p.pool; // XXXX
  bgp_init_bucket_table(c);
  bgp_init_prefix_table(c);

  c->next_hop_addr = c->cf->next_hop_addr;
  c->link_addr = IPA_NONE;
  c->packets_to_send = 0;

  /* Try to use source address as next hop address */
  if (ipa_zero(c->next_hop_addr))
  {
    if (bgp_channel_is_ipv4(c) && ipa_is_ip4(src))
      c->next_hop_addr = src;

    if (bgp_channel_is_ipv6(c) && ipa_is_ip6(src) && !ipa_is_link_local(src))
      c->next_hop_addr = src;
  }

  /* Set link-local address for IPv6 single-hop BGP */
  if (bgp_channel_is_ipv6(c) && p->neigh)
  {
    c->link_addr = p->link_addr;

    if (ipa_zero(c->link_addr))
      log(L_WARN "%s: Missing link-local address", p->p.name);
  }

  /* No next hop address is valid on IPv6 link-local BGP */
  if (ipa_zero(c->next_hop_addr) && !ipa_is_link_local(src))
    log(L_WARN "%s: Missing next hop address", p->p.name);

  return 0; /* XXXX: Currently undefined */
}

static void
bgp_channel_shutdown(struct channel *C)
{
  struct bgp_channel *c = (void *) C;

  /* XXXX: cleanup bucket and prefix tables */

  c->next_hop_addr = IPA_NONE;
  c->link_addr = IPA_NONE;
}

static void
bgp_channel_cleanup(struct channel *C)
{
  struct bgp_channel *c = (void *) C;

  rt_unlock_table(c->igp_table);
}

void
bgp_postconfig(struct proto_config *CF)
{
  struct bgp_config *cf = (void *) CF;
  int internal = (cf->local_as == cf->remote_as);

  /* Do not check templates at all */
  if (cf->c.class == SYM_TEMPLATE)
    return;


  /* EBGP direct by default, IBGP multihop by default */
  if (cf->multihop < 0)
    cf->multihop = internal ? 64 : 0;


  if (!cf->local_as)
    cf_error("Local AS number must be set");

  if (ipa_zero(cf->remote_ip))
    cf_error("Neighbor must be configured");

  if (!cf->remote_as)
    cf_error("Remote AS number must be set");

  // if (ipa_is_link_local(c->remote_ip) && !c->iface)
  //   cf_error("Link-local neighbor address requires specified interface");

  if (!ipa_is_link_local(cf->remote_ip) != !cf->iface)
    cf_error("Link-local address and interface scope must be used together");

  if (!(cf->capabilities && cf->enable_as4) && (cf->remote_as > 0xFFFF))
    cf_error("Neighbor AS number out of range (AS4 not available)");

  if (!internal && cf->rr_client)
    cf_error("Only internal neighbor can be RR client");

  if (internal && cf->rs_client)
    cf_error("Only external neighbor can be RS client");

  if (!cf->confederation && cf->confederation_member)
    cf_error("Confederation ID must be set for member sessions");

  if (cf->multihop && (ipa_is_link_local(cf->local_ip) ||
		       ipa_is_link_local(cf->remote_ip)))
    cf_error("Multihop BGP cannot be used with link-local addresses");

  if (cf->multihop && cf->check_link)
    cf_error("Multihop BGP cannot depend on link state");

  if (cf->multihop && cf->bfd && ipa_zero(cf->local_ip))
    cf_error("Multihop BGP with BFD requires specified local address");


  struct bgp_channel_config *cc;
  WALK_LIST(cc, CF->channels)
  {
    /* Disable after error incompatible with restart limit action */
    if ((cc->c.in_limit.action == PLA_RESTART) && cf->disable_after_error)
      cc->c.in_limit.action = PLA_DISABLE;

    /* Different default based on rs_client */
    if (!cc->missing_lladdr)
      cc->missing_lladdr = cf->rs_client ? MLL_IGNORE : MLL_SELF;

    /* Different default for gw_mode */
    if (!cc->gw_mode)
      cc->gw_mode = cf->multihop ? GW_RECURSIVE : GW_DIRECT;

    /* Default based on proto config */
    if (cc->gr_able == 0xff)
      cc->gr_able = (cf->gr_mode == BGP_GR_ABLE);

    if (cf->multihop && (cc->gw_mode == GW_DIRECT))
      cf_error("Multihop BGP cannot use direct gateway mode");

    if ((cc->gw_mode == GW_RECURSIVE) && cc->c.table->sorted)
      cf_error("BGP in recursive mode prohibits sorted table");

    if (cf->deterministic_med && cc->c.table->sorted)
      cf_error("BGP with deterministic MED prohibits sorted table");

    if (cc->secondary && !cc->c.table->sorted)
      cf_error("BGP with secondary option requires sorted table");
  }
}

static int
bgp_reconfigure(struct proto *P, struct proto_config *CF)
{
  struct bgp_proto *p = (void *) P;
  struct bgp_config *new = (void *) CF;
  struct bgp_config *old = p->cf;

  if (proto_get_router_id(CF) != p->local_id)
    return 0;

  int same = !memcmp(((byte *) old) + sizeof(struct proto_config),
		     ((byte *) new) + sizeof(struct proto_config),
		     // password item is last and must be checked separately
		     OFFSETOF(struct bgp_config, password) - sizeof(struct proto_config))
    && ((!old->password && !new->password)
	|| (old->password && new->password && !strcmp(old->password, new->password)));

  /* FIXME: Move channel reconfiguration to generic protocol code ? */
  struct channel *C, *C2;
  struct bgp_channel_config *cc;

  WALK_LIST(C, p->p.channels)
    C->stale = 1;

  WALK_LIST(cc, new->c.channels)
  {
    C = (struct channel *) bgp_find_channel(p, cc->afi);
    same = proto_configure_channel(P, &C, &cc->c) && same;
    C->stale = 0;
  }

  WALK_LIST_DELSAFE(C, C2, p->p.channels)
    if (C->stale)
      same = proto_configure_channel(P, &C, NULL) && same;


  if (same && (p->start_state > BSS_PREPARE))
    bgp_update_bfd(p, new->bfd);

  /* We should update our copy of configuration ptr as old configuration will be freed */
  if (same)
    p->cf = new;

  return same;
}

static int
bgp_channel_reconfigure(struct channel *C, struct channel_config *CC)
{
  struct bgp_channel *c = (void *) C;
  struct bgp_channel_config *new = (void *) CC;
  struct bgp_channel_config *old = c->cf;

  if (memcmp(((byte *) old) + sizeof(struct channel_config),
	     ((byte *) new) + sizeof(struct channel_config),
	     /* igp_table item is last and must be checked separately */
	     OFFSETOF(struct bgp_channel_config, igp_table) - sizeof(struct channel_config)))
    return 0;

  if (get_igp_table(old) != get_igp_table(new))
    return 0;

  c->cf = new;
  return 1;
}

static void
bgp_copy_config(struct proto_config *dest UNUSED, struct proto_config *src UNUSED)
{
  /* Just a shallow copy */
}


/**
 * bgp_error - report a protocol error
 * @c: connection
 * @code: error code (according to the RFC)
 * @subcode: error sub-code
 * @data: data to be passed in the Notification message
 * @len: length of the data
 *
 * bgp_error() sends a notification packet to tell the other side that a protocol
 * error has occurred (including the data considered erroneous if possible) and
 * closes the connection.
 */
void
bgp_error(struct bgp_conn *c, uint code, uint subcode, byte *data, int len)
{
  struct bgp_proto *p = c->bgp;

  if (c->state == BS_CLOSE)
    return;

  bgp_log_error(p, BE_BGP_TX, "Error", code, subcode, data, ABS(len));
  bgp_store_error(p, c, BE_BGP_TX, (code << 16) | subcode);
  bgp_conn_enter_close_state(c);

  c->notify_code = code;
  c->notify_subcode = subcode;
  c->notify_data = data;
  c->notify_size = (len > 0) ? len : 0;
  bgp_schedule_packet(c, NULL, PKT_NOTIFICATION);

  if (code != 6)
  {
    bgp_update_startup_delay(p);
    bgp_stop(p, 0);
  }
}

/**
 * bgp_store_error - store last error for status report
 * @p: BGP instance
 * @c: connection
 * @class: error class (BE_xxx constants)
 * @code: error code (class specific)
 *
 * bgp_store_error() decides whether given error is interesting enough
 * and store that error to last_error variables of @p
 */
void
bgp_store_error(struct bgp_proto *p, struct bgp_conn *c, u8 class, u32 code)
{
  /* During PS_UP, we ignore errors on secondary connection */
  if ((p->p.proto_state == PS_UP) && c && (c != p->conn))
    return;

  /* During PS_STOP, we ignore any errors, as we want to report
   * the error that caused transition to PS_STOP
   */
  if (p->p.proto_state == PS_STOP)
    return;

  p->last_error_class = class;
  p->last_error_code = code;
}

static char *bgp_state_names[] = { "Idle", "Connect", "Active", "OpenSent", "OpenConfirm", "Established", "Close" };
static char *bgp_err_classes[] = { "", "Error: ", "Socket: ", "Received: ", "BGP Error: ", "Automatic shutdown: ", ""};
static char *bgp_misc_errors[] = { "", "Neighbor lost", "Invalid next hop", "Kernel MD5 auth failed", "No listening socket", "Link down", "BFD session down", "Graceful restart"};
static char *bgp_auto_errors[] = { "", "Route limit exceeded"};

static const char *
bgp_last_errmsg(struct bgp_proto *p)
{
  switch (p->last_error_class)
  {
  case BE_MISC:
    return bgp_misc_errors[p->last_error_code];
  case BE_SOCKET:
    return (p->last_error_code == 0) ? "Connection closed" : strerror(p->last_error_code);
  case BE_BGP_RX:
  case BE_BGP_TX:
    return bgp_error_dsc(p->last_error_code >> 16, p->last_error_code & 0xFF);
  case BE_AUTO_DOWN:
    return bgp_auto_errors[p->last_error_code];
  default:
    return "";
  }
}

static const char *
bgp_state_dsc(struct bgp_proto *p)
{
  if (p->p.proto_state == PS_DOWN)
    return "Down";

  int state = MAX(p->incoming_conn.state, p->outgoing_conn.state);
  if ((state == BS_IDLE) && (p->start_state >= BSS_CONNECT) && p->cf->passive)
    return "Passive";

  return bgp_state_names[state];
}

static void
bgp_get_status(struct proto *P, byte *buf)
{
  struct bgp_proto *p = (struct bgp_proto *) P;

  const char *err1 = bgp_err_classes[p->last_error_class];
  const char *err2 = bgp_last_errmsg(p);

  if (P->proto_state == PS_DOWN)
    bsprintf(buf, "%s%s", err1, err2);
  else
    bsprintf(buf, "%-14s%s%s", bgp_state_dsc(p), err1, err2);
}

static void
bgp_show_proto_info(struct proto *P)
{
  struct bgp_proto *p = (struct bgp_proto *) P;
  struct bgp_conn *c = p->conn;

  cli_msg(-1006, "  BGP state:          %s", bgp_state_dsc(p));
  cli_msg(-1006, "    Neighbor address: %I%J", p->cf->remote_ip, p->cf->iface);
  cli_msg(-1006, "    Neighbor AS:      %u", p->remote_as);

  if (p->gr_active_num)
    cli_msg(-1006, "    Neighbor graceful restart active");

  if (P->proto_state == PS_START)
  {
    struct bgp_conn *oc = &p->outgoing_conn;

    if ((p->start_state < BSS_CONNECT) &&
	(p->startup_timer->expires))
      cli_msg(-1006, "    Error wait:       %d/%d",
	      p->startup_timer->expires - now, p->startup_delay);

    if ((oc->state == BS_ACTIVE) &&
	(oc->connect_timer->expires))
      cli_msg(-1006, "    Connect delay:    %d/%d",
	      oc->connect_timer->expires - now, p->cf->connect_delay_time);

    if (p->gr_active_num && p->gr_timer->expires)
      cli_msg(-1006, "    Restart timer:    %d/-", p->gr_timer->expires - now);
  }
  else if (P->proto_state == PS_UP)
  {
    cli_msg(-1006, "    Neighbor ID:      %R", p->remote_id);
/* XXXX
      cli_msg(-1006, "    Neighbor caps:   %s%s%s%s%s%s%s",
	      c->peer_refresh_support ? " refresh" : "",
	      c->peer_enhanced_refresh_support ? " enhanced-refresh" : "",
	      c->peer_gr_able ? " restart-able" : (c->peer_gr_aware ? " restart-aware" : ""),
	      c->peer_as4_support ? " AS4" : "",
	      (c->peer_add_path & ADD_PATH_RX) ? " add-path-rx" : "",
	      (c->peer_add_path & ADD_PATH_TX) ? " add-path-tx" : "",
	      c->peer_ext_messages_support ? " ext-messages" : "");
      cli_msg(-1006, "    Session:          %s%s%s%s%s%s%s%s",
	      p->is_internal ? "internal" : "external",
	      p->cf->multihop ? " multihop" : "",
	      p->rr_client ? " route-reflector" : "",
	      p->rs_client ? " route-server" : "",
	      p->as4_session ? " AS4" : "",
	      p->add_path_rx ? " add-path-rx" : "",
	      p->add_path_tx ? " add-path-tx" : "",
	      p->ext_messages ? " ext-messages" : "");
*/
    cli_msg(-1006, "    Source address:   %I", p->source_addr);
    cli_msg(-1006, "    Hold timer:       %d/%d",
	    tm_remains(c->hold_timer), c->hold_time);
    cli_msg(-1006, "    Keepalive timer:  %d/%d",
	    tm_remains(c->keepalive_timer), c->keepalive_time);
  }

  if ((p->last_error_class != BE_NONE) &&
      (p->last_error_class != BE_MAN_DOWN))
  {
    const char *err1 = bgp_err_classes[p->last_error_class];
    const char *err2 = bgp_last_errmsg(p);
    cli_msg(-1006, "    Last error:       %s%s", err1, err2);
  }

  {
    /* XXXX ?? */
    struct channel *c;
    WALK_LIST(c, p->p.channels)
      channel_show_info(c);
  }
}

struct channel_class channel_bgp = {
  .channel_size =	sizeof(struct bgp_channel),
  .config_size =	sizeof(struct bgp_channel_config),
  .init =		bgp_channel_init,
  .start =		bgp_channel_start,
  .shutdown =		bgp_channel_shutdown,
  .cleanup =		bgp_channel_cleanup,
  .reconfigure =	bgp_channel_reconfigure,
};

struct protocol proto_bgp = {
  .name = 		"BGP",
  .template = 		"bgp%d",
  .attr_class = 	EAP_BGP,
  .preference = 	DEF_PREF_BGP, 
  .channel_mask =	NB_IP | NB_VPN,
  .proto_size =		sizeof(struct bgp_proto),
  .config_size =	sizeof(struct bgp_config),
  .postconfig =		bgp_postconfig,
  .init = 		bgp_init,
  .start = 		bgp_start,
  .shutdown = 		bgp_shutdown,
  .reconfigure = 	bgp_reconfigure,
  .copy_config = 	bgp_copy_config,
  .get_status = 	bgp_get_status,
  .get_attr = 		bgp_get_attr,
  .get_route_info = 	bgp_get_route_info,
  .show_proto_info = 	bgp_show_proto_info
};
