/*
 *	BIRD -- The Resource Public Key Infrastructure (RPKI) to Router Protocol
 *
 *	(c) 2015 CZ.NIC
 *	(c) 2015 Pavel Tvrdik <pawel.tvrdik@gmail.com>
 *
 *	Using RTRlib: http://rpki.realmv6.org/
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: RPKI To Router (RPKI-RTR)
 *
 * The RPKI-RTR protocol is implemented in several files: |rpki.c| containing
 * the routes handling, protocol logic, timer events, cache connection,
 * reconfiguration, configuration and protocol glue with BIRD core, |packets.c|
 * containing the RPKI packets handling and finally all transports files:
 * |transport.c|, |tcp_transport.c| and |ssh_transport.c|.
 *
 * The |transport.c| is a middle layer and interface for each specific
 * transport. Transport is a way how to wrap a communication with a cache
 * server. There is supported an unprotected TCP transport and an encrypted
 * SSHv2 transport. The SSH transport requires LibSSH library. LibSSH is
 * loading dynamically using |dlopen()| function. SSH support is integrated in
 * |sysdep/unix/io.c|. Each transport must implement an initialization
 * function, an open function and a socket identification function. That's all.
 *
 * This implementation is based on the RTRlib (http://rpki.realmv6.org/). The
 * BIRD takes over files |packets.c|, |rtr.c| (inside |rpki.c|), |transport.c|,
 * |tcp_transport.c| and |ssh_transport.c| from RTRlib.
 *
 * A RPKI-RTR connection is described by a structure &rpki_cache. The main
 * logic is located in |rpki_cache_change_state()| function. There is a state
 * machine. The standard starting state flow looks like |Down| ~> |Connecting|
 * ~> |Sync-Start| ~> |Sync-Running| ~> |Established| and then the last three
 * states are periodically repeated.
 *
 * |Connecting| state establishes the transport connection. The state from a
 * call |rpki_cache_change_state(CONNECTING)| to a call |rpki_connected_hook()|
 *
 * |Sync-Start| state starts with sending |Reset Query| or |Serial Query| and
 * then waits for |Cache Response|. The state from |rpki_connected_hook()| to
 * |rpki_handle_cache_response_pdu()|
 *
 * During |Sync-Running| BIRD receives data with IPv4/IPv6 Prefixes from cache
 * server. The state starts from |rpki_handle_cache_response_pdu()| and ends
 * in |rpki_handle_end_of_data_pdu()|.
 *
 * |Established| state means that BIRD has synced all data with cache server.
 * Schedules a refresh timer event that invokes |Sync-Start|. Schedules Expire
 * timer event and stops a Retry timer event.
 *
 * |Transport Error| state means that we have some troubles with a network
 * connection. We cannot connect to a cache server or we wait too long for some
 * expected PDU for received - |Cache Response| or |End of Data|. It closes
 * current connection and schedules a Retry timer event.
 *
 * |Fatal Protocol Error| is occurred e.g. by received a bad Session ID. We
 * restart a protocol, so all ROAs are flushed immediately.
 *
 * The RPKI-RTR protocol (RFC 6810 bis) defines configurable refresh, retry and
 * expire intervals. For maintaining a connection are used timer events that
 * are scheduled by |rpki_schedule_next_refresh()|,
 * |rpki_schedule_next_retry()| and |rpki_schedule_next_expire()| functions.
 *
 * A Refresh timer event performs a sync of |Established| connection. So it
 * shifts state to |Sync-Start|. If at the beginning of second call of a
 * refresh event is connection in |Sync-Start| state then we didn't receive a
 * |Cache Response| from a cache server and we invoke |Transport Error| state.
 *
 * A Retry timer event attempts to connect cache server. It is activated after
 * |Transport Error| state and terminated by reaching |Established| state.
 * If cache connection is still connecting to the cache server at the beginning
 * of an event call then the Retry timer event invokes |Transport Error| state.
 *
 * An Expire timer event checks expiration of ROAs. If a last successful sync
 * was more ago than the expire interval then the Expire timer event invokes a
 * protocol restart thereby removes all ROAs learned from that cache server and
 * continue trying to connect to cache server. The Expire event is activated
 * by initial successful loading of ROAs, receiving End of Data PDU.
 *
 * A reconfiguration of cache connection works well without restarting when we
 * change only intervals values.
 *
 * Supported standards:
 * - RFC 6810 - main RPKI-RTR standard
 * - RFC 6810 bis - an explicit timing parameters and protocol version number negotiation
 */

#include <stdlib.h>
#include <netdb.h>

#undef LOCAL_DEBUG

#include "rpki.h"
#include "lib/string.h"
#include "nest/cli.h"

/* Return values for reconfiguration functions */
#define NEED_RESTART 		0
#define SUCCESSFUL_RECONF 	1

static int rpki_open_connection(struct rpki_cache *cache);
static void rpki_close_connection(struct rpki_cache *cache);
static void rpki_schedule_next_refresh(struct rpki_cache *cache);
static void rpki_schedule_next_retry(struct rpki_cache *cache);
static void rpki_schedule_next_expire_check(struct rpki_cache *cache);
static void rpki_stop_refresh_timer_event(struct rpki_cache *cache);
static void rpki_stop_retry_timer_event(struct rpki_cache *cache);
static void rpki_stop_expire_timer_event(struct rpki_cache *cache);


/*
 * 	Routes handling
 */

void
rpki_table_add_roa(struct rpki_cache *cache, struct channel *channel, const net_addr_union *pfxr)
{
  struct rpki_proto *p = cache->p;

  rta a0 = {
    .src = p->p.main_source,
    .source = RTS_RPKI,
    .scope = SCOPE_UNIVERSE,
    .dest = RTD_NONE,
  };

  rta *a = rta_lookup(&a0);
  rte *e = rte_get_temp(a);

  e->pflags = 0;

  rte_update2(channel, &pfxr->n, e, a0.src);
}

void
rpki_table_remove_roa(struct rpki_cache *cache, struct channel *channel, const net_addr_union *pfxr)
{
  struct rpki_proto *p = cache->p;
  rte_update2(channel, &pfxr->n, NULL, p->p.main_source);
}


/*
 *	RPKI Protocol Logic
 */

static const char *str_cache_states[] = {
  [RPKI_CS_CONNECTING] 		= "Connecting",
  [RPKI_CS_ESTABLISHED] 	= "Established",
  [RPKI_CS_RESET] 		= "Reseting",
  [RPKI_CS_SYNC_START] 		= "Sync-Start",
  [RPKI_CS_SYNC_RUNNING] 	= "Sync-Running",
  [RPKI_CS_FAST_RECONNECT] 	= "Fast-Reconnect",
  [RPKI_CS_NO_INCR_UPDATE_AVAIL]= "No-Increment-Update-Available",
  [RPKI_CS_ERROR_NO_DATA_AVAIL] = "Cache-Error-No-Data-Available",
  [RPKI_CS_ERROR_FATAL] 	= "Fatal-Protocol-Error",
  [RPKI_CS_ERROR_TRANSPORT] 	= "Transport-Error",
  [RPKI_CS_SHUTDOWN] 		= "Down"
};

/**
 * rpki_cache_state_to_str - give a text representation of cache state
 * @state: A cache state
 *
 * The function converts logic cache state into string.
 */
const char *
rpki_cache_state_to_str(enum rpki_cache_state state)
{
  return str_cache_states[state];
}

/**
 * rpki_start_cache - connect to a cache server
 * @cache: RPKI connection instance
 *
 * This function is a high level method to kick up a connection to a cache server.
 */
static void
rpki_start_cache(struct rpki_cache *cache)
{
  rpki_cache_change_state(cache, RPKI_CS_CONNECTING);
}

/**
 * rpki_force_restart_proto - force shutdown and start protocol again
 * @p: RPKI protocol instance
 *
 * This function calls shutdown and frees all protocol resources as well.
 * After calling this function should be no operations with protocol data,
 * they could be freed already.
 */
static void
rpki_force_restart_proto(struct rpki_proto *p)
{
  if (p->cache)
  {
    CACHE_DBG(p->cache, "Connection object destroying");
  }

  /* Sign as freed */
  p->cache = NULL;

  proto_notify_state(&p->p, PS_DOWN);
}

/**
 * rpki_cache_change_state - check and change cache state
 * @cache: RPKI cache instance
 * @new_state: suggested new state
 *
 * This function makes transitions between internal states.
 * It represents the core of logic management of RPKI protocol.
 * Cannot transit into the same state as cache is in already.
 */
void
rpki_cache_change_state(struct rpki_cache *cache, const enum rpki_cache_state new_state)
{
  const enum rpki_cache_state old_state = cache->state;

  if (old_state == new_state)
    return;

  cache->state = new_state;
  CACHE_TRACE(D_EVENTS, cache, "Changing from %s to %s state", rpki_cache_state_to_str(old_state), rpki_cache_state_to_str(new_state));

  switch (new_state)
  {
  case RPKI_CS_CONNECTING:
  {
    sock *sk = cache->tr_sock->sk;

    if (sk == NULL || sk->fd < 0)
      rpki_open_connection(cache);
    else
      rpki_cache_change_state(cache, RPKI_CS_SYNC_START);

    rpki_schedule_next_retry(cache);
    break;
  }

  case RPKI_CS_ESTABLISHED:
    rpki_schedule_next_refresh(cache);
    rpki_schedule_next_expire_check(cache);
    rpki_stop_retry_timer_event(cache);
    break;

  case RPKI_CS_RESET:
    /* Resetting cache connection. */
    cache->request_session_id = 1;
    cache->serial_num = 0;
    rpki_cache_change_state(cache, RPKI_CS_SYNC_START);
    break;

  case RPKI_CS_SYNC_START:
    /* Requesting for receive ROAs from a cache server. */
    if (cache->request_session_id)
    {
      /* Send request for Session ID */
      if (rpki_send_reset_query(cache) != RPKI_SUCCESS)
	rpki_cache_change_state(cache, RPKI_CS_ERROR_TRANSPORT);
    }
    else
    {
      /* We have already a session_id. So send a Serial Query and start an incremental sync */
      if (rpki_send_serial_query(cache) != RPKI_SUCCESS)
	rpki_cache_change_state(cache, RPKI_CS_ERROR_TRANSPORT);
    }
    break;

  case RPKI_CS_SYNC_RUNNING:
    /* The state between Cache Response and End of Data. Only waiting for
     * receiving all IP Prefix PDUs and finally a End of Data PDU. */
    break;

  case RPKI_CS_NO_INCR_UPDATE_AVAIL:
    /* Server was unable to answer the last Serial Query and sent Cache Reset. */
    rpki_cache_change_state(cache, RPKI_CS_RESET);
    break;

  case RPKI_CS_ERROR_NO_DATA_AVAIL:
    /* No validation records are available on the cache server. */
    rpki_cache_change_state(cache, RPKI_CS_RESET);
    break;

  case RPKI_CS_ERROR_FATAL:
    /* Fatal protocol error occurred. */
    rpki_force_restart_proto(cache->p);
    break;

  case RPKI_CS_ERROR_TRANSPORT:
    /* Error on the transport socket occurred. */
    rpki_close_connection(cache);
    rpki_schedule_next_retry(cache);
    rpki_stop_refresh_timer_event(cache);
    break;

  case RPKI_CS_FAST_RECONNECT:
    /* Reconnect without any waiting period */
    rpki_close_connection(cache);
    rpki_cache_change_state(cache, RPKI_CS_CONNECTING);
    break;

  case RPKI_CS_SHUTDOWN:
    bug("This isn't never really called.");
    break;
  };
}


/*
 * 	RPKI Timer Events
 */

static void
rpki_schedule_next_refresh(struct rpki_cache *cache)
{
  btime t = cache->refresh_interval S;

  CACHE_DBG(cache, "after %t s", t);
  tm_start(cache->refresh_timer, t);
}

static void
rpki_schedule_next_retry(struct rpki_cache *cache)
{
  btime t = cache->retry_interval S;

  CACHE_DBG(cache, "after %t s", t);
  tm_start(cache->retry_timer, t);
}

static void
rpki_schedule_next_expire_check(struct rpki_cache *cache)
{
  /* A minimum time to wait is 1 second */
  btime t = cache->last_update + cache->expire_interval S - current_time();
  t = MAX(t, 1 S);

  CACHE_DBG(cache, "after %t s", t);
  tm_start(cache->expire_timer, t);
}

static void
rpki_stop_refresh_timer_event(struct rpki_cache *cache)
{
  CACHE_DBG(cache, "Stop");
  tm_stop(cache->refresh_timer);
}

static void
rpki_stop_retry_timer_event(struct rpki_cache *cache)
{
  CACHE_DBG(cache, "Stop");
  tm_stop(cache->retry_timer);
}

static void UNUSED
rpki_stop_expire_timer_event(struct rpki_cache *cache)
{
  CACHE_DBG(cache, "Stop");
  tm_stop(cache->expire_timer);
}

static int
rpki_do_we_recv_prefix_pdu_in_last_seconds(struct rpki_cache *cache)
{
  if (!cache->last_rx_prefix)
    return 0;

  return ((current_time() - cache->last_rx_prefix) <= 2 S);
}

/**
 * rpki_refresh_hook - control a scheduling of downloading data from cache server
 * @tm: refresh timer with cache connection instance in data
 *
 * This function is periodically called during &ESTABLISHED or &SYNC* state
 * cache connection.  The first refresh schedule is invoked after receiving a
 * |End of Data| PDU and has run by some &ERROR is occurred.
 */
static void
rpki_refresh_hook(timer *tm)
{
  struct rpki_cache *cache = tm->data;

  CACHE_DBG(cache, "%s", rpki_cache_state_to_str(cache->state));

  switch (cache->state)
  {
  case RPKI_CS_ESTABLISHED:
    rpki_cache_change_state(cache, RPKI_CS_SYNC_START);
    break;

  case RPKI_CS_SYNC_START:
    /* We sent Serial/Reset Query in last refresh hook call
     * and didn't receive Cache Response yet. It is probably
     * troubles with network. */
  case RPKI_CS_SYNC_RUNNING:
    /* We sent Serial/Reset Query in last refresh hook call
     * and we got Cache Response but didn't get End-Of-Data yet.
     * It could be a trouble with network or only too long synchronization. */
    if (!rpki_do_we_recv_prefix_pdu_in_last_seconds(cache))
    {
      CACHE_TRACE(D_EVENTS, cache, "Sync takes more time than refresh interval %us, resetting connection", cache->refresh_interval);
      rpki_cache_change_state(cache, RPKI_CS_ERROR_TRANSPORT);
    }
    break;

  default:
    break;
  }

  if (cache->state != RPKI_CS_SHUTDOWN && cache->state != RPKI_CS_ERROR_TRANSPORT)
    rpki_schedule_next_refresh(cache);
  else
    rpki_stop_refresh_timer_event(cache);
}

/**
 * rpki_retry_hook - control a scheduling of retrying connection to cache server
 * @tm: retry timer with cache connection instance in data
 *
 * This function is periodically called during &ERROR* state cache connection.
 * The first retry schedule is invoked after any &ERROR* state occurred and
 * ends by reaching of &ESTABLISHED state again.
 */
static void
rpki_retry_hook(timer *tm)
{
  struct rpki_cache *cache = tm->data;

  CACHE_DBG(cache, "%s", rpki_cache_state_to_str(cache->state));

  switch (cache->state)
  {
  case RPKI_CS_ESTABLISHED:
  case RPKI_CS_SHUTDOWN:
    break;

  case RPKI_CS_CONNECTING:
  case RPKI_CS_SYNC_START:
  case RPKI_CS_SYNC_RUNNING:
    if (!rpki_do_we_recv_prefix_pdu_in_last_seconds(cache))
    {
      /* We tried to establish a connection in last retry hook call and haven't done
       * yet. It looks like troubles with network. We are aggressive here. */
      CACHE_TRACE(D_EVENTS, cache, "Sync takes more time than retry interval %us, resetting connection.", cache->retry_interval);
      rpki_cache_change_state(cache, RPKI_CS_ERROR_TRANSPORT);
    }
    break;

  default:
    rpki_cache_change_state(cache, RPKI_CS_CONNECTING);
    break;
  }

  if (cache->state != RPKI_CS_ESTABLISHED)
    rpki_schedule_next_retry(cache);
  else
    rpki_stop_retry_timer_event(cache);
}

/**
 * rpki_expire_hook - control a expiration of ROA entries
 * @tm: expire timer with cache connection instance in data
 *
 * This function is scheduled after received a |End of Data| PDU.
 * A waiting interval is calculated dynamically by last update.
 * If we reach an expiration time then we invoke a restarting
 * of the protocol.
 */
static void
rpki_expire_hook(timer *tm)
{
  struct rpki_cache *cache = tm->data;

  if (!cache->last_update)
    return;

  CACHE_DBG(cache, "%s", rpki_cache_state_to_str(cache->state));

  btime t = cache->last_update + cache->expire_interval S - current_time();
  if (t <= 0)
  {
    CACHE_TRACE(D_EVENTS, cache, "All ROAs expired");
    rpki_force_restart_proto(cache->p);
  }
  else
  {
    CACHE_DBG(cache, "Remains %t seconds to become ROAs obsolete", t);
    rpki_schedule_next_expire_check(cache);
  }
}

/**
 * rpki_check_refresh_interval - check validity of refresh interval value
 * @seconds: suggested value
 *
 * This function validates value and should return |NULL|.
 * If the check doesn't pass then returns error message.
 */
const char *
rpki_check_refresh_interval(uint seconds)
{
  if (seconds < 1)
    return "Minimum allowed refresh interval is 1 second";
  if (seconds > 86400)
    return "Maximum allowed refresh interval is 86400 seconds";
  return NULL;
}

/**
 * rpki_check_retry_interval - check validity of retry interval value
 * @seconds: suggested value
 *
 * This function validates value and should return |NULL|.
 * If the check doesn't pass then returns error message.
 */
const char *
rpki_check_retry_interval(uint seconds)
{
  if (seconds < 1)
    return "Minimum allowed retry interval is 1 second";
  if (seconds > 7200)
    return "Maximum allowed retry interval is 7200 seconds";
  return NULL;
}

/**
 * rpki_check_expire_interval - check validity of expire interval value
 * @seconds: suggested value
 *
 * This function validates value and should return |NULL|.
 * If the check doesn't pass then returns error message.
 */
const char *
rpki_check_expire_interval(uint seconds)
{
  if (seconds < 600)
    return "Minimum allowed expire interval is 600 seconds";
  if (seconds > 172800)
    return "Maximum allowed expire interval is 172800 seconds";
  return NULL;
}


/*
 * 	RPKI Cache
 */

static struct rpki_cache *
rpki_init_cache(struct rpki_proto *p, struct rpki_config *cf)
{
  pool *pool = rp_new(p->p.pool, cf->hostname);

  struct rpki_cache *cache = mb_allocz(pool, sizeof(struct rpki_cache));

  cache->pool = pool;
  cache->p = p;

  cache->state = RPKI_CS_SHUTDOWN;
  cache->request_session_id = 1;
  cache->version = RPKI_MAX_VERSION;

  cache->refresh_interval = cf->refresh_interval;
  cache->retry_interval = cf->retry_interval;
  cache->expire_interval = cf->expire_interval;
  cache->refresh_timer = tm_new_init(pool, &rpki_refresh_hook, cache, 0, 0);
  cache->retry_timer = tm_new_init(pool, &rpki_retry_hook, cache, 0, 0);
  cache->expire_timer = tm_new_init(pool, &rpki_expire_hook, cache, 0, 0);

  cache->tr_sock = mb_allocz(pool, sizeof(struct rpki_tr_sock));
  cache->tr_sock->cache = cache;

  switch (cf->tr_config.type)
  {
  case RPKI_TR_TCP: rpki_tr_tcp_init(cache->tr_sock); break;
  case RPKI_TR_SSH: rpki_tr_ssh_init(cache->tr_sock); break;
  };

  CACHE_DBG(cache, "Connection object created");

  return cache;
}

/**
 * rpki_get_cache_ident - give a text representation of cache server name
 * @cache: RPKI connection instance
 *
 * The function converts cache connection into string.
 */
const char *
rpki_get_cache_ident(struct rpki_cache *cache)
{
  return rpki_tr_ident(cache->tr_sock);
}

static int
rpki_open_connection(struct rpki_cache *cache)
{
  CACHE_TRACE(D_EVENTS, cache, "Opening a connection");

  if (rpki_tr_open(cache->tr_sock) == RPKI_TR_ERROR)
  {
    rpki_cache_change_state(cache, RPKI_CS_ERROR_TRANSPORT);
    return RPKI_TR_ERROR;
  }

  return RPKI_TR_SUCCESS;
}

static void
rpki_close_connection(struct rpki_cache *cache)
{
  CACHE_TRACE(D_EVENTS, cache, "Closing a connection");
  rpki_tr_close(cache->tr_sock);
  proto_notify_state(&cache->p->p, PS_START);
}

static int
rpki_shutdown(struct proto *P)
{
  struct rpki_proto *p = (void *) P;

  rpki_force_restart_proto(p);

  /* Protocol memory pool will be automatically freed */
  return PS_DOWN;
}


/*
 * 	RPKI Reconfiguration
 */

static int
rpki_try_fast_reconnect(struct rpki_cache *cache)
{
  if (cache->state == RPKI_CS_ESTABLISHED)
  {
    rpki_cache_change_state(cache, RPKI_CS_FAST_RECONNECT);
    return SUCCESSFUL_RECONF;
  }

  return NEED_RESTART;
}

/**
 * rpki_reconfigure_cache - a cache reconfiguration
 * @p: RPKI protocol instance
 * @cache: a cache connection
 * @new: new RPKI configuration
 * @old: old RPKI configuration
 *
 * This function reconfigures existing single cache server connection with new
 * existing configuration.  Generally, a change of time intervals could be
 * reconfigured without restarting and all others changes requires a restart of
 * protocol.  Returns |NEED_TO_RESTART| or |SUCCESSFUL_RECONF|.
 */
static int
rpki_reconfigure_cache(struct rpki_proto *p UNUSED, struct rpki_cache *cache, struct rpki_config *new, struct rpki_config *old)
{
  u8 try_fast_reconnect = 0;

  if (strcmp(old->hostname, new->hostname) != 0)
  {
    CACHE_TRACE(D_EVENTS, cache, "Cache server address changed to %s", new->hostname);
    return NEED_RESTART;
  }

  if (old->port != new->port)
  {
    CACHE_TRACE(D_EVENTS, cache, "Cache server port changed to %u", new->port);
    return NEED_RESTART;
  }

  if (old->tr_config.type != new->tr_config.type)
  {
    CACHE_TRACE(D_EVENTS, cache, "Transport type changed");
    return NEED_RESTART;
  }
  else if (new->tr_config.type == RPKI_TR_SSH)
  {
    struct rpki_tr_ssh_config *ssh_old = (void *) old->tr_config.spec;
    struct rpki_tr_ssh_config *ssh_new = (void *) new->tr_config.spec;
    if ((strcmp(ssh_old->bird_private_key, ssh_new->bird_private_key) != 0) ||
	(strcmp(ssh_old->cache_public_key, ssh_new->cache_public_key) != 0) ||
	(strcmp(ssh_old->user, ssh_new->user) != 0))
    {
      CACHE_TRACE(D_EVENTS, cache, "Settings of SSH transport configuration changed");
      try_fast_reconnect = 1;
    }
  }

#define TEST_INTERVAL(name, Name) 						\
    if (cache->name##_interval != new->name##_interval ||			\
	old->keep_##name##_interval != new->keep_##name##_interval) 		\
    { 										\
      cache->name##_interval = new->name##_interval;				\
      CACHE_TRACE(D_EVENTS, cache, #Name " interval changed to %u seconds %s", cache->name##_interval, (new->keep_##name##_interval ? "and keep it" : "")); \
      try_fast_reconnect = 1; 							\
    }
  TEST_INTERVAL(refresh, Refresh);
  TEST_INTERVAL(retry, Retry);
  TEST_INTERVAL(expire, Expire);
#undef TEST_INTERVAL

  if (try_fast_reconnect)
    return rpki_try_fast_reconnect(cache);

  return SUCCESSFUL_RECONF;
}

/**
 * rpki_reconfigure - a protocol reconfiguration hook
 * @P: a protocol instance
 * @CF: a new protocol configuration
 *
 * This function reconfigures whole protocol.
 * It sets new protocol configuration into a protocol structure.
 * Returns |NEED_TO_RESTART| or |SUCCESSFUL_RECONF|.
 */
static int
rpki_reconfigure(struct proto *P, struct proto_config *CF)
{
  struct rpki_proto *p = (void *) P;
  struct rpki_config *new = (void *) CF;
  struct rpki_config *old = (void *) p->p.cf;
  struct rpki_cache *cache = p->cache;

  if (!proto_configure_channel(&p->p, &p->roa4_channel, proto_cf_find_channel(CF, NET_ROA4)) ||
      !proto_configure_channel(&p->p, &p->roa6_channel, proto_cf_find_channel(CF, NET_ROA6)))
    return NEED_RESTART;

  if (rpki_reconfigure_cache(p, cache, new, old) != SUCCESSFUL_RECONF)
    return NEED_RESTART;

  return SUCCESSFUL_RECONF;
}


/*
 * 	RPKI Protocol Glue
 */

static struct proto *
rpki_init(struct proto_config *CF)
{
  struct proto *P = proto_new(CF);
  struct rpki_proto *p = (void *) P;

  proto_configure_channel(&p->p, &p->roa4_channel, proto_cf_find_channel(CF, NET_ROA4));
  proto_configure_channel(&p->p, &p->roa6_channel, proto_cf_find_channel(CF, NET_ROA6));

  return P;
}

static int
rpki_start(struct proto *P)
{
  struct rpki_proto *p = (void *) P;
  struct rpki_config *cf = (void *) P->cf;

  p->cache = rpki_init_cache(p, cf);
  rpki_start_cache(p->cache);

  return PS_START;
}

static void
rpki_get_status(struct proto *P, byte *buf)
{
  struct rpki_proto *p = (struct rpki_proto *) P;

  if (P->proto_state == PS_DOWN)
  {
    *buf = 0;
    return;
  }

  if (p->cache)
    bsprintf(buf, "%s", rpki_cache_state_to_str(p->cache->state));
  else
    bsprintf(buf, "No cache server configured");
}

static void
rpki_show_proto_info_timer(const char *name, uint num, timer *t)
{
  if (tm_active(t))
    cli_msg(-1006, "  %-16s: %t/%u", name, tm_remains(t), num);
  else
    cli_msg(-1006, "  %-16s: ---", name);
}

static void
rpki_show_proto_info(struct proto *P)
{
  struct rpki_proto *p = (struct rpki_proto *) P;
  struct rpki_config *cf = (void *) p->p.cf;
  struct rpki_cache *cache = p->cache;

  if (P->proto_state == PS_DOWN)
    return;

  if (cache)
  {
    const char *transport_name = "---";

    switch (cf->tr_config.type)
    {
    case RPKI_TR_SSH: transport_name = "SSHv2"; break;
    case RPKI_TR_TCP: transport_name = "Unprotected over TCP"; break;
    };

    cli_msg(-1006, "  Cache server:     %s", rpki_get_cache_ident(cache));
    cli_msg(-1006, "  Status:           %s", rpki_cache_state_to_str(cache->state));
    cli_msg(-1006, "  Transport:        %s", transport_name);
    cli_msg(-1006, "  Protocol version: %u", cache->version);

    if (cache->request_session_id)
      cli_msg(-1006, "  Session ID:       ---");
    else
      cli_msg(-1006, "  Session ID:       %u", cache->session_id);

    if (cache->last_update)
    {
      cli_msg(-1006, "  Serial number:    %u", cache->serial_num);
      cli_msg(-1006, "  Last update:      before %t s", current_time() - cache->last_update);
    }
    else
    {
      cli_msg(-1006, "  Serial number:    ---");
      cli_msg(-1006, "  Last update:      ---");
    }

    rpki_show_proto_info_timer("Refresh timer", cache->refresh_interval, cache->refresh_timer);
    rpki_show_proto_info_timer("Retry timer", cache->retry_interval, cache->retry_timer);
    rpki_show_proto_info_timer("Expire timer", cache->expire_interval, cache->expire_timer);

    if (p->roa4_channel)
      channel_show_info(p->roa4_channel);
    else
      cli_msg(-1006, "  No roa4 channel");

    if (p->roa6_channel)
      channel_show_info(p->roa6_channel);
    else
      cli_msg(-1006, "  No roa6 channel");
  }
}


/*
 * 	RPKI Protocol Configuration
 */

/**
 * rpki_check_config - check and complete configuration of RPKI protocol
 * @cf: RPKI configuration
 *
 * This function is called at the end of parsing RPKI protocol configuration.
 */
void
rpki_check_config(struct rpki_config *cf)
{
  /* Do not check templates at all */
  if (cf->c.class == SYM_TEMPLATE)
    return;

  if (ipa_zero(cf->ip) && cf->hostname == NULL)
    cf_error("IP address or hostname of cache server must be set");

  /* Set default transport type */
  if (cf->tr_config.spec == NULL)
  {
    cf->tr_config.spec = cfg_allocz(sizeof(struct rpki_tr_tcp_config));
    cf->tr_config.type = RPKI_TR_TCP;
  }

  if (cf->port == 0)
  {
    /* Set default port numbers */
    switch (cf->tr_config.type)
    {
    case RPKI_TR_SSH:
      cf->port = RPKI_SSH_PORT;
      break;
    default:
      cf->port = RPKI_TCP_PORT;
    }
  }
}

static void
rpki_postconfig(struct proto_config *CF)
{
  /* Define default channel */
  if (EMPTY_LIST(CF->channels))
    channel_config_new(NULL, net_label[CF->net_type], CF->net_type, CF);
}

static void
rpki_copy_config(struct proto_config *dest UNUSED, struct proto_config *src UNUSED)
{
  /* FIXME: Should copy transport */
}

struct protocol proto_rpki = {
  .name = 		"RPKI",
  .template = 		"rpki%d",
  .class =		PROTOCOL_RPKI,
  .preference = 	DEF_PREF_RPKI,
  .proto_size = 	sizeof(struct rpki_proto),
  .config_size =	sizeof(struct rpki_config),
  .init = 		rpki_init,
  .start = 		rpki_start,
  .postconfig = 	rpki_postconfig,
  .channel_mask =	(NB_ROA4 | NB_ROA6),
  .show_proto_info =	rpki_show_proto_info,
  .shutdown = 		rpki_shutdown,
  .copy_config = 	rpki_copy_config,
  .reconfigure = 	rpki_reconfigure,
  .get_status = 	rpki_get_status,
};
