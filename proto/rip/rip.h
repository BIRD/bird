/*
 * Structures for RIP protocol
 *
 FIXME: in V6, they insert additional entry whenever next hop differs. Such entry is identified by 0xff in metric.
 */

#include "nest/route.h"
#include "nest/password.h"
#include "nest/locks.h"

#define EA_RIP_TAG	EA_CODE(EAP_RIP, 0)
#define EA_RIP_METRIC	EA_CODE(EAP_RIP, 1)

/* http://blog.ipspace.net/2008/10/rip-trivia-maximum-rip-packet-size.html */
#define MAX_RTEs_IN_PACKET_WITHOUT_AUTH		25
#define MAX_RTEs_IN_PACKET_WITH_PLAIN_TEXT_AUTH	24
#define MAX_RTEs_IN_PACKET_WITH_MD5_AUTH	23
#define RIP_RTE_SIZE				20
#define IPV6_HEADER_SIZE			40
#define UDP_HEADER_SIZE				4
#define RIP_NG_HEADER_SIZE			4

#define RIP_V1		1
#define RIP_V2		2
#define RIP_NG		1	/* A new version numbering */

#ifndef IPV6
#define RIP_PORT	520	/* RIP for IPv4 */
#else
#define RIP_PORT	521	/* RIPng */
#endif

#define RIP_TIMEOUT_TIME	120
#define RIP_GARBAGE_TIME	RIP_TIMEOUT_TIME + 180

#define OK		1
#define FAIL		0

#define BAD(x)					\
  do						\
  {						\
    log(L_REMOTE "%s: " x, p->p.name);	\
    return 1;					\
  } while(0)

struct rip_connection
{
  node n;

  int num;
  struct rip_proto *rip;
  ip_addr addr;
  sock *send;
  struct rip_iface *rif;
  struct fib_iterator iter;

  ip_addr daddr;
  int dport;
  int done;
};

struct rip_packet_heading /* 4 bytes */
{
  u8 command;
#define RIPCMD_REQUEST		1	/* want info */
#define RIPCMD_RESPONSE		2	/* responding to request */
  u8 version;
#define RIP_V1			1
#define RIP_V2			2
#define RIP_NG 			1	/* this is verion 1 of RIPng */
  u16 unused;
};

#ifndef IPV6
struct rip_block /* 20 bytes */
{
  u16 family; /* 0xffff on first message means this is authentication */
  u16 tag;
  ip_addr network;
  ip_addr netmask;
  ip_addr next_hop;
  u32 metric;
};
#else
struct rip_block /* IPv6 version!, 20 bytes, too */
{
  ip_addr network;
  u16 tag;
  u8 pxlen;
  u8 metric;
};
#endif

struct rip_block_auth /* 20 bytes */
{
  u16 must_be_FFFF;
  u16 auth_type;
  u16 packet_len;
  u8 key_id;
  u8 auth_len;
  u32 seq;
  u32 zero0;
  u32 zero1;
};

struct rip_md5_tail /* 20 bytes */
{
  u16 must_be_FFFF;
  u16 must_be_0001;
  char md5[16];
};

struct rip_entry
{
  struct fib_node n;

  ip_addr from;
  ip_addr next_hop;
  int metric;
  u16 tag;

  bird_clock_t updated, changed; /* update - renewal, change - modification - need to be resent */
  int flags;
};

struct rip_packet
{
  struct rip_packet_heading heading;
  struct rip_block block[MAX_RTEs_IN_PACKET_WITHOUT_AUTH];
};

struct rip_iface
{
  node n;
  struct rip_proto *rip;
  struct iface *iface;
  sock *sock;
  struct rip_connection *busy;
  int metric; /* You don't want to put struct rip_patt *patt here -- think about reconfigure */
  int mode;
  int check_ttl; /* Check incoming packets for TTL 255 */
  int triggered;
  struct object_lock *lock;
  int multicast;
};

struct rip_iface_config
{
  struct iface_patt i;

  int metric; /* If you add entries here, don't forget to modify patt_compare! */
  int mode;
#define IM_BROADCAST 2
#define IM_QUIET 4
#define IM_NOLISTEN 8
#define IM_VERSION1 16
  int tx_tos;
  int tx_priority;
  int ttl_security; /* bool + 2 for TX only (send, but do not check on RX) */
};

struct rip_config
{
  struct proto_config c;
  list iface_list; /* Patterns configured -- keep it first; see rip_reconfigure why */
  list *passwords; /* Passwords, keep second */

  int infinity; /* User configurable data; must be comparable with memcmp */
  int port;
  int period;
  int garbage_time;
  int timeout_time;

  int auth_type;
#define AUTH_NONE 0
#define AUTH_PLAINTEXT 2
#define AUTH_MD5 3
  int honor;
#define HONOR_NEVER 0
#define HONOR_NEIGHBOR 1
#define HONOR_ALWAYS 2
};

struct rip_proto
{
  struct proto p;
  timer *timer;
  list connections;
  struct fib rtable;
  list interfaces; /* Interfaces we really know about */
  int tx_count; /* Do one regular update once in a while */
  int rnd_count; /* Randomize sending time */
};

void rip_init_instance(struct proto *p);
void rip_init_config(struct rip_config *cf);

/* Authentication functions */

int rip_incoming_authentication(struct rip_proto *p, struct rip_block_auth *block, struct rip_packet *packet, int num, ip_addr from);
int rip_outgoing_authentication(struct rip_proto *p, struct rip_block_auth *block, struct rip_packet *packet, int num);
