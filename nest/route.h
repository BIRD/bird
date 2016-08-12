/*
 *	BIRD Internet Routing Daemon -- Routing Table
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_ROUTE_H_
#define _BIRD_ROUTE_H_

#include "lib/lists.h"
#include "lib/resource.h"
#include "sysdep/unix/timer.h"
//#include "nest/protocol.h"

struct ea_list;
struct protocol;
struct proto;
struct rte_src;
struct symbol;
struct filter;
struct cli;

/*
 *	Generic data structure for storing network prefixes. Also used
 *	for the master routing table. Currently implemented as a hash
 *	table.
 *
 *	Available operations:
 *		- insertion of new entry
 *		- deletion of entry
 *		- searching for entry by network prefix
 *		- asynchronous retrieval of fib contents
 */

struct fib_node {
  struct fib_node *next;		/* Next in hash chain */
  struct fib_iterator *readers;		/* List of readers of this node */
  byte flags;				/* User-defined, will be removed */
  net_addr addr[0];
};

struct fib_iterator {			/* See lib/slists.h for an explanation */
  struct fib_iterator *prev, *next;	/* Must be synced with struct fib_node! */
  byte efef;				/* 0xff to distinguish between iterator and node */
  byte pad[3];
  struct fib_node *node;		/* Or NULL if freshly merged */
  uint hash;
};

typedef void (*fib_init_fn)(void *);

struct fib {
  pool *fib_pool;			/* Pool holding all our data */
  slab *fib_slab;			/* Slab holding all fib nodes */
  struct fib_node **hash_table;		/* Node hash table */
  uint hash_size;			/* Number of hash table entries (a power of two) */
  uint hash_order;			/* Binary logarithm of hash_size */
  uint hash_shift;			/* 32 - hash_order */
  uint addr_type;			/* Type of address data stored in fib (NET_*) */
  uint node_size;			/* FIB node size, 0 for nonuniform */
  uint node_offset;			/* Offset of fib_node struct inside of user data */
  uint entries;				/* Number of entries */
  uint entries_min, entries_max;	/* Entry count limits (else start rehashing) */
  fib_init_fn init;			/* Constructor */
};

static inline void * fib_node_to_user(struct fib *f, struct fib_node *e)
{ return e ? (void *) ((char *) e - f->node_offset) : NULL; }

static inline struct fib_node * fib_user_to_node(struct fib *f, void *e)
{ return e ? (void *) ((char *) e + f->node_offset) : NULL; }

void fib_init(struct fib *f, pool *p, uint addr_type, uint node_size, uint node_offset, uint hash_order, fib_init_fn init);
void *fib_find(struct fib *, const net_addr *);	/* Find or return NULL if doesn't exist */
void *fib_get_chain(struct fib *f, const net_addr *a); /* Find first node in linked list from hash table */
void *fib_get(struct fib *, const net_addr *); 	/* Find or create new if nonexistent */
void *fib_route(struct fib *, const net_addr *); /* Longest-match routing lookup */
void fib_delete(struct fib *, void *);	/* Remove fib entry */
void fib_free(struct fib *);		/* Destroy the fib */
void fib_check(struct fib *);		/* Consistency check for debugging */

void fit_init(struct fib_iterator *, struct fib *); /* Internal functions, don't call */
struct fib_node *fit_get(struct fib *, struct fib_iterator *);
void fit_put(struct fib_iterator *, struct fib_node *);
void fit_put_next(struct fib *f, struct fib_iterator *i, struct fib_node *n, uint hpos);


#define FIB_WALK(fib, type, z) do {				\
	struct fib_node *fn_, **ff_ = (fib)->hash_table;	\
	uint count_ = (fib)->hash_size;				\
	type *z;						\
	while (count_--)					\
	  for (fn_ = *ff_++; z = fib_node_to_user(fib, fn_); fn_=fn_->next)

#define FIB_WALK_END } while (0)

#define FIB_ITERATE_INIT(it, fib) fit_init(it, fib)

#define FIB_ITERATE_START(fib, it, type, z) do {		\
	struct fib_node *fn_ = fit_get(fib, it);		\
	uint count_ = (fib)->hash_size;				\
	uint hpos_ = (it)->hash;				\
	type *z;						\
	for(;;) {						\
	  if (!fn_)						\
            {							\
	       if (++hpos_ >= count_)				\
		 break;						\
	       fn_ = (fib)->hash_table[hpos_];			\
	       continue;					\
	    }							\
	  z = fib_node_to_user(fib, fn_);

#define FIB_ITERATE_END fn_ = fn_->next; } } while(0)

#define FIB_ITERATE_PUT(it) fit_put(it, fn_)

#define FIB_ITERATE_PUT_NEXT(it, fib) fit_put_next(fib, it, fn_, hpos_)

#define FIB_ITERATE_UNLINK(it, fib) fit_get(fib, it)


/*
 *	Master Routing Tables. Generally speaking, each of them contains a FIB
 *	with each entry pointing to a list of route entries representing routes
 *	to given network (with the selected one at the head).
 *
 *	Each of the RTE's contains variable data (the preference and protocol-dependent
 *	metrics) and a pointer to a route attribute block common for many routes).
 *
 *	It's guaranteed that there is at most one RTE for every (prefix,proto) pair.
 */

struct rtable_config {
  node n;
  char *name;
  struct rtable *table;
  struct proto_config *krt_attached;	/* Kernel syncer attached to this table */
  uint addr_type;			/* Type of address data stored in table (NET_*) */
  int gc_max_ops;			/* Maximum number of operations before GC is run */
  int gc_min_time;			/* Minimum time between two consecutive GC runs */
  byte sorted;				/* Routes of network are sorted according to rte_better() */
};

typedef struct rtable {
  node n;				/* Node in list of all tables */
  struct fib fib;
  char *name;				/* Name of this table */
  list channels;			/* List of attached channels (struct channel) */
  uint addr_type;			/* Type of address data stored in table (NET_*) */
  int pipe_busy;			/* Pipe loop detection */
  int use_count;			/* Number of protocols using this table */
  struct hostcache *hostcache;
  struct rtable_config *config;		/* Configuration of this table */
  struct config *deleted;		/* Table doesn't exist in current configuration,
					 * delete as soon as use_count becomes 0 and remove
					 * obstacle from this routing table.
					 */
  struct event *rt_event;		/* Routing table event */
  int gc_counter;			/* Number of operations since last GC */
  bird_clock_t gc_time;			/* Time of last GC */
  byte prune_state;			/* Table prune state, 1 -> scheduled, 2-> running */
  byte hcu_scheduled;			/* Hostcache update is scheduled */
  byte nhu_state;			/* Next Hop Update state */
  byte mpls_flags;			/* MPLS table attributes */
  struct fib_iterator prune_fit;	/* Rtable prune FIB iterator */
  struct fib_iterator nhu_fit;		/* Next Hop Update FIB iterator */
} rtable;

#define RT_MPLS_LABELED		0x1

typedef struct network {
  struct rte *routes;			/* Available routes for this network */
  struct fib_node n;			/* FIB flags reserved for kernel syncer */
} net;

struct hostcache {
  slab *slab;				/* Slab holding all hostentries */
  struct hostentry **hash_table;	/* Hash table for hostentries */
  unsigned hash_order, hash_shift;
  unsigned hash_max, hash_min;
  unsigned hash_items;
  linpool *lp;				/* Linpool for trie */
  struct f_trie *trie;			/* Trie of prefixes that might affect hostentries */
  list hostentries;			/* List of all hostentries */
  byte update_hostcache;
};

struct hostentry {
  node ln;
  ip_addr addr;				/* IP address of host, part of key */
  ip_addr link;				/* (link-local) IP address of host, used as gw
					   if host is directly attached */
  struct rtable *tab;			/* Dependent table, part of key */
  struct hostentry *next;		/* Next in hash chain */
  unsigned hash_key;			/* Hash key */
  unsigned uc;				/* Use count */
  struct rta *src;			/* Source rta entry */
  struct nexthop *nh;			/* Chosen next hop */
  byte dest;				/* Chosen route destination type (RTD_...) */
  u32 igp_metric;			/* Chosen route IGP metric */
};

typedef struct rte {
  struct rte *next;
  net *net;				/* Network this RTE belongs to */
  struct channel *sender;		/* Channel used to send the route to the routing table */
  struct rta *attrs;			/* Attributes of this route */
  byte flags;				/* Flags (REF_...) */
  byte pflags;				/* Protocol-specific flags */
  word pref;				/* Route preference */
  bird_clock_t lastmod;			/* Last modified */
  union {				/* Protocol-dependent data (metrics etc.) */
#ifdef CONFIG_RIP
    struct {
      struct iface *from;		/* Incoming iface */
      u8 metric;			/* RIP metric */
      u16 tag;				/* External route tag */
    } rip;
#endif
#ifdef CONFIG_OSPF
    struct {
      u32 metric1, metric2;		/* OSPF Type 1 and Type 2 metrics */
      u32 tag;				/* External route tag */
      u32 router_id;			/* Router that originated this route */
    } ospf;
#endif
#ifdef CONFIG_BGP
    struct {
      u8 suppressed;			/* Used for deterministic MED comparison */
    } bgp;
#endif
#ifdef CONFIG_BABEL
    struct {
      u16 metric;			/* Babel metric */
      u64 router_id;			/* Babel router id */
    } babel;
#endif
    struct {				/* Routes generated by krt sync (both temporary and inherited ones) */
      s8 src;				/* Alleged route source (see krt.h) */
      u8 proto;				/* Kernel source protocol ID */
      u8 seen;				/* Seen during last scan */
      u8 best;				/* Best route in network, propagated to core */
      u32 metric;			/* Kernel metric */
    } krt;
  } u;
} rte;

#define REF_COW		1		/* Copy this rte on write */
#define REF_FILTERED	2		/* Route is rejected by import filter */
#define REF_STALE	4		/* Route is stale in a refresh cycle */
#define REF_DISCARD	8		/* Route is scheduled for discard */

/* Route is valid for propagation (may depend on other flags in the future), accepts NULL */
static inline int rte_is_valid(rte *r) { return r && !(r->flags & REF_FILTERED); }

/* Route just has REF_FILTERED flag */
static inline int rte_is_filtered(rte *r) { return !!(r->flags & REF_FILTERED); }


/* Types of route announcement, also used as flags */
#define RA_OPTIMAL	1		/* Announcement of optimal route change */
#define RA_ACCEPTED	2		/* Announcement of first accepted route */
#define RA_ANY		3		/* Announcement of any route change */
#define RA_MERGED	4		/* Announcement of optimal route merged with next ones */

/* Return value of import_control() callback */
#define RIC_ACCEPT	1		/* Accepted by protocol */
#define RIC_PROCESS	0		/* Process it through import filter */
#define RIC_REJECT	-1		/* Rejected by protocol */
#define RIC_DROP	-2		/* Silently dropped by protocol */

struct config;

void rt_init(void);
void rt_preconfig(struct config *);
void rt_commit(struct config *new, struct config *old);
void rt_lock_table(rtable *);
void rt_unlock_table(rtable *);
void rt_setup(pool *, rtable *, char *, struct rtable_config *);
static inline net *net_find(rtable *tab, const net_addr *addr) { return (net *) fib_find(&tab->fib, addr); }
static inline net *net_get(rtable *tab, const net_addr *addr) { return (net *) fib_get(&tab->fib, addr); }
void *net_route(rtable *tab, const net_addr *n);
int net_roa_check(rtable *tab, const net_addr *n, u32 asn);
rte *rte_find(net *net, struct rte_src *src);
rte *rte_get_temp(struct rta *);
void rte_update2(struct channel *c, net_addr *n, rte *new, struct rte_src *src);
/* rte_update() moved to protocol.h to avoid dependency conflicts */
void rte_discard(rtable *tab, rte *old);
int rt_examine(rtable *t, net_addr *a, struct proto *p, struct filter *filter);
rte *rt_export_merged(struct channel *c, net *net, rte **rt_free, struct ea_list **tmpa, int silent);
void rt_refresh_begin(rtable *t, struct channel *c);
void rt_refresh_end(rtable *t, struct channel *c);
void rt_schedule_prune(rtable *t);
void rte_dump(rte *);
void rte_free(rte *);
rte *rte_do_cow(rte *);
static inline rte * rte_cow(rte *r) { return (r->flags & REF_COW) ? rte_do_cow(r) : r; }
rte *rte_cow_rta(rte *r, linpool *lp);
void rt_dump(rtable *);
void rt_dump_all(void);
int rt_feed_channel(struct channel *c);
void rt_feed_channel_abort(struct channel *c);
struct rtable_config *rt_new_table(struct symbol *s, uint addr_type);


struct rt_show_data {
  net_addr *addr;
  rtable *table;
  struct filter *filter;
  int verbose;
  struct fib_iterator fit;
  struct proto *show_protocol;
  struct proto *export_protocol;
  struct channel *export_channel;
  int export_mode, primary_only, filtered;
  struct config *running_on_config;
  int net_counter, rt_counter, show_counter;
  int stats, show_for;
};
void rt_show(struct rt_show_data *);

/* Value of export_mode in struct rt_show_data */
#define RSEM_NONE	0		/* Export mode not used */
#define RSEM_PREEXPORT	1		/* Routes ready for export, before filtering */
#define RSEM_EXPORT	2		/* Routes accepted by export filter */
#define RSEM_NOEXPORT	3		/* Routes rejected by export filter */

/*
 *	Route Attributes
 *
 *	Beware: All standard BGP attributes must be represented here instead
 *	of making them local to the route. This is needed to ensure proper
 *	construction of BGP route attribute lists.
 */

/* Nexthop structure */
struct nexthop {
  ip_addr gw;				/* Next hop */
  struct iface *iface;			/* Outgoing interface */
  struct nexthop *next;
  byte weight;
  byte labels_append;			/* Number of labels before hostentry was applied */
  byte labels;				/* Number of labels prepended */
  u32 label[0];
};

struct rte_src {
  struct rte_src *next;			/* Hash chain */
  struct proto *proto;			/* Protocol the source is based on */
  u32 private_id;			/* Private ID, assigned by the protocol */
  u32 global_id;			/* Globally unique ID of the source */
  unsigned uc;				/* Use count */
};


typedef struct rta {
  struct rta *next, **pprev;		/* Hash chain */
  u32 uc;				/* Use count */
  u32 hash_key;				/* Hash over important fields */
  struct ea_list *eattrs;		/* Extended Attribute chain */
  struct rte_src *src;			/* Route source that created the route */
  struct hostentry *hostentry;		/* Hostentry for recursive next-hops */
  ip_addr from;				/* Advertising router */
  u32 igp_metric;			/* IGP metric to next hop (for iBGP routes) */
  u8 source;				/* Route source (RTS_...) */
  u8 scope;				/* Route scope (SCOPE_... -- see ip.h) */
  u8 dest;				/* Route destination type (RTD_...) */
  u8 aflags;
  struct nexthop nh;			/* Next hop */
} rta;

#define RTS_DUMMY 0			/* Dummy route to be removed soon */
#define RTS_STATIC 1			/* Normal static route */
#define RTS_INHERIT 2			/* Route inherited from kernel */
#define RTS_DEVICE 3			/* Device route */
#define RTS_STATIC_DEVICE 4		/* Static device route */
#define RTS_REDIRECT 5			/* Learned via redirect */
#define RTS_RIP 6			/* RIP route */
#define RTS_OSPF 7			/* OSPF route */
#define RTS_OSPF_IA 8			/* OSPF inter-area route */
#define RTS_OSPF_EXT1 9			/* OSPF external route type 1 */
#define RTS_OSPF_EXT2 10		/* OSPF external route type 2 */
#define RTS_BGP 11			/* BGP route */
#define RTS_PIPE 12			/* Inter-table wormhole */
#define RTS_BABEL 13			/* Babel route */

#define RTC_UNICAST 0
#define RTC_BROADCAST 1
#define RTC_MULTICAST 2
#define RTC_ANYCAST 3			/* IPv6 Anycast */

#define RTD_UNICAST 0			/* Next hop is neighbor router */
#define RTD_BLACKHOLE 2			/* Silently drop packets */
#define RTD_UNREACHABLE 3		/* Reject as unreachable */
#define RTD_PROHIBIT 4			/* Administratively prohibited */
#define RTD_NONE 6			/* Invalid RTD */

					/* Flags for net->n.flags, used by kernel syncer */
#define KRF_INSTALLED 0x80		/* This route should be installed in the kernel */
#define KRF_SYNC_ERROR 0x40		/* Error during kernel table synchronization */

#define RTAF_CACHED 1			/* This is a cached rta */

#define IGP_METRIC_UNKNOWN 0x80000000	/* Default igp_metric used when no other
					   protocol-specific metric is availabe */


/* Route has regular, reachable nexthop (i.e. not RTD_UNREACHABLE and like) */
static inline int rte_is_reachable(rte *r)
{ uint d = r->attrs->dest; return (d == RTD_UNICAST); }


/*
 *	Extended Route Attributes
 */

typedef struct eattr {
  word id;				/* EA_CODE(EAP_..., protocol-dependent ID) */
  byte flags;				/* Protocol-dependent flags */
  byte type;				/* Attribute type and several flags (EAF_...) */
  union {
    u32 data;
    struct adata *ptr;			/* Attribute data elsewhere */
  } u;
} eattr;

#define EAP_GENERIC 0			/* Generic attributes */
#define EAP_BGP 1			/* BGP attributes */
#define EAP_RIP 2			/* RIP */
#define EAP_OSPF 3			/* OSPF */
#define EAP_KRT 4			/* Kernel route attributes */
#define EAP_BABEL 5			/* Babel attributes */
#define EAP_MAX 6

#define EA_CODE(proto,id) (((proto) << 8) | (id))
#define EA_PROTO(ea) ((ea) >> 8)
#define EA_ID(ea) ((ea) & 0xff)

#define EA_GEN_IGP_METRIC EA_CODE(EAP_GENERIC, 0)

#define EA_CODE_MASK 0xffff
#define EA_ALLOW_UNDEF 0x10000		/* ea_find: allow EAF_TYPE_UNDEF */
#define EA_BIT(n) ((n) << 24)		/* Used in bitfield accessors */

#define EAF_TYPE_MASK 0x0f		/* Mask with this to get type */
#define EAF_TYPE_INT 0x01		/* 32-bit unsigned integer number */
#define EAF_TYPE_OPAQUE 0x02		/* Opaque byte string (not filterable) */
#define EAF_TYPE_IP_ADDRESS 0x04	/* IP address */
#define EAF_TYPE_ROUTER_ID 0x05		/* Router ID (IPv4 address) */
#define EAF_TYPE_AS_PATH 0x06		/* BGP AS path (encoding per RFC 1771:4.3) */
#define EAF_TYPE_BITFIELD 0x09		/* 32-bit embedded bitfield */
#define EAF_TYPE_INT_SET 0x0a		/* Set of u32's (e.g., a community list) */
#define EAF_TYPE_EC_SET 0x0e		/* Set of pairs of u32's - ext. community list */
#define EAF_TYPE_UNDEF 0x0f		/* `force undefined' entry */
#define EAF_EMBEDDED 0x01		/* Data stored in eattr.u.data (part of type spec) */
#define EAF_VAR_LENGTH 0x02		/* Attribute length is variable (part of type spec) */
#define EAF_ORIGINATED 0x40		/* The attribute has originated locally */
#define EAF_TEMP 0x80			/* A temporary attribute (the one stored in the tmp attr list) */

struct adata {
  uint length;				/* Length of data */
  byte data[0];
};

static inline int adata_same(struct adata *a, struct adata *b)
{ return (a->length == b->length && !memcmp(a->data, b->data, a->length)); }


typedef struct ea_list {
  struct ea_list *next;			/* In case we have an override list */
  byte flags;				/* Flags: EALF_... */
  byte rfu;
  word count;				/* Number of attributes */
  eattr attrs[0];			/* Attribute definitions themselves */
} ea_list;

#define EALF_SORTED 1			/* Attributes are sorted by code */
#define EALF_BISECT 2			/* Use interval bisection for searching */
#define EALF_CACHED 4			/* Attributes belonging to cached rta */

struct rte_src *rt_find_source(struct proto *p, u32 id);
struct rte_src *rt_get_source(struct proto *p, u32 id);
static inline void rt_lock_source(struct rte_src *src) { src->uc++; }
static inline void rt_unlock_source(struct rte_src *src) { src->uc--; }
void rt_prune_sources(void);

struct ea_walk_state {
  ea_list *eattrs;			/* Ccurrent ea_list, initially set by caller */
  eattr *ea;				/* Current eattr, initially NULL */
  u32 visited[4];			/* Bitfield, limiting max to 128 */
};

eattr *ea_find(ea_list *, unsigned ea);
eattr *ea_walk(struct ea_walk_state *s, uint id, uint max);
int ea_get_int(ea_list *, unsigned ea, int def);
void ea_dump(ea_list *);
void ea_sort(ea_list *);		/* Sort entries in all sub-lists */
unsigned ea_scan(ea_list *);		/* How many bytes do we need for merged ea_list */
void ea_merge(ea_list *from, ea_list *to); /* Merge sub-lists to allocated buffer */
int ea_same(ea_list *x, ea_list *y);	/* Test whether two ea_lists are identical */
uint ea_hash(ea_list *e);	/* Calculate 16-bit hash value */
ea_list *ea_append(ea_list *to, ea_list *what);
void ea_format_bitfield(struct eattr *a, byte *buf, int bufsize, const char **names, int min, int max);

#define NEXTHOP_MAX_SIZE (sizeof(struct nexthop) + sizeof(u32)*MPLS_MAX_LABEL_STACK)

static inline size_t nexthop_size(const struct nexthop *nh)
{ return sizeof(struct nexthop) + sizeof(u32)*nh->labels; }
int nexthop__same(struct nexthop *x, struct nexthop *y); /* Compare multipath nexthops */
static inline int nexthop_same(struct nexthop *x, struct nexthop *y)
{ return (x == y) || nexthop__same(x, y); }
struct nexthop *nexthop_merge(struct nexthop *x, struct nexthop *y, int rx, int ry, int max, linpool *lp);
static inline void nexthop_link(struct rta *a, struct nexthop *from)
{ memcpy(&a->nh, from, nexthop_size(from)); }

void rta_init(void);
static inline size_t rta_size(const rta *a) { return sizeof(rta) + sizeof(u32)*a->nh.labels; }
#define RTA_MAX_SIZE (sizeof(rta) + sizeof(u32)*MPLS_MAX_LABEL_STACK)
rta *rta_lookup(rta *);			/* Get rta equivalent to this one, uc++ */
static inline int rta_is_cached(rta *r) { return r->aflags & RTAF_CACHED; }
static inline rta *rta_clone(rta *r) { r->uc++; return r; }
void rta__free(rta *r);
static inline void rta_free(rta *r) { if (r && !--r->uc) rta__free(r); }
rta *rta_do_cow(rta *o, linpool *lp);
static inline rta * rta_cow(rta *r, linpool *lp) { return rta_is_cached(r) ? rta_do_cow(r, lp) : r; }
void rta_dump(rta *);
void rta_dump_all(void);
void rta_show(struct cli *, rta *, ea_list *);
void rta_set_recursive_next_hop(rtable *dep, rta *a, rtable *tab, ip_addr *gw, ip_addr *ll);

/*
 * rta_set_recursive_next_hop() acquires hostentry from hostcache and fills
 * rta->hostentry field.  New hostentry has zero use count. Cached rta locks its
 * hostentry (increases its use count), uncached rta does not lock it. Hostentry
 * with zero use count is removed asynchronously during host cache update,
 * therefore it is safe to hold such hostentry temorarily. Hostentry holds a
 * lock for a 'source' rta, mainly to share multipath nexthops.
 *
 * There is no need to hold a lock for hostentry->dep table, because that table
 * contains routes responsible for that hostentry, and therefore is non-empty if
 * given hostentry has non-zero use count. If the hostentry has zero use count,
 * the entry is removed before dep is referenced.
 *
 * The protocol responsible for routes with recursive next hops should hold a
 * lock for a 'source' table governing that routes (argument tab to
 * rta_set_recursive_next_hop()), because its routes reference hostentries
 * (through rta) related to the governing table. When all such routes are
 * removed, rtas are immediately removed achieving zero uc. Then the 'source'
 * table lock could be immediately released, although hostentries may still
 * exist - they will be freed together with the 'source' table.
 */

static inline void rt_lock_hostentry(struct hostentry *he) { if (he) he->uc++; }
static inline void rt_unlock_hostentry(struct hostentry *he) { if (he) he->uc--; }


extern struct protocol *attr_class_to_protocol[EAP_MAX];

/*
 *	Default protocol preferences
 */

#define DEF_PREF_DIRECT	    	240	/* Directly connected */
#define DEF_PREF_STATIC		200	/* Static route */
#define DEF_PREF_MPLS		170	/* MPLS routes generated by MPLS protocol */
#define DEF_PREF_OSPF		150	/* OSPF intra-area, inter-area and type 1 external routes */
#define DEF_PREF_BABEL		130	/* Babel */
#define DEF_PREF_RIP		120	/* RIP */
#define DEF_PREF_BGP		100	/* BGP */
#define DEF_PREF_INHERITED	10	/* Routes inherited from other routing daemons */

/*
 *	Route Origin Authorization
 */

#define ROA_UNKNOWN	0
#define ROA_VALID	1
#define ROA_INVALID	2

#endif
