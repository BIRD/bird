/*
 *	BIRD Internet Routing Daemon -- Filters
 *
 *	(c) 1999 Pavel Machek <pavel@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_FILT_H_
#define _BIRD_FILT_H_

#include "lib/resource.h"
#include "lib/ip.h"
#include "nest/route.h"
#include "nest/attrs.h"

/* Filter instruction types */

#define FI__TWOCHAR(a,b)	((a<<8) | b)
#define FI__LIST \
  F(FI_ADD,			  0, '+') \
  F(FI_SUBTRACT,		  0, '-') \
  F(FI_MULTIPLY,		  0, '*') \
  F(FI_DIVIDE,			  0, '/') \
  F(FI_AND,			  0, '&') \
  F(FI_OR,			  0, '|') \
  F(FI_PAIR_CONSTRUCT,		'm', 'p') \
  F(FI_EC_CONSTRUCT,		'm', 'c') \
  F(FI_LC_CONSTRUCT,		'm', 'l') \
  F(FI_PATHMASK_CONSTRUCT,	'm', 'P') \
  F(FI_NEQ,			'!', '=') \
  F(FI_EQ,			'=', '=') \
  F(FI_LT,			  0, '<') \
  F(FI_LTE,			'<', '=') \
  F(FI_NOT,			  0, '!') \
  F(FI_MATCH,			  0, '~') \
  F(FI_NOT_MATCH,		'!', '~') \
  F(FI_DEFINED,			'd', 'e') \
  F(FI_TYPE,			  0, 'T') \
  F(FI_IS_V4,			'I', 'i') \
  F(FI_SET,			  0, 's') \
  F(FI_CONSTANT,		  0, 'c') \
  F(FI_VARIABLE,		  0, 'V') \
  F(FI_CONSTANT_INDIRECT,	  0, 'C') \
  F(FI_PRINT,			  0, 'p') \
  F(FI_CONDITION,		  0, '?') \
  F(FI_NOP,			  0, '0') \
  F(FI_PRINT_AND_DIE,		'p', ',') \
  F(FI_RTA_GET,			  0, 'a') \
  F(FI_RTA_SET,			'a', 'S') \
  F(FI_EA_GET,			'e', 'a') \
  F(FI_EA_SET,			'e', 'S') \
  F(FI_PREF_GET,		  0, 'P') \
  F(FI_PREF_SET,		'P', 'S') \
  F(FI_LENGTH,			  0, 'L') \
  F(FI_ROA_MAXLEN,		'R', 'M') \
  F(FI_ROA_ASN,			'R', 'A') \
  F(FI_SADR_SRC,		'n', 's') \
  F(FI_IP,			'c', 'p') \
  F(FI_ROUTE_DISTINGUISHER,	'R', 'D') \
  F(FI_AS_PATH_FIRST,		'a', 'f') \
  F(FI_AS_PATH_LAST,		'a', 'l') \
  F(FI_AS_PATH_LAST_NAG,	'a', 'L') \
  F(FI_RETURN,			  0, 'r') \
  F(FI_CALL,			'c', 'a') \
  F(FI_CLEAR_LOCAL_VARS,	'c', 'V') \
  F(FI_SWITCH,			'S', 'W') \
  F(FI_IP_MASK,			'i', 'M') \
  F(FI_EMPTY,			  0, 'E') \
  F(FI_PATH_PREPEND,		'A', 'p') \
  F(FI_CLIST_ADD_DEL,		'C', 'a') \
  F(FI_ROA_CHECK,		'R', 'C') \
  F(FI_FORMAT,			  0, 'F') \
  F(FI_ASSERT,			'a', 's')

enum f_instruction_code {
#define F(c,a,b) \
  c,
FI__LIST
#undef F
  FI__MAX,
} PACKED;

const char *f_instruction_name(enum f_instruction_code fi);

enum f_type {
/* Type numbers must be in 0..0xff range */
  T_MASK = 0xff,

/* Internal types */
/* Do not use type of zero, that way we'll see errors easier. */
  T_VOID = 1,

/* User visible types, which fit in int */
  T_INT = 0x10,
  T_BOOL = 0x11,
  T_PAIR = 0x12,  /*	Notice that pair is stored as integer: first << 16 | second */
  T_QUAD = 0x13,

/* Put enumerational types in 0x30..0x3f range */
  T_ENUM_LO = 0x30,
  T_ENUM_HI = 0x3f,

  T_ENUM_RTS = 0x30,
  T_ENUM_BGP_ORIGIN = 0x31,
  T_ENUM_SCOPE = 0x32,
  T_ENUM_RTC = 0x33,
  T_ENUM_RTD = 0x34,
  T_ENUM_ROA = 0x35,
  T_ENUM_NETTYPE = 0x36,
  T_ENUM_RA_PREFERENCE = 0x37,

/* new enums go here */
  T_ENUM_EMPTY = 0x3f,	/* Special hack for atomic_aggr */

#define T_ENUM T_ENUM_LO ... T_ENUM_HI

/* Bigger ones */
  T_IP = 0x20,
  T_NET = 0x21,
  T_STRING = 0x22,
  T_PATH_MASK = 0x23,	/* mask for BGP path */
  T_PATH = 0x24,		/* BGP path */
  T_CLIST = 0x25,		/* Community list */
  T_EC = 0x26,		/* Extended community value, u64 */
  T_ECLIST = 0x27,		/* Extended community list */
  T_LC = 0x28,		/* Large community value, lcomm */
  T_LCLIST = 0x29,		/* Large community list */
  T_RD = 0x2a,		/* Route distinguisher for VPN addresses */

  T_RETURN = 0x40,
  T_SET = 0x80,
  T_PREFIX_SET = 0x81,
};


struct f_inst {		/* Instruction */
  struct f_inst *next;	/* Structure is 16 bytes, anyway */
  enum f_instruction_code fi_code;
  u16 aux;		/* Extension to instruction code, T_*, EA_*, EAF_*  */
  union {
    uint i;
    void *p;
  } a1;			/* The first argument */
  union {
    uint i;
    void *p;
  } a2;			/* The second argument */
  union {
    int i;
    void *p;
  } a3;			/* The third argument */
  int lineno;
};

#define arg1 a1.p
#define arg2 a2.p

/* Not enough fields in f_inst for three args used by roa_check() */
struct f_inst_roa_check {
  struct f_inst i;
  struct rtable_config *rtc;
};

struct f_prefix {
  net_addr net;
  u8 lo, hi;
};

struct f_val {
  enum f_type type;		/* T_*  */
  union {
    u32 i;
    u64 ec;
    lcomm lc;
    ip_addr ip;
    const net_addr *net;
    char *s;
    struct f_tree *t;
    struct f_trie *ti;
    struct adata *ad;
    struct f_path_mask *path_mask;
  } val;
};

/* To allow direct copying between eattrs and f_val. */

union f_val_eattr {
  struct f_val f;
  struct eattr e;
};

struct f_dynamic_attr {
  int type;
  enum f_type f_type;
  int ea_code;
};

struct f_static_attr {
  enum f_type f_type;
  int sa_code;
  int readonly;
};

struct filter {
  char *name;
  struct f_inst *root;
};

struct f_inst *f_new_inst(enum f_instruction_code fi_code);
struct f_inst *f_new_inst_da(enum f_instruction_code fi_code, struct f_dynamic_attr da);
struct f_inst *f_new_inst_sa(enum f_instruction_code fi_code, struct f_static_attr sa);
static inline struct f_dynamic_attr f_new_dynamic_attr(int type, enum f_type f_type, int code) /* Type as core knows it, type as filters know it, and code of dynamic attribute */
{ return (struct f_dynamic_attr) { .type = type, .f_type = f_type, .ea_code = code }; }   /* f_type currently unused; will be handy for static type checking */
static inline struct f_static_attr f_new_static_attr(enum f_type f_type, int code, int readonly)
{ return (struct f_static_attr) { .f_type = f_type, .sa_code = code, .readonly = readonly }; }
struct f_tree *f_new_tree(void);
struct f_inst *f_generate_complex(int operation, int operation_aux, struct f_dynamic_attr da, struct f_inst *argument);
struct f_inst *f_generate_roa_check(struct rtable_config *table, struct f_inst *prefix, struct f_inst *asn);


struct f_tree *build_tree(struct f_tree *);
struct f_tree *find_tree(struct f_tree *t, struct f_val val);
int same_tree(struct f_tree *t1, struct f_tree *t2);
void tree_format(struct f_tree *t, buffer *buf);

struct f_trie *f_new_trie(linpool *lp, uint node_size);
void *trie_add_prefix(struct f_trie *t, const net_addr *n, uint l, uint h);
int trie_match_net(struct f_trie *t, const net_addr *n);
int trie_same(struct f_trie *t1, struct f_trie *t2);
void trie_format(struct f_trie *t, buffer *buf);

struct ea_list;
struct rte;

int f_run(struct filter *filter, struct rte **rte, struct linpool *tmp_pool, int flags);
struct f_val f_eval_rte(struct f_inst *expr, struct rte **rte, struct linpool *tmp_pool);
struct f_val f_eval(struct f_inst *expr, struct linpool *tmp_pool);
uint f_eval_int(struct f_inst *expr);

char *filter_name(struct filter *filter);
int filter_same(struct filter *new, struct filter *old);

int i_same(struct f_inst *f1, struct f_inst *f2);

int val_compare(struct f_val v1, struct f_val v2);
int val_same(struct f_val v1, struct f_val v2);

void val_format(struct f_val v, buffer *buf);


#define F_NOP 0
#define F_NONL 1
#define F_ACCEPT 2	/* Need to preserve ordering: accepts < rejects! */
#define F_REJECT 3
#define F_ERROR 4
#define F_QUITBIRD 5

#define FILTER_ACCEPT NULL
#define FILTER_REJECT ((void *) 1)
#define FILTER_UNDEF  ((void *) 2)	/* Used in BGP */


#define SA_FROM		 1
#define SA_GW		 2
#define SA_NET		 3
#define SA_PROTO	 4
#define SA_SOURCE	 5
#define SA_SCOPE	 6
#define SA_DEST    	 7
#define SA_IFNAME  	 8
#define SA_IFINDEX    	 9


struct f_tree {
  struct f_tree *left, *right;
  struct f_val from, to;
  void *data;
};

struct f_trie_node
{
  ip_addr addr, mask, accept;
  uint plen;
  struct f_trie_node *c[2];
};

struct f_trie
{
  linpool *lp;
  int zero;
  uint node_size;
  struct f_trie_node root[0];		/* Root trie node follows */
};

#define NEW_F_VAL struct f_val * val; val = cfg_alloc(sizeof(struct f_val));

#define FF_SILENT 2			/* Silent filter execution */

/* Bird Tests */
struct f_bt_test_suite {
  node n;			/* Node in config->tests */
  struct f_inst *fn;		/* Root of function */
  const char *fn_name;		/* Name of test */
  const char *dsc;		/* Description */
};

/* Hook for call bt_assert() function in configuration */
extern void (*bt_assert_hook)(int result, struct f_inst *assert);

#endif
