/*
 *	BIRD Internet Routing Daemon -- Network addresses
 *
 *	(c) 2015 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_NET_H_
#define _BIRD_NET_H_

#include "lib/ip.h"
#include "lib/hash.h"


#define NET_IP4		1
#define NET_IP6		2
#define NET_VPN4	3
#define NET_VPN6	4
#define NET_ROA4	5
#define NET_ROA6	6
#define NET_FLOW4	7
#define NET_FLOW6	8
#define NET_MPLS	9
#define NET_IP4_MPLS	10
#define NET_IP6_MPLS	11
#define NET_VPN4_MPLS	12
#define NET_VPN6_MPLS	13
#define NET_MAX		14

#define NB_IP4		(1 << NET_IP4)
#define NB_IP6		(1 << NET_IP6)
#define NB_VPN4		(1 << NET_VPN4)
#define NB_VPN6		(1 << NET_VPN6)
#define NB_ROA4		(1 << NET_ROA4)
#define NB_ROA6		(1 << NET_ROA6)
#define NB_FLOW4	(1 << NET_FLOW4)
#define NB_FLOW6	(1 << NET_FLOW6)
#define NB_MPLS		(1 << NET_MPLS)

#define NB_IP		(NB_IP4 | NB_IP6)
#define NB_VPN		(NB_VPN4 | NB_VPN6)
#define NB_ANY		0xffffffff

#define NET_DO_ALL \
  NET_DO_FIXLEN \
  NET_DO_VARLEN

#define NET_DO_FIXLEN \
  NET_DO(ip4,IP4) \
  NET_DO(ip6,IP6) \
  NET_DO(vpn4,VPN4) \
  NET_DO(vpn6,VPN6) \
  NET_DO(roa4,ROA4) \
  NET_DO(roa6,ROA6) \
  NET_DO(mpls,MPLS)

#define NET_DO_VARLEN \
  NET_DO(flow4,FLOW4) \
  NET_DO(flow6,FLOW6) \
  NET_DO(ip4_mpls,IP4_MPLS) \
  NET_DO(ip6_mpls,IP6_MPLS) \
  NET_DO(vpn4_mpls,VPN4_MPLS) \
  NET_DO(vpn6_mpls,VPN6_MPLS) \

#define NET_CASE_ALL(v) \
  case NET_IP##v: \
  case NET_VPN##v: \
  case NET_ROA##v: \
  case NET_FLOW##v: \
  case NET_IP##v##_MPLS: \
  case NET_VPN##v##_MPLS

#define NET_ADDR_COMMON \
  u8 type; \
  u8 pxlen; \
  u16 length

typedef struct net_addr_ip4 {
  NET_ADDR_COMMON;
  ip4_addr prefix;
} net_addr_ip4;

typedef struct net_addr_ip6 {
  NET_ADDR_COMMON;
  ip6_addr prefix;
} net_addr_ip6;

typedef struct net_addr_vpn4 {
  NET_ADDR_COMMON;
  ip4_addr prefix;
  u64 rd;
} net_addr_vpn4;

typedef struct net_addr_vpn6 {
  NET_ADDR_COMMON;
  ip6_addr prefix;
  u64 rd;
} net_addr_vpn6;

typedef struct net_addr_roa4 {
  NET_ADDR_COMMON;
  ip4_addr prefix;
  u32 max_pxlen;
  u32 asn;
} net_addr_roa4;

typedef struct net_addr_roa6 {
  NET_ADDR_COMMON;
  ip6_addr prefix;
  u32 max_pxlen;
  u32 asn;
} net_addr_roa6;

typedef struct net_addr_flow4 {
  NET_ADDR_COMMON;
  ip4_addr prefix;
  byte data[0];
} net_addr_flow4;

typedef struct net_addr_flow6 {
  NET_ADDR_COMMON;
  ip6_addr prefix;
  byte data[0];
} net_addr_flow6;

typedef struct net_addr_mpls {
  NET_ADDR_COMMON;
  u32 label;
} net_addr_mpls;

#define NET_DO(f) \
typedef struct net_addr_##f##_mpls { \
  NET_ADDR_COMMON; \
  net_addr_##f addr; \
  u32 label[0]; \
} net_addr_##f##_mpls

NET_DO(ip4);
NET_DO(ip6);
NET_DO(vpn4);
NET_DO(vpn6);

#undef NET_DO

#define NET_ADDR_MPLS_LABEL_STACK_LEN(n) (((n)->length - sizeof((n)->addr))/sizeof(u32))


typedef union net_addr {
  struct {
    NET_ADDR_COMMON;
  };

#define NET_DO(mi,mj) net_addr_##mi mi;
  NET_DO_ALL
#undef NET_DO
} net_addr;


extern const char * const net_label[];
extern const u16 net_addr_length[];
extern const u8  net_max_prefix_length[];
extern const u16 net_max_text_length[];

#define NET_MAX_TEXT_LENGTH	256


#define NET_ADDR_IP4(prefix,pxlen) \
  ((net_addr_ip4) { NET_IP4, pxlen, sizeof(net_addr_ip4), prefix })

#define NET_ADDR_IP6(prefix,pxlen) \
  ((net_addr_ip6) { NET_IP6, pxlen, sizeof(net_addr_ip6), prefix })

#define NET_ADDR_VPN4(prefix,pxlen,rd) \
  ((net_addr_vpn4) { NET_VPN4, pxlen, sizeof(net_addr_vpn4), prefix, rd })

#define NET_ADDR_VPN6(prefix,pxlen,rd) \
  ((net_addr_vpn6) { NET_VPN6, pxlen, sizeof(net_addr_vpn6), prefix, rd })

#define NET_ADDR_ROA4(prefix,pxlen,max_pxlen,asn) \
  ((net_addr_roa4) { NET_ROA4, pxlen, sizeof(net_addr_roa4), prefix, max_pxlen, asn })

#define NET_ADDR_ROA6(prefix,pxlen,max_pxlen,asn) \
  ((net_addr_roa6) { NET_ROA6, pxlen, sizeof(net_addr_roa6), prefix, max_pxlen, asn })

#define NET_ADDR_FLOW4(prefix,pxlen,dlen) \
  ((net_addr_flow4) { NET_FLOW4, pxlen, sizeof(net_addr_ip4) + dlen, prefix })

#define NET_ADDR_FLOW6(prefix,pxlen,dlen) \
  ((net_addr_flow6) { NET_FLOW6, pxlen, sizeof(net_addr_ip6) + dlen, prefix })

#define NET_ADDR_MPLS(label) \
  ((net_addr_mpls) { NET_MPLS, 20, sizeof(net_addr_mpls), label })


static inline void net_fill_ip4(net_addr *a, ip4_addr prefix, uint pxlen)
{ *(net_addr_ip4 *)a = NET_ADDR_IP4(prefix, pxlen); }

static inline void net_fill_ip6(net_addr *a, ip6_addr prefix, uint pxlen)
{ *(net_addr_ip6 *)a = NET_ADDR_IP6(prefix, pxlen); }

static inline void net_fill_vpn4(net_addr *a, ip4_addr prefix, uint pxlen, u64 rd)
{ *(net_addr_vpn4 *)a = NET_ADDR_VPN4(prefix, pxlen, rd); }

static inline void net_fill_vpn6(net_addr *a, ip6_addr prefix, uint pxlen, u64 rd)
{ *(net_addr_vpn6 *)a = NET_ADDR_VPN6(prefix, pxlen, rd); }

static inline void net_fill_roa4(net_addr *a, ip4_addr prefix, uint pxlen, uint max_pxlen, u32 asn)
{ *(net_addr_roa4 *)a = NET_ADDR_ROA4(prefix, pxlen, max_pxlen, asn); }

static inline void net_fill_roa6(net_addr *a, ip6_addr prefix, uint pxlen, uint max_pxlen, u32 asn)
{ *(net_addr_roa6 *)a = NET_ADDR_ROA6(prefix, pxlen, max_pxlen, asn); }

static inline void net_fill_mpls(net_addr *a, u32 label)
{ *(net_addr_mpls *)a = NET_ADDR_MPLS(label); }

static inline void net_fill_ipa(net_addr *a, ip_addr prefix, uint pxlen)
{
  if (ipa_is_ip4(prefix))
    net_fill_ip4(a, ipa_to_ip4(prefix), pxlen);
  else
    net_fill_ip6(a, ipa_to_ip6(prefix), pxlen);
}

static inline void net_fill_ip_host(net_addr *a, ip_addr prefix)
{
  if (ipa_is_ip4(prefix))
    net_fill_ip4(a, ipa_to_ip4(prefix), IP4_MAX_PREFIX_LENGTH);
  else
    net_fill_ip6(a, ipa_to_ip6(prefix), IP6_MAX_PREFIX_LENGTH);
}

static inline void net_fill_flow4(net_addr *a, ip4_addr prefix, uint pxlen, byte *data, uint dlen)
{
  net_addr_flow4 *f = (void *) a;
  *f = NET_ADDR_FLOW4(prefix, pxlen, dlen);
  memcpy(f->data, data, dlen);
}

static inline void net_fill_flow6(net_addr *a, ip6_addr prefix, uint pxlen, byte *data, uint dlen)
{
  net_addr_flow6 *f = (void *) a;
  *f = NET_ADDR_FLOW6(prefix, pxlen, dlen);
  memcpy(f->data, data, dlen);
}

static inline void net_add_mpls_label_stack(net_addr *a, uint len, u32 *label)
{
  switch (a->type) {
#define NET_DO(mi,mj) \
    case NET_##mj: \
      a->type = NET_##mj##_MPLS; \
      a->length = sizeof(net_addr_##mi##_mpls) + len * 4; \
      for (uint i=0; i<len; i++) \
	a->mi##_mpls.label[i] = label[i]; \
      break;
    NET_DO(ip4,IP4)
    NET_DO(ip6,IP6)
    NET_DO(vpn4,VPN4)
    NET_DO(vpn6,VPN6)
#undef NET_DO
    default:
      bug("Adding mpls stack to net_addr_%s not implemented.", net_label[a->type]);
  }
}

static inline int net_val_match(u8 type, u32 mask)
{ return !!((1 << type) & mask); }

static inline int net_type_match(const net_addr *a, u32 mask)
{ return net_val_match(a->type, mask); }

static inline int net_is_ip(const net_addr *a)
{ return (a->type == NET_IP4) || (a->type == NET_IP6); }

static inline int net_is_roa(const net_addr *a)
{ return (a->type == NET_ROA4) || (a->type == NET_ROA6); }


static inline ip4_addr net4_prefix(const net_addr *a)
{ return ((net_addr_ip4 *) a)->prefix; }

static inline ip6_addr net6_prefix(const net_addr *a)
{ return ((net_addr_ip6 *) a)->prefix; }

static inline ip_addr net_prefix(const net_addr *a)
{
  switch (a->type)
  {
NET_CASE_ALL(4):
    return ipa_from_ip4(net4_prefix(a));

NET_CASE_ALL(6):
    return ipa_from_ip6(net6_prefix(a));

  case NET_MPLS:
  default:
    return IPA_NONE;
  }
}

static inline u32 net_mpls(const net_addr *a)
{
  if (a->type == NET_MPLS)
    return ((net_addr_mpls *) a)->label;

  bug("Can't call net_mpls on non-mpls net_addr");
}

static inline uint net4_pxlen(const net_addr *a)
{ return a->pxlen; }

static inline uint net6_pxlen(const net_addr *a)
{ return a->pxlen; }

static inline uint net_pxlen(const net_addr *a)
{ return a->pxlen; }

ip_addr net_pxmask(const net_addr *a);

#define NET_DO(mi,mj) \
  static inline int net_equal_##mi(const net_addr_##mi *a, const net_addr_##mi *b) \
  { return !memcmp(a, b, sizeof(net_addr_##mi)); }
NET_DO_FIXLEN
#undef NET_DO

#define NET_DO(mi,mj) \
static inline int net_equal_##mi(const net_addr_##mi *a, const net_addr_##mi *b) \
{ return (a->length == b->length) && !memcmp(a, b, a->length); }
NET_DO_VARLEN
#undef NET_DO

static inline int net_equal(const net_addr *a, const net_addr *b)
{
  if (a->type != b->type)
    return 0;

  switch (a->type)
  {
#define NET_DO(mi,mj) \
    case NET_##mj: \
      return net_equal_##mi((const net_addr_##mi *) a, (const net_addr_##mi *) b);
      NET_DO_ALL
#undef NET_DO
  }
  return 0;
}


static inline int net_equal_prefix_roa4(const net_addr_roa4 *a, const net_addr_roa4 *b)
{ return ip4_equal(a->prefix, b->prefix) && (a->pxlen == b->pxlen); }

static inline int net_equal_prefix_roa6(const net_addr_roa6 *a, const net_addr_roa6 *b)
{ return ip6_equal(a->prefix, b->prefix) && (a->pxlen == b->pxlen); }

static inline int net_zero_ip4(const net_addr_ip4 *a)
{ return !a->pxlen && ip4_zero(a->prefix); }

static inline int net_zero_ip6(const net_addr_ip6 *a)
{ return !a->pxlen && ip6_zero(a->prefix); }

static inline int net_zero_vpn4(const net_addr_vpn4 *a)
{ return !a->pxlen && ip4_zero(a->prefix) && !a->rd; }

static inline int net_zero_vpn6(const net_addr_vpn6 *a)
{ return !a->pxlen && ip6_zero(a->prefix) && !a->rd; }

static inline int net_zero_roa4(const net_addr_roa4 *a)
{ return !a->pxlen && ip4_zero(a->prefix) && !a->max_pxlen && !a->asn; }

static inline int net_zero_roa6(const net_addr_roa6 *a)
{ return !a->pxlen && ip6_zero(a->prefix) && !a->max_pxlen && !a->asn; }

static inline int net_zero_flow4(const net_addr_flow4 *a)
{ return !a->pxlen && ip4_zero(a->prefix) && !a->data; }

static inline int net_zero_flow6(const net_addr_flow6 *a)
{ return !a->pxlen && ip6_zero(a->prefix) && !a->data; }

static inline int net_zero_mpls(const net_addr_mpls *a)
{ return !a->label; }


static inline int net_compare_ip4(const net_addr_ip4 *a, const net_addr_ip4 *b)
{ return ip4_compare(a->prefix, b->prefix) ?: uint_cmp(a->pxlen, b->pxlen); }

static inline int net_compare_ip6(const net_addr_ip6 *a, const net_addr_ip6 *b)
{ return ip6_compare(a->prefix, b->prefix) ?: uint_cmp(a->pxlen, b->pxlen); }

static inline int net_compare_vpn4(const net_addr_vpn4 *a, const net_addr_vpn4 *b)
{ return u64_cmp(a->rd, b->rd) ?: ip4_compare(a->prefix, b->prefix) ?: uint_cmp(a->pxlen, b->pxlen); }

static inline int net_compare_vpn6(const net_addr_vpn6 *a, const net_addr_vpn6 *b)
{ return u64_cmp(a->rd, b->rd) ?: ip6_compare(a->prefix, b->prefix) ?: uint_cmp(a->pxlen, b->pxlen); }

static inline int net_compare_roa4(const net_addr_roa4 *a, const net_addr_roa4 *b)
{ return ip4_compare(a->prefix, b->prefix) ?: uint_cmp(a->pxlen, b->pxlen) ?: uint_cmp(a->max_pxlen, b->max_pxlen) ?: uint_cmp(a->asn, b->asn); }

static inline int net_compare_roa6(const net_addr_roa6 *a, const net_addr_roa6 *b)
{ return ip6_compare(a->prefix, b->prefix) ?: uint_cmp(a->pxlen, b->pxlen) ?: uint_cmp(a->max_pxlen, b->max_pxlen) ?: uint_cmp(a->asn, b->asn); }

static inline int net_compare_flow4(const net_addr_flow4 *a, const net_addr_flow4 *b)
{ return ip4_compare(a->prefix, b->prefix) ?: uint_cmp(a->pxlen, b->pxlen) ?: uint_cmp(a->length, b->length) ?: memcmp(a->data, b->data, a->length - sizeof(net_addr_flow4)); }

static inline int net_compare_flow6(const net_addr_flow6 *a, const net_addr_flow6 *b)
{ return ip6_compare(a->prefix, b->prefix) ?: uint_cmp(a->pxlen, b->pxlen) ?: uint_cmp(a->length, b->length) ?: memcmp(a->data, b->data, a->length - sizeof(net_addr_flow6)); }

static inline int net_compare_mpls(const net_addr_mpls *a, const net_addr_mpls *b)
{ return uint_cmp(a->label, b->label); }

#define NET_DO(f) \
  static inline int net_compare_##f##_mpls(const net_addr_##f##_mpls *a, const net_addr_##f##_mpls *b) \
{ return net_compare_##f(&(a->addr), &(b->addr)) ?: uint_cmp(a->length, b->length) ?: memcmp(a->label, b->label, a->length - sizeof(net_addr_##f##_mpls)); }
NET_DO(ip4)
NET_DO(ip6)
NET_DO(vpn4)
NET_DO(vpn6)
#undef NET_DO

int net_compare(const net_addr *a, const net_addr *b);


#define NET_DO(mi,mj) \
  static inline void net_copy_##mi(net_addr_##mi *dst, const net_addr_##mi *src) \
  { memcpy(dst, src, sizeof(net_addr_##mi)); }
NET_DO_FIXLEN
#undef NET_DO

#define NET_DO(mi,mj) \
  static inline void net_copy_##mi(net_addr_##mi *dst, const net_addr_##mi *src) \
  { memcpy(dst, src, src->length); }
NET_DO_VARLEN
#undef NET_DO

static inline void net_copy(net_addr *dst, const net_addr *src)
{
  switch (src->type)
  {
#define NET_DO(mi,mj) \
    case NET_##mj: \
      return net_copy_##mi((net_addr_##mi *) dst, (const net_addr_##mi *) src);
      NET_DO_ALL
#undef NET_DO
  }
}


static inline u32 net_hash_ip4(const net_addr_ip4 *n)
{ return ip4_hash(n->prefix) ^ ((u32) n->pxlen << 26); }

static inline u32 net_hash_ip6(const net_addr_ip6 *n)
{ return ip6_hash(n->prefix) ^ ((u32) n->pxlen << 26); }

/* XXXX */
static inline u32 u64_hash(u64 a)
{ return u32_hash(a); }

static inline u32 net_hash_vpn4(const net_addr_vpn4 *n)
{ return ip4_hash(n->prefix) ^ ((u32) n->pxlen << 26) ^ u64_hash(n->rd); }

static inline u32 net_hash_vpn6(const net_addr_vpn6 *n)
{ return ip6_hash(n->prefix) ^ ((u32) n->pxlen << 26) ^ u64_hash(n->rd); }

static inline u32 net_hash_roa4(const net_addr_roa4 *n)
{ return ip4_hash(n->prefix) ^ ((u32) n->pxlen << 26); }

static inline u32 net_hash_roa6(const net_addr_roa6 *n)
{ return ip6_hash(n->prefix) ^ ((u32) n->pxlen << 26); }

static inline u32 net_hash_flow4(const net_addr_flow4 *n)
{ return ip4_hash(n->prefix) ^ ((u32) n->pxlen << 26); }

static inline u32 net_hash_flow6(const net_addr_flow6 *n)
{ return ip6_hash(n->prefix) ^ ((u32) n->pxlen << 26); }

static inline u32 net_hash_mpls(const net_addr_mpls *n)
{ return n->label; }

#define NET_DO(f) \
  static inline u32 net_hash_##f##_mpls(const net_addr_##f##_mpls *n) \
  { return net_hash_##f(&(n->addr)); }
NET_DO(ip4)
NET_DO(ip6)
NET_DO(vpn4)
NET_DO(vpn6)
#undef NET_DO

u32 net_hash(const net_addr *a);


static inline int net_validate_ip4(const net_addr_ip4 *n)
{
  return (n->pxlen <= IP4_MAX_PREFIX_LENGTH) &&
    ip4_zero(ip4_and(n->prefix, ip4_not(ip4_mkmask(n->pxlen))));
}

static inline int net_validate_ip6(const net_addr_ip6 *n)
{
  return (n->pxlen <= IP6_MAX_PREFIX_LENGTH) &&
    ip6_zero(ip6_and(n->prefix, ip6_not(ip6_mkmask(n->pxlen))));
}

static inline int net_validate_mpls(const net_addr_mpls *n)
{
  return n->label < (1<<20);
}

int net_validate(const net_addr *N);


static inline void net_normalize_ip4(net_addr_ip4 *n)
{ n->prefix = ip4_and(n->prefix, ip4_mkmask(n->pxlen)); }

static inline void net_normalize_ip6(net_addr_ip6 *n)
{ n->prefix = ip6_and(n->prefix, ip6_mkmask(n->pxlen)); }

void net_normalize(net_addr *N);


int net_classify(const net_addr *N);
int net_format(const net_addr *N, char *buf, int buflen);


int ipa_in_netX(const ip_addr A, const net_addr *N);
int net_in_netX(const net_addr *A, const net_addr *N);


#endif
