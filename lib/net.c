
#include "nest/bird.h"
#include "lib/ip.h"
#include "lib/net.h"
#include "lib/flowspec.h"


const char * const net_label[] = {
#define NET_DO(mi,mj) [NET_##mj] = STRINGIFY(mi),
  NET_DO_ALL
#undef NET_DO
};

const u16 net_addr_length[] = {
#define NET_DO(mi,mj) [NET_##mj] = sizeof(net_addr_##mi),
  NET_DO_FIXLEN /* variable-length net_addr flavors are assigned 0 here */
#undef NET_DO
};

const u8 net_max_prefix_length[] = {
  [NET_IP4] 	= IP4_MAX_PREFIX_LENGTH,
  [NET_IP6] 	= IP6_MAX_PREFIX_LENGTH,
  [NET_VPN4] 	= IP4_MAX_PREFIX_LENGTH,
  [NET_VPN6] 	= IP6_MAX_PREFIX_LENGTH,
  [NET_ROA4] 	= IP4_MAX_PREFIX_LENGTH,
  [NET_ROA6] 	= IP6_MAX_PREFIX_LENGTH,
  [NET_FLOW4] 	= IP4_MAX_PREFIX_LENGTH,
  [NET_FLOW6] 	= IP6_MAX_PREFIX_LENGTH,
  [NET_MPLS]	= 0,
  [NET_IP4_MPLS] 	= IP4_MAX_PREFIX_LENGTH,
  [NET_IP6_MPLS] 	= IP6_MAX_PREFIX_LENGTH,
  [NET_VPN4_MPLS] 	= IP4_MAX_PREFIX_LENGTH,
  [NET_VPN6_MPLS] 	= IP6_MAX_PREFIX_LENGTH,
};

const u16 net_max_text_length[] = {
  [NET_IP4] 	= 18,	/* "255.255.255.255/32" */
  [NET_IP6] 	= 43,	/* "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128" */
  [NET_VPN4] 	= 40,	/* "4294967296:4294967296 255.255.255.255/32" */
  [NET_VPN6] 	= 65,	/* "4294967296:4294967296 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128" */
  [NET_ROA4] 	= 34,	/* "255.255.255.255/32-32 AS4294967295" */
  [NET_ROA6] 	= 60,	/* "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128-128 AS4294967295" */
  [NET_FLOW4] 	= 0,	/* "flow4 { ... }" */
  [NET_FLOW6] 	= 0,	/* "flow6 { ... }" */
  [NET_MPLS]	= 7,	/* "1048575" */
  [NET_IP4_MPLS] = 18 + 5 + 8*MPLS_MAX_LABEL_STACK, /* ip + " mpls " + "1048575/1048575/..." */
  [NET_IP6_MPLS] = 43 + 5 + 8*MPLS_MAX_LABEL_STACK,
  [NET_VPN4_MPLS] = 40 + 5 + 8*MPLS_MAX_LABEL_STACK,
  [NET_VPN6_MPLS] = 65 + 5 + 8*MPLS_MAX_LABEL_STACK,
};

static int
net_format_ip4(const net_addr_ip4 *n, char *buf, int buflen)
{ return bsnprintf(buf, buflen, "%I4/%d", n->prefix, n->pxlen); }

static int
net_format_ip6(const net_addr_ip6 *n, char *buf, int buflen)
{ return bsnprintf(buf, buflen, "%I6/%d", n->prefix, n->pxlen); }

static int
net_format_vpn4(const net_addr_vpn4 *n, char *buf, int buflen)
{
  switch (n->rd >> 48)
    {
      case 0: return bsnprintf(buf, buflen, "0:%u:%u %I4/%d", (u32) (n->rd >> 32), (u32) n->rd, n->prefix, n->pxlen);
      case 1: return bsnprintf(buf, buflen, "1:%I4:%u %I4/%d", ip4_from_u32(n->rd >> 16), (u32) (n->rd & 0xffff), n->prefix, n->pxlen);
      case 2: return bsnprintf(buf, buflen, "2:%u:%u %I4/%d", (u32) (n->rd >> 16), (u32) (n->rd & 0xffff), n->prefix, n->pxlen);
    }
  return bsnprintf(buf, buflen, "X: %016x %I4/%d", n->rd, n->prefix, n->pxlen);
}

static int
net_format_vpn6(const net_addr_vpn6 *n, char *buf, int buflen)
{
  /* XXX: RD format is specified for VPN4; not found any for VPN6, reusing the same as for VPN4. */
  switch (n->rd >> 48)
    {
      case 0: return bsnprintf(buf, buflen, "0:%u:%u %I6/%d", (u32) (n->rd >> 32), (u32) n->rd, n->prefix, n->pxlen);
      case 1: return bsnprintf(buf, buflen, "1:%I4:%u %I6/%d", ip4_from_u32(n->rd >> 16), (u32) (n->rd & 0xffff), n->prefix, n->pxlen);
      case 2: return bsnprintf(buf, buflen, "2:%u:%u %I6/%d", (u32) (n->rd >> 16), (u32) (n->rd & 0xffff), n->prefix, n->pxlen);
    }
  return bsnprintf(buf, buflen, "X: %016x %I6/%d", n->rd, n->prefix, n->pxlen);
}

static int
net_format_roa4(const net_addr_roa4 *n, char *buf, int buflen)
{ return bsnprintf(buf, buflen, "%I4/%u-%u AS%u",  n->prefix, n->pxlen, n->max_pxlen, n->asn); }

static int
net_format_roa6(const net_addr_roa6 *n, char *buf, int buflen)
{ return bsnprintf(buf, buflen, "%I6/%u-%u AS%u",  n->prefix, n->pxlen, n->max_pxlen, n->asn); }

static int
net_format_flow4(const net_addr_flow4 *n, char *buf, int buflen)
{ return flow4_net_format(buf, buflen, n); }

static int
net_format_flow6(const net_addr_flow6 *n, char *buf, int buflen)
{ return flow6_net_format(buf, buflen, n); }

static int
net_format_mpls(const net_addr_mpls *n, char *buf, int buflen)
{ return bsnprintf(buf, buflen, "%u", n->label); }

#define NET_DO(f) \
static int net_format_##f##_mpls(const net_addr_##f##_mpls *n, char *buf, int buflen) { \
  int k = net_format_##f(&(n->addr), buf, buflen); \
  if (!NET_ADDR_MPLS_LABEL_STACK_LEN(n)) \
    return k; \
  k += bsnprintf(buf, buflen, "mpls %u", n->label[0]); \
  for (uint i = 1; i < NET_ADDR_MPLS_LABEL_STACK_LEN(n); i++) \
    k += bsnprintf(buf, buflen, "/%u"); \
  return k; \
}

NET_DO(ip4)
NET_DO(ip6)
NET_DO(vpn4)
NET_DO(vpn6)
#undef NET_DO

int
net_format(const net_addr *n, char *buf, int buflen)
{
  buf[0] = 0;

  switch (n->type)
  {
#define NET_DO(mi,mj) case NET_##mj: return net_format_##mi(&(n->mi), buf, buflen);
    NET_DO_ALL
#undef NET_DO
  }

  bug("unknown network type");
} 

ip_addr
net_pxmask(const net_addr *a)
{
  switch (a->type)
  {
  NET_CASE_ALL(4):
    return ipa_from_ip4(ip4_mkmask(net4_pxlen(a)));

  NET_CASE_ALL(6):
    return ipa_from_ip6(ip6_mkmask(net6_pxlen(a)));

  case NET_MPLS:
  default:
    return IPA_NONE;
  }
}

int
net_compare(const net_addr *a, const net_addr *b)
{
  if (a->type != b->type)
    return uint_cmp(a->type, b->type);

  switch (a->type)
  {
#define NET_DO(mi,mj) case NET_##mj: return net_compare_##mi((const net_addr_##mi *) a, (const net_addr_##mi *) b);
    NET_DO_ALL
#undef NET_DO
  }
  return 0;
}

#define NET_HASH(a,t) net_hash_##t((const net_addr_##t *) a)

u32
net_hash(const net_addr *n)
{
  switch (n->type)
  {
#define NET_DO(mi,mj) case NET_##mj: return NET_HASH(n, mi);
    NET_DO_ALL
#undef NET_DO
  default: bug("invalid type");
  }
}


int
net_validate(const net_addr *N)
{
  switch (N->type)
  {
  NET_CASE_ALL(4):
    return net_validate_ip4((net_addr_ip4 *) N);

  NET_CASE_ALL(6):
    return net_validate_ip6((net_addr_ip6 *) N);

  case NET_MPLS:
    return net_validate_mpls((net_addr_mpls *) N);

  default:
    return 0;
  }
}

void
net_normalize(net_addr *n)
{
  switch (n->type)
  {
  NET_CASE_ALL(4):
    return net_normalize_ip4(&n->ip4);

  NET_CASE_ALL(6):
    return net_normalize_ip6(&n->ip6);

  case NET_MPLS:
    return;
  }
}

int
net_classify(const net_addr *n)
{
  switch (n->type)
  {
  NET_CASE_ALL(4):
    return ip4_zero(n->ip4.prefix) ? (IADDR_HOST | SCOPE_UNIVERSE) : ip4_classify(n->ip4.prefix);

  NET_CASE_ALL(6):
    return ip6_zero(n->ip6.prefix) ? (IADDR_HOST | SCOPE_UNIVERSE) : ip6_classify(&n->ip6.prefix);

  case NET_MPLS:
    return IADDR_HOST | SCOPE_UNIVERSE;
  }

  return IADDR_INVALID;
}

int
ipa_in_netX(const ip_addr a, const net_addr *n)
{
  switch (n->type)
  {
  NET_CASE_ALL(4):
    if (!ipa_is_ip4(a)) return 0;
    return ip4_zero(ip4_and(ip4_xor(ipa_to_ip4(a), net4_prefix(n)),
			    ip4_mkmask(net4_pxlen(n))));

  NET_CASE_ALL(6):
    if (ipa_is_ip4(a)) return 0;
    return ip6_zero(ip6_and(ip6_xor(ipa_to_ip6(a), net6_prefix(n)),
			    ip6_mkmask(net6_pxlen(n))));

  case NET_MPLS:
  default:
    return 0;
  }
}

int
net_in_netX(const net_addr *a, const net_addr *n)
{
  if (a->type != n->type)
    return 0;

  return (net_pxlen(n) <= net_pxlen(a)) && ipa_in_netX(net_prefix(a), n);
}
