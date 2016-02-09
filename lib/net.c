
#include "nest/bird.h"
#include "lib/ip.h"
#include "lib/net.h"


const char * const net_label[] = {
  [NET_IP4] = "ipv4",
  [NET_IP6] = "ipv6",
  [NET_VPN4] = "vpn4",
  [NET_VPN6] = "vpn6",
  [NET_ROA4] = "roa4",
  [NET_ROA6] = "roa6",
  [NET_VPN6] = "vpn6",
  [NET_MPLS] = "mpls",
};

const u16 net_addr_length[] = {
  [NET_IP4] = sizeof(net_addr_ip4),
  [NET_IP6] = sizeof(net_addr_ip6),
  [NET_VPN4] = sizeof(net_addr_vpn4),
  [NET_VPN6] = sizeof(net_addr_vpn6),
  [NET_ROA4] = sizeof(net_addr_roa4),
  [NET_ROA6] = sizeof(net_addr_roa6),
  [NET_MPLS] = sizeof(net_addr_mpls),
};

const u8 net_max_prefix_length[] = {
  [NET_IP4] = IP4_MAX_PREFIX_LENGTH,
  [NET_IP6] = IP6_MAX_PREFIX_LENGTH,
  [NET_VPN4] = IP4_MAX_PREFIX_LENGTH,
  [NET_VPN6] = IP6_MAX_PREFIX_LENGTH,
  [NET_ROA4] = IP4_MAX_PREFIX_LENGTH,
  [NET_ROA6] = IP6_MAX_PREFIX_LENGTH,
  [NET_MPLS] = 0
};

const u16 net_max_text_length[] = {
  [NET_IP4] = 18,	/* "255.255.255.255/32" */
  [NET_IP6] = 43,	/* "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128" */
  [NET_VPN4] = 40,	/* "4294967296:4294967296 255.255.255.255/32" */
  [NET_VPN6] = 65,	/* "4294967296:4294967296 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128" */
  [NET_ROA4] = 34,      /* "255.255.255.255/32-32 AS4294967295" */
  [NET_ROA6] = 60,      /* "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128-128 AS4294967295" */
  [NET_MPLS] = 7,       /* "1048575" */
};


int
net_format(const net_addr *N, char *buf, int buflen)
{
  net_addr_union *n = (void *) N;

  switch (n->n.type)
  {
  case NET_IP4:
    return bsnprintf(buf, buflen, "%I4/%d", n->ip4.prefix, n->ip4.pxlen);
  case NET_IP6:
    return bsnprintf(buf, buflen, "%I6/%d", n->ip6.prefix, n->ip6.pxlen);
  case NET_VPN4:
    switch (n->vpn4.rd >> 48)
    {
      case 0: return bsnprintf(buf, buflen, "0:%u:%u %I4/%d", (u32) (n->vpn4.rd >> 32), (u32) n->vpn4.rd, n->vpn4.prefix, n->vpn4.pxlen);
      case 1: return bsnprintf(buf, buflen, "1:%I4:%u %I4/%d", ip4_from_u32(n->vpn4.rd >> 16), (u32) (n->vpn4.rd & 0xffff), n->vpn4.prefix, n->vpn4.pxlen);
      case 2: return bsnprintf(buf, buflen, "2:%u:%u %I4/%d", (u32) (n->vpn4.rd >> 16), (u32) (n->vpn4.rd & 0xffff), n->vpn4.prefix, n->vpn4.pxlen);
    }
    return 0;

    /* XXX: RD format is specified for VPN4; not found any for VPN6, reusing the same as for VPN4. */
  case NET_VPN6:
    switch (n->vpn4.rd >> 48)
    {
      case 0: return bsnprintf(buf, buflen, "0:%u:%u %I6/%d", (u32) (n->vpn6.rd >> 32), (u32) n->vpn6.rd, n->vpn6.prefix, n->vpn6.pxlen);
      case 1: return bsnprintf(buf, buflen, "1:%I4:%u %I6/%d", ip4_from_u32(n->vpn6.rd >> 16), (u32) (n->vpn6.rd & 0xffff), n->vpn6.prefix, n->vpn6.pxlen);
      case 2: return bsnprintf(buf, buflen, "2:%u:%u %I6/%d", (u32) (n->vpn6.rd >> 16), (u32) (n->vpn6.rd & 0xffff), n->vpn6.prefix, n->vpn6.pxlen);
    }
    return 0;
  case NET_ROA4:
    return bsnprintf(buf, buflen, "%I4/%u-%u AS%u",  n->roa4.prefix, n->roa4.pxlen, n->roa4.max_pxlen, n->roa4.asn);
  case NET_ROA6:
    return bsnprintf(buf, buflen, "%I6/%u-%u AS%u",  n->roa6.prefix, n->roa6.pxlen, n->roa6.max_pxlen, n->roa6.asn);
  case NET_MPLS:
    return bsnprintf(buf, buflen, "%u", n->mpls.label);
  }

  return 0;
}

ip_addr
net_pxmask(const net_addr *a)
{
  switch (a->type)
  {
  case NET_IP4:
  case NET_VPN4:
  case NET_ROA4:
    return ipa_from_ip4(ip4_mkmask(net4_pxlen(a)));

  case NET_IP6:
  case NET_VPN6:
  case NET_ROA6:
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
  case NET_IP4:
    return net_compare_ip4((const net_addr_ip4 *) a, (const net_addr_ip4 *) b);
  case NET_IP6:
    return net_compare_ip6((const net_addr_ip6 *) a, (const net_addr_ip6 *) b);
  case NET_VPN4:
    return net_compare_vpn4((const net_addr_vpn4 *) a, (const net_addr_vpn4 *) b);
  case NET_VPN6:
    return net_compare_vpn6((const net_addr_vpn6 *) a, (const net_addr_vpn6 *) b);
  case NET_ROA4:
    return net_compare_roa4((const net_addr_roa4 *) a, (const net_addr_roa4 *) b);
  case NET_ROA6:
    return net_compare_roa6((const net_addr_roa6 *) a, (const net_addr_roa6 *) b);
  case NET_MPLS:
    return net_compare_mpls((const net_addr_mpls *) a, (const net_addr_mpls *) b);
  }
  return 0;
}

int
net_validate(const net_addr *N)
{
  switch (N->type)
  {
  case NET_IP4:
  case NET_VPN4:
  case NET_ROA4:
    return net_validate_ip4((net_addr_ip4 *) N);

  case NET_IP6:
  case NET_VPN6:
  case NET_ROA6:
    return net_validate_ip6((net_addr_ip6 *) N);

  case NET_MPLS:
    return net_validate_mpls((net_addr_mpls *) N);

  default:
    return 0;
  }
}

void
net_normalize(net_addr *N)
{
  net_addr_union *n = (void *) N;

  switch (n->n.type)
  {
  case NET_IP4:
  case NET_VPN4:
  case NET_ROA4:
    return net_normalize_ip4(&n->ip4);

  case NET_IP6:
  case NET_VPN6:
  case NET_ROA6:
    return net_normalize_ip6(&n->ip6);

  case NET_MPLS:
    return;
  }
}

int
net_classify(const net_addr *N)
{
  net_addr_union *n = (void *) N;

  switch (n->n.type)
  {
  case NET_IP4:
  case NET_VPN4:
  case NET_ROA4:
    return ip4_zero(n->ip4.prefix) ? (IADDR_HOST | SCOPE_UNIVERSE) : ip4_classify(n->ip4.prefix);

  case NET_IP6:
  case NET_VPN6:
  case NET_ROA6:
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
  case NET_IP4:
  case NET_VPN4:
  case NET_ROA4:
    if (!ipa_is_ip4(a)) return 0;
    return ip4_zero(ip4_and(ip4_xor(ipa_to_ip4(a), net4_prefix(n)),
			    ip4_mkmask(net4_pxlen(n))));

  case NET_IP6:
  case NET_VPN6:
  case NET_ROA6:
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
