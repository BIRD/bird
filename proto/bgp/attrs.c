/*
 *	BIRD -- BGP Attributes
 *
 *	(c) 2000 Martin Mares <mj@ucw.cz>
 *	(c) 2008--2016 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2008--2016 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#undef LOCAL_DEBUG

#include <stdlib.h>

#include "nest/bird.h"
#include "nest/iface.h"
#include "nest/protocol.h"
#include "nest/route.h"
#include "nest/attrs.h"
#include "conf/conf.h"
#include "lib/resource.h"
#include "lib/string.h"
#include "lib/unaligned.h"

#include "bgp.h"

/*
 *   UPDATE message error handling
 *
 * All checks from RFC 4271 6.3 are done as specified with these exceptions:
 *  - The semantic check of an IP address from NEXT_HOP attribute is missing.
 *  - Checks of some optional attribute values are missing.
 *  - Syntactic and semantic checks of NLRIs (done in DECODE_PREFIX())
 *    are probably inadequate.
 *
 * Loop detection based on AS_PATH causes updates to be withdrawn. RFC
 * 4271 does not explicitly specifiy the behavior in that case.
 *
 * Loop detection related to route reflection (based on ORIGINATOR_ID
 * and CLUSTER_LIST) causes updates to be withdrawn. RFC 4456 8
 * specifies that such updates should be ignored, but that is generally
 * a bad idea.
 *
 * Error checking of optional transitive attributes is done according to
 * draft-ietf-idr-optional-transitive-03, but errors are handled always
 * as withdraws.
 *
 * Unexpected AS_CONFED_* segments in AS_PATH are logged and removed,
 * but unknown segments cause a session drop with Malformed AS_PATH
 * error (see validate_path()). The behavior in such case is not
 * explicitly specified by RFC 4271. RFC 5065 specifies that
 * inconsistent AS_CONFED_* segments should cause a session drop, but
 * implementations that pass invalid AS_CONFED_* segments are
 * widespread.
 *
 * Error handling of AS4_* attributes is done as specified by
 * draft-ietf-idr-rfc4893bis-03. There are several possible
 * inconsistencies between AGGREGATOR and AS4_AGGREGATOR that are not
 * handled by that draft, these are logged and ignored (see
 * bgp_reconstruct_4b_attrs()).
 *
 * BGP attribute table has several hooks:
 *
 * export - Hook that validates and normalizes attribute during export phase.
 * Receives eattr, may modify it (e.g., sort community lists for canonical
 * representation), UNSET() it (e.g., skip empty lists), or WITHDRAW() it if
 * necessary. May assume that eattr has value valid w.r.t. its type, but may be
 * invalid w.r.t. BGP constraints. Optional.
 *
 * encode - Hook that converts internal representation to external one during
 * packet writing. Receives eattr and puts it in the buffer (including attribute
 * header). Returns number of bytes, or -1 if not enough space. May assume that
 * eattr has value valid w.r.t. its type and validated by export hook. Mandatory
 * for all known attributes that exist internally after export phase (i.e., all
 * except pseudoattributes MP_(UN)REACH_NLRI).
 *
 * decode - Hook that converts external representation to internal one during
 * packet parsing. Receives attribute data in buffer, validates it and adds
 * attribute to ea_list. If data are invalid, steps DISCARD(), WITHDRAW() or
 * bgp_parse_error() may be used to escape. Mandatory for all known attributes.
 *
 * format - Optional hook that converts eattr to textual representation.
 */

// XXXX review pool usage : c->c.proto->pool


struct bgp_attr_desc {
  const char *name;
  uint type;
  uint flags;
  void (*export)(struct bgp_export_state *s, eattr *a);
  int  (*encode)(struct bgp_write_state *s, eattr *a, byte *buf, uint size);
  void (*decode)(struct bgp_parse_state *s, uint code, uint flags, byte *data, uint len, ea_list **to);
  void (*format)(eattr *ea, byte *buf, uint size);
};

static const struct bgp_attr_desc bgp_attr_table[];

static inline int bgp_attr_known(uint code);

eattr *
bgp_set_attr(ea_list **attrs, struct linpool *pool, uint code, uint flags, uintptr_t val)
{
  ASSERT(bgp_attr_known(code));

  ea_list *a = lp_alloc(pool, sizeof(ea_list) + sizeof(eattr));
  eattr *e = &a->attrs[0];

  a->flags = EALF_SORTED;
  a->count = 1;
  a->next = *attrs;
  *attrs = a;

  e->id = EA_CODE(EAP_BGP, code);
  e->type = bgp_attr_table[code].type;
  e->flags = flags;

  if (e->type & EAF_EMBEDDED)
    e->u.data = (u32) val;
  else
    e->u.ptr = (struct adata *) val;

  return e;
}



#define REPORT(msg, args...) \
  ({ log(L_REMOTE "%s: " msg, s->proto->p.name, ## args); })

#define DISCARD(msg, args...) \
  ({ REPORT(msg, ## args); return; })

#define WITHDRAW(msg, args...) \
  ({ REPORT(msg, ## args); s->err_withdraw = 1; return; })

#define UNSET(a) \
  ({ a->type = EAF_TYPE_UNDEF; return; })

#define NEW_BGP		"Discarding %s attribute received from AS4-aware neighbor"
#define BAD_EBGP	"Discarding %s attribute received from EBGP neighbor"
#define BAD_LENGTH	"Malformed %s attribute - invalid length (%u)"
#define BAD_VALUE	"Malformed %s attribute - invalid value (%u)"
#define NO_MANDATORY	"Missing mandatory %s attribute"


static inline int
bgp_put_attr_hdr3(byte *buf, uint code, uint flags, uint len)
{
  *buf++ = flags;
  *buf++ = code;
  *buf++ = len;
  return 3;
}

static inline int
bgp_put_attr_hdr4(byte *buf, uint code, uint flags, uint len)
{
  *buf++ = flags | BAF_EXT_LEN;
  *buf++ = code;
  put_u16(buf, len);
  return 4;
}

static inline int
bgp_put_attr_hdr(byte *buf, uint code, uint flags, uint len)
{
  if (len < 256)
    return bgp_put_attr_hdr3(buf, code, flags, len);
  else
    return bgp_put_attr_hdr4(buf, code, flags, len);
}

static int
bgp_encode_u8(struct bgp_write_state *s UNUSED, eattr *a, byte *buf, uint size)
{
  if (size < (3+1))
    return -1;

  bgp_put_attr_hdr3(buf, EA_ID(a->id), a->flags, 1);
  buf[3] = a->u.data;

  return 3+1;
}

static int
bgp_encode_u32(struct bgp_write_state *s UNUSED, eattr *a, byte *buf, uint size)
{
  if (size < (3+4))
    return -1;

  bgp_put_attr_hdr3(buf, EA_ID(a->id), a->flags, 4);
  put_u32(buf+3, a->u.data);

  return 3+4;
}

static int
bgp_encode_u32s(struct bgp_write_state *s UNUSED, eattr *a, byte *buf, uint size)
{
  uint len = a->u.ptr->length;

  if (size < (4+len))
    return -1;

  uint hdr = bgp_put_attr_hdr(buf, EA_ID(a->id), a->flags, len);
  put_u32s(buf + hdr, (u32 *) a->u.ptr->data, len / 4);

  return hdr + len;
}

static int
bgp_put_attr(byte *buf, uint size, uint code, uint flags, byte *data, uint len)
{
  if (size < (4+len))
    return -1;

  uint hdr = bgp_put_attr_hdr(buf, code, flags, len);
  memcpy(buf + hdr, data, len);

  return hdr + len;
}

static int
bgp_encode_raw(struct bgp_write_state *s UNUSED, eattr *a, byte *buf, uint size)
{
  return bgp_put_attr(buf, size, EA_ID(a->id), a->flags, a->u.ptr->data, a->u.ptr->length);
}


/*
 *	Attribute hooks
 */

static void
bgp_export_origin(struct bgp_export_state *s, eattr *a)
{
  if (a->u.data > 2)
    WITHDRAW(BAD_VALUE, "ORIGIN", a->u.data);
}

static void
bgp_decode_origin(struct bgp_parse_state *s, uint code UNUSED, uint flags, byte *data, uint len, ea_list **to)
{
  if (len != 1)
    WITHDRAW(BAD_LENGTH, "ORIGIN", len);

  if (data[0] > 2)
    WITHDRAW(BAD_VALUE, "ORIGIN", data[0]);

  bgp_set_attr_u32(to, s->pool, BA_ORIGIN, flags, data[0]);
}

static void
bgp_format_origin(eattr *a, byte *buf, uint size UNUSED)
{
  static const char *bgp_origin_names[] = { "IGP", "EGP", "Incomplete" };

  bsprintf(buf, (a->u.data <= 2) ? bgp_origin_names[a->u.data] : "?");
}


static int
bgp_encode_as_path(struct bgp_write_state *s, eattr *a, byte *buf, uint size)
{
  byte *data = a->u.ptr->data;
  uint len = a->u.ptr->length;

  if (!s->as4_session)
  {
    /* Prepare 16-bit AS_PATH (from 32-bit one) in a temporary buffer */
    byte *src = data;
    data = alloca(len);
    len = as_path_32to16(data, src, len);
  }

  return bgp_put_attr(buf, size, BA_AS_PATH, a->flags, data, len);
}

static void
bgp_decode_as_path(struct bgp_parse_state *s, uint code UNUSED, uint flags, byte *data, uint len, ea_list **to)
{
  char err[128];

  if (!as_path_valid(data, len, (s->as4_session ? 4 : 2), err, sizeof(err)))
    WITHDRAW("Malformed AS_PATH attribute - %s", err);

  if (!s->as4_session)
  {
    /* Prepare 32-bit AS_PATH (from 16-bit one) in a temporary buffer */
    byte *src = data;
    data = alloca(2*len);
    len = as_path_16to32(data, src, len);
  }

  bgp_set_attr_data(to, s->pool, BA_AS_PATH, flags, data, len);
}


static int
bgp_encode_next_hop(struct bgp_write_state *s, eattr *a, byte *buf, uint size)
{
  /*
   * The NEXT_HOP attribute is used only in traditional (IPv4) BGP. In MP-BGP,
   * the next hop is encoded as a part of the MP_REACH_NLRI attribute, so we
   * store it and encode it later by AFI-specific hooks.
   */

  if (s->channel->afi == BGP_AF_IPV4)
  {
    ASSERT(a->u.ptr->length == sizeof(ip_addr));

    if (size < (3+4))
      return -1;

    bgp_put_attr_hdr3(buf, BA_NEXT_HOP, a->flags, 4);
    put_ip4(buf+3, ipa_to_ip4( *(ip_addr *) a->u.ptr->data ));

    return 3+4;
  }
  else
  {
    s->mp_next_hop = a;
    return 0;
  }
}

static void
bgp_decode_next_hop(struct bgp_parse_state *s, uint code UNUSED, uint flags UNUSED, byte *data, uint len, ea_list **to UNUSED)
{
  if (len != 4)
    WITHDRAW(BAD_LENGTH, "NEXT_HOP", len);

  /* Semantic checks are done later */
  s->ip_next_hop_len = len;
  s->ip_next_hop_data = data;
}

/* TODO: This function should use AF-specific hook */
static void
bgp_format_next_hop(eattr *a, byte *buf, uint size UNUSED)
{
  ip_addr *nh = (void *) a->u.ptr->data;
  uint len = a->u.ptr->length;

  ASSERT((len == 16) || (len == 32));

  /* in IPv6, we may have two addresses in NEXT HOP */
  if ((len == 16) || ipa_zero(nh[1]))
    bsprintf(buf, "%I", nh[0]);
  else
    bsprintf(buf, "%I %I", nh[0], nh[1]);
}


static void
bgp_decode_med(struct bgp_parse_state *s, uint code UNUSED, uint flags, byte *data, uint len, ea_list **to)
{
  if (len != 4)
    WITHDRAW(BAD_LENGTH, "MULTI_EXIT_DISC", len);

  u32 val = get_u32(data);
  bgp_set_attr_u32(to, s->pool, BA_MULTI_EXIT_DISC, flags, val);
}


static void
bgp_export_local_pref(struct bgp_export_state *s, eattr *a)
{
  if (!s->proto->is_interior)
    UNSET(a);
}

static void
bgp_decode_local_pref(struct bgp_parse_state *s, uint code UNUSED, uint flags, byte *data, uint len, ea_list **to)
{
  if (!s->proto->is_interior)
    DISCARD(BAD_EBGP, "LOCAL_PREF");

  if (len != 4)
    WITHDRAW(BAD_LENGTH, "LOCAL_PREF", len);

  u32 val = get_u32(data);
  bgp_set_attr_u32(to, s->pool, BA_LOCAL_PREF, flags, val);
}


static void
bgp_decode_atomic_aggr(struct bgp_parse_state *s, uint code UNUSED, uint flags, byte *data UNUSED, uint len, ea_list **to)
{
  if (len != 0)
    DISCARD(BAD_LENGTH, "ATOMIC_AGGR", len);

  bgp_set_attr_data(to, s->pool, BA_ATOMIC_AGGR, flags, NULL, 0);
}

static int
bgp_encode_aggregator(struct bgp_write_state *s, eattr *a, byte *buf, uint size)
{
  byte *data = a->u.ptr->data;
  uint len = a->u.ptr->length;

  if (!s->as4_session)
  {
    /* Prepare 16-bit AGGREGATOR (from 32-bit one) in a temporary buffer */
    byte *src = data;
    data = alloca(6);
    len = aggregator_32to16(data, src);
  }

  return bgp_put_attr(buf, size, BA_AGGREGATOR, a->flags, data, len);
}

static void
bgp_decode_aggregator(struct bgp_parse_state *s, uint code UNUSED, uint flags, byte *data, uint len, ea_list **to)
{
  if (len != (s->as4_session ? 8 : 6))
    DISCARD(BAD_LENGTH, "AGGREGATOR", len);

  if (!s->as4_session)
  {
    /* Prepare 32-bit AGGREGATOR (from 16-bit one) in a temporary buffer */
    byte *src = data;
    data = alloca(8);
    len = aggregator_16to32(data, src);
  }

  bgp_set_attr_data(to, s->pool, BA_AGGREGATOR, flags, data, len);
}

static void
bgp_format_aggregator(eattr *a, byte *buf, uint size UNUSED)
{
  byte *data = a->u.ptr->data;

  bsprintf(buf, "%I4 AS%u", get_ip4(data+4), get_u32(data+0));
}


static void
bgp_export_community(struct bgp_export_state *s, eattr *a)
{
  if (a->u.ptr->length == 0)
    UNSET(a);

  a->u.ptr = int_set_sort(s->pool, a->u.ptr);
}

static void
bgp_decode_community(struct bgp_parse_state *s, uint code UNUSED, uint flags, byte *data, uint len, ea_list **to)
{
  if (!len || (len % 4))
    WITHDRAW(BAD_LENGTH, "COMMUNITY", len);

  struct adata *ad = lp_alloc_adata(s->pool, len);
  get_u32s(data, (u32 *) ad->data, len / 4);
  bgp_set_attr_ptr(to, s->pool, BA_COMMUNITY, flags, ad);
}


static void
bgp_export_originator_id(struct bgp_export_state *s, eattr *a)
{
  if (!s->proto->is_internal)
    UNSET(a);
}

static void
bgp_decode_originator_id(struct bgp_parse_state *s, uint code UNUSED, uint flags, byte *data, uint len, ea_list **to)
{
  if (!s->proto->is_internal)
    DISCARD(BAD_EBGP, "ORIGINATOR_ID");

  if (len != 4)
    WITHDRAW(BAD_LENGTH, "ORIGINATOR_ID", len);

  u32 val = get_u32(data);
  bgp_set_attr_u32(to, s->pool, BA_ORIGINATOR_ID, flags, val);
}


static void
bgp_export_cluster_list(struct bgp_export_state *s UNUSED, eattr *a)
{
  if (!s->proto->is_internal)
    UNSET(a);

  if (a->u.ptr->length == 0)
    UNSET(a);
}

static void
bgp_decode_cluster_list(struct bgp_parse_state *s, uint code UNUSED, uint flags, byte *data, uint len, ea_list **to)
{
  if (!s->proto->is_internal)
    DISCARD(BAD_EBGP, "CLUSTER_LIST");

  if (!len || (len % 4))
    WITHDRAW(BAD_LENGTH, "CLUSTER_LIST", len);

  struct adata *ad = lp_alloc_adata(s->pool, len);
  get_u32s(data, (u32 *) ad->data, len / 4);
  bgp_set_attr_ptr(to, s->pool, BA_CLUSTER_LIST, flags, ad);
}

static void
bgp_format_cluster_list(eattr *a, byte *buf, uint size)
{
  /* Truncates cluster lists larger than buflen, probably not a problem */
  int_set_format(a->u.ptr, 0, -1, buf, size);
}


static inline u32
get_af3(byte *buf)
{
  return (get_u16(buf) << 16) | buf[2];
}

static void
bgp_decode_mp_reach_nlri(struct bgp_parse_state *s, uint code UNUSED, uint flags UNUSED, byte *data, uint len, ea_list **to UNUSED)
{
  /*
   *	2 B	MP_REACH_NLRI data - Address Family Identifier
   *	1 B	MP_REACH_NLRI data - Subsequent Address Family Identifier
   *	1 B	MP_REACH_NLRI data - Length of Next Hop Network Address
   *	var	MP_REACH_NLRI data - Network Address of Next Hop
   *	1 B	MP_REACH_NLRI data - Reserved (zero)
   *	var	MP_REACH_NLRI data - Network Layer Reachability Information
   */

  if ((len < 5) || (len < (5 + (uint) data[3])))
    bgp_parse_error(s, 9);

  s->mp_reach_af = get_af3(data);
  s->mp_next_hop_len = data[3];
  s->mp_next_hop_data = data + 4;
  s->mp_reach_len = len - 5 - s->mp_next_hop_len;
  s->mp_reach_nlri = data + 5 + s->mp_next_hop_len;
}


static void
bgp_decode_mp_unreach_nlri(struct bgp_parse_state *s, uint code UNUSED, uint flags UNUSED, byte *data, uint len, ea_list **to UNUSED)
{
  /*
   *	2 B	MP_UNREACH_NLRI data - Address Family Identifier
   *	1 B	MP_UNREACH_NLRI data - Subsequent Address Family Identifier
   *	var	MP_UNREACH_NLRI data - Network Layer Reachability Information
   */

  if (len < 3)
    bgp_parse_error(s, 9);

  s->mp_unreach_af = get_af3(data);
  s->mp_unreach_len = len - 3;
  s->mp_unreach_nlri = data + 3;
}


static void
bgp_export_ext_community(struct bgp_export_state *s, eattr *a)
{
  if (a->u.ptr->length == 0)
    UNSET(a);

  a->u.ptr = ec_set_sort(s->pool, a->u.ptr);
}

static void
bgp_decode_ext_community(struct bgp_parse_state *s, uint code UNUSED, uint flags, byte *data, uint len, ea_list **to)
{
  if (!len || (len % 8))
    WITHDRAW(BAD_LENGTH, "EXT_COMMUNITY", len);

  struct adata *ad = lp_alloc_adata(s->pool, len);
  get_u32s(data, (u32 *) ad->data, len / 4);
  bgp_set_attr_ptr(to, s->pool, BA_EXT_COMMUNITY, flags, ad);
}


static void
bgp_decode_as4_aggregator(struct bgp_parse_state *s, uint code UNUSED, uint flags, byte *data, uint len, ea_list **to)
{
  if (s->as4_session)
    DISCARD(NEW_BGP, "AS4_AGGREGATOR");

  if (len != 8)
    DISCARD(BAD_LENGTH, "AS4_AGGREGATOR", len);

  bgp_set_attr_data(to, s->pool, BA_AS4_AGGREGATOR, flags, data, len);
}

static void
bgp_decode_as4_path(struct bgp_parse_state *s, uint code UNUSED, uint flags, byte *data, uint len, ea_list **to)
{
  char err[128];

  if (s->as4_session)
    DISCARD(NEW_BGP, "AS4_PATH");

  if (len < 6)
    DISCARD(BAD_LENGTH, "AS4_PATH", len);

  if (!as_path_valid(data, len, 4, err, sizeof(err)))
    DISCARD("Malformed AS4_PATH attribute - %s", err);

  /* XXXX remove CONFED segments */
  bgp_set_attr_data(to, s->pool, BA_AS4_PATH, flags, data, len);
}

static void
bgp_export_large_community(struct bgp_export_state *s, eattr *a)
{
  if (a->u.ptr->length == 0)
    UNSET(a);

  a->u.ptr = lc_set_sort(s->pool, a->u.ptr);
}

static void
bgp_decode_large_community(struct bgp_parse_state *s, uint code UNUSED, uint flags, byte *data, uint len, ea_list **to)
{
  if (!len || (len % 12))
    WITHDRAW(BAD_LENGTH, "LARGE_COMMUNITY", len);

  struct adata *ad = lp_alloc_adata(s->pool, len);
  get_u32s(data, (u32 *) ad->data, len / 4);
  bgp_set_attr_ptr(to, s->pool, BA_LARGE_COMMUNITY, flags, ad);
}

static inline void
bgp_decode_unknown(struct bgp_parse_state *s, uint code, uint flags, byte *data, uint len, ea_list **to)
{
  bgp_set_attr_data(to, s->pool, code, flags, data, len);
}

static inline void
bgp_export__mpls_label_stack(struct bgp_export_state *s, eattr *a)
{
  net_add_mpls_label_stack(s->n, (a->u.ptr->length)/4, (u32 *) a->u.ptr->data);
  UNSET(a);
}


/*
 *	Attribute table
 */

static const struct bgp_attr_desc bgp_attr_table[] = {
  [BA_ORIGIN] = {
    .name = "origin",
    .type = EAF_TYPE_INT,
    .flags = BAF_TRANSITIVE,
    .export = bgp_export_origin,
    .encode = bgp_encode_u8,
    .decode = bgp_decode_origin,
    .format = bgp_format_origin,
  },
  [BA_AS_PATH] = {
    .name = "as_path",
    .type = EAF_TYPE_AS_PATH,
    .flags = BAF_TRANSITIVE,
    .encode = bgp_encode_as_path,
    .decode = bgp_decode_as_path,
  },
  [BA_NEXT_HOP] = {
    .name = "next_hop",
    .type = EAF_TYPE_IP_ADDRESS,
    .flags = BAF_TRANSITIVE,
    .encode = bgp_encode_next_hop,
    .decode = bgp_decode_next_hop,
    .format = bgp_format_next_hop,
  },
  [BA_MULTI_EXIT_DISC] = {
    .name = "med",
    .type = EAF_TYPE_INT,
    .flags = BAF_OPTIONAL,
    .encode = bgp_encode_u32,
    .decode = bgp_decode_med,
  },
  [BA_LOCAL_PREF] = {
    .name = "local_pref",
    .type = EAF_TYPE_INT,
    .flags = BAF_TRANSITIVE,
    .export = bgp_export_local_pref,
    .encode = bgp_encode_u32,
    .decode = bgp_decode_local_pref,
  },
  [BA_ATOMIC_AGGR] = {
    .name = "atomic_aggr",
    .type = EAF_TYPE_OPAQUE,
    .flags = BAF_TRANSITIVE,
    .encode = bgp_encode_raw,
    .decode = bgp_decode_atomic_aggr,
  },
  [BA_AGGREGATOR] = {
    .name = "aggregator",
    .type = EAF_TYPE_OPAQUE,
    .flags = BAF_OPTIONAL | BAF_TRANSITIVE,
    .encode = bgp_encode_aggregator,
    .decode = bgp_decode_aggregator,
    .format = bgp_format_aggregator,
  },
  [BA_COMMUNITY] = {
    .name = "community",
    .type = EAF_TYPE_INT_SET,
    .flags = BAF_OPTIONAL | BAF_TRANSITIVE,
    .export = bgp_export_community,
    .encode = bgp_encode_u32s,
    .decode = bgp_decode_community,
  },
  [BA_ORIGINATOR_ID] = {
    .name = "originator_id",
    .type = EAF_TYPE_ROUTER_ID,
    .flags = BAF_OPTIONAL,
    .export = bgp_export_originator_id,
    .encode = bgp_encode_u32,
    .decode = bgp_decode_originator_id,
  },
  [BA_CLUSTER_LIST] = {
    .name = "cluster_list",
    .type = EAF_TYPE_INT_SET,
    .flags = BAF_OPTIONAL,
    .export = bgp_export_cluster_list,
    .encode = bgp_encode_u32s,
    .decode = bgp_decode_cluster_list,
    .format = bgp_format_cluster_list,
  },
  [BA_MP_REACH_NLRI] = {
    .name = "mp_reach_nlri",
    .type = EAF_TYPE_OPAQUE,
    .flags = BAF_OPTIONAL,
    .decode = bgp_decode_mp_reach_nlri,
  },
  [BA_MP_UNREACH_NLRI] = {
    .name = "mp_unreach_nlri",
    .type = EAF_TYPE_OPAQUE,
    .flags = BAF_OPTIONAL,
    .decode = bgp_decode_mp_unreach_nlri,
  },
  [BA_EXT_COMMUNITY] = {
    .name = "ext_community",
    .type = EAF_TYPE_EC_SET,
    .flags = BAF_OPTIONAL | BAF_TRANSITIVE,
    .export = bgp_export_ext_community,
    .encode = bgp_encode_u32s,
    .decode = bgp_decode_ext_community,
  },
  [BA_AS4_PATH] = {
    .name = "as4_path",
    .type = EAF_TYPE_AS_PATH,
    .flags = BAF_OPTIONAL | BAF_TRANSITIVE,
    .encode = bgp_encode_raw,
    .decode = bgp_decode_as4_path,
  },
  [BA_AS4_AGGREGATOR] = {
    .name = "as4_aggregator",
    .type = EAF_TYPE_OPAQUE,
    .flags = BAF_OPTIONAL | BAF_TRANSITIVE,
    .encode = bgp_encode_raw,
    .decode = bgp_decode_as4_aggregator,
    .format = bgp_format_aggregator,
  },
  [BA_LARGE_COMMUNITY] = {
    .name = "large_community",
    .type = EAF_TYPE_LC_SET,
    .flags = BAF_OPTIONAL | BAF_TRANSITIVE,
    .export = bgp_export_large_community,
    .encode = bgp_encode_u32s,
    .decode = bgp_decode_large_community,
  },
  [BA__MPLS_LABEL_STACK] = {
    .name = "_mpls_label_stack",
    .type = EAF_TYPE_INT_SET,
    .export = bgp_export__mpls_label_stack,
  },
};

static inline int
bgp_attr_known(uint code)
{
  return (code < ARRAY_SIZE(bgp_attr_table)) && bgp_attr_table[code].name;
}


/*
 *	Attribute export
 */

static inline void
bgp_export_attr(struct bgp_export_state *s, eattr *a, ea_list *to)
{
  if (EA_PROTO(a->id) != EAP_BGP)
    return;

  uint code = EA_ID(a->id);

  if (bgp_attr_known(code))
  {
    const struct bgp_attr_desc *desc = &bgp_attr_table[code];

    /* The flags might have been zero if the attr was added by filters */
    a->flags = (a->flags & BAF_PARTIAL) | desc->flags;

    /* Set partial bit if new opt-trans attribute is attached to non-local route */
    if ((s->src != NULL) && (a->type & EAF_ORIGINATED) &&
	(a->flags & BAF_OPTIONAL) && (a->flags & BAF_TRANSITIVE))
      a->flags |= BAF_PARTIAL;

    /* Call specific hook */
    CALL(desc->export, s, a);

    /* Attribute might become undefined in hook */
    if ((a->type & EAF_TYPE_MASK) == EAF_TYPE_UNDEF)
      return;
  }
  else
  {
    /* Don't re-export unknown non-transitive attributes */
    if (!(a->flags & BAF_TRANSITIVE))
      return;

    a->flags |= BAF_PARTIAL;
  }

  /* Append updated attribute */
  to->attrs[to->count++] = *a;
}

/**
 * bgp_export_attrs - export BGP attributes
 * @s: BGP export state
 * @attrs: a list of extended attributes
 *
 * The bgp_export_attrs() function takes a list of attributes and merges it to
 * one newly allocated and sorted segment. Attributes are validated and
 * normalized by type-specific export hooks and attribute flags are updated.
 * Some attributes may be eliminated (e.g. unknown non-tranitive attributes, or
 * empty community sets).
 *
 * Result: one sorted attribute list segment, or NULL if attributes are unsuitable.
 */
static inline ea_list *
bgp_export_attrs(struct bgp_export_state *s, ea_list *attrs)
{
  /* Merge the attribute list */
  ea_list *new = lp_alloc(s->pool, ea_scan(attrs));
  ea_merge(attrs, new);
  ea_sort(new);

  uint i, count;
  count = new->count;
  new->count = 0;

  /* Export each attribute */
  for (i = 0; i < count; i++)
    bgp_export_attr(s, &new->attrs[i], new);

  if (s->err_withdraw)
    return NULL;

  return new;

}


/*
 *	Attribute encoding
 */

static inline int
bgp_encode_attr(struct bgp_write_state *s, eattr *a, byte *buf, uint size)
{
  ASSERT(EA_PROTO(a->id) == EAP_BGP);

  uint code = EA_ID(a->id);

  if (bgp_attr_known(code))
    return bgp_attr_table[code].encode(s, a, buf, size);
  else
    return bgp_encode_raw(s, a, buf, size);
}

/**
 * bgp_encode_attrs - encode BGP attributes
 * @s: BGP write state
 * @attrs: a list of extended attributes
 * @buf: buffer
 * @end: buffer end
 *
 * The bgp_encode_attrs() function takes a list of extended attributes
 * and converts it to its BGP representation (a part of an Update message).
 *
 * Result: Length of the attribute block generated or -1 if not enough space.
 */
int
bgp_encode_attrs(struct bgp_write_state *s, ea_list *attrs, byte *buf, byte *end)
{
  byte *pos = buf;
  int i, len;

  for (i = 0; i < attrs->count; i++)
  {
    len = bgp_encode_attr(s, &attrs->attrs[i], pos, end - pos);

    if (len < 0)
      return -1;

    pos += len;
  }

  return pos - buf;
}


/*
 *	Attribute decoding
 */

static void bgp_process_as4_attrs(ea_list **attrs, struct linpool *pool);

static inline int
bgp_as_path_loopy(struct bgp_proto *p, ea_list *attrs, u32 asn)
{
  eattr *e = bgp_find_attr(attrs, BA_AS_PATH);
  int num = p->cf->allow_local_as + 1;
  return (e && (num > 0) && as_path_contains(e->u.ptr, asn, num));
}

static inline int
bgp_originator_id_loopy(struct bgp_proto *p, ea_list *attrs)
{
  eattr *e = bgp_find_attr(attrs, BA_ORIGINATOR_ID);
  return (e && (e->u.data == p->local_id));
}

static inline int
bgp_cluster_list_loopy(struct bgp_proto *p, ea_list *attrs)
{
  eattr *e = bgp_find_attr(attrs, BA_CLUSTER_LIST);
  return (e && int_set_contains(e->u.ptr, p->rr_cluster_id));
}

static inline void
bgp_decode_attr(struct bgp_parse_state *s, uint code, uint flags, byte *data, uint len, ea_list **to)
{
  /* Handle duplicate attributes; RFC 7606 3 (g) */
  if (BIT32_TEST(s->attrs_seen, code))
  {
    if ((code == BA_MP_REACH_NLRI) || (code == BA_MP_UNREACH_NLRI))
      bgp_parse_error(s, 1);
    else
      DISCARD("Discarding duplicate attribute (code %u)", code);
  }
  BIT32_SET(s->attrs_seen, code);

  if (bgp_attr_known(code))
  {
    const struct bgp_attr_desc *desc = &bgp_attr_table[code];

    /* Handle conflicting flags; RFC 7606 3 (c) */
    if ((flags ^ desc->flags) & (BAF_OPTIONAL | BAF_TRANSITIVE))
      WITHDRAW("Malformed %s attribute - conflicting flags (%02x)", desc->name, flags);

    desc->decode(s, code, flags, data, len, to);
  }
  else /* Unknown attribute */
  {
    if (!(flags & BAF_OPTIONAL))
      WITHDRAW("Unknown attribute (code %u) - conflicting flags (%02x)", code, flags);

    bgp_decode_unknown(s, code, flags, data, len, to);
  }
}

/**
 * bgp_decode_attrs - check and decode BGP attributes
 * @s: BGP parse state
 * @data: start of attribute block
 * @len: length of attribute block
 *
 * This function takes a BGP attribute block (a part of an Update message), checks
 * its consistency and converts it to a list of BIRD route attributes represented
 * by an (uncached) &rta.
 */
ea_list *
bgp_decode_attrs(struct bgp_parse_state *s, byte *data, uint len)
{
  struct bgp_proto *p = s->proto;
  ea_list *attrs = NULL;
  uint code, flags, alen;
  byte *pos = data;

  /* Parse the attributes */
  while (len)
  {
    alen = 0;

    /* Read attribute type */
    if (len < 2)
      goto framing_error;
    flags = pos[0];
    code = pos[1];
    ADVANCE(pos, len, 2);

    /* Read attribute length */
    if (flags & BAF_EXT_LEN)
    {
      if (len < 2)
	goto framing_error;
      alen = get_u16(pos);
      ADVANCE(pos, len, 2);
    }
    else
    {
      if (len < 1)
	goto framing_error;
      alen = *pos;
      ADVANCE(pos, len, 1);
    }

    if (alen > len)
      goto framing_error;

    DBG("Attr %02x %02x %u\n", code, flags, alen);

    bgp_decode_attr(s, code, flags, pos, alen, &attrs);
    ADVANCE(pos, len, alen);
  }

  if (s->err_withdraw)
    goto withdraw;

  /* If there is no reachability NLRI, we are finished */
  if (!s->ip_reach_len && !s->mp_reach_len)
    return NULL;


  /* Handle missing mandatory attributes; RFC 7606 3 (d) */
  if (!BIT32_TEST(s->attrs_seen, BA_ORIGIN))
  { REPORT(NO_MANDATORY, "ORIGIN"); goto withdraw; }

  if (!BIT32_TEST(s->attrs_seen, BA_AS_PATH))
  { REPORT(NO_MANDATORY, "AS_PATH"); goto withdraw; }

  /* When receiving attributes from non-AS4-aware BGP speaker, we have to
     reconstruct AS_PATH and AGGREGATOR attributes; RFC 6793 4.2.3 */
  if (!p->as4_session)
    bgp_process_as4_attrs(&attrs, s->pool);

  /* Reject routes with our ASN in AS_PATH attribute */
  if (bgp_as_path_loopy(p, attrs, p->local_as))
    goto withdraw;

  /* Reject routes with our Confederation ID in AS_PATH attribute; RFC 5065 4 */
  if ((p->public_as != p->local_as) && bgp_as_path_loopy(p, attrs, p->public_as))
    goto withdraw;

  /* Reject routes with our Router ID in ORIGINATOR_ID attribute; RFC 4456 8 */
  if (p->is_internal && bgp_originator_id_loopy(p, attrs))
    goto withdraw;

  /* Reject routes with our Cluster ID in CLUSTER_LIST attribute; RFC 4456 8 */
  if (p->rr_client && bgp_cluster_list_loopy(p, attrs))
    goto withdraw;

  /* If there is no local preference, define one */
  if (!BIT32_TEST(s->attrs_seen, BA_LOCAL_PREF))
    bgp_set_attr_u32(&attrs, s->pool, BA_LOCAL_PREF, 0, p->cf->default_local_pref);

  return attrs;


framing_error:
  /* RFC 7606 4 - handle attribute framing errors */
  REPORT("Malformed attribute list - framing error (%u/%u) at %d",
	 alen, len, (int) (pos - s->attrs));

withdraw:
  /* RFC 7606 5.2 - handle missing NLRI during errors */
  if (!s->ip_reach_len && !s->mp_reach_len)
    bgp_parse_error(s, 1);

  s->err_withdraw = 1;
  return NULL;
}


/*
 *	Route bucket hash table
 */

#define RBH_KEY(b)		b->eattrs, b->hash
#define RBH_NEXT(b)		b->next
#define RBH_EQ(a1,h1,a2,h2)	h1 == h2 && ea_same(a1, a2)
#define RBH_FN(a,h)		h

#define RBH_REHASH		bgp_rbh_rehash
#define RBH_PARAMS		/8, *2, 2, 2, 8, 20


HASH_DEFINE_REHASH_FN(RBH, struct bgp_bucket)

void
bgp_init_bucket_table(struct bgp_channel *c)
{
  HASH_INIT(c->bucket_hash, c->pool, 8);

  init_list(&c->bucket_queue);
  c->withdraw_bucket = NULL;
}

static struct bgp_bucket *
bgp_get_bucket(struct bgp_channel *c, ea_list *new)
{
  /* Hash and lookup */
  u32 hash = ea_hash(new);
  struct bgp_bucket *b = HASH_FIND(c->bucket_hash, RBH, new, hash);

  if (b)
    return b;

  uint ea_size = sizeof(ea_list) + new->count * sizeof(eattr);
  uint ea_size_aligned = BIRD_ALIGN(ea_size, CPU_STRUCT_ALIGN);
  uint size = sizeof(struct bgp_bucket) + ea_size_aligned;
  uint i;
  byte *dest;

  /* Gather total size of non-inline attributes */
  for (i = 0; i < new->count; i++)
  {
    eattr *a = &new->attrs[i];

    if (!(a->type & EAF_EMBEDDED))
      size += BIRD_ALIGN(sizeof(struct adata) + a->u.ptr->length, CPU_STRUCT_ALIGN);
  }

  /* Create the bucket */
  b = mb_alloc(c->pool, size);
  init_list(&b->prefixes);
  b->hash = hash;

  /* Copy list of extended attributes */
  memcpy(b->eattrs, new, ea_size);
  dest = ((byte *) b->eattrs) + ea_size_aligned;

  /* Copy values of non-inline attributes */
  for (i = 0; i < new->count; i++)
  {
    eattr *a = &b->eattrs->attrs[i];

    if (!(a->type & EAF_EMBEDDED))
    {
      struct adata *oa = a->u.ptr;
      struct adata *na = (struct adata *) dest;
      memcpy(na, oa, sizeof(struct adata) + oa->length);
      a->u.ptr = na;
      dest += BIRD_ALIGN(sizeof(struct adata) + na->length, CPU_STRUCT_ALIGN);
    }
  }

  /* Insert the bucket to send queue and bucket hash */
  add_tail(&c->bucket_queue, &b->send_node);
  HASH_INSERT2(c->bucket_hash, RBH, c->pool, b);

  return b;
}

static struct bgp_bucket *
bgp_get_withdraw_bucket(struct bgp_channel *c)
{
  if (!c->withdraw_bucket)
  {
    c->withdraw_bucket = mb_allocz(c->pool, sizeof(struct bgp_bucket));
    init_list(&c->withdraw_bucket->prefixes);
  }

  return c->withdraw_bucket;
}

void
bgp_free_bucket(struct bgp_channel *c, struct bgp_bucket *b)
{
  rem_node(&b->send_node);
  HASH_REMOVE2(c->bucket_hash, RBH, c->pool, b);
  mb_free(b);
}

void
bgp_defer_bucket(struct bgp_channel *c, struct bgp_bucket *b)
{
  rem_node(&b->send_node);
  add_tail(&c->bucket_queue, &b->send_node);
}

void
bgp_withdraw_bucket(struct bgp_channel *c, struct bgp_bucket *b)
{
  struct bgp_proto *p = (void *) c->c.proto;
  struct bgp_bucket *wb = bgp_get_withdraw_bucket(c);

  log(L_ERR "%s: Attribute list too long", p->p.name);
  while (!EMPTY_LIST(b->prefixes))
  {
    struct bgp_prefix *px = HEAD(b->prefixes);

    log(L_ERR "%s: - withdrawing %N", p->p.name, &px->net);
    rem_node(&px->buck_node);
    add_tail(&wb->prefixes, &px->buck_node);
  }
}


/*
 *	Prefix hash table
 */

#define PXH_KEY(px)		px->net, px->path_id, px->hash
#define PXH_NEXT(px)		px->next
#define PXH_EQ(n1,i1,h1,n2,i2,h2) h1 == h2 && i1 == i2 && net_equal(n1, n2)
#define PXH_FN(n,i,h)		h

#define PXH_REHASH		bgp_pxh_rehash
#define PXH_PARAMS		/8, *2, 2, 2, 8, 20


HASH_DEFINE_REHASH_FN(PXH, struct bgp_prefix)

void
bgp_init_prefix_table(struct bgp_channel *c)
{
  HASH_INIT(c->prefix_hash, c->pool, 8);

  c->prefix_slab = sl_new(c->pool, sizeof(struct bgp_prefix) +
			  net_addr_length[c->c.net_type]);
}

static struct bgp_prefix *
bgp_get_prefix(struct bgp_channel *c, net_addr *net, u32 path_id)
{
  u32 hash = net_hash(net) ^ u32_hash(path_id);

  struct bgp_prefix *px = HASH_FIND(c->prefix_hash, PXH, net, path_id, hash);

  if (px)
  {
    rem_node(&px->buck_node);
    return px;
  }

  px = sl_alloc(c->prefix_slab);
  px->buck_node.next = NULL;
  px->buck_node.prev = NULL;
  px->hash = hash;
  px->path_id = path_id;
  net_copy(px->net, net);

  HASH_INSERT2(c->prefix_hash, PXH, c->pool, px);

  return px;
}

void
bgp_free_prefix(struct bgp_channel *c, struct bgp_prefix *px)
{
  rem_node(&px->buck_node);
  HASH_REMOVE2(c->prefix_hash, PXH, c->pool, px);
  sl_free(c->prefix_slab, px);
}


/*
 *	BGP protocol glue
 */

int
bgp_import_control(struct proto *P, rte **new, ea_list **attrs UNUSED, struct linpool *pool UNUSED)
{
  rte *e = *new;
  struct proto *SRC = e->attrs->src->proto;
  struct bgp_proto *p = (struct bgp_proto *) P;
  struct bgp_proto *src = (SRC->proto == &proto_bgp) ? (struct bgp_proto *) SRC : NULL;

  /* Reject our routes */
  if (src == p)
    return -1;

  /* Accept non-BGP routes */
  if (src == NULL)
    return 0;

  /* IBGP route reflection, RFC 4456 */
  if (p->is_internal && src->is_internal && (p->local_as == src->local_as))
  {
    /* Rejected unless configured as route reflector */
    if (!p->rr_client && !src->rr_client)
      return -1;

    /* Generally, this should be handled when path is received, but we check it
       also here as rr_cluster_id may be undefined or different in src. */
    if (p->rr_cluster_id && bgp_cluster_list_loopy(p, e->attrs->eattrs))
      return -1;
  }

  /* Handle well-known communities, RFC 1997 */
  struct eattr *c;
  if (p->cf->interpret_communities &&
      (c = ea_find(e->attrs->eattrs, EA_CODE(EAP_BGP, BA_COMMUNITY))))
  {
    struct adata *d = c->u.ptr;

    /* Do not export anywhere */
    if (int_set_contains(d, BGP_COMM_NO_ADVERTISE))
      return -1;

    /* Do not export outside of AS (or member-AS) */
    if (!p->is_internal && int_set_contains(d, BGP_COMM_NO_EXPORT_SUBCONFED))
      return -1;

    /* Do not export outside of AS (or confederation) */
    if (!p->is_interior && int_set_contains(d, BGP_COMM_NO_EXPORT))
      return -1;
  }

  return 0;
}

static const adata null_adata;	/* adata of length 0 */

static inline void
bgp_path_prepend(ea_list **attrs, struct linpool *pool, int seg, u32 as, int strip)
{
  eattr *a = bgp_find_attr(*attrs, BA_AS_PATH);
  adata *d = as_path_prepend2(pool, a ? a->u.ptr : &null_adata, seg, as, strip);
  bgp_set_attr_ptr(attrs, pool, BA_AS_PATH, 0, d);
}

static inline void
bgp_cluster_list_prepend(ea_list **attrs, struct linpool *pool, u32 id)
{
  eattr *a = bgp_find_attr(*attrs, BA_CLUSTER_LIST);
  adata *d = int_set_add(pool, a ? a->u.ptr : NULL, id);
  bgp_set_attr_ptr(attrs, pool, BA_CLUSTER_LIST, 0, d);
}

static ea_list *
bgp_update_attrs(struct bgp_proto *p, struct bgp_channel *c, rte *e, ea_list *attrs, net_addr *n, struct linpool *pool)
{
  struct proto *SRC = e->attrs->src->proto;
  struct bgp_proto *src = (SRC->proto == &proto_bgp) ? (void *) SRC : NULL;
  struct bgp_export_state s = {
    .proto = p, .channel = c, .pool = pool, .src = src, .route = e, .n = n,
  };
  eattr *a;

  /* ORIGIN attribute - mandatory, attach if missing */
  if (! bgp_find_attr(attrs, BA_ORIGIN))
    bgp_set_attr_u32(&attrs, pool, BA_ORIGIN, 0, src ? ORIGIN_INCOMPLETE : ORIGIN_IGP);

  /* AS_PATH attribute - keep or prepend ASN */
  if (p->is_internal ||
      (p->rs_client && src && src->rs_client))
  {
    /* IBGP or route server -> just ensure there is one */
    if (! bgp_find_attr(attrs, BA_AS_PATH))
      bgp_set_attr_ptr(&attrs, pool, BA_AS_PATH, 0, lp_alloc_adata(pool, 0));
  }
  else if (p->is_interior)
  {
    /* Confederation -> prepend ASN as CONFED_SEQUENCE, keep CONFED_* segments */
    bgp_path_prepend(&attrs, pool, AS_PATH_CONFED_SEQUENCE, p->public_as, 0);
  }
  else /* Regular EBGP (no RS, no confederation) */
  {
    /* Regular EBGP -> prepend ASN as regular segment, strip CONFED_* segments */
    bgp_path_prepend(&attrs, pool, AS_PATH_SEQUENCE, p->public_as, 1);

    /* MULTI_EXIT_DESC attribute - accept only if set in export filter */
    a = bgp_find_attr(attrs, BA_MULTI_EXIT_DISC);
    if (a && !(a->type & EAF_FRESH))
      bgp_unset_attr(&attrs, pool, BA_MULTI_EXIT_DISC);
  }

  /* NEXT_HOP attribute - delegated to AF-specific hook */
  a = bgp_find_attr(attrs, BA_NEXT_HOP);
  bgp_update_next_hop(&s, a, &attrs);

  /* LOCAL_PREF attribute - required for IBGP, attach if missing */
  if (p->is_interior && ! bgp_find_attr(attrs, BA_LOCAL_PREF))
    bgp_set_attr_u32(&attrs, pool, BA_LOCAL_PREF, 0, p->cf->default_local_pref);

  /* IBGP route reflection, RFC 4456 */
  if (src && src->is_internal && p->is_internal && (src->local_as == p->local_as))
  {
    /* ORIGINATOR_ID attribute - attach if not already set */
    if (! bgp_find_attr(attrs, BA_ORIGINATOR_ID))
      bgp_set_attr_u32(&attrs, pool, BA_ORIGINATOR_ID, 0, src->remote_id);

    /* CLUSTER_LIST attribute - prepend cluster ID */
    if (src->rr_cluster_id)
      bgp_cluster_list_prepend(&attrs, pool, src->rr_cluster_id);

    /* Handle different src and dst cluster ID - prepend both ones */
    if (p->rr_cluster_id && (src->rr_cluster_id != p->rr_cluster_id))
      bgp_cluster_list_prepend(&attrs, pool, p->rr_cluster_id);
  }

  /* AS4_* transition attributes, RFC 6793 4.2.2 */
  if (! p->as4_session)
  {
    a = bgp_find_attr(attrs, BA_AS_PATH);
    if (a && as_path_contains_as4(a->u.ptr))
    {
      bgp_set_attr_ptr(&attrs, pool, BA_AS_PATH, 0, as_path_to_old(pool, a->u.ptr));
      bgp_set_attr_ptr(&attrs, pool, BA_AS4_PATH, 0, as_path_strip_confed(pool, a->u.ptr));
    }

    a = bgp_find_attr(attrs, BA_AGGREGATOR);
    if (a && aggregator_contains_as4(a->u.ptr))
    {
      bgp_set_attr_ptr(&attrs, pool, BA_AGGREGATOR, 0, aggregator_to_old(pool, a->u.ptr));
      bgp_set_attr_ptr(&attrs, pool, BA_AS4_AGGREGATOR, 0, a->u.ptr);
    }
  }

  /* Apply per-attribute export hooks for validatation and normalization */
  return bgp_export_attrs(&s, attrs);
}

void
bgp_rt_notify(struct proto *P, struct channel *C, net *n, rte *new, rte *old, ea_list *attrs)
{
  struct bgp_proto *p = (void *) P;
  struct bgp_channel *c = (void *) C;
  struct bgp_bucket *buck;
  struct bgp_prefix *px;
  u32 path;

  net_addr *na = n->n.addr;

  if (new)
  {
    na = alloca(sizeof(net_addr) + MPLS_MAX_LABEL_STACK * sizeof(u32));
    net_copy(na, n->n.addr);

    attrs = bgp_update_attrs(p, c, new, attrs, na, bgp_linpool);

    /* If attributes are invalid, we fail back to withdraw */
    buck = attrs ? bgp_get_bucket(c, attrs) : bgp_get_withdraw_bucket(c);
    path = new->attrs->src->global_id;

    lp_flush(bgp_linpool);
  }
  else
  {
    buck = bgp_get_withdraw_bucket(c);
    path = old->attrs->src->global_id;
  }

  px = bgp_get_prefix(c, na, c->add_path_tx ? path : 0);
  add_tail(&buck->prefixes, &px->buck_node);

  bgp_schedule_packet(p->conn, c, PKT_UPDATE);
}


static inline u32
bgp_get_neighbor(rte *r)
{
  eattr *e = ea_find(r->attrs->eattrs, EA_CODE(EAP_BGP, BA_AS_PATH));
  u32 as;

  if (e && as_path_get_first(e->u.ptr, &as))
    return as;
  else
    return ((struct bgp_proto *) r->attrs->src->proto)->remote_as;
}

static inline int
rte_resolvable(rte *rt)
{
  int rd = rt->attrs->dest;
  return (rd == RTD_UNICAST);
}

int
bgp_rte_better(rte *new, rte *old)
{
  struct bgp_proto *new_bgp = (struct bgp_proto *) new->attrs->src->proto;
  struct bgp_proto *old_bgp = (struct bgp_proto *) old->attrs->src->proto;
  eattr *x, *y;
  u32 n, o;

  /* Skip suppressed routes (see bgp_rte_recalculate()) */
  n = new->u.bgp.suppressed;
  o = old->u.bgp.suppressed;
  if (n > o)
    return 0;
  if (n < o)
    return 1;

  /* RFC 4271 9.1.2.1. Route resolvability test */
  n = rte_resolvable(new);
  o = rte_resolvable(old);
  if (n > o)
    return 1;
  if (n < o)
    return 0;

  /* Start with local preferences */
  x = ea_find(new->attrs->eattrs, EA_CODE(EAP_BGP, BA_LOCAL_PREF));
  y = ea_find(old->attrs->eattrs, EA_CODE(EAP_BGP, BA_LOCAL_PREF));
  n = x ? x->u.data : new_bgp->cf->default_local_pref;
  o = y ? y->u.data : old_bgp->cf->default_local_pref;
  if (n > o)
    return 1;
  if (n < o)
    return 0;

  /* RFC 4271 9.1.2.2. a)  Use AS path lengths */
  if (new_bgp->cf->compare_path_lengths || old_bgp->cf->compare_path_lengths)
  {
    x = ea_find(new->attrs->eattrs, EA_CODE(EAP_BGP, BA_AS_PATH));
    y = ea_find(old->attrs->eattrs, EA_CODE(EAP_BGP, BA_AS_PATH));
    n = x ? as_path_getlen(x->u.ptr) : AS_PATH_MAXLEN;
    o = y ? as_path_getlen(y->u.ptr) : AS_PATH_MAXLEN;
    if (n < o)
      return 1;
    if (n > o)
      return 0;
  }

  /* RFC 4271 9.1.2.2. b) Use origins */
  x = ea_find(new->attrs->eattrs, EA_CODE(EAP_BGP, BA_ORIGIN));
  y = ea_find(old->attrs->eattrs, EA_CODE(EAP_BGP, BA_ORIGIN));
  n = x ? x->u.data : ORIGIN_INCOMPLETE;
  o = y ? y->u.data : ORIGIN_INCOMPLETE;
  if (n < o)
    return 1;
  if (n > o)
    return 0;

  /* RFC 4271 9.1.2.2. c) Compare MED's */
  /* Proper RFC 4271 path selection cannot be interpreted as finding
   * the best path in some ordering. It is implemented partially in
   * bgp_rte_recalculate() when deterministic_med option is
   * active. Without that option, the behavior is just an
   * approximation, which in specific situations may lead to
   * persistent routing loops, because it is nondeterministic - it
   * depends on the order in which routes appeared. But it is also the
   * same behavior as used by default in Cisco routers, so it is
   * probably not a big issue.
   */
  if (new_bgp->cf->med_metric || old_bgp->cf->med_metric ||
      (bgp_get_neighbor(new) == bgp_get_neighbor(old)))
  {
    x = ea_find(new->attrs->eattrs, EA_CODE(EAP_BGP, BA_MULTI_EXIT_DISC));
    y = ea_find(old->attrs->eattrs, EA_CODE(EAP_BGP, BA_MULTI_EXIT_DISC));
    n = x ? x->u.data : new_bgp->cf->default_med;
    o = y ? y->u.data : old_bgp->cf->default_med;
    if (n < o)
      return 1;
    if (n > o)
      return 0;
  }

  /* RFC 4271 9.1.2.2. d) Prefer external peers */
  if (new_bgp->is_interior > old_bgp->is_interior)
    return 0;
  if (new_bgp->is_interior < old_bgp->is_interior)
    return 1;

  /* RFC 4271 9.1.2.2. e) Compare IGP metrics */
  n = new_bgp->cf->igp_metric ? new->attrs->igp_metric : 0;
  o = old_bgp->cf->igp_metric ? old->attrs->igp_metric : 0;
  if (n < o)
    return 1;
  if (n > o)
    return 0;

  /* RFC 4271 9.1.2.2. f) Compare BGP identifiers */
  /* RFC 4456 9. a) Use ORIGINATOR_ID instead of local neighbor ID */
  x = ea_find(new->attrs->eattrs, EA_CODE(EAP_BGP, BA_ORIGINATOR_ID));
  y = ea_find(old->attrs->eattrs, EA_CODE(EAP_BGP, BA_ORIGINATOR_ID));
  n = x ? x->u.data : new_bgp->remote_id;
  o = y ? y->u.data : old_bgp->remote_id;

  /* RFC 5004 - prefer older routes */
  /* (if both are external and from different peer) */
  if ((new_bgp->cf->prefer_older || old_bgp->cf->prefer_older) &&
      !new_bgp->is_internal && n != o)
    return 0;

  /* rest of RFC 4271 9.1.2.2. f) */
  if (n < o)
    return 1;
  if (n > o)
    return 0;

  /* RFC 4456 9. b) Compare cluster list lengths */
  x = ea_find(new->attrs->eattrs, EA_CODE(EAP_BGP, BA_CLUSTER_LIST));
  y = ea_find(old->attrs->eattrs, EA_CODE(EAP_BGP, BA_CLUSTER_LIST));
  n = x ? int_set_get_size(x->u.ptr) : 0;
  o = y ? int_set_get_size(y->u.ptr) : 0;
  if (n < o)
    return 1;
  if (n > o)
    return 0;

  /* RFC 4271 9.1.2.2. g) Compare peer IP adresses */
  return (ipa_compare(new_bgp->cf->remote_ip, old_bgp->cf->remote_ip) < 0);
}


int
bgp_rte_mergable(rte *pri, rte *sec)
{
  struct bgp_proto *pri_bgp = (struct bgp_proto *) pri->attrs->src->proto;
  struct bgp_proto *sec_bgp = (struct bgp_proto *) sec->attrs->src->proto;
  eattr *x, *y;
  u32 p, s;

  /* Skip suppressed routes (see bgp_rte_recalculate()) */
  if (pri->u.bgp.suppressed != sec->u.bgp.suppressed)
    return 0;

  /* RFC 4271 9.1.2.1. Route resolvability test */
  if (!rte_resolvable(sec))
    return 0;

  /* Start with local preferences */
  x = ea_find(pri->attrs->eattrs, EA_CODE(EAP_BGP, BA_LOCAL_PREF));
  y = ea_find(sec->attrs->eattrs, EA_CODE(EAP_BGP, BA_LOCAL_PREF));
  p = x ? x->u.data : pri_bgp->cf->default_local_pref;
  s = y ? y->u.data : sec_bgp->cf->default_local_pref;
  if (p != s)
    return 0;

  /* RFC 4271 9.1.2.2. a)  Use AS path lengths */
  if (pri_bgp->cf->compare_path_lengths || sec_bgp->cf->compare_path_lengths)
  {
    x = ea_find(pri->attrs->eattrs, EA_CODE(EAP_BGP, BA_AS_PATH));
    y = ea_find(sec->attrs->eattrs, EA_CODE(EAP_BGP, BA_AS_PATH));
    p = x ? as_path_getlen(x->u.ptr) : AS_PATH_MAXLEN;
    s = y ? as_path_getlen(y->u.ptr) : AS_PATH_MAXLEN;

    if (p != s)
      return 0;

//    if (DELTA(p, s) > pri_bgp->cf->relax_multipath)
//      return 0;
  }

  /* RFC 4271 9.1.2.2. b) Use origins */
  x = ea_find(pri->attrs->eattrs, EA_CODE(EAP_BGP, BA_ORIGIN));
  y = ea_find(sec->attrs->eattrs, EA_CODE(EAP_BGP, BA_ORIGIN));
  p = x ? x->u.data : ORIGIN_INCOMPLETE;
  s = y ? y->u.data : ORIGIN_INCOMPLETE;
  if (p != s)
    return 0;

  /* RFC 4271 9.1.2.2. c) Compare MED's */
  if (pri_bgp->cf->med_metric || sec_bgp->cf->med_metric ||
      (bgp_get_neighbor(pri) == bgp_get_neighbor(sec)))
  {
    x = ea_find(pri->attrs->eattrs, EA_CODE(EAP_BGP, BA_MULTI_EXIT_DISC));
    y = ea_find(sec->attrs->eattrs, EA_CODE(EAP_BGP, BA_MULTI_EXIT_DISC));
    p = x ? x->u.data : pri_bgp->cf->default_med;
    s = y ? y->u.data : sec_bgp->cf->default_med;
    if (p != s)
      return 0;
  }

  /* RFC 4271 9.1.2.2. d) Prefer external peers */
  if (pri_bgp->is_internal != sec_bgp->is_internal)
    return 0;

  /* RFC 4271 9.1.2.2. e) Compare IGP metrics */
  p = pri_bgp->cf->igp_metric ? pri->attrs->igp_metric : 0;
  s = sec_bgp->cf->igp_metric ? sec->attrs->igp_metric : 0;
  if (p != s)
    return 0;

  /* Remaining criteria are ignored */

  return 1;
}


static inline int
same_group(rte *r, u32 lpref, u32 lasn)
{
  return (r->pref == lpref) && (bgp_get_neighbor(r) == lasn);
}

static inline int
use_deterministic_med(rte *r)
{
  struct proto *P = r->attrs->src->proto;
  return (P->proto == &proto_bgp) && ((struct bgp_proto *) P)->cf->deterministic_med;
}

int
bgp_rte_recalculate(rtable *table, net *net, rte *new, rte *old, rte *old_best)
{
  rte *r, *s;
  rte *key = new ? new : old;
  u32 lpref = key->pref;
  u32 lasn = bgp_get_neighbor(key);
  int old_is_group_best = 0;

  /*
   * Proper RFC 4271 path selection is a bit complicated, it cannot be
   * implemented just by rte_better(), because it is not a linear
   * ordering. But it can be splitted to two levels, where the lower
   * level chooses the best routes in each group of routes from the
   * same neighboring AS and higher level chooses the best route (with
   * a slightly different ordering) between the best-in-group routes.
   *
   * When deterministic_med is disabled, we just ignore this issue and
   * choose the best route by bgp_rte_better() alone. If enabled, the
   * lower level of the route selection is done here (for the group
   * to which the changed route belongs), all routes in group are
   * marked as suppressed, just chosen best-in-group is not.
   *
   * Global best route selection then implements higher level by
   * choosing between non-suppressed routes (as they are always
   * preferred over suppressed routes). Routes from BGP protocols
   * that do not set deterministic_med are just never suppressed. As
   * they do not participate in the lower level selection, it is OK
   * that this fn is not called for them.
   *
   * The idea is simple, the implementation is more problematic,
   * mostly because of optimizations in rte_recalculate() that
   * avoids full recalculation in most cases.
   *
   * We can assume that at least one of new, old is non-NULL and both
   * are from the same protocol with enabled deterministic_med. We
   * group routes by both neighbor AS (lasn) and preference (lpref),
   * because bgp_rte_better() does not handle preference itself.
   */

  /* If new and old are from different groups, we just process that
     as two independent events */
  if (new && old && !same_group(old, lpref, lasn))
  {
    int i1, i2;
    i1 = bgp_rte_recalculate(table, net, NULL, old, old_best);
    i2 = bgp_rte_recalculate(table, net, new, NULL, old_best);
    return i1 || i2;
  }

  /*
   * We could find the best-in-group and then make some shortcuts like
   * in rte_recalculate, but as we would have to walk through all
   * net->routes just to find it, it is probably not worth. So we
   * just have two simpler fast cases that use just the old route.
   * We also set suppressed flag to avoid using it in bgp_rte_better().
   */

  if (new)
    new->u.bgp.suppressed = 1;

  if (old)
  {
    old_is_group_best = !old->u.bgp.suppressed;
    old->u.bgp.suppressed = 1;
    int new_is_better = new && bgp_rte_better(new, old);

    /* The first case - replace not best with worse (or remove not best) */
    if (!old_is_group_best && !new_is_better)
      return 0;

    /* The second case - replace the best with better */
    if (old_is_group_best && new_is_better)
    {
      /* new is best-in-group, the see discussion below - this is
	 a special variant of NBG && OBG. From OBG we can deduce
	 that same_group(old_best) iff (old == old_best)  */
      new->u.bgp.suppressed = 0;
      return (old == old_best);
    }
  }

  /* The default case - find a new best-in-group route */
  r = new; /* new may not be in the list */
  for (s=net->routes; rte_is_valid(s); s=s->next)
    if (use_deterministic_med(s) && same_group(s, lpref, lasn))
    {
      s->u.bgp.suppressed = 1;
      if (!r || bgp_rte_better(s, r))
	r = s;
    }

  /* Simple case - the last route in group disappears */
  if (!r)
    return 0;

  /* Found best-in-group */
  r->u.bgp.suppressed = 0;

  /*
   * There are generally two reasons why we have to force
   * recalculation (return 1): First, the new route may be wrongfully
   * chosen to be the best in the first case check in
   * rte_recalculate(), this may happen only if old_best is from the
   * same group. Second, another (different than new route)
   * best-in-group is chosen and that may be the proper best (although
   * rte_recalculate() without ignore that possibility).
   *
   * There are three possible cases according to whether the old route
   * was the best in group (OBG, stored in old_is_group_best) and
   * whether the new route is the best in group (NBG, tested by r == new).
   * These cases work even if old or new is NULL.
   *
   * NBG -> new is a possible candidate for the best route, so we just
   *        check for the first reason using same_group().
   *
   * !NBG && OBG -> Second reason applies, return 1
   *
   * !NBG && !OBG -> Best in group does not change, old != old_best,
   *                 rte_better(new, old_best) is false and therefore
   *                 the first reason does not apply, return 0
   */

  if (r == new)
    return old_best && same_group(old_best, lpref, lasn);
  else
    return old_is_group_best;
}


/*
 * Reconstruct AS_PATH and AGGREGATOR according to RFC 6793 4.2.3
 */
static void
bgp_process_as4_attrs(ea_list **attrs, struct linpool *pool)
{
  eattr *p2 = bgp_find_attr(*attrs, BA_AS_PATH);
  eattr *p4 = bgp_find_attr(*attrs, BA_AS4_PATH);
  eattr *a2 = bgp_find_attr(*attrs, BA_AGGREGATOR);
  eattr *a4 = bgp_find_attr(*attrs, BA_AS4_AGGREGATOR);

  /* First, unset AS4_* attributes */
  if (p4) bgp_unset_attr(attrs, pool, BA_AS4_PATH);
  if (a4) bgp_unset_attr(attrs, pool, BA_AS4_AGGREGATOR);

  /* Handle AGGREGATOR attribute */
  if (a2 && a4)
  {
    u32 a2_asn = get_u32(a2->u.ptr->data);

    /* If routes were aggregated by an old router, then AS4_PATH and
       AS4_AGGREGATOR are invalid. In that case we give up. */
    if (a2_asn != AS_TRANS)
      return;

    /* Use AS4_AGGREGATOR instead of AGGREGATOR */
    a2->u.ptr = a4->u.ptr;
  }

  /* Handle AS_PATH attribute */
  if (p2 && p4)
  {
    int p2_len = as_path_getlen(p2->u.ptr);
    int p4_len = as_path_getlen(p4->u.ptr);

    /* AS_PATH is too short, give up */
    if (p2_len < p4_len)
      return;

    /* Merge AS_PATH and AS4_PATH */
    as_path_cut(p2->u.ptr, p2_len - p4_len);
    p2->u.ptr = as_path_merge(pool, p2->u.ptr, p4->u.ptr);
  }
}

int
bgp_get_attr(eattr *a, byte *buf, int buflen)
{
  uint i = EA_ID(a->id);
  const struct bgp_attr_desc *d;
  int len;

  if (bgp_attr_known(i))
  {
    d = &bgp_attr_table[i];
    len = bsprintf(buf, "%s", d->name);
    buf += len;
    if (d->format)
    {
      *buf++ = ':';
      *buf++ = ' ';
      d->format(a, buf, buflen - len - 2);
      return GA_FULL;
    }
    return GA_NAME;
  }

  bsprintf(buf, "%02x%s", i, (a->flags & BAF_TRANSITIVE) ? " [t]" : "");
  return GA_NAME;
}

void
bgp_get_route_info(rte *e, byte *buf, ea_list *attrs)
{
  eattr *p = ea_find(attrs, EA_CODE(EAP_BGP, BA_AS_PATH));
  eattr *o = ea_find(attrs, EA_CODE(EAP_BGP, BA_ORIGIN));
  u32 origas;

  buf += bsprintf(buf, " (%d", e->pref);

  if (e->u.bgp.suppressed)
    buf += bsprintf(buf, "-");

  if (e->attrs->hostentry)
  {
    if (!rte_resolvable(e))
      buf += bsprintf(buf, "/-");
    else if (e->attrs->igp_metric >= IGP_METRIC_UNKNOWN)
      buf += bsprintf(buf, "/?");
    else
      buf += bsprintf(buf, "/%d", e->attrs->igp_metric);
  }
  buf += bsprintf(buf, ") [");

  if (p && as_path_get_last(p->u.ptr, &origas))
    buf += bsprintf(buf, "AS%u", origas);
  if (o)
    buf += bsprintf(buf, "%c", "ie?"[o->u.data]);
  strcpy(buf, "]");
}
