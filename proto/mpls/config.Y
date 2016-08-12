/*
 *	BIRD -- MPLS configuration
 *
 *	(c) 2016 Jan Moskyto Matejka <mq@ucw.cz>
 *	(c) 2016 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

CF_HDR

#include "proto/mpls/mpls.h"

CF_DEFINES

#define MPLS_CFG ((struct mpls_config *) this_proto)

CF_DECLS

CF_KEYWORDS(MPLS, SOMETHING)

CF_GRAMMAR

CF_ADDTO(proto, mpls_proto '}')

mpls_proto_start: proto_start MPLS
{
  this_proto = proto_config_new(&proto_mpls, $1);
};

mpls_proto:
   mpls_proto_start proto_name '{'
 | mpls_proto proto_item ';'
 | mpls_proto proto_channel ';' {
    if ($2->net_type == NET_MPLS) {
      if (MPLS_CFG->mpls_channel)
	cf_error("Only one MPLS channel allowed in MPLS protocol");
      MPLS_CFG->mpls_channel = 1;
    }
  }
 ;

CF_CODE

CF_END
