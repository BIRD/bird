#ifndef _BIRD_MPLS_H_
#define _BIRD_MPLS_H_

#include "nest/protocol.h"
#include "nest/route.h"

struct mpls_config {
  struct proto_config c;
  u8 mpls_channel; /* check (bool) whether there is a MPLS channel configured */
};

struct mpls_proto {
  struct proto p;
  struct channel *mpls_channel;
};

#endif
