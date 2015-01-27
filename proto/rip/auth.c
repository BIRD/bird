/*
 *	Rest in pieces - RIP protocol
 *
 *	Copyright (c) 1999 Pavel Machek <pavel@ucw.cz>
 *	Copyright (c) 2004 Ondrej Filip <feela@network.cz>
 *
 *	Bug fixes by Eric Leblond <eleblond@init-sys.com>, April 2003
 * 
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#undef LOCAL_DEBUG

#include "nest/bird.h"
#include "nest/iface.h"
#include "nest/protocol.h"
#include "nest/route.h"
#include "lib/socket.h"
#include "lib/resource.h"
#include "lib/lists.h"
#include "lib/timer.h"
#include "lib/md5.h"
#include "lib/string.h"

#include "rip.h"

#define PACKET_LEN(num) (num * sizeof(struct rip_block) + sizeof(struct rip_packet_heading))

/*
 * rip_incoming_authentication - check authentication of incomming packet and return 1 if there's problem.
 */
int
rip_incoming_authentication(struct rip_proto *p, struct rip_block_auth *block, struct rip_packet *packet, int num, ip_addr who_told_me)
{
  struct rip_config *cf = (struct rip_config *) p->p.cf;
  DBG("Incoming authentication: ");
  switch (ntohs(block->auth_type))
  { /* Authentication type */
    case AUTH_PLAINTEXT:
      {
	struct password_item *passwd = password_find(cf->passwords, 1);
	DBG("Plaintext passwd");
	if (!passwd)
	{
	  log(L_AUTH "No passwords set and password authentication came");
	  return 1;
	}
	if (strncmp((char *) (&block->packet_len), passwd->password, 16))
	{
	  log(L_AUTH "Passwd authentication failed!");
	  DBG("Expected %s, got %.16s\n", passwd->password, &block->packet_len);
	  return 1;
	}
      }
      break;
    case AUTH_MD5:
      DBG("md5 password");
      {
	struct password_item *pass = NULL, *ptmp;
	struct rip_md5_tail *tail;
	struct MD5Context ctxt;
	char md5sum_packet[16];
	char md5sum_computed[16];
	struct neighbor *neigh = neigh_find(&p->p, &who_told_me, 0);
	list *l = cf->passwords;

	if (ntohs(block->packet_len) != PACKET_LEN(num) - sizeof(struct rip_md5_tail))
	{
	  log(L_ERR "Packet length in MD5 does not match computed value");
	  return 1;
	}

	tail = (struct rip_md5_tail *) ((char *) packet + (ntohs(block->packet_len)));
	if ((tail->must_be_FFFF != 0xffff) || (ntohs(tail->must_be_0001) != 0x0001))
	{
	  log(L_ERR "MD5 tail signature is not there");
	  return 1;
	}

	WALK_LIST(ptmp, *l)
	{
	  if (block->key_id != ptmp->id)
	    continue;
	  if ((ptmp->genfrom > now_real) || (ptmp->gento < now_real))
	    continue;
	  pass = ptmp;
	  break;
	}

	if (!pass)
	  return 1;

	if (!neigh)
	{
	  log(L_AUTH "Non-neighbour MD5 checksummed packet?");
	}
	else
	{
	  if (neigh->aux > block->seq)
	  {
	    log(L_AUTH "MD5 protected packet with lower numbers");
	    return 1;
	  }
	  neigh->aux = block->seq;
	}

	memcpy(md5sum_packet, tail->md5, 16);
	password_cpy(tail->md5, pass->password, 16);

	MD5Init(&ctxt);
	MD5Update(&ctxt, (char *) packet, ntohs(block->packet_len) + sizeof(struct rip_block_auth));
	MD5Final(md5sum_computed, &ctxt);
	if (memcmp(md5sum_packet, md5sum_computed, 16))
	  return 1;
      }
  }
    
  return 0;
}

/*
 * rip_outgoing_authentication - append authentication information to the packet.
 * %num: number of rip_blocks already in packets. This function returns size of packet to send.
 */
int
rip_outgoing_authentication(struct rip_config *cf, struct rip_block_auth *block, struct rip_packet *packet, int num)
{
  struct password_item *passwd = password_find(cf->passwords, 1);

  if (!cf->auth_type)
    return PACKET_LEN(num);

  DBG("Outgoing authentication: ");

  if (!passwd) {
    log(L_ERR "No suitable password found for authentication");
    return PACKET_LEN(num);
  }

  block->auth_type = htons(cf->auth_type);
  block->must_be_FFFF = 0xffff;
  switch (cf->auth_type) {
  case AUTH_PLAINTEXT:
    password_cpy( (char *) (&block->packet_len), passwd->password, 16);
    return PACKET_LEN(num);
  case AUTH_MD5:
    {
      struct rip_md5_tail *tail;
      struct MD5Context ctxt;
      static u32 sequence = 0;

      if (num > MAX_RTEs_IN_PACKET_WITH_MD5_AUTH)
	bug("We can not add MD5 authentication to this long packet");

      /* need to preset the sequence number to a sane value */
      if (!sequence)
	sequence = (u32) time(NULL);

      block->key_id = passwd->id;
      block->auth_len = sizeof(struct rip_block_auth);
      block->seq = sequence++;
      block->zero0 = 0;
      block->zero1 = 0;
      block->packet_len = htons(PACKET_LEN(num));
      tail = (struct rip_md5_tail *) ((char *) packet + PACKET_LEN(num));
      tail->must_be_FFFF = 0xffff;
      tail->must_be_0001 = htons(0x0001);

      password_cpy(tail->md5, passwd->password, 16);
      MD5Init(&ctxt);
      MD5Update(&ctxt, (char *) packet, PACKET_LEN(num) + sizeof(struct  rip_md5_tail));
      MD5Final(tail->md5, &ctxt);
      return PACKET_LEN(num) + block->auth_len;
    }
  default:
    bug("Unknown authtype in outgoing authentication?");
  }
}
