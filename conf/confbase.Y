/*
 *	BIRD -- Configuration Parser Top
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

CF_HDR

#define PARSER 1

#include "nest/bird.h"
#include "conf/conf.h"
#include "lib/resource.h"
#include "lib/socket.h"
#include "lib/timer.h"
#include "lib/string.h"
#include "nest/protocol.h"
#include "nest/iface.h"
#include "nest/route.h"
#include "nest/cli.h"
#include "filter/filter.h"

/* FIXME: Turn on YYERROR_VERBOSE and work around lots of bison bugs? */

CF_DEFINES

static void
check_u16(uint val)
{
  if (val > 0xFFFF)
    cf_error("Value %u out of range (0-65535)", val);
}

CF_DECLS

%union {
  uint i;
  u32 i32;
  u64 i64;
  ip_addr a;
  ip4_addr ip4;
  ip6_addr ip6;
  net_addr net;
  net_addr *net_ptr;
  struct symbol *s;
  char *t;
  struct rtable_config *r;
  struct channel_config *cc;
  struct f_inst *x;
  struct f_dynamic_attr fda;
  struct f_static_attr fsa;
  enum f_method efm;
  struct filter *f;
  struct f_tree *e;
  struct f_trie *trie;
  struct f_val v;
  struct f_path_mask *h;
  struct password_item *p;
  struct rt_show_data *ra;
  struct sym_show_data *sd;
  struct lsadb_show_data *ld;
  struct iface *iface;
  void *g;
  btime time;
  struct f_prefix px;
  struct proto_spec ps;
  struct channel_limit cl;
  struct timeformat *tf;
  mpls_label_stack *mls;
}

%token END CLI_MARKER INVALID_TOKEN ELSECOL DDOT
%token GEQ LEQ NEQ AND OR
%token PO PC
%token <i> NUM ENUM
%token <ip4> IP4
%token <ip6> IP6
%token <i64> VPN_RD
%token <s> SYM
%token <t> TEXT
%type <iface> ipa_scope

%type <i> expr bool pxlen4
%type <time> expr_us time
%type <a> ipa
%type <net> net_ip4_ net_ip6_ net_ip6 net_ip_ net_ip net_or_ipa
%type <net_ptr> net_ net_any net_vpn4_ net_vpn6_ net_vpn_ net_roa4_ net_roa6_ net_roa_ net_ip6_sadr_ net_mpls_
%type <mls> label_stack_start label_stack

%type <t> text opttext

%nonassoc PREFIX_DUMMY
%left AND OR
%nonassoc '=' '<' '>' '~' GEQ LEQ NEQ NMA PO PC
%left '+' '-'
%left '*' '/' '%'
%left '!'
%nonassoc '.'

CF_KEYWORDS(DEFINE, ON, OFF, YES, NO, S, MS, US, PORT, VPN, MPLS, FROM)

CF_GRAMMAR

/* Basic config file structure */

config: conf_entries END { return 0; }
 | CLI_MARKER cli_cmd { return 0; }
 ;

conf_entries:
   /* EMPTY */
 | conf_entries conf
 ;

CF_ADDTO(conf, ';')


/* Constant expressions */

CF_ADDTO(conf, definition)
definition:
   DEFINE SYM '=' term ';' {
     struct f_val *val = cfg_alloc(sizeof(struct f_val));
     *val = f_eval($4, cfg_mem);
     if (val->type == T_RETURN) cf_error("Runtime error");
     cf_define_symbol($2, SYM_CONSTANT | val->type, val);
   }
 ;

expr:
   NUM
 | '(' term ')' { $$ = f_eval_int($2); }
 | SYM {
     if ($1->class != (SYM_CONSTANT | T_INT)) cf_error("Number expected");
     $$ = SYM_VAL($1).i; }
 ;


expr_us:
   expr S  { $$ = $1 S_; }
 | expr MS { $$ = $1 MS_; }
 | expr US { $$ = $1 US_; }
 ;

/* Switches */

bool:
   expr { $$ = !!$1; }
 | ON { $$ = 1; }
 | YES { $$ = 1; }
 | OFF { $$ = 0; }
 | NO { $$ = 0; }
 | /* Silence means agreement */ { $$ = 1; }
 ;


/* Addresses */

ipa:
   IP4 { $$ = ipa_from_ip4($1); }
 | IP6 { $$ = ipa_from_ip6($1); }
 | SYM {
     if ($1->class != (SYM_CONSTANT | T_IP)) cf_error("IP address expected");
     $$ = SYM_VAL($1).ip;
   }
 ;

ipa_scope:
   /* empty */ { $$ = NULL; }
 | '%' SYM { $$ = if_get_by_name($2->name); }
 ;


/* Networks - internal */

pxlen4:
   '/' NUM {
     if ($2 > IP4_MAX_PREFIX_LENGTH) cf_error("Invalid prefix length %u", $2);
     $$ = $2;
   }
 ;

net_ip4_: IP4 pxlen4
{
  net_fill_ip4(&($$), $1, $2);

  net_addr_ip4 *n = (void *) &($$);
  if (!net_validate_ip4(n))
    cf_error("Invalid IPv4 prefix %I4/%d, maybe you wanted %I4/%d",
	     n->prefix, n->pxlen, ip4_and(n->prefix, ip4_mkmask(n->pxlen)), n->pxlen);
};

net_ip6_: IP6 '/' NUM
{
  if ($3 > IP6_MAX_PREFIX_LENGTH)
    cf_error("Invalid prefix length %u", $3);

  net_fill_ip6(&($$), $1, $3);

  net_addr_ip6 *n = (void *) &($$);
  if (!net_validate_ip6(n))
    cf_error("Invalid IPv6 prefix %I6/%d, maybe you wanted %I6/%d",
	     n->prefix, n->pxlen, ip6_and(n->prefix, ip6_mkmask(n->pxlen)), n->pxlen);
};

net_ip6_sadr_: IP6 '/' NUM FROM IP6 '/' NUM
{
  if ($3 > IP6_MAX_PREFIX_LENGTH)
    cf_error("Invalid prefix length %u", $3);

  if ($7 > IP6_MAX_PREFIX_LENGTH)
    cf_error("Invalid prefix length %u", $7);

  $$ = cfg_alloc(sizeof(net_addr_ip6_sadr));
  net_fill_ip6_sadr($$, $1, $3, $5, $7);

  net_addr_ip6_sadr *n = (void *) $$;
  if (!net_validate_ip6_sadr(n))
    cf_error("Invalid SADR IPv6 prefix %I6/%d from %I6/%d, maybe you wanted %I6/%d from %I6/%d",
	     n->dst_prefix, n->dst_pxlen, n->src_prefix, n->src_pxlen,
	     ip6_and(n->dst_prefix, ip6_mkmask(n->dst_pxlen)), n->dst_pxlen,
	     ip6_and(n->src_prefix, ip6_mkmask(n->src_pxlen)), n->src_pxlen);
};

net_vpn4_: VPN_RD net_ip4_
{
  $$ = cfg_alloc(sizeof(net_addr_vpn4));
  net_fill_vpn4($$, net4_prefix(&$2), net4_pxlen(&$2), $1);
}

net_vpn6_: VPN_RD net_ip6_
{
  $$ = cfg_alloc(sizeof(net_addr_vpn6));
  net_fill_vpn6($$, net6_prefix(&$2), net6_pxlen(&$2), $1);
}

net_roa4_: net_ip4_ MAX NUM AS NUM
{
  $$ = cfg_alloc(sizeof(net_addr_roa4));
  net_fill_roa4($$, net4_prefix(&$1), net4_pxlen(&$1), $3, $5);
  if ($3 < net4_pxlen(&$1) || $3 > IP4_MAX_PREFIX_LENGTH)
    cf_error("Invalid max prefix length %u", $3);
};

net_roa6_: net_ip6_ MAX NUM AS NUM
{
  $$ = cfg_alloc(sizeof(net_addr_roa6));
  net_fill_roa6($$, net6_prefix(&$1), net6_pxlen(&$1), $3, $5);
  if ($3 < net6_pxlen(&$1) || $3 > IP6_MAX_PREFIX_LENGTH)
    cf_error("Invalid max prefix length %u", $3);
};

net_mpls_: MPLS NUM
{
  $$ = cfg_alloc(sizeof(net_addr_roa6));
  net_fill_mpls($$, $2);
}

net_ip_: net_ip4_ | net_ip6_ ;
net_vpn_: net_vpn4_ | net_vpn6_ ;
net_roa_: net_roa4_ | net_roa6_ ;

net_:
   net_ip_ { $$ = cfg_alloc($1.length); net_copy($$, &($1)); }
 | net_vpn_
 | net_roa_
 | net_flow_
 | net_ip6_sadr_
 | net_mpls_
 ;


/* Networks - regular */

net_ip6:
   net_ip6_
 | SYM {
     if (($1->class != (SYM_CONSTANT | T_NET)) || (SYM_VAL($1).net->type != NET_IP6))
       cf_error("IPv6 network expected");
     $$ = * SYM_VAL($1).net;
   }
 ;

net_ip:
   net_ip_
 | SYM {
     if (($1->class != (SYM_CONSTANT | T_NET)) || !net_is_ip(SYM_VAL($1).net))
       cf_error("IP network expected");
     $$ = * SYM_VAL($1).net;
   }
 ;

net_any:
   net_
 | SYM {
     if ($1->class != (SYM_CONSTANT | T_NET))
       cf_error("Network expected");
     $$ = (net_addr *) SYM_VAL($1).net; /* Avoid const warning */
   }
 ;

net_or_ipa:
   net_ip4_
 | net_ip6_
 | IP4 { net_fill_ip4(&($$), $1, IP4_MAX_PREFIX_LENGTH); }
 | IP6 { net_fill_ip6(&($$), $1, IP6_MAX_PREFIX_LENGTH); }
 | SYM {
     if ($1->class == (SYM_CONSTANT | T_IP))
       net_fill_ip_host(&($$), SYM_VAL($1).ip);
     else if (($1->class == (SYM_CONSTANT | T_NET)) && net_is_ip(SYM_VAL($1).net))
       $$ = * SYM_VAL($1).net;
     else
       cf_error("IP address or network expected");
   }
 ;

label_stack_start: NUM
{
  $$ = cfg_allocz(sizeof(mpls_label_stack));
  $$->len = 1;
  $$->stack[0] = $1;
};

label_stack:
    label_stack_start
  | label_stack '/' NUM {
    if ($1->len >= MPLS_MAX_LABEL_STACK)
      cf_error("Too many labels in stack");
    $1->stack[$1->len++] = $3;
    $$ = $1;
  }
;

time:
   TEXT {
     $$ = tm_parse_time($1);
     if (!$$)
       cf_error("Invalid date/time");
   }
 ;

text:
   TEXT
 | SYM {
     if ($1->class != (SYM_CONSTANT | T_STRING)) cf_error("String expected");
     $$ = SYM_VAL($1).s;
   }
 ;

opttext:
    TEXT
 | /* empty */ { $$ = NULL; }
 ;


CF_CODE

CF_END
