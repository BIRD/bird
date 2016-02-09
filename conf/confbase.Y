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
#include "sysdep/unix/timer.h"
#include "lib/string.h"
#include "nest/protocol.h"
#include "nest/iface.h"
#include "nest/route.h"
#include "nest/cli.h"
#include "filter/filter.h"

/* FIXME: Turn on YYERROR_VERBOSE and work around lots of bison bugs? */

CF_DEFINES

static void
check_u16(unsigned val)
{
  if (val > 0xFFFF)
    cf_error("Value %d out of range (0-65535)", val);
}

CF_DECLS

%union {
  int i;
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
  bird_clock_t time;
  struct f_prefix px;
  struct proto_spec ps;
  struct channel_limit cl;
  struct timeformat *tf;
  u32 *lbl;
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
%type <i32> expr_us
%type <time> datetime
%type <a> ipa
%type <net> net_ip4_ net_ip6_ net_ip6 net_ip_ net_ip net_or_ipa
%type <net_ptr> net_ net_any net_vpn4_ net_vpn6_ net_vpn_ net_roa4_ net_roa6_ net_roa_
%type <lbl> label_stack_start label_stack

%type <t> text opttext

%nonassoc PREFIX_DUMMY
%left AND OR
%nonassoc '=' '<' '>' '~' GEQ LEQ NEQ PO PC
%left '+' '-'
%left '*' '/' '%'
%left '!'
%nonassoc '.'

CF_KEYWORDS(DEFINE, ON, OFF, YES, NO, S, MS, US, PORT, VPN)

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
   expr S  { $$ = (u32) $1 * 1000000; }
 | expr MS { $$ = (u32) $1 * 1000; }
 | expr US { $$ = (u32) $1 * 1; }
 ;

/* expr_u16: expr { check_u16($1); $$ = $1; }; */

/* Switches */

bool:
   expr {$$ = !!$1; }
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
     if ($2 < 0 || $2 > IP4_MAX_PREFIX_LENGTH) cf_error("Invalid prefix length %d", $2);
     $$ = $2;
   }
 | ':' IP4 {
     $$ = ip4_masklen($2);
     if ($$ == 255) cf_error("Invalid netmask %I4", $2);
   }
 ;

net_ip4_: IP4 pxlen4
{
  net_fill_ip4(&($$), $1, $2);
  if (!net_validate_ip4((net_addr_ip4 *) &($$)))
    cf_error("Invalid IPv4 prefix");
};

net_ip6_: IP6 '/' NUM
{
  net_fill_ip6(&($$), $1, $3);
  if ($3 < 0 || $3 > IP6_MAX_PREFIX_LENGTH)
    cf_error("Invalid prefix length %d", $3);
  if (!net_validate_ip6((net_addr_ip6 *) &($$)))
    cf_error("Invalid IPv6 prefix");
};

net_vpn4_: VPN_RD net_ip4_
{
  $$ = cfg_alloc(sizeof(net_addr_vpn4));
  net_fill_vpn4($$, ((net_addr_ip4 *)&$2)->prefix, $2.pxlen, $1);
}

net_vpn6_: VPN_RD net_ip6_
{
  $$ = cfg_alloc(sizeof(net_addr_vpn6));
  net_fill_vpn6($$, ((net_addr_ip6 *)&$2)->prefix, $2.pxlen, $1);
}

net_roa4_: net_ip4_ MAX NUM AS NUM
{
  $$ = cfg_alloc(sizeof(net_addr_roa4));
  net_fill_roa4($$, net4_prefix(&$1), net4_pxlen(&$1), $3, $5);
  if ($3 < net4_pxlen(&$1) || $3 > IP4_MAX_PREFIX_LENGTH)
    cf_error("Invalid max prefix length %d", $3);
};

net_roa6_: net_ip6_ MAX NUM AS NUM
{
  $$ = cfg_alloc(sizeof(net_addr_roa6));
  net_fill_roa6($$, net6_prefix(&$1), net6_pxlen(&$1), $3, $5);
  if ($3 < net6_pxlen(&$1) || $3 > IP6_MAX_PREFIX_LENGTH)
    cf_error("Invalid max prefix length %d", $3);
};

net_ip_: net_ip4_ | net_ip6_ ;
net_roa_: net_roa4_ | net_roa6_ ;
net_vpn_: net_vpn4_ | net_vpn6_ ;

net_:
   net_ip_ { $$ = cfg_alloc($1.length); net_copy($$, &($1)); }
 | net_vpn_
 | net_roa_
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
  $$ = cfg_allocz(sizeof(u32) * (MPLS_MAX_LABEL_STACK+1));
  $$[0] = 1;
  $$[1] = $1;
};

label_stack:
    label_stack_start
  | label_stack '/' NUM {
    if ($1[0] >= MPLS_MAX_LABEL_STACK)
      cf_error("Too many labels in stack.");
    $1[++$1[0]] = $3;
    $$ = $1;
  }
;

datetime:
   TEXT {
     $$ = tm_parse_datetime($1);
     if (!$$)
       cf_error("Invalid date and time");
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
