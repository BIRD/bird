/*
 *	Filters: Utility Functions Tests
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <string.h>
#include <stdlib.h>

#include "test/birdtest.h"
#include "test/bt-utils.h"

#include "filter/filter.h"
#include "conf/conf.h"

static int
t_simple(void)
{
  bt_bird_init();

#define TESTING_FILTER_NAME	"my_filter"
#define TESTING_FILTER_BODY	"{ \n"					\
				"   if net ~ 10.0.0.0/20 then \n" 	\
				"     accept; \n"			\
				"   else \n"				\
				"     reject;\n"			\
				"} \n"

  struct config *cfg = bt_config_parse(
    BT_CONFIG_SIMPLE
    "filter " TESTING_FILTER_NAME "1" " " TESTING_FILTER_BODY
    "filter " TESTING_FILTER_NAME "2" " " TESTING_FILTER_BODY);

  if (cfg)
  {
    struct symbol *sym_f1 = cf_get_symbol(TESTING_FILTER_NAME "1");
    struct symbol *sym_f2 = cf_get_symbol(TESTING_FILTER_NAME "2");

    struct filter *f1 = sym_f1->def;
    struct filter *f2 = sym_f2->def;

    bt_assert(strcmp(filter_name(f1), TESTING_FILTER_NAME "1") == 0);
    bt_assert(strcmp(filter_name(f2), TESTING_FILTER_NAME "2") == 0);

    bt_assert(filter_same(f1,f2));
  }

  /* TODO: check the testing filter */

  return BT_SUCCESS;
}
#undef TESTING_FILTER_NAME
#undef TESTING_FILTER_BODY

static int
test_config_file(const void *filename_void)
{
  bt_bird_init();

  size_t fn_size = strlen((const char *) filename_void) + 1;
  char *filename = alloca(fn_size);
  strncpy(filename, filename_void, fn_size);
  bt_debug("Testing configuration %s\n", filename);

  return bt_config_file_parse(filename) ? BT_SUCCESS : BT_FAILURE;
}

static int t_config_file1(const void *fname) { return test_config_file(fname); }
static int t_config_file2(const void *fname) { return test_config_file(fname); }
static int t_config_file3(const void *fname) { return test_config_file(fname); }
static int t_config_file4(const void *fname) { return test_config_file(fname); }

int
main(int argc, char *argv[])
{
  bt_init(argc, argv);

#define TEST_FNAME_1 "filter/test.conf"
#define TEST_FNAME_2 "filter/test.conf2"
#define TEST_FNAME_3 "filter/test_bgp_filtering.conf"
#define TEST_FNAME_4 "filter/test6.conf"
#define bt_test_suite_arg_(x) bt_test_suite_arg(t_config_file##x, TEST_FNAME_##x, TEST_FNAME_##x)

  bt_test_suite(t_simple, "Simple filter testing");
  bt_test_suite_arg_(1);
  bt_test_suite_arg_(2);
  bt_test_suite_arg_(3);
  bt_test_suite_arg_(4);

  return bt_exit_value();
}
