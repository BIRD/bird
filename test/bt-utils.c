/*
 *	BIRD Test -- Utils for testing parsing configuration file
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include "test/birdtest.h"
#include "test/bt-utils.h"

#include "nest/bird.h"
#include "nest/route.h"
#include "nest/protocol.h"

#include "sysdep/unix/unix.h"
#include "sysdep/unix/krt.h"

#include "nest/iface.h"
#include "nest/locks.h"

#include "filter/filter.h"

#define BETWEEN(a, b, c)  (((a) >= (b)) && ((a) <= (c)))

static const byte *bt_config_parse_pos;
static uint bt_config_parse_remain_len;

/* This is cf_read_hook for hard-coded text configuration */
static int
cf_static_read(byte *dest, uint max_len, int fd UNUSED)
{
  if (max_len > bt_config_parse_remain_len)
    max_len = bt_config_parse_remain_len;
  memcpy(dest, bt_config_parse_pos, max_len);
  bt_config_parse_pos += max_len;
  bt_config_parse_remain_len -= max_len;
  return max_len;
}

/* This is cf_read_hook for reading configuration files,
 * function is copied from main.c, cf_read() */
static int
cf_file_read(byte *dest, uint max_len, int fd)
{
  int l = read(fd, dest, max_len);
  if (l < 0)
    cf_error("Read error");
  return l;
}

void
bt_bird_init(void)
{
  if(bt_verbose)
    log_init_debug("");
  log_switch(bt_verbose != 0, NULL, NULL);

  resource_init();
  olock_init();
  timer_init();
  io_init();
  rt_init();
  if_init();
  config_init();

  protos_build();
  proto_build(&proto_unix_kernel);
  proto_build(&proto_unix_iface);
}

void bt_bird_cleanup(void)
{
  for (int i = 0; i < PROTOCOL__MAX; i++)
    class_to_protocol[i] = NULL;

  config = new_config = NULL;
}

static char *
bt_load_file(const char *filename, int quiet)
{
  FILE *f = fopen(filename, "rb");
  if (!quiet)
    bt_assert_msg(f != NULL, "Open %s", filename);

  if (f == NULL)
    return NULL;

  fseek(f, 0, SEEK_END);
  long file_size_ = ftell(f);
  fseek(f, 0, SEEK_SET);

  if (file_size_ < 0)
    return NULL;

  size_t file_size = file_size_;
  size_t read_size = 0;

  char *file_body = mb_allocz(&root_pool, file_size+1);

  /* XXX: copied from cf-lex.c */
  errno=0;
  while ((read_size += fread(file_body+read_size, 1, file_size-read_size, f)) != file_size && ferror(f))
  {
    bt_debug("iteration \n");
    if(errno != EINTR)
    {
      bt_abort_msg("errno: %d", errno);
      break;
    }
    errno=0;
    clearerr(f);
  }
  fclose(f);

  if (!quiet)
    bt_assert_msg(read_size == file_size, "Read %s", filename);

  return file_body;
}

static void
bt_show_cfg_error(const struct config *cfg)
{
  int lino = 0;
  int lino_delta = 5;
  int lino_err = cfg->err_lino;

  const char *str = bt_load_file(cfg->err_file_name, 1);

  while (str && *str)
  {
    lino++;
    if (BETWEEN(lino, lino_err - lino_delta, lino_err + lino_delta))
      bt_debug("%4u%s", lino, (lino_err == lino ? " >> " : "    "));
    do
    {
      if (BETWEEN(lino, lino_err - lino_delta, lino_err + lino_delta))
	bt_debug("%c", *str);
    } while (*str && *(str++) != '\n');
  }
  bt_debug("\n");
}

static struct config *
bt_config_parse__(struct config *cfg)
{
  bt_assert_msg(config_parse(cfg) == 1, "Parse %s", cfg->file_name);

  if (cfg->err_msg)
  {
    bt_debug("Parse error %s, line %d: %s\n", cfg->err_file_name, cfg->err_lino, cfg->err_msg);
    bt_show_cfg_error(cfg);
    return NULL;
  }

  config_commit(cfg, RECONFIG_HARD, 0);
  new_config = cfg;

  return cfg;
}

struct config *
bt_config_parse(const char *cfg_str)
{
  struct config *cfg = config_alloc("configuration");

  bt_config_parse_pos = cfg_str;
  bt_config_parse_remain_len = strlen(cfg_str);
  cf_read_hook = cf_static_read;

  return bt_config_parse__(cfg);
}

struct config *
bt_config_file_parse(const char *filepath)
{
  struct config *cfg = config_alloc(filepath);

  cfg->file_fd = open(filepath, O_RDONLY);
  bt_assert_msg(cfg->file_fd > 0, "Open %s", filepath);
  if (cfg->file_fd < 0)
    return NULL;

  cf_read_hook = cf_file_read;

  return bt_config_parse__(cfg);
}

/*
 * Returns @base raised to the power of @power.
 */
uint
bt_naive_pow(uint base, uint power)
{
  uint result = 1;
  uint i;
  for (i = 0; i < power; i++)
    result *= base;
  return result;
}

/**
 * bytes_to_hex - transform data into hexadecimal representation
 * @buf: preallocated string buffer
 * @in_data: data for transformation
 * @size: the length of @in_data
 *
 * This function transforms @in_data of length @size into hexadecimal
 * representation and writes it into @buf.
 */
void
bt_bytes_to_hex(char *buf, const byte *in_data, size_t size)
{
  size_t i;
  for(i = 0; i < size; i++)
    sprintf(buf + i*2, "%02x", in_data[i]);
}

