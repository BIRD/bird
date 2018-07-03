src := assert.c a-path.c a-set.c cli.c cmds.c iface.c locks.c neighbor.c password.c proto.c rt-attr.c rt-dev.c rt-fib.c rt-show.c rt-table.c
obj := $(src-o-files)
$(all-daemon)
$(cf-local)

tests_src := a-set_test.c a-path_test.c
tests_targets := $(tests_targets) $(tests-target-files)
tests_objs := $(tests_objs) $(src-o-files)
