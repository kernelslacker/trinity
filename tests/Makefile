# tests/Makefile -- test-binary build for the PURE-module test seam.
#
# Usage:
#   make -C tests             # build and run the test binary (debug)
#   make -C tests ASAN=1      # rebuild and run under -fsanitize=address
#   make -C tests NDEBUG=1    # rebuild and run with -DNDEBUG (all fixtures pass)
#   make -C tests clean       # remove build artefacts
#
# The test binary links a small set of PURE modules from the main
# tree against the fake shm + RNG providers in this directory.  It
# does NOT reuse the top-level Makefile's OBJS -- that would drag the
# whole trinity build in, defeating the point of a PURE-module test
# seam.  New PURE modules migrate onto the test target one at a time
# by adding them to REAL_SRCS below.  PARENT_SRCS is the exception: a
# few non-PURE TUs, linked with --gc-sections so that only the code a
# test reaches needs fakes (fake_parent.c).
#
# Object files and the linked binary are keyed by build flavor:
#   normal -> build/          + test-bin
#   ASAN   -> build-asan/     + test-bin-asan
#   NDEBUG -> build-ndebug/   + test-bin-ndebug
# All three flavors can coexist -- switching flavors never relinks stale
# objects from another flavor into a binary that lacks its runtime, so
# no clean is required between flavor switches.  This Makefile also
# never stomps the main tree's object cache.
#
# Depends on ../config.h from `./configure` in the tree root; run
# configure once before building the test binary.

TOP		:= ..
CC		?= gcc
CFLAGS		?= -g -O2

CFLAGS		+= -std=gnu11 -Wall -Wextra
CFLAGS		+= -I$(TOP) -I$(TOP)/include
CFLAGS		+= -include $(TOP)/config.h
CFLAGS		+= -D_GNU_SOURCE -D__linux__
# Match the top-level Makefile's warning knobs on the PURE modules we
# reuse so the test link surfaces the same diagnostics production does.
CFLAGS		+= -Wformat=2 -Winit-self -Wnested-externs -Wpacked -Wshadow
CFLAGS		+= -Wundef -Wwrite-strings -Wno-format-nonliteral
CFLAGS		+= -Wstrict-prototypes -Wmissing-prototypes -fsigned-char
CFLAGS		+= -Wno-missing-field-initializers

# mprotect failure injection: wrap mprotect so fixture 7 can fail
# individual seal calls without touching production code.  The wrapper
# (__wrap_mprotect in deferred_free_test.c) is transparent when
# g_mprotect_fail_countdown == 0 (the default).
LDFLAGS		+= -Wl,--wrap=mprotect

# alloc_track lookup counting: cmp_field_scan_test.c wraps
# alloc_track_lookup_size so it can count the struct-field scans'
# extent lookups and answer them itself.  The wrapper forwards to the
# real lookup outside that test.
LDFLAGS		+= -Wl,--wrap=alloc_track_lookup_size

# malloc and lseek failure injection: kcov_persist_test.c wraps both so
# it can fail one scratch allocation or one seek of the warm-start
# loader.  The wrappers forward to the real calls unless armed.
LDFLAGS		+= -Wl,--wrap=malloc
LDFLAGS		+= -Wl,--wrap=lseek

# ASAN target: `make -C tests ASAN=1` swaps in the ASAN knobs the
# arch-program #10 spec calls for on the integration path.  -Og +
# -ggdb3 mirror the top-level `make asan` recipe so a failing
# selftest under the test binary lands the same backtrace shape a
# failing selftest inside the live trinity would.  Objects land in
# a flavor-specific BUILDDIR so an ASAN-instrumented .o never leaks
# into a subsequent non-ASAN link (and vice versa).
#
# NDEBUG target: `make -C tests NDEBUG=1` compiles with -DNDEBUG,
# disabling assert() guards in persist/deferred-free.c.  All twelve
# fixtures pass green in NDEBUG builds; fixture 7 uses the bool return
# value of deferred_free_seal_all() in place of debug_assert_sealed().
# The NDEBUG binary lands in build-ndebug/ so it never contaminates
# a subsequent debug or ASAN build.
ifeq ($(ASAN),1)
BUILDDIR	:= build-asan
TEST_BIN	:= test-bin-asan
CFLAGS		+= -U_FORTIFY_SOURCE -fsanitize=address -Og -ggdb3
LDFLAGS		+= -fsanitize=address
else ifeq ($(NDEBUG),1)
BUILDDIR	:= build-ndebug
TEST_BIN	:= test-bin-ndebug
CFLAGS		+= -DNDEBUG
else
BUILDDIR	:= build
TEST_BIN	:= test-bin
endif

# PURE-module sources reused verbatim from the main tree.  Kept
# explicit (not a wildcard) so a new PURE addition is a deliberate
# one-line change, not a "someone added a file and the test binary
# silently pulled it in" surprise.
REAL_SRCS	:= \
	$(TOP)/args/struct_fill.c \
	$(TOP)/args/struct_mutate.c \
	$(TOP)/args/struct_mutate_selftest.c \
	$(TOP)/struct_catalog/variant.c \
	$(TOP)/struct_catalog/address.c \
	$(TOP)/utils/shared_freelist.c \
	$(TOP)/utils/shared_str_heap.c \
	$(TOP)/utils/pidstat-probe.c \
	$(TOP)/utils/tmpdir.c \
	$(TOP)/persist/deferred-free.c \
	$(TOP)/fds/fds-protected.c \
	$(TOP)/lib/jsonl.c \
	$(TOP)/fds/owned-fd-ring.c \
	$(TOP)/fds/fds.c \
	$(TOP)/fds/fds-registry.c \
	$(TOP)/dispatch/extrafork-reap.c \
	$(TOP)/mm/fault-read.c \
	$(TOP)/mm/fault-write.c

# Parent TUs, linked for reset_epoch_state(), the reaper, the zombie
# reaper, the rotation-events sink and sanity_check_tables(), plus
# utils/uid.c for drop_privs(), the child-side args/generate-args.c
# for generic_sanitise() and arg_meta_init(), and health/signals-policy.c
# for mask_signals_child() and setup_main_signals(), with the fault
# handlers they install (signals-fault-handler.c, signals-async-safe.c).
# rand/random-address.c and random_syscall/dispatch-step.c bring the
# writable pool and redqueen_pin_field().  They also pull in functions
# the tests never call (main_loop() reaches most of the parent,
# dispatch_step() most of the child), so each function gets its own
# section and --gc-sections drops the unreached ones.  -fdata-sections
# gives each function its own jump-table section too: in a shared
# .rodata, one reached switch keeps every other function's case targets,
# and their references, alive.  fake_parent.c covers the rest;
# sanitiser_owned_mask_test.c fakes fill_arg().
PARENT_SRCS	:= \
	$(TOP)/main/loop.c \
	$(TOP)/main/reap.c \
	$(TOP)/main/reap-zombie.c \
	$(TOP)/stats/rotation_event.c \
	$(TOP)/tables/table-meta.c \
	$(TOP)/utils/uid.c \
	$(TOP)/args/generate-args.c \
	$(TOP)/health/signals-policy.c \
	$(TOP)/health/signals-fault-handler.c \
	$(TOP)/health/signals-async-safe.c \
	$(TOP)/rand/random-address.c \
	$(TOP)/random_syscall/dispatch-step.c
LDFLAGS		+= -Wl,--gc-sections

# The CMP-hint collect path, linked for cmp_hints_collect() and the
# struct-field scans it drives.  Same section-per-function treatment
# as the parent TUs; cmp_field_scan_test.c fakes the rest of the
# cmp_hints core it reaches.
CMP_SRCS	:= \
	$(TOP)/cmp_hints/collect.c \
	$(TOP)/cmp_hints/field.c \
	$(TOP)/cmp_hints/hyp-len-correlated.c \
	$(TOP)/cmp_hints/hyp-pool.c

# The minicorpus save, replay and warm-start file paths, linked for
# minicorpus_save_with_reason(), minicorpus_replay(),
# minicorpus_save_file() and minicorpus_load_file(), with the fd and
# stale-tmp helpers the file path uses.  Same section-per-function
# treatment; minicorpus_abi_test.c fakes the persist envelope, crc32(),
# the blob corpus and the mutator chain.
MINICORPUS_SRCS	:= \
	$(TOP)/persist/minicorpus-core.c \
	$(TOP)/persist/minicorpus-file.c \
	$(TOP)/persist/minicorpus-save.c \
	$(TOP)/persist/minicorpus-select.c \
	$(TOP)/lib/fd.c \
	$(TOP)/utils/persist-util.c

# The kcov bitmap warm-start save and load paths, linked for
# kcov_bitmap_save_file() and kcov_bitmap_load_file(), with the fd and
# stale-tmp helpers they use from MINICORPUS_SRCS.  Same
# section-per-function treatment; kcov_persist_test.c owns
# kcov_kaslr_base, while kcov_shm, the persist envelope and crc32()
# come from cmp_field_scan_test.c and minicorpus_abi_test.c.
KCOV_PERSIST_SRCS := \
	$(TOP)/kcov/persist.c

FAKE_SRCS	:= \
	fake_rng.c \
	fake_shm.c \
	fake_stubs.c \
	rnd_stream_golden.c \
	shared_freelist_selftest.c \
	shared_str_heap_selftest.c \
	dispatch_stage_order_test.c \
	deferred_free_test.c \
	stats_opclock_lossless_test.c \
	struct_field_bounds_test.c \
	kmsg_trigger_selftest.c \
	pidstat_probe_selftest.c \
	exit_reason_test.c \
	parent_stop_test.c \
	child_fault_test.c \
	stop_file_test.c \
	fd_protected_test.c \
	owned_fd_ring_test.c \
	fake_fds.c \
	fd_replenish_test.c \
	drop_privs_test.c \
	tmpdir_test.c \
	fake_parent.c \
	epoch_reset_test.c \
	reap_stop_test.c \
	extrafork_reap_test.c \
	cmp_field_scan_test.c \
	sanitiser_owned_mask_test.c \
	minicorpus_abi_test.c \
	redqueen_pin_test.c \
	kcov_persist_test.c \
	test_main.c

# Objects for REAL sources land under build/real/ (mirroring the
# source path); fake objects land under build/.  The isolated layout
# keeps this build orthogonal to the top-level Makefile's cache.
REAL_OBJS	:= $(patsubst $(TOP)/%.c,$(BUILDDIR)/real/%.o,$(REAL_SRCS))
PARENT_OBJS	:= $(patsubst $(TOP)/%.c,$(BUILDDIR)/real/%.o,$(PARENT_SRCS))
CMP_OBJS	:= $(patsubst $(TOP)/%.c,$(BUILDDIR)/real/%.o,$(CMP_SRCS))
MINICORPUS_OBJS	:= $(patsubst $(TOP)/%.c,$(BUILDDIR)/real/%.o,$(MINICORPUS_SRCS))
KCOV_PERSIST_OBJS := $(patsubst $(TOP)/%.c,$(BUILDDIR)/real/%.o,$(KCOV_PERSIST_SRCS))
FAKE_OBJS	:= $(patsubst %.c,$(BUILDDIR)/%.o,$(FAKE_SRCS))
TEST_OBJS	:= $(REAL_OBJS) $(PARENT_OBJS) $(CMP_OBJS) $(MINICORPUS_OBJS) $(KCOV_PERSIST_OBJS) $(FAKE_OBJS)

.PHONY: all test test-asan test-ndebug clean

all: $(TEST_BIN)
	./$(TEST_BIN)

test:
	$(MAKE) ASAN=0 NDEBUG=0

test-asan:
	$(MAKE) ASAN=1

test-ndebug:
	$(MAKE) NDEBUG=1

$(TEST_BIN): $(TEST_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(TEST_OBJS)

$(PARENT_OBJS) $(CMP_OBJS) $(MINICORPUS_OBJS) $(KCOV_PERSIST_OBJS): CFLAGS += -ffunction-sections -fdata-sections

# -MMD writes a .d file beside each object listing the headers it was
# built from, so editing a header rebuilds the objects that include it.
# -MP gives each header an empty rule, so a deleted or renamed one does
# not break the next build.
$(BUILDDIR)/real/%.o: $(TOP)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

$(BUILDDIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

-include $(TEST_OBJS:.o=.d)

clean:
	@rm -rf build build-asan build-ndebug test-bin test-bin-asan test-bin-ndebug
