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
# by adding them to REAL_SRCS below.
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

# ASAN target: `make -C tests ASAN=1` swaps in the ASAN knobs the
# arch-program #10 spec calls for on the integration path.  -Og +
# -ggdb3 mirror the top-level `make asan` recipe so a failing
# selftest under the test binary lands the same backtrace shape a
# failing selftest inside the live trinity would.  Objects land in
# a flavor-specific BUILDDIR so an ASAN-instrumented .o never leaks
# into a subsequent non-ASAN link (and vice versa).
#
# NDEBUG target: `make -C tests NDEBUG=1` compiles with -DNDEBUG,
# disabling assert() guards in persist/deferred-free.c.  All seven
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
	$(TOP)/persist/deferred-free.c

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
	test_main.c

# Objects for REAL sources land under build/real/ (mirroring the
# source path); fake objects land under build/.  The isolated layout
# keeps this build orthogonal to the top-level Makefile's cache.
REAL_OBJS	:= $(patsubst $(TOP)/%.c,$(BUILDDIR)/real/%.o,$(REAL_SRCS))
FAKE_OBJS	:= $(patsubst %.c,$(BUILDDIR)/%.o,$(FAKE_SRCS))

.PHONY: all test test-asan test-ndebug clean

all: $(TEST_BIN)
	./$(TEST_BIN)

test:
	$(MAKE) ASAN=0 NDEBUG=0

test-asan:
	$(MAKE) ASAN=1

test-ndebug:
	$(MAKE) NDEBUG=1

$(TEST_BIN): $(REAL_OBJS) $(FAKE_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(REAL_OBJS) $(FAKE_OBJS)

$(BUILDDIR)/real/%.o: $(TOP)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILDDIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	@rm -rf build build-asan build-ndebug test-bin test-bin-asan test-bin-ndebug
