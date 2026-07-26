# tests/Makefile -- test-binary build for the PURE-module test seam.
#
# Usage:
#   make -C tests             # build the test binary
#   make -C tests ASAN=1      # rebuild under -fsanitize=address
#   make -C tests clean       # remove build artefacts
#
# The test binary links a small set of PURE modules from the main
# tree against the fake shm + RNG providers in this directory.  It
# does NOT reuse the top-level Makefile's OBJS -- that would drag the
# whole trinity build in, defeating the point of a PURE-module test
# seam.  New PURE modules migrate onto the test target one at a time
# by adding them to REAL_SRCS below.
#
# All object files land under build/ so this Makefile never stomps
# the main tree's object cache -- ASAN and non-ASAN test-bin builds
# stay independent of each other and of the top-level `make` build.
#
# Depends on ../config.h from `./configure` in the tree root; run
# configure once before building the test binary.

TOP		:= ..
BUILDDIR	:= build
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

# ASAN target: `make -C tests ASAN=1` swaps in the ASAN knobs the
# arch-program #10 spec calls for on the integration path.  -Og +
# -ggdb3 mirror the top-level `make asan` recipe so a failing
# selftest under the test binary lands the same backtrace shape a
# failing selftest inside the live trinity would.
ifeq ($(ASAN),1)
CFLAGS		+= -U_FORTIFY_SOURCE -fsanitize=address -Og -ggdb3
LDFLAGS		+= -fsanitize=address
endif

# PURE-module sources reused verbatim from the main tree.  Kept
# explicit (not a wildcard) so a new PURE addition is a deliberate
# one-line change, not a "someone added a file and the test binary
# silently pulled it in" surprise.
REAL_SRCS	:= \
	$(TOP)/args/struct_mutate.c \
	$(TOP)/args/struct_mutate_selftest.c \
	$(TOP)/struct_catalog/variant.c \
	$(TOP)/struct_catalog/address.c \
	$(TOP)/utils/shared_freelist.c \
	$(TOP)/utils/shared_str_heap.c

FAKE_SRCS	:= \
	fake_rng.c \
	fake_shm.c \
	fake_stubs.c \
	rnd_stream_golden.c \
	shared_freelist_selftest.c \
	shared_str_heap_selftest.c \
	test_main.c

# Objects for REAL sources land under build/real/ (mirroring the
# source path); fake objects land under build/.  The isolated layout
# keeps this build orthogonal to the top-level Makefile's cache.
REAL_OBJS	:= $(patsubst $(TOP)/%.c,$(BUILDDIR)/real/%.o,$(REAL_SRCS))
FAKE_OBJS	:= $(patsubst %.c,$(BUILDDIR)/%.o,$(FAKE_SRCS))

TEST_BIN	:= test-bin

.PHONY: all clean

all: $(TEST_BIN)

$(TEST_BIN): $(REAL_OBJS) $(FAKE_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(REAL_OBJS) $(FAKE_OBJS)

$(BUILDDIR)/real/%.o: $(TOP)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILDDIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	@rm -rf $(BUILDDIR) $(TEST_BIN)
