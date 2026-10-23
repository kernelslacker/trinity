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
CONFIG_H	:= $(TOP)/config.h

CFLAGS		+= -std=gnu11 -Wall -Wextra
CFLAGS		+= -I$(dir $(CONFIG_H)) -I$(TOP) -I$(TOP)/include
CFLAGS		+= -include $(CONFIG_H)
CFLAGS		+= -D_GNU_SOURCE -D__linux__
# Match the top-level Makefile's warning knobs on the PURE modules we
# reuse so the test link surfaces the same diagnostics production does.
CFLAGS		+= -Wformat=2 -Winit-self -Wnested-externs -Wpacked -Wshadow
CFLAGS		+= -Wundef -Wwrite-strings -Wno-format-nonliteral
CFLAGS		+= -Wstrict-prototypes -Wmissing-prototypes -fsigned-char
CFLAGS		+= -Wno-missing-field-initializers
ifneq ($(SYSROOT),)
CFLAGS		+= --sysroot=$(SYSROOT)
endif

# mprotect failure injection: wrap mprotect so fixture 7 can fail
# individual seal calls without touching production code.  The wrapper
# (__wrap_mprotect in deferred_free_test.c) is transparent when
# g_mprotect_fail_countdown == 0 (the default).
LDFLAGS		+= -Wl,--wrap=mprotect

# malloc and lseek failure injection: kcov_persist_test.c wraps both so
# it can fail one scratch allocation or one seek of the warm-start
# loader.  The wrappers forward to the real calls unless armed.
LDFLAGS		+= -Wl,--wrap=malloc
LDFLAGS		+= -Wl,--wrap=lseek

# close() counter: kcov_persist_test.c counts the closes a warm-start
# load or save makes, to check that it closes the one fd it opened
# exactly once.  The wrapper always forwards to the real close().
LDFLAGS		+= -Wl,--wrap=close

# NETLINK_GENERIC socket seam: genl_ops_test.c wraps socket() to hand the
# genl family resolver a unix socketpair that carries a canned controller
# reply.  Any other AF_NETLINK request fails, so no test can open a real
# netlink socket; every other domain goes to the real call.
LDFLAGS		+= -Wl,--wrap=socket

# kill probe injection: fake_parent.c wraps kill() so a test can fail a
# kill(pid, 0) probe with any errno and count the probes.  The wrapper
# forwards to the real kill() unless armed.
LDFLAGS		+= -Wl,--wrap=kill

# pread() failure injection: pidstat_probe_selftest.c wraps pread() so it
# can fail the read of a task's stat fd with any errno, or end it empty.
# The wrapper forwards to the real pread() unless armed.
LDFLAGS		+= -Wl,--wrap=pread

# kill_pid() stand-in: utils/utils.c is linked for get_num_fds() and
# crc32(), and its kill_pid() would SIGKILL the tasks the tests hold.
# fake_parent.c wraps it with one that only records the pid.
LDFLAGS		+= -Wl,--wrap=kill_pid

# Fake CLOCK_MONOTONIC: fake_parent.c wraps clock_gettime(), sleep() and
# usleep() so a test can run out the shutdown wait's 30 s bound or the
# spawn path's backoff and stall deadline without sleeping.  The
# wrappers forward to the real calls unless a test has started the fake
# clock.
LDFLAGS		+= -Wl,--wrap=clock_gettime -Wl,--wrap=sleep -Wl,--wrap=usleep

# replace_child() stand-in: main/spawn.c is linked for fork_children()
# and replace_child(), and the reap and zombie tests keep the stand-in
# that only logs the refill.  fake_parent.c wraps replace_child() with
# it; spawn_test.c calls the real one as __real_replace_child().
LDFLAGS		+= -Wl,--wrap=replace_child

# get_num_fds() failure injection: fake_parent.c wraps it so a test can
# make spawn_child() see any errno from the fd count.  The wrapper counts
# for real unless a test has set fake_num_fds_errno.
LDFLAGS		+= -Wl,--wrap=get_num_fds

# fill_arg() stand-in: args/argtype_table.c is linked for its table and
# defines the real fill_arg(), which would run the generators.
# sanitiser_owned_mask_test.c wraps it with one that records the slot.
LDFLAGS		+= -Wl,--wrap=fill_arg

# ASAN target: `make -C tests ASAN=1` swaps in the ASAN knobs the
# arch-program #10 spec calls for on the integration path.  -Og +
# -ggdb3 mirror the top-level `make asan` recipe so a failing
# selftest under the test binary lands the same backtrace shape a
# failing selftest inside the live trinity would.  Objects land in
# a flavor-specific BUILDDIR so an ASAN-instrumented .o never leaks
# into a subsequent non-ASAN link (and vice versa).
#
# NDEBUG target: `make -C tests NDEBUG=1` compiles with -DNDEBUG,
# disabling assert() guards in persist/deferred-free-regions.c.  All twelve
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
	$(TOP)/persist/deferred-free-alloc-track.c \
	$(TOP)/persist/deferred-free-gen-arena.c \
	$(TOP)/persist/deferred-free-record.c \
	$(TOP)/persist/deferred-free-regions.c \
	$(TOP)/fds/fds-protected.c \
	$(TOP)/lib/jsonl.c \
	$(TOP)/fds/owned-fd-ring.c \
	$(TOP)/fds/fds.c \
	$(TOP)/fds/fds-registry.c \
	$(TOP)/dispatch/extrafork-reap.c \
	$(TOP)/child/child-pidns-init.c \
	$(TOP)/lib/userns-bootstrap.c \
	$(TOP)/mm/fault-read.c \
	$(TOP)/mm/fault-write.c

# Parent TUs, linked for reset_epoch_state(), the shutdown wait, the
# reaper, the zombie reaper, fork_children() and replace_child(), the
# rotation-events sink and sanity_check_tables(), plus utils/uid.c for
# drop_privs(), utils/utils.c for get_num_fds() and crc32(), the
# child-side args/generate-args.c for generic_sanitise() and
# arg_meta_init(), and health/signals-policy.c for mask_signals_child()
# and setup_main_signals(), with the fault handlers they install
# (signals-fault-handler.c, signals-async-safe.c).
# rand/random-address.c and random_syscall/dispatch-step.c bring the
# writable pool, avoid_shared_buffer_out() and redqueen_pin_field().
# random_syscall/chain-subst.c brings apply_chain_substitution() and the
# value mask the RedQueen pin shares with it; redqueen_pin_test.c fakes the
# type-graph observer the substitution feeds.
# random_syscall/fd-group.c brings account_fd_and_group(), which
# owned_fd_ring_test.c runs over the real owned-fd rings; the live-fd
# ring push and the two knobs it reads are faked there.
# ioctls/loop.c brings the loop group's sanitiser, which registers itself
# at load time; fake_ioctls.c fakes the ioctl registry it reaches.
# ioctls/pidfd.c, vfio.c, vduse.c and drm.c bring the groups with a cmd
# that returns an fd, and syscalls/ioctl.c the entry that picks among
# them; ioctl_sanitise_test.c fakes the group lookup that entry reaches.
# ioctls/socket.c, epoll.c and perf_event.c bring the other groups that
# name a typed-fd class, whose fd_test the same test runs against fake
# object pools.
# syscalls/process/prctl.c, syscalls/sched/sched_getscheduler.c and
# syscalls/socket/recv.c bring syscall_prctl, syscall_sched_getscheduler
# and the recv family, whose post handlers post_oracle_test.c drives
# (prctl and recvmsg through their own sanitisers) with the post_state
# table, post_snapshot_or_skip() and the corrupt-pointer bump faked;
# sanitiser_owned_mask_test.c runs prctl's sanitiser too, for the slot it
# owns.  args/valresult.c is what recvfrom's sanitiser reaches.
# dispatch/syscall-post.c brings enforce_count_bound(), which runs ahead
# of those handlers.
# dispatch/syscall.c and dispatch/syscall-exec.c bring do_syscall() with the
# __do_syscall() and do_extrafork() it routes to, which
# dispatch_extrafork_test.c drives with the kcov bracket and the other calls
# the live path reaches faked.  args/arg_coupling.c brings the coupling
# validator __do_syscall() runs on the final argument slots.
# tables/tables.c brings deactivate_extrafork_syscalls(), which
# tables_extrafork_test.c drives over fake tables with the deactivation
# it makes faked.
# syscalls/fs/path/fchdir.c and fchroot.c, syscalls/process/setns.c and
# lib/sanitiser-fd.c bring the entries whose sanitisers open an fd and the
# helper that closes it, which the same test runs through sanitise, dispatch
# and cleanup with the post_state table faked as post_oracle_test.c has it.
# syscalls/fs/dup.c brings syscall_dup, syscall_dup2 and syscall_dup3,
# whose post handlers dup_pool_test.c drives against a fake object pool.
# syscalls/keyctl/keyctl.c, syscalls/socket/socket.c and
# syscalls/socket/socketpair.c bring syscall_keyctl, syscall_socket and
# syscall_socketpair, whose sanitisers sanitiser_owned_mask_test.c runs
# against the empty pools in fake_objects.c and the domain tables in
# fake_net.c; args/output-poison.c is the poison stamp socketpair's
# sanitiser makes.  syscalls/concurrency/futex_wake.c,
# syscalls/quota/quotactl.c, syscalls/sched/nice.c and
# syscalls/process/personality.c bring syscall_futex_wake,
# syscall_quotactl, syscall_nice and syscall_personality, whose
# sanitisers it runs the same way.  args/argtype_table.c brings
# argtype_table[], whose replay classes the corpus predicates read and
# corpus_replay_class_test.c checks; fake_arg_gens.c stands in for the
# generators its rows name.
# They also pull in functions the tests never call (main_loop() reaches
# most of the parent, dispatch_step() most of the child), so each
# function gets its own section and --gc-sections drops the unreached
# ones.  -fdata-sections gives each function its own jump-table section
# too: in a shared .rodata, one reached switch keeps every other
# function's case targets, and their references, alive.  fake_parent.c
# covers the rest; sanitiser_owned_mask_test.c wraps fill_arg().
PARENT_SRCS	:= \
	$(TOP)/main/loop.c \
	$(TOP)/main/reap.c \
	$(TOP)/main/reap-zombie.c \
	$(TOP)/main/spawn.c \
	$(TOP)/stats/rotation_event.c \
	$(TOP)/tables/table-meta.c \
	$(TOP)/tables/tables.c \
	$(TOP)/utils/uid.c \
	$(TOP)/utils/utils.c \
	$(TOP)/args/generate-args.c \
	$(TOP)/args/arg_coupling.c \
	$(TOP)/health/signals-policy.c \
	$(TOP)/health/signals-fault-handler.c \
	$(TOP)/health/signals-async-safe.c \
	$(TOP)/rand/random-address.c \
	$(TOP)/random_syscall/dispatch-step.c \
	$(TOP)/random_syscall/chain-subst.c \
	$(TOP)/random_syscall/fd-group.c \
	$(TOP)/ioctls/loop.c \
	$(TOP)/ioctls/pidfd.c \
	$(TOP)/ioctls/vfio.c \
	$(TOP)/ioctls/vduse.c \
	$(TOP)/ioctls/drm.c \
	$(TOP)/ioctls/socket.c \
	$(TOP)/ioctls/epoll.c \
	$(TOP)/ioctls/perf_event.c \
	$(TOP)/syscalls/ioctl.c \
	$(TOP)/syscalls/process/prctl.c \
	$(TOP)/syscalls/sched/sched_getscheduler.c \
	$(TOP)/syscalls/socket/recv.c \
	$(TOP)/args/valresult.c \
	$(TOP)/dispatch/syscall-post.c \
	$(TOP)/dispatch/syscall.c \
	$(TOP)/dispatch/syscall-exec.c \
	$(TOP)/syscalls/fs/path/fchdir.c \
	$(TOP)/syscalls/fs/path/fchroot.c \
	$(TOP)/syscalls/process/setns.c \
	$(TOP)/lib/sanitiser-fd.c \
	$(TOP)/syscalls/fs/dup.c \
	$(TOP)/syscalls/keyctl/keyctl.c \
	$(TOP)/syscalls/socket/socket.c \
	$(TOP)/syscalls/socket/socketpair.c \
	$(TOP)/args/output-poison.c \
	$(TOP)/syscalls/concurrency/futex_wake.c \
	$(TOP)/syscalls/quota/quotactl.c \
	$(TOP)/syscalls/sched/nice.c \
	$(TOP)/syscalls/process/personality.c \
	$(TOP)/args/argtype_table.c
LDFLAGS		+= -Wl,--gc-sections

# The CMP-hint collect path, linked for cmp_hints_collect().  Same
# section-per-function treatment as the parent TUs; cmp_collect_test.c
# fakes the rest of the cmp_hints core it reaches.
CMP_SRCS	:= \
	$(TOP)/cmp_hints/collect.c

# The minicorpus save, replay and warm-start file paths, linked for
# minicorpus_save_with_reason(), minicorpus_replay(),
# minicorpus_save_file() and minicorpus_load_file(), with the fd and
# stale-tmp helpers the file path uses, and the cold-overflow probe
# that asks the ring which ABIs it holds.  Same section-per-function
# treatment; minicorpus_abi_test.c fakes the persist envelope, the blob
# corpus, the mutator chain and the cold-skip classifier.
MINICORPUS_SRCS	:= \
	$(TOP)/persist/minicorpus-core.c \
	$(TOP)/persist/minicorpus-file.c \
	$(TOP)/persist/minicorpus-save.c \
	$(TOP)/persist/minicorpus-select.c \
	$(TOP)/random_syscall/warm-reserve.c \
	$(TOP)/lib/fd.c \
	$(TOP)/utils/persist-util.c

# The chain corpus ring and its warm-start file, linked for
# chain_corpus_save(), chain_corpus_save_file() and
# chain_corpus_load_file(), with the fd and stale-tmp helpers from
# MINICORPUS_SRCS.  Same section-per-function treatment, so the init and
# snapshot code and the rest of the chain cluster stay out of the link;
# chain_corpus_test.c uses the lock and persist envelope fakes from
# cmp_collect_test.c and minicorpus_abi_test.c.
CHAIN_SRCS	:= \
	$(TOP)/random_syscall/chain-corpus.c \
	$(TOP)/random_syscall/chain-persist.c

# The kcov bitmap warm-start save and load paths, linked for
# kcov_bitmap_save_file() and kcov_bitmap_load_file(), with the fd and
# stale-tmp helpers they use from MINICORPUS_SRCS.  Same
# section-per-function treatment; kcov_persist_test.c owns
# kcov_kaslr_base, while kcov_shm and the persist envelope come from
# cmp_collect_test.c and minicorpus_abi_test.c.
KCOV_PERSIST_SRCS := \
	$(TOP)/kcov/persist.c

# The netlink message generator and the genl family registry, linked for
# netlink_gen_msg() and genl_resolve_families().  The registries in
# genl/families.c and nfnl/subsystems.c name every grammar in their
# directories, so each directory is linked whole.  Same
# section-per-function treatment; genl_ops_test.c fakes the RNG helpers
# these reach and feeds the resolver a canned controller reply.
NETLINK_SRCS	:= $(wildcard $(TOP)/net/netlink/*.c \
			      $(TOP)/net/netlink/genl/*.c \
			      $(TOP)/net/netlink/nfnl/*.c)

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
	fake_objects.c \
	fake_net.c \
	fd_replenish_test.c \
	drop_privs_test.c \
	tmpdir_test.c \
	fake_parent.c \
	epoch_reset_test.c \
	reap_stop_test.c \
	reap_dead_kids_test.c \
	extrafork_reap_test.c \
	pidns_init_test.c \
	userns_bootstrap_test.c \
	dispatch_extrafork_test.c \
	tables_extrafork_test.c \
	cmp_collect_test.c \
	sanitiser_owned_mask_test.c \
	minicorpus_abi_test.c \
	chain_corpus_test.c \
	fake_arg_gens.c \
	corpus_replay_class_test.c \
	redqueen_pin_test.c \
	asb_relocate_test.c \
	fake_ioctls.c \
	loop_status_test.c \
	ioctl_sanitise_test.c \
	genl_ops_test.c \
	kcov_persist_test.c \
	shutdown_wait_test.c \
	reap_fault_beacon_test.c \
	get_num_fds_test.c \
	spawn_test.c \
	post_oracle_test.c \
	dup_pool_test.c \
	test_main.c

# The periodic KCOV CMP dump and the core --stats-json emitters, linked for
# kcov_cmp_stats_periodic_dump() and dump_stats_json_*(), with the render
# siblings the dump fans out to and the descriptor tables the JSON walks.
# They join PARENT_SRCS, so they get the same section-per-function
# treatment and --gc-sections; stats_render_test.c fakes the log sink and
# the few helpers the siblings reach.
PARENT_SRCS	+= $(wildcard $(TOP)/stats/kcov/cmp/*.c) \
		   $(TOP)/stats/json/common.c \
		   $(TOP)/stats/json/core.c \
		   $(TOP)/stats/category.c \
		   $(wildcard $(TOP)/stats/categories/*.c) \
		   $(wildcard $(TOP)/stats/subsys/*.c)
FAKE_SRCS	+= stats_render_test.c \
		   stats_render_golden.c

# syscalls/fs/close.c, close_range.c and fcntl.c and
# syscalls/pidfd/pidfd_getfd.c bring syscall_close, syscall_close_range,
# syscall_fcntl and syscall_pidfd_getfd, whose post handlers
# dup_pool_test.c drives against its fake object pool, and fds/fds-dup.c
# the pooling of a copied fd that dup.c and fcntl.c share.  Same
# section-per-function treatment as the parent TUs above.
PARENT_SRCS	+= $(TOP)/syscalls/fs/close.c \
		   $(TOP)/syscalls/fs/close_range.c \
		   $(TOP)/syscalls/fs/fcntl.c \
		   $(TOP)/syscalls/pidfd/pidfd_getfd.c \
		   $(TOP)/fds/fds-dup.c

# syscalls/socket/accept.c and socketcall.c bring the accept entries and
# syscall_socketcall, whose post handlers dup_pool_test.c drives the same
# way.
PARENT_SRCS	+= $(TOP)/syscalls/socket/accept.c \
		   $(TOP)/syscalls/socket/socketcall.c

# syscalls/fs/open.c and creat.c bring the open family, whose post handlers
# dup_pool_test.c drives against the same pool, and fds/fds-pool.c the
# capped pool they put a file or directory in; it drives the post handler
# of syscalls/ioctl.c, linked above, the same way.
PARENT_SRCS	+= $(TOP)/syscalls/fs/open.c \
		   $(TOP)/syscalls/fs/creat.c \
		   $(TOP)/fds/fds-pool.c

# Objects for REAL sources land under build/real/ (mirroring the
# source path); fake objects land under build/.  The isolated layout
# keeps this build orthogonal to the top-level Makefile's cache.
REAL_OBJS	:= $(patsubst $(TOP)/%.c,$(BUILDDIR)/real/%.o,$(REAL_SRCS))
PARENT_OBJS	:= $(patsubst $(TOP)/%.c,$(BUILDDIR)/real/%.o,$(PARENT_SRCS))
CMP_OBJS	:= $(patsubst $(TOP)/%.c,$(BUILDDIR)/real/%.o,$(CMP_SRCS))
MINICORPUS_OBJS	:= $(patsubst $(TOP)/%.c,$(BUILDDIR)/real/%.o,$(MINICORPUS_SRCS))
CHAIN_OBJS	:= $(patsubst $(TOP)/%.c,$(BUILDDIR)/real/%.o,$(CHAIN_SRCS))
KCOV_PERSIST_OBJS := $(patsubst $(TOP)/%.c,$(BUILDDIR)/real/%.o,$(KCOV_PERSIST_SRCS))
NETLINK_OBJS	:= $(patsubst $(TOP)/%.c,$(BUILDDIR)/real/%.o,$(NETLINK_SRCS))
FAKE_OBJS	:= $(patsubst %.c,$(BUILDDIR)/%.o,$(FAKE_SRCS))
TEST_OBJS	:= $(REAL_OBJS) $(PARENT_OBJS) $(CMP_OBJS) $(MINICORPUS_OBJS) $(CHAIN_OBJS) $(KCOV_PERSIST_OBJS) $(NETLINK_OBJS) $(FAKE_OBJS)

.PHONY: all test test-asan test-ndebug clean objs

all: $(TEST_BIN)
	./$(TEST_BIN)

test:
	$(MAKE) ASAN=0 NDEBUG=0

test-asan:
	$(MAKE) ASAN=1

test-ndebug:
	$(MAKE) NDEBUG=1

# Compile every object, link nothing and run nothing.  The top-level
# `make uapi-check` builds them this way, with its own BUILDDIR,
# CONFIG_H and SYSROOT.
objs: $(TEST_OBJS)

$(TEST_BIN): $(TEST_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(TEST_OBJS)

$(PARENT_OBJS) $(CMP_OBJS) $(MINICORPUS_OBJS) $(CHAIN_OBJS) $(KCOV_PERSIST_OBJS) $(NETLINK_OBJS): CFLAGS += -ffunction-sections -fdata-sections

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
