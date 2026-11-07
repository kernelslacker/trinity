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

# Netlink socket seam: fake_net.c wraps socket() so a test can say what
# an AF_NETLINK socket() returns; genl_ops_test.c hands the genl family
# resolver a unix socketpair that carries a canned controller reply.
# Unhooked, an AF_NETLINK request fails, so no test can open a real
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

# get_rand_testfile_fd() stand-in: fds/testfiles.c is linked for the
# testfile pool's init and defines the real picker, which reads a pool no
# sanitiser test installs.  arg_coupling_test.c wraps it with one that finds
# no testfile.
LDFLAGS		+= -Wl,--wrap=get_rand_testfile_fd

# The page-cache pickers' stand-ins: fds/pagecache.c and
# writeable-pagecache.c are linked for their pools' init and define the
# real pickers, which read pools no sanitiser test installs.
# arg_coupling_test.c wraps both with ones that find no fd.
LDFLAGS		+= -Wl,--wrap=get_rand_pagecache_fd \
		   -Wl,--wrap=get_rand_writeable_pagecache_fd

# The bpf pickers' stand-ins: fds/bpf.c is linked for bpf_pick_test.c,
# which runs the pickers through __real_, and every other caller gets
# fake_fds.c's wrappers, which read no pool.
LDFLAGS		+= -Wl,--wrap=get_rand_bpf_map -Wl,--wrap=get_rand_bpf_fd \
		   -Wl,--wrap=get_rand_bpf_prog -Wl,--wrap=get_rand_bpf_prog_fd \
		   -Wl,--wrap=get_rand_bpf_link_fd -Wl,--wrap=get_rand_bpf_btf_fd \
		   -Wl,--wrap=get_rand_bpf_token_fd

# set_object_fd() stand-in: objects/dispatch.c is linked for
# fd_from_object(), and no test is meant to reach its set_object_fd(),
# which fake_objects.c wraps with one that aborts.
LDFLAGS		+= -Wl,--wrap=set_object_fd

# fchown() stand-in: testfile_pool_test.c wraps it to see whom a root
# run's testfile init hands the files to, which the kernel would refuse a
# non-root test.  The wrapper forwards to the real fchown() unless armed.
LDFLAGS		+= -Wl,--wrap=fchown

# get_testfile_path() stand-in: args/pools/pathnames.c is linked for the
# pathname pool, and the sanitiser tests name the path a testfile pin
# takes through arg_coupling_test.c's wrapper.
LDFLAGS		+= -Wl,--wrap=get_testfile_path

# get_objhead() stand-in: objects/registry.c is linked for the
# for_each_obj snapshot, and its get_objhead() would resolve pools
# through childdata no test builds.  fake_objects.c wraps it with the
# stand-in a test installs its pools through.
LDFLAGS		+= -Wl,--wrap=get_objhead

# alloc_object() and add_object() hooks: the pool clones in
# mm/maps-lifecycle.c would otherwise take their objects from, and put them
# into, the object registry.  fake_objects.c wraps both; a test sets
# fake_alloc_object or fake_add_object to take the call, and unset the
# calls go to the real alloc_object() and to the fake add_object().
LDFLAGS		+= -Wl,--wrap=alloc_object -Wl,--wrap=add_object

# munmap() refusal injection: arg_coupling_test.c wraps munmap so a test
# can have it refuse a range with EPERM, unmapping nothing, as the kernel
# refuses one that holds a sealed VMA.  The wrapper forwards to the real
# munmap() unless armed.
LDFLAGS		+= -Wl,--wrap=munmap

# getuid() and getgid() stand-ins: arg_coupling_test.c wraps both so a
# test can try ids that fit 16 bits and ids that do not.  The wrappers
# forward to the real calls unless armed.
LDFLAGS		+= -Wl,--wrap=getuid -Wl,--wrap=getgid

# geteuid() stand-in: canary_path_test.c wraps it so a canary/ dir the
# test made reads as another uid's.  The wrapper forwards to the real
# call unless armed.
LDFLAGS		+= -Wl,--wrap=geteuid

# getresuid() and getresgid() stand-ins: post_oracle_test.c wraps both so
# the set*id oracles can read back ids the test process does not hold.
# The wrappers forward to the real calls unless armed.
LDFLAGS		+= -Wl,--wrap=getresuid -Wl,--wrap=getresgid

# epoll_ctl() stand-in: epoll_volatility_test.c wraps it to count the
# masks the childop's MOD arm sends.  The wrapper always forwards to
# the real call.
LDFLAGS		+= -Wl,--wrap=epoll_ctl

# unlink() stand-in: fake_fds.c wraps it so a provider test can plant a
# symlink under a name between the provider's unlink and its create.
# The wrapper forwards to the real call unless armed.
LDFLAGS		+= -Wl,--wrap=unlink

# get_map() and get_map_with_prot() stand-ins: mm/maps-pick.c is linked
# for get_map_handle(), and its wrappers would draw from pools most tests
# never build.  post_oracle_test.c wraps both: get_map() hands out the
# mapping a test names in fake_map_drawn, get_map_with_prot() none.
LDFLAGS		+= -Wl,--wrap=get_map -Wl,--wrap=get_map_with_prot

# valresult_alloc() tracking: args/valresult.c is linked for recvfrom's
# sanitiser, whose value-result buffers valresult_free() hands to deferred
# free, and that takes only a chunk the alloc-track holds, which this binary's
# zmalloc_tracked() never registers.  arg_coupling_test.c wraps
# valresult_alloc() to register both buffers, as production's does.
LDFLAGS		+= -Wl,--wrap=valresult_alloc

# syscall() stand-in: landlock_test.c wraps it so that, while it has a model
# kernel armed, the Landlock calls trinity_raw_syscall() makes in the fd
# provider and the post handler land in that model.  A suite that models a
# call of its own, as dup_pool_test.c does bpf()'s info query, hooks it
# through fake_syscall.  The wrapper forwards every other call, and the
# Landlock ones when nothing is armed, to the real syscall().
LDFLAGS		+= -Wl,--wrap=syscall

# ioctl() stand-in: procfs_self_test.c wraps it so that the PAGEMAP_SCAN the
# procfs-self sanitiser sends to learn which categories the kernel has lands
# in a model of pagemap_scan_get_args(), whatever kernel the test runs on.
# The wrapper forwards every other request to the real ioctl().
LDFLAGS		+= -Wl,--wrap=ioctl

# ctime-rule seams: ctime_rule_test.c wraps ctime_marks_change() and
# stat_mnt_id() so that the oracles' tests can have the rule hold or fail,
# and a kernel without unique mount ids answer as one with them, on any
# host.  Both wrappers forward to the real functions unless armed.
LDFLAGS		+= -Wl,--wrap=ctime_marks_change -Wl,--wrap=stat_mnt_id

# publish_resource() hook: syscalls/landlock/landlock_create_ruleset.c is
# linked for its post handler, which publishes the new ruleset's fd, and
# dup_pool_test.c defines a stand-in that fills a pool of its own.
# landlock_test.c wraps the call so it can see what the ruleset holds at the
# moment it is published; unhooked, the call goes on to the stand-in.
LDFLAGS		+= -Wl,--wrap=publish_resource

# pick_cmsg_kind() and cmsg_build() stand-ins: lib/cmsg_build.c is linked
# for cmsg_build_test.c, which runs the builder through __real_, and the
# send.c sanitisers get arg_coupling_test.c's wrappers, which build no
# control message.
LDFLAGS		+= -Wl,--wrap=pick_cmsg_kind -Wl,--wrap=cmsg_build

# get_writable_address() refusal: listmount_test.c wraps it so a test can
# fail a sanitiser's buffer draw, which the pools never refuse once made.
# The wrapper forwards to the real call unless armed.
LDFLAGS		+= -Wl,--wrap=get_writable_address

# ebpf_gen_program() spy: bpf_gen_test.c wraps it to tell the eBPF program
# a BPF_PROG_LOAD was handed from a classic one.  The wrapper always
# forwards to the real call.
LDFLAGS		+= -Wl,--wrap=ebpf_gen_program

# accept_unblocker_fire() stand-in: the accept and socketcall sanitisers
# get dup_pool_test.c's wrapper, which fails a handler that fires it, and
# unblocker_test.c fires the real connector through __real_.
LDFLAGS		+= -Wl,--wrap=accept_unblocker_fire

# ASAN target: `make -C tests ASAN=1` swaps in the ASAN knobs for the
# integration path.  -Og +
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
	$(TOP)/args/pools/kallsyms-symbols.c \
	$(TOP)/args/pools/exec-paths.c \
	$(TOP)/args/struct_validate.c \
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
# object pools.  ioctls/userfaultfd.c brings the userfaultfd group, whose
# fd_test the same test runs against the fake pools for the child-local
# fds the per-child provider seeds.
# ioctls/ext.c brings the ext group, whose sanitiser ioctl_args_test.c runs
# with the drm group's, for the args they build; its fd_test is not run.
# ioctls/hidraw.c, input.c and joystick.c bring the groups that rewrite a
# size-0 request to a random length, whose sanitisers ioctl_args_test.c
# runs.  ioctls/ioctl-arg.c brings the arg tiers they rebuild a3 with,
# which ioctl_args_test.c also runs on its own; the EFAULT probe they
# reach is efault_cache.c's.
# ioctls/procfs-self.c brings the procfs-self group, whose fd_test and
# sanitiser procfs_self_test.c runs: the sanitiser opens real procfs files of
# the test process, and get_map() hands out the mapping the test names, as
# post_oracle_test.c has it.  The owned-fd ring and the protected-fd registry
# it reaches are the real ones.
# ioctls/nsfs.c brings the nsfs group, whose fd_test and sanitiser nsfs_test.c
# runs over the test process's own namespace files, and fd_is_nsfs(), which
# the ioctl post handler asks.  ioctls/efault_cache.c brings the probe
# nsfs_test.c checks the group is kept out of; fake_ioctls.c registers the
# groups with it.
# syscalls/process/prctl.c, syscalls/sched/sched_getscheduler.c,
# syscalls/sched/sched_getaffinity.c, syscalls/cred/getgroups.c,
# syscalls/fs/getcwd.c and syscalls/socket/recv.c bring syscall_prctl,
# syscall_sched_getscheduler, syscall_sched_getaffinity,
# syscall_getgroups, syscall_getcwd and the recv family, whose post
# handlers post_oracle_test.c drives (prctl, sched_getaffinity, getgroups,
# getcwd and recvmsg through their own sanitisers) with the post_state
# table, post_snapshot_or_skip() and the corrupt-pointer bump faked;
# utils/proc-status.c is the /proc/self/status reader the
# sched_getaffinity and getgroups oracles compare against.
# sanitiser_owned_mask_test.c runs prctl's sanitiser too, for the slot it
# owns, and arg_coupling_test.c runs the recv and recvfrom sanitisers and
# their .vet_final hook over the fake pool mapping.  args/valresult.c is
# what recvfrom's sanitiser reaches.
# dispatch/syscall-post.c brings enforce_count_bound(), which runs ahead
# of those handlers.
# dispatch/syscall.c and dispatch/syscall-exec.c bring do_syscall() with the
# __do_syscall() and do_extrafork() it routes to, which
# dispatch_extrafork_test.c drives with the kcov bracket and the other calls
# the live path reaches faked.  args/arg_coupling.c brings the coupling
# validator __do_syscall() runs on the final argument slots;
# arg_coupling_test.c drives its per-syscall rules over the regions
# fake_shm.c is told to track.
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
# with no object pools behind the real readers and the domain tables in
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
	$(TOP)/ioctls/userfaultfd.c \
	$(TOP)/ioctls/epoll.c \
	$(TOP)/ioctls/perf_event.c \
	$(TOP)/ioctls/ext.c \
	$(TOP)/ioctls/hidraw.c \
	$(TOP)/ioctls/input.c \
	$(TOP)/ioctls/joystick.c \
	$(TOP)/ioctls/procfs-self.c \
	$(TOP)/ioctls/nsfs.c \
	$(TOP)/ioctls/efault_cache.c \
	$(TOP)/ioctls/ioctl-arg.c \
	$(TOP)/syscalls/ioctl.c \
	$(TOP)/syscalls/process/prctl.c \
	$(TOP)/syscalls/sched/sched_getscheduler.c \
	$(TOP)/syscalls/sched/sched_getaffinity.c \
	$(TOP)/syscalls/cred/getgroups.c \
	$(TOP)/syscalls/fs/getcwd.c \
	$(TOP)/utils/proc-status.c \
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

# The CMP-hint collect path, linked for cmp_hints_collect(), and the
# typed-hypothesis credit the consume stash feeds.  Same
# section-per-function treatment as the parent TUs; cmp_collect_test.c
# fakes the rest of the cmp_hints core it reaches.
CMP_SRCS	:= \
	$(TOP)/cmp_hints/collect.c \
	$(TOP)/cmp_hints/hyp-credit.c

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
# netlink_gen_msg(), append_specced_nlattr() and genl_resolve_families().
# The registries in genl/families.c and nfnl/subsystems.c name every
# grammar in their directories, so each directory is linked whole.  Same
# section-per-function treatment; genl_ops_test.c fakes the RNG helpers
# these reach and feeds the resolver a canned controller reply,
# nfnl_gen_test.c runs the nfnl grammars through the generator and
# rtnl_gen_test.c the rtnetlink message builders.
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
	struct_fill_elem_test.c \
	persist_util_test.c \
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
	cmp_hyp_credit_test.c \
	sanitiser_owned_mask_test.c \
	minicorpus_abi_test.c \
	chain_corpus_test.c \
	fake_arg_gens.c \
	corpus_replay_class_test.c \
	redqueen_pin_test.c \
	arg_coupling_test.c \
	asb_relocate_test.c \
	fake_ioctls.c \
	loop_status_test.c \
	ioctl_sanitise_test.c \
	ioctl_args_test.c \
	procfs_self_test.c \
	nsfs_test.c \
	genl_ops_test.c \
	nfnl_gen_test.c \
	rtnl_gen_test.c \
	kcov_persist_test.c \
	shutdown_wait_test.c \
	reap_fault_beacon_test.c \
	get_num_fds_test.c \
	spawn_test.c \
	post_oracle_test.c \
	scrub_inputs_test.c \
	dup_pool_test.c \
	ctime_rule_test.c \
	stat_recall_test.c \
	xattr_recall_test.c \
	selector_recall_test.c \
	readlink_recall_test.c \
	name_to_handle_at_test.c \
	results_test.c \
	frontier_window_test.c \
	listmount_recall_test.c \
	sockname_recall_test.c \
	pid_recall_test.c \
	mount_pool_test.c \
	bpf_gen_test.c \
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

# fds/canary.c brings the canary pool's provider, which registers itself at
# load time, and childops/mm/pagecache-canary-check.c the childop that
# reopens the pool's files.  canary_path_test.c runs the provider's init hook
# against the object-pool hooks in fake_objects.c, then the childop.  Same
# section-per-function treatment as the parent TUs above.
PARENT_SRCS	+= $(TOP)/fds/canary.c \
		   $(TOP)/childops/mm/pagecache-canary-check.c
FAKE_SRCS	+= canary_path_test.c

# fds/testfiles.c brings the testfile pool's provider, which registers itself
# at load time, and fds/files.c the fopen() opener it draws from.
# testfile_pool_test.c runs the provider's init hook against the object-pool
# hooks in fake_objects.c, with the mmap_fd() of the mm/maps-lifecycle.c
# linked below mapping each fd.  Same section-per-function treatment as the
# parent TUs above.
PARENT_SRCS	+= $(TOP)/fds/testfiles.c \
		   $(TOP)/fds/files.c
FAKE_SRCS	+= testfile_pool_test.c

# utils/writer-watch.c brings the --writer-watch breakpoint's probe, open
# and arm.  writer_watch_test.c answers their perf_event_open() with a model
# of the kernel's checks, through the fake_syscall hook of landlock_test.c.
PARENT_SRCS	+= $(TOP)/utils/writer-watch.c
FAKE_SRCS	+= writer_watch_test.c

# childops/fs/inode-spewer.c brings inode_spewer_reap(), which
# inode_spewer_test.c runs over spew dirs and a planted symlink in a tmp/
# of its own.  Same section-per-function treatment as the parent TUs
# above.
PARENT_SRCS	+= $(TOP)/childops/fs/inode-spewer.c
FAKE_SRCS	+= inode_spewer_test.c

# fds/sparse-files.c, writeable-pagecache.c and pagecache.c bring the
# sparse-file, writeable page-cache and page-cache pools' providers, which
# register themselves at load time.  planted_name_test.c runs their init
# hooks against the object-pool hooks in fake_objects.c, with a symlink
# planted under one of their names.  Same section-per-function treatment
# as the parent TUs above.
PARENT_SRCS	+= $(TOP)/fds/sparse-files.c \
		   $(TOP)/fds/writeable-pagecache.c \
		   $(TOP)/fds/pagecache.c
FAKE_SRCS	+= planted_name_test.c

# child/child-sentinel.c brings the divergence sentinel's tick.
# sentinel_test.c answers its uname() and sysinfo() with a model, through
# the fake_syscall hook of landlock_test.c, and stands in for the pre-crash
# ring it records each divergence in.
PARENT_SRCS	+= $(TOP)/child/child-sentinel.c
FAKE_SRCS	+= sentinel_test.c

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
# capped pool they put a file or directory in; it drives the post handlers
# of syscalls/ioctl.c, linked above, and syscalls/poll/epoll_create.c the
# same way.  syscalls/fs/ctime-rule.c brings the rule openat's O_PATH oracle
# judges a held ctime by, which ctime_rule_test.c checks.
PARENT_SRCS	+= $(TOP)/syscalls/fs/open.c \
		   $(TOP)/syscalls/fs/ctime-rule.c \
		   $(TOP)/syscalls/fs/creat.c \
		   $(TOP)/syscalls/poll/epoll_create.c \
		   $(TOP)/fds/fds-pool.c \
		   $(TOP)/dispatch/syscall-retfd.c

# syscalls/fs/stat/newstat.c, newlstat.c, newfstat.c and stat.c bring
# syscall_newstat, syscall_newlstat, syscall_newfstatat, syscall_newfstat
# and syscall_statx, whose sanitisers and post handlers
# stat_recall_test.c runs on a file of its own, and stat-recall.c the
# verdict their re-call oracles reach; statfs.c and fstatfs.c bring
# syscall_statfs and syscall_fstatfs, which it runs the same way, and
# file_getattr.c syscall_file_getattr, whose re-call it answers through
# landlock_test.c's syscall() seam.  syscalls/fs/mount/statmount.c
# brings syscall_statmount, whose sanitiser and post handler it runs on
# the mount / lies on, and whose pool of mount ids mount_pool_test.c holds
# to ids a real statmount() answers for.  syscalls/fs/mount/listmount.c
# brings syscall_listmount, whose pool the same test holds to ids a real
# listmount() lists under, and whose re-call listmount_recall_test.c runs
# on a mount of the host's own.
PARENT_SRCS	+= $(TOP)/syscalls/fs/mount/statmount.c \
		   $(TOP)/syscalls/fs/mount/listmount.c \
		   $(TOP)/syscalls/fs/stat/statfs.c \
		   $(TOP)/syscalls/fs/stat/fstatfs.c \
		   $(TOP)/syscalls/fs/stat/newstat.c \
		   $(TOP)/syscalls/fs/stat/newlstat.c \
		   $(TOP)/syscalls/fs/stat/newfstat.c \
		   $(TOP)/syscalls/fs/stat/stat.c \
		   $(TOP)/syscalls/fs/stat/file_getattr.c \
		   $(TOP)/syscalls/fs/stat/stat-recall.c

# syscalls/bpf.c and its sibling TUs bring syscall_bpf, whose sanitiser
# bpf_gen_test.c runs, and whose BPF_PROG_STREAM_OPEN post handler
# dup_pool_test.c drives against its fake object pool.  The program
# generators the other arms reach are linked as they are, and
# the struct_catalog/bpf*.c tables bring the map, program and attach type
# lists the sanitisers draw from; the pickers the arms draw their fds from
# are faked in fake_fds.c.  The schema fill the link_create sanitiser takes
# an attach type's tail from is args/struct_validate.c, in REAL_SRCS, run on
# the bpf_attr row of the catalog fake_stubs.c holds.
PARENT_SRCS	+= $(wildcard $(TOP)/syscalls/bpf*.c) \
		   $(wildcard $(TOP)/net/bpf/*.c) \
		   $(wildcard $(TOP)/struct_catalog/bpf*.c)

# syscalls/fs/read.c, syscalls/mq/mq_timedreceive.c, the getters and
# listers under syscalls/xattr/ and the value-buffer pickers they share
# bring the entries whose sanitisers arg_coupling_test.c runs under the
# count rule; post_oracle_test.c runs the xattr post handlers' bounds, and
# xattr_recall_test.c their re-calls, on files of its own.
PARENT_SRCS	+= $(TOP)/syscalls/fs/read.c \
		   $(TOP)/syscalls/mq/mq_timedreceive.c \
		   $(TOP)/syscalls/xattr/getxattr.c \
		   $(TOP)/syscalls/xattr/lgetxattr.c \
		   $(TOP)/syscalls/xattr/fgetxattr.c \
		   $(TOP)/syscalls/xattr/listxattr.c \
		   $(TOP)/syscalls/xattr/listxattrat.c \
		   $(TOP)/args/pools/xattr.c

# syscalls/clock/clock_getres.c, syscalls/process/getrlimit.c,
# getrusage.c, prlimit64.c and syscalls/fs/stat/sysfs.c bring the
# selector re-call oracles whose sanitisers and post handlers
# selector_recall_test.c runs, sysfs's answered through landlock_test.c's
# syscall() seam, and utils/rlimit-safe.c the resource picks prlimit64's
# sanitiser makes.
PARENT_SRCS	+= $(TOP)/syscalls/clock/clock_getres.c \
		   $(TOP)/syscalls/process/getrlimit.c \
		   $(TOP)/syscalls/process/getrusage.c \
		   $(TOP)/syscalls/process/prlimit64.c \
		   $(TOP)/syscalls/fs/stat/sysfs.c \
		   $(TOP)/utils/rlimit-safe.c

# syscalls/fs/readlink.c brings readlink, whose count bound
# post_oracle_test.c drives, and readlinkat, whose re-call
# readlink_recall_test.c runs on symlinks of its own.
PARENT_SRCS	+= $(TOP)/syscalls/fs/readlink.c

# syscalls/fs/path/name_to_handle_at.c brings name_to_handle_at, whose
# pathname and flags name_to_handle_at_test.c runs its sanitiser on.
PARENT_SRCS	+= $(TOP)/syscalls/fs/path/name_to_handle_at.c

# dispatch/results.c brings the fd and length scoreboards results_test.c
# has handle_success() and handle_failure() score.
PARENT_SRCS	+= $(TOP)/dispatch/results.c

# strategy/strategy-frontier-window.c brings frontier_window_advance(),
# whose rotations frontier_window_test.c runs over one syscall's ring.
PARENT_SRCS	+= $(TOP)/strategy/strategy-frontier-window.c

# syscalls/socket/getsockname.c and getpeername.c bring getsockname and
# getpeername, whose re-calls sockname_recall_test.c runs on sockets of
# its own, handed to the sanitisers through post_oracle_test.c's
# fd_from_socketinfo(); sockname-recall.c is the oracle getsockname runs.
PARENT_SRCS	+= $(TOP)/syscalls/socket/getsockname.c \
		   $(TOP)/syscalls/socket/getpeername.c \
		   $(TOP)/syscalls/socket/sockname-recall.c

# syscalls/cred/setgroups.c brings setgroups, whose getgroups() and
# /proc/self/status compares post_oracle_test.c runs.
PARENT_SRCS	+= $(TOP)/syscalls/cred/setgroups.c

# syscalls/clock/gettimeofday.c and clock_gettime.c,
# syscalls/timer/timer_gettime.c and timerfd_gettime.c and
# syscalls/itimer/getitimer.c bring the wall-clock compare and the range
# checks post_oracle_test.c runs on native and compat answers.
PARENT_SRCS	+= $(TOP)/syscalls/clock/gettimeofday.c \
		   $(TOP)/syscalls/clock/clock_gettime.c \
		   $(TOP)/syscalls/timer/timer_gettime.c \
		   $(TOP)/syscalls/timer/timerfd_gettime.c \
		   $(TOP)/syscalls/itimer/getitimer.c

# syscalls/io_uring/io_uring_register.c brings io_uring_register, whose
# per-opcode retval shapes post_oracle_test.c runs, and the payload
# builders its sanitiser calls.
PARENT_SRCS	+= $(TOP)/syscalls/io_uring/io_uring_register.c \
		   $(TOP)/syscalls/io_uring/io_uring_register-payloads.c

# syscalls/fsnotify/fanotify_init.c and syscalls/timer/timerfd_create.c
# bring fanotify_init and timerfd_create, whose published fds
# post_oracle_test.c checks the tags of.
PARENT_SRCS	+= $(TOP)/syscalls/fsnotify/fanotify_init.c \
		   $(TOP)/syscalls/timer/timerfd_create.c

# syscalls/fs/fallocate.c and syscalls/fs/ftruncate.c bring fallocate,
# ftruncate and ftruncate64, whose post handlers post_oracle_test.c checks
# invalidate the pooled mappings of the file the kernel cut, through a
# fake of mm/maps-proc.c's invalidate_obj_mmap_by_fd().
PARENT_SRCS	+= $(TOP)/syscalls/fs/fallocate.c \
		   $(TOP)/syscalls/fs/ftruncate.c

# syscalls/signal/rt_sigpending.c brings rt_sigpending, whose
# untouched-buffer check and /proc/self/status compare post_oracle_test.c
# runs.
PARENT_SRCS	+= $(TOP)/syscalls/signal/rt_sigpending.c

# syscalls/aio/io_submit.c brings io_submit, whose iocb pointer array
# arg_coupling_test.c reads at the call's width, with no aio context set
# up and the post handler's pool publishes hooked.
PARENT_SRCS	+= $(TOP)/syscalls/aio/io_submit.c

# syscalls/lsm/lsm_get_self_attr.c brings lsm_get_self_attr, whose re-call
# selector_recall_test.c runs against a fake of the syscall.
PARENT_SRCS	+= $(TOP)/syscalls/lsm/lsm_get_self_attr.c

# syscalls/concurrency/get_robust_list.c, syscalls/sched/sched_getattr.c
# and sched_rr_get_interval.c bring get_robust_list, sched_getattr and
# sched_rr_get_interval, whose re-calls on the calling task
# pid_recall_test.c runs.
PARENT_SRCS	+= $(TOP)/syscalls/concurrency/get_robust_list.c \
		   $(TOP)/syscalls/sched/sched_getattr.c \
		   $(TOP)/syscalls/sched/sched_rr_get_interval.c

# syscalls/fs/write.c and syscalls/fs/splice/vmsplice.c bring writev /
# pwritev / pwritev2 and vmsplice, whose iovec sanitisers and post
# handler arg_coupling_test.c runs over compat arrays on the last
# iovec-pool slice, and syscalls/process/process_vm_readv.c and
# process_vm_writev.c the process_vm pair, whose directional scrub
# the same case runs.  The writeable-pagecache fd pick the pwritev
# sanitisers reach is faked there, returning -1 for an empty pool.
PARENT_SRCS	+= $(TOP)/syscalls/fs/write.c \
		   $(TOP)/syscalls/fs/splice/vmsplice.c \
		   $(TOP)/syscalls/process/process_vm_readv.c \
		   $(TOP)/syscalls/process/process_vm_writev.c

# syscalls/ipc/sysv/shmat.c brings shmat, whose sanitiser
# arg_coupling_test.c runs over a fake pool mapping, which the get_map()
# of post_oracle_test.c hands out, and a SysV segment of the test's own,
# and ipc.c the ipc() multiplexer, whose sanitiser, .vet_final hook and
# .cleanup it runs with the sysv id pickers faked there.  semctl.c brings
# semctl, whose array-building sanitiser it runs too, msgctl.c msgctl,
# whose IPC_SET buffer it checks, and ipc-common.c the post-state helpers
# their post handlers reach.  shmctl.c brings shmctl, whose untouched-
# buffer check post_oracle_test.c runs with semctl's and msgctl's, and
# msgsnd.c msgsnd, whose flag draw arg_coupling_test.c checks.
PARENT_SRCS	+= $(TOP)/syscalls/ipc/sysv/shmat.c \
		   $(TOP)/syscalls/ipc/sysv/ipc.c \
		   $(TOP)/syscalls/ipc/sysv/semctl.c \
		   $(TOP)/syscalls/ipc/sysv/msgctl.c \
		   $(TOP)/syscalls/ipc/sysv/msgsnd.c \
		   $(TOP)/syscalls/ipc/sysv/shmctl.c \
		   $(TOP)/syscalls/ipc/sysv/ipc-common.c

# syscalls/mm/numa/get_mempolicy.c brings get_mempolicy, whose sanitiser
# arg_coupling_test.c runs over the fake pool mapping the mm tests use
# and whose re-call selector_recall_test.c runs against a fake, and
# syscalls/socket/send.c send and sendto, whose shared sanitiser
# arg_coupling_test.c runs the same way, with the sendmsg builders an
# ASAN build keeps linked faked there.
PARENT_SRCS	+= $(TOP)/syscalls/mm/numa/get_mempolicy.c \
		   $(TOP)/syscalls/socket/send.c

# fds/sockets-lane.c brings lane_netlink_socketinfo(), which the sendmsg
# sanitiser of the send.c linked above calls, and which lane_socket_test.c
# runs over a socket pool it installs through the get_objhead() stand-in,
# with the netlink sockets of the fake_net.c seam.  userns_lane_test.c runs
# check_uid() in a lane child, with lane_socket_test.c's lane flag.
PARENT_SRCS	+= $(TOP)/fds/sockets-lane.c
FAKE_SRCS	+= lane_socket_test.c \
		   userns_lane_test.c

# syscalls/process/seccomp.c and syscalls/concurrency/set_robust_list.c
# bring seccomp, whose GET_ACTION_AVAIL word, and set_robust_list, whose
# self-linked head, scrub_inputs_test.c follows through the blanket scrub,
# and syscalls/process/listns.c listns, whose request it checks the
# record owns once the sanitiser has moved it into the pool, and whose
# count bound post_oracle_test.c drives.
PARENT_SRCS	+= $(TOP)/syscalls/process/seccomp.c \
		   $(TOP)/syscalls/concurrency/set_robust_list.c \
		   $(TOP)/syscalls/process/listns.c

# syscalls/hardware/getrandom.c brings getrandom, whose sanitiser and
# .vet_final hook arg_coupling_test.c runs over a real mapping, as the
# sanitiser stamps the buffer it hands the kernel.
PARENT_SRCS	+= $(TOP)/syscalls/hardware/getrandom.c

# syscalls/syslog.c brings syslog, whose sanitiser and .vet_final hook
# arg_coupling_test.c runs over the fake pool mapping, which the get_map()
# of post_oracle_test.c hands out.
PARENT_SRCS	+= $(TOP)/syscalls/syslog.c

# syscalls/mm/mprotect.c, munmap.c and madvise.c bring mprotect,
# pkey_mprotect, munmap and madvise, whose sanitisers arg_coupling_test.c
# runs over a fake pool mapping, and mm/maps-arg.c the
# common_set_mmap_ptr_len() they pick their range with and the
# map_range_vet() validate_arg_coupling() holds it to.  The pkey pool,
# the heap-slip log, the /proc/self/maps oracle and the pool
# invalidation they reach are faked there.
PARENT_SRCS	+= $(TOP)/syscalls/mm/mprotect.c \
		   $(TOP)/syscalls/mm/munmap.c \
		   $(TOP)/syscalls/mm/madvise.c \
		   $(TOP)/mm/maps-arg.c

# syscalls/mm/process_madvise.c brings process_madvise, whose .vet_final
# hook arg_coupling_test.c runs over arrays in the iovec pool, and whose
# sanitiser it runs with a pidfd for the test process.
PARENT_SRCS	+= $(TOP)/syscalls/mm/process_madvise.c

# syscalls/mm/mremap.c and mincore.c bring mremap and mincore, whose
# sanitisers and post handlers arg_coupling_test.c runs over the same
# fake pool mapping, mmap.c mmap and mmap2, whose sanitiser it runs with
# an empty fd pool, flags drawn from a random subset, and the huge page
# size and post_mmap()'s dirty walk faked there, and mm/image-segments.c
# the image table the test fills from the binary's own segments, which
# mremap's fixed target is kept off.
PARENT_SRCS	+= $(TOP)/syscalls/mm/mremap.c \
		   $(TOP)/syscalls/mm/mincore.c \
		   $(TOP)/syscalls/mm/mmap.c \
		   $(TOP)/mm/image-segments.c

# syscalls/poll/epoll_wait.c and epoll_pwait.c bring the epoll_wait
# family, whose shared .vet_final hook arg_coupling_test.c runs through
# validate_arg_coupling().
PARENT_SRCS	+= $(TOP)/syscalls/poll/epoll_wait.c \
		   $(TOP)/syscalls/poll/epoll_pwait.c

# syscalls/process/wait4.c, waitpid.c and waitid.c bring the wait family,
# whose .vet_final hooks pidns_init_test.c runs through
# validate_arg_coupling().
PARENT_SRCS	+= $(TOP)/syscalls/process/wait4.c \
		   $(TOP)/syscalls/process/waitpid.c \
		   $(TOP)/syscalls/process/waitid.c

# syscalls/mm/numa/set_mempolicy_home_node.c brings set_mempolicy_home_node,
# whose sanitiser and .vet_final hook arg_coupling_test.c runs over the
# fake pool mapping the munmap tests use, and so does
# syscalls/mm/remap_file_pages.c for remap_file_pages.
# syscalls/mm/mseal.c brings mseal, whose sanitiser maps a real scratch
# mapping in the test process and whose hook and cleanup the same test
# runs.  syscalls/mm/numa/move_pages.c brings move_pages, whose sanitiser
# and hook it runs too, the arrays on the heap with every map lookup empty.
# syscalls/mm/map_shadow_stack.c brings map_shadow_stack, whose post
# handler's unmap it holds to a stand-in mapping through the munmap wrap.
PARENT_SRCS	+= $(TOP)/syscalls/mm/numa/set_mempolicy_home_node.c \
		   $(TOP)/syscalls/mm/mseal.c \
		   $(TOP)/syscalls/mm/remap_file_pages.c \
		   $(TOP)/syscalls/mm/numa/move_pages.c \
		   $(TOP)/syscalls/mm/map_shadow_stack.c

# objects/registry-pick.c and registry.c bring the pool readers:
# get_random_object(), objpool_check(), objects_empty() and
# objects_pool_empty(), and the for_each_obj snapshot.  They read the
# pools a test installs through the get_objhead() stand-in, or none:
# keyctl's sanitiser asks for a key serial pool that is not there.
# objects/objpool-arena.c brings the arena a child's local pools live
# in, which objpool_reader_test.c builds its pools from.
# mm/maps-lifecycle.c brings clone_global_mmap_pool(), whose dedup walk
# the same test runs over a local pool that already holds every global
# map, so it never reaches the alloc_object() and add_object() of a
# fresh clone.
PARENT_SRCS	+= $(TOP)/objects/registry-pick.c \
		   $(TOP)/objects/registry.c \
		   $(TOP)/objects/objpool-arena.c \
		   $(TOP)/mm/maps-lifecycle.c
FAKE_SRCS	+= objpool_reader_test.c

# maps_name_test.c runs map_destructor() and the pool clones of the
# mm/maps-lifecycle.c linked above over fake pools, and the post handler
# of the syscalls/mm/mmap.c linked above too.
FAKE_SRCS	+= maps_name_test.c

# maps_pick_test.c runs get_map_handle() over a pool it installs through
# the get_objhead() stand-in.
PARENT_SRCS	+= $(TOP)/mm/maps-pick.c
FAKE_SRCS	+= maps_pick_test.c

# syscalls/perf/ brings the perf_event_attr body builders, linked for
# maybe_fill_perf_attr_body() with the sample, tuple and config pickers it
# draws from and the PMU table those read, which stays empty here.
# struct_catalog/perf.c brings the field rows that describe the struct.
# perf_attr_test.c fills attrs through that entry point and holds them to the
# rules perf_copy_attr() applies, and the rows to the struct.
PARENT_SRCS	+= $(TOP)/syscalls/perf/perf_event_open-attr-build.c \
		   $(TOP)/syscalls/perf/perf_event_open-config-picker.c \
		   $(TOP)/syscalls/perf/perf_event_open-pmu-discovery.c \
		   $(TOP)/syscalls/perf/perf_event_open-sample-flags.c \
		   $(TOP)/syscalls/perf/perf_event_open-tuples.c \
		   $(TOP)/struct_catalog/perf.c
FAKE_SRCS	+= perf_attr_test.c

# syscalls/landlock/landlock_add_rule.c brings syscall_landlock_add_rule,
# whose sanitiser landlock_test.c runs and holds to what the kernel answers a
# rule with, fds/landlock.c the provider, whose init hook it runs against
# the fake object-pool hooks and a model of the Landlock syscalls, and
# landlock_create_ruleset.c syscall_landlock_create_ruleset, whose sanitiser
# and post handler it runs against the same model, with args/csfu.c the
# size-bucket builder the sanitiser draws its attr from.
PARENT_SRCS	+= $(TOP)/syscalls/landlock/landlock_add_rule.c \
		   $(TOP)/syscalls/landlock/landlock_create_ruleset.c \
		   $(TOP)/fds/landlock.c \
		   $(TOP)/fds/fds-diag.c \
		   $(TOP)/args/csfu.c
FAKE_SRCS	+= landlock_test.c

# lib/numa.c brings cpulist_weight(), which numa_test.c holds to the cpu
# lists the kernel prints and to lists it cannot count.
PARENT_SRCS	+= $(TOP)/lib/numa.c
FAKE_SRCS	+= numa_test.c

# syscalls/sched/getcpu.c and syscalls/cred/capget.c bring getcpu and
# capget, whose post handlers post_oracle_test.c drives through their own
# sanitisers, capget's re-call against a model through fake_syscall.
PARENT_SRCS	+= $(TOP)/syscalls/sched/getcpu.c \
		   $(TOP)/syscalls/cred/capget.c

# syscalls/cred/setreuid.c, setresuid.c, setregid.c and setresgid.c bring
# the set*id calls whose getres[ug]id() compares post_oracle_test.c runs.
PARENT_SRCS	+= $(TOP)/syscalls/cred/setreuid.c \
		   $(TOP)/syscalls/cred/setresuid.c \
		   $(TOP)/syscalls/cred/setregid.c \
		   $(TOP)/syscalls/cred/setresgid.c

# fds/bpf.c brings the bpf object pickers bpf_pick_test.c runs against the
# pools it installs through the get_objhead() stand-in, and
# objects/dispatch.c the fd_from_object() they read an object's fd with.
PARENT_SRCS	+= $(TOP)/fds/bpf.c \
		   $(TOP)/objects/dispatch.c
FAKE_SRCS	+= bpf_pick_test.c

# args/pools/pathnames.c brings the pathname pool, which
# pathname_pool_test.c builds from -V directories of its own.
PARENT_SRCS	+= $(TOP)/args/pools/pathnames.c
FAKE_SRCS	+= pathname_pool_test.c

# io_uring_register_test.c runs io_uring_register's sanitiser, linked above
# for post_oracle_test.c, and holds it to the payloads the kernel takes.
FAKE_SRCS	+= io_uring_register_test.c

# args/gen_arg_time.c brings the time generators, in place of
# fake_arg_gens.c's stand-ins, which gen_arg_time_test.c holds to the
# layout each call's ABI reads, syscalls/timer/timer_settime.c the
# sanitiser that rewrites ARG_ITIMERSPEC's struct, and
# syscalls/fs/timestamp/utimensat.c, syscalls/timer/timerfd_settime.c,
# syscalls/poll/pselect6.c, syscalls/poll/select.c,
# syscalls/clock/adjtimex.c and syscalls/clock/clock_adjtime.c ones that
# build their own.
PARENT_SRCS	+= $(TOP)/args/gen_arg_time.c \
		   $(TOP)/syscalls/timer/timer_settime.c \
		   $(TOP)/syscalls/fs/timestamp/utimensat.c \
		   $(TOP)/syscalls/timer/timerfd_settime.c \
		   $(TOP)/syscalls/poll/pselect6.c \
		   $(TOP)/syscalls/poll/select.c \
		   $(TOP)/syscalls/clock/adjtimex.c \
		   $(TOP)/syscalls/clock/clock_adjtime.c
FAKE_SRCS	+= gen_arg_time_test.c

# syscalls/concurrency/futex.c brings futex's sanitiser, which
# futex_test.c runs with every futex word pool empty.
PARENT_SRCS	+= $(TOP)/syscalls/concurrency/futex.c
FAKE_SRCS	+= futex_test.c

# syscalls/signal/sigaction.c brings rt_sigaction's sanitiser, whose act
# rt_sigaction_test.c reads at the kernel's offsets for each ABI.
PARENT_SRCS	+= $(TOP)/syscalls/signal/sigaction.c
FAKE_SRCS	+= rt_sigaction_test.c

# childops/misc/epoll-volatility.c brings the epoll_volatility childop,
# whose epoll_ctl() calls epoll_volatility_test.c counts on real epfds;
# rand/interesting-numbers.c is the edge values its ADD masks draw.
PARENT_SRCS	+= $(TOP)/childops/misc/epoll-volatility.c \
		   $(TOP)/rand/interesting-numbers.c
FAKE_SRCS	+= epoll_volatility_test.c

# fds/userfaultfd.c brings the userfaultfd provider, whose child-init
# hook userfaultfd_arm_test.c runs, answering the handshake itself
# through procfs_self_test.c's ioctl() stand-in.
PARENT_SRCS	+= $(TOP)/fds/userfaultfd.c
FAKE_SRCS	+= userfaultfd_arm_test.c

# lib/cmsg_build.c brings the sendmsg control builder, whose messages
# for AF_UNIX and AF_NETLINK cmsg_build_test.c holds to what
# __scm_send() takes.
PARENT_SRCS	+= $(TOP)/lib/cmsg_build.c
FAKE_SRCS	+= cmsg_build_test.c

# childops/net/rxrpc-key-install.c brings the rxrpc_key_install childop,
# whose add_key() payloads rxrpc_key_install_test.c holds to a model of
# the net/rxrpc/key.c parsers through landlock_test.c's syscall() hook.
PARENT_SRCS	+= $(TOP)/childops/net/rxrpc-key-install.c
FAKE_SRCS	+= rxrpc_key_install_test.c

# syscalls/concurrency/futex_wait.c brings futex_wait's sanitiser, whose
# futex word and timeout futex_wait_test.c checks on a compat call.
PARENT_SRCS	+= $(TOP)/syscalls/concurrency/futex_wait.c
FAKE_SRCS	+= futex_wait_test.c

# syscalls/lsm/lsm_list_modules.c brings lsm_list_modules' sanitiser,
# whose buffers lsm_list_modules_test.c checks on a compat call.
PARENT_SRCS	+= $(TOP)/syscalls/lsm/lsm_list_modules.c
FAKE_SRCS	+= lsm_list_modules_test.c

# listmount_test.c runs syscall_listmount's sanitiser, linked above for
# the recall test, with its id-buffer draw refused.
FAKE_SRCS	+= listmount_test.c

# struct_fill_fd_test.c runs struct_fill_passes() on an FT_FD field fed
# by fake_stubs.c's fd pool, against the real protected-fd registry.
FAKE_SRCS	+= struct_fill_fd_test.c

# budgeted_test.c reads BUDGETED() (include/child.h) over the fake shm's
# childop multipliers.
FAKE_SRCS	+= budgeted_test.c

# net/unblocker.c brings the accept unblocker, whose connector
# unblocker_test.c fires at a unix SOCK_SEQPACKET listener.
PARENT_SRCS	+= $(TOP)/net/unblocker.c
FAKE_SRCS	+= unblocker_test.c

# syscalls/x86/modify_ldt.c brings modify_ldt's sanitiser, whose buffers
# modify_ldt_test.c checks; it compiles to nothing off x86, as the test
# does.
PARENT_SRCS	+= $(TOP)/syscalls/x86/modify_ldt.c
FAKE_SRCS	+= modify_ldt_test.c

# fds/seccomp_notif.c brings the seccomp-notif provider, whose filter
# seccomp_notif_test.c catches through landlock_test.c's syscall() seam
# and runs; it compiles to nothing without USE_SECCOMP, as the test does.
PARENT_SRCS	+= $(TOP)/fds/seccomp_notif.c
FAKE_SRCS	+= seccomp_notif_test.c

# child/cred_throttle.c brings cred_class_for_entry(), the credential
# classification cred_class_test.c checks.
PARENT_SRCS	+= $(TOP)/child/cred_throttle.c
FAKE_SRCS	+= cred_class_test.c

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
