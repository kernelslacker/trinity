/*
 * Per-child setup coordinator: this file's init_child() is the sole
 * setup entry point child_process() calls, and its body is the
 * readable phase map for the forked-process bring-up sequence.  Each
 * phase's implementation lives in a sibling child-init-*.c:
 *
 *   - child-init-clean.c   coredump toggles, fault-injection fd
 *                          setup (make-it-fail, fail-nth), tainted-
 *                          mask fd, FPU dirtier, per-slot occupant
 *                          reset (clean_childdata).
 *   - child-init-isolate.c stdio + controlling-terminal isolation
 *                          (fd 0/1/2 -> /dev/null, parent-fd drops,
 *                          setsid()).
 *   - child-init-freeze.c  initial sibling-childdata + shared-region
 *                          mprotect(PROT_READ) sweeps and the parent
 *                          rendezvous / per-child object-pool bring-
 *                          up that follows.
 *   - child-init-sandbox.c shm->ready barrier, fault-injector arm,
 *                          per-child unshare()s, root-only
 *                          drop_privs, capset()-to-empty + oracle
 *                          anchor capture, rlimit / cgroup / umask
 *                          sweep in munge_process.
 *   - child-init-runtime.c kcov bring-up, uniarch active-syscalls
 *                          pin, explorer-pool slot flag, A/B-
 *                          comparison cohort stamps, heap-bounds
 *                          re-snapshot, RLIMIT_AS pin, one-shot
 *                          disable_coredumps.
 *
 * All five phase files' entry points are declared in
 * include/child-internal.h; init_child() below calls them in the
 * order they appear as the fork-side setup sequence.  Deliberately
 * kept as a coordinator rather than folded into constructor-like
 * side effects so the phase ordering stays readable in one place.
 */

#include <errno.h>
#include <malloc.h>
#include <signal.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/personality.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/capability.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "arch.h"
#include "child.h"
#include "child-internal.h"
#include "fd.h"
#include "futex.h"
#include "fd-event.h"
#include "kcov.h"
#include "maps.h"
#include "minicorpus.h"
#include "objects.h"
#include "params.h"
#include "pids.h"
#include "pre_crash_ring.h"
#include "random.h"
#include "rnd.h"
#include "self_cgroup.h"
#include "shm.h"
#include "signals.h"
#include "stats.h"
#include "stats_ring.h"
#include "syscall.h"
#include "trinity.h"	// ARRAY_SIZE
#include "writer-watch.h"
#include "uid.h"
#include "utils.h"	// zmalloc

#include "kernel/sched.h"
/*
 * Called from the fork_children loop in the main process.
 */
void init_child(struct childdata *child, int childno)
{
	init_child_isolate_io();

	/*
	 * Override init_child_isolate_io()'s stderr -> /dev/null
	 * baseline with a per-child memfd buffer so glibc's
	 * malloc_printerr / __libc_message / __fortify_fail family
	 * writes survive long enough for child_fault_handler() to
	 * flush them into the on-disk bug log on a real crash.
	 * Clean exits discard the memfd with the process so trinity's
	 * own outputerr() noise never reaches disk.  Falls back to
	 * /dev/null on memfd_create() failure (see signals.c).
	 */
	init_stderr_memfd();

	init_child_freeze_shared(child, childno);

	init_child_rendezvous_parent(child, childno);

	init_child_setup_sandbox(child, childno);

	/*
	 * Post-fork per-provider bring-up.  Providers whose kernel-side
	 * resource lifecycle is tied to the creating task's mm (KVM VM /
	 * vCPU fds most obviously) must create their objects here rather
	 * than in the parent-side .init hook, otherwise every child
	 * inherits a parent-owned object that the kernel refuses from
	 * child context.  Sequenced after init_child_setup_sandbox() so
	 * per-child unshare/drop_privs/rlimit tightening are already in
	 * effect and the child's kernel-object view matches what the
	 * fuzz loop will actually see; sequenced before
	 * init_child_runtime_config() so the RLIMIT_AS 4 GiB pin does
	 * not clip legitimate per-provider mmaps at bring-up time.
	 * No-op today for every existing provider (child_init == NULL);
	 * providers opt in explicitly.
	 */
	run_fd_provider_child_init(child);

	init_child_runtime_config(child, childno);

	/*
	 * Turn on glibc's verbose heap-corruption abort path.  Without
	 * this, malloc_printerr emits a short "<assertion>" string on a
	 * silent abort(); with M_CHECK_ACTION=3 it formats a fuller
	 * message ("free(): double free detected in tcache 2",
	 * "malloc(): unsorted double linked list corrupted", &c) into
	 * __abort_msg before raising SIGABRT.  The fault handler in
	 * signals.c reads that pointer (cached at init_abort_msg_capture
	 * time below) and writes it into the per-pid bug log, which is
	 * what lets the post-mortem bucket aborts by corruption mode
	 * rather than landing them all under malloc+0x150.
	 *
	 * Use mallopt() rather than MALLOC_CHECK_=3 in the environment:
	 * trinity fuzzes execve, and any leaked MALLOC_CHECK_ in the
	 * inherited envp would perturb the child-of-child's malloc
	 * behaviour.  mallopt() is in-process only and inherited across
	 * fork, so this single call covers the child and any further
	 * children it forks for fuzzing.
	 *
	 * Cost is a 5-15%% malloc-path overhead -- acceptable for the
	 * bucketing payoff, and the syscall fuzzer is not malloc-bound.
	 *
	 * Paired with init_abort_msg_capture(), which resolves glibc's
	 * __abort_msg via dlsym(RTLD_DEFAULT, ...) and caches the
	 * pointer for the signal-safe read in the SIGABRT handler.
	 * Placed at the bottom of init_child so RTLD_DEFAULT's symbol
	 * table is fully populated by the time dlsym runs.
	 */
	(void)mallopt(M_CHECK_ACTION, 3);

	/*
	 * Pin glibc to a single arena so heap_bounds_init()'s one-shot
	 * /proc/self/maps snapshot covers ALL glibc allocations.  Glibc
	 * normally spawns secondary mmap'd arenas on demand (per-thread,
	 * under allocation pressure, large mallocs that bypass
	 * MMAP_THRESHOLD); range_overlaps_libc_heap() only sees the
	 * snapshotted brk + the arenas present at snapshot time and has
	 * a live re-test for the brk arm but not the mmap-arena arm, so
	 * a post-snapshot secondary arena is a blind spot.  A fuzzed
	 * pointer landing in that arena then passes the sanitiser, the
	 * kernel writes through it and scribbles glibc chunk metadata,
	 * surfacing later as `free(): invalid size` / check_uid aborts
	 * with no obvious proximate cause.  M_ARENA_MAX=1 forbids
	 * spawning a second arena and M_ARENA_TEST=1 disables the
	 * contention-growth heuristic that would otherwise try.  The
	 * child is effectively single-threaded in the syscall loop, so
	 * arena-contention cost is ~zero.
	 */
	(void)mallopt(M_ARENA_MAX, 1);
	(void)mallopt(M_ARENA_TEST, 1);

	init_abort_msg_capture();

	/*
	 * Arm the Stage-2 writer-pinning canary hardware breakpoint last.
	 * Default-OFF: writer_watch_arm_child() short-circuits when
	 * --writer-watch was not passed (writer_watch_addr == 0).  Runs
	 * after mask_signals_child() has installed the SIGTRAP handler
	 * (mask_signals_child is called earlier via init_child_setup_sandbox
	 * -> ... -> the child fork-side init path), so a trap delivered
	 * to this thread immediately after arming is dispatched to
	 * writer_trap_handler instead of the kernel-default core-dump
	 * behaviour. */
	writer_watch_arm_child();

	/*
	 * --self-corrupt-canary sentinel allocation (default OFF).  The
	 * init helper short-circuits when the flag was not passed, so
	 * an operator not opting in pays no zmalloc, no memset, and no
	 * per-child heap footprint.  When the flag is on, allocates the
	 * 64-byte magic-filled buffer whose bytes the pre/post-dispatch
	 * signature loop folds into its XOR checksum. */
	self_corrupt_canary_init_child();
}
