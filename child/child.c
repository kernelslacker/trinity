/*
 * Each process that gets forked runs this code.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <malloc.h>
#include <signal.h>
#include <stdatomic.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/personality.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/capability.h>
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
#include "list.h"
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
#include "strategy.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"	// ARRAY_SIZE
#include "uid.h"
#include "deferred-free.h"
#include "sanitise.h"
#include "sequence.h"
#include "utils.h"	// zmalloc
#include "vma-pressure.h"

#include "kernel/if_packet.h"
/*
 * Pin op_nr — the trailing field of the per-syscall hot block — to an
 * offset under 64 so a future field reorder that moves any of the hot
 * block (kcov, last_group, op_nr) past the leading cacheline boundary
 * fails the build instead of silently regressing the per-call
 * cache-miss budget the layout was tuned for.
 */
_Static_assert(offsetof(struct childdata, op_nr) < 64,
	"struct childdata: op_nr (per-syscall hot field) escaped the leading cacheline");

/*
 * Pin the syscallrecord (and therefore its trailing seq counter, mutated
 * by every writer via srec_publish_begin / srec_publish_end) to an
 * offset >= 64 so a future field reorder that drags the cold per-call
 * record into the hot cacheline fails the build instead of silently
 * blowing the per-call cache-miss budget the layout was tuned for.
 */
_Static_assert(offsetof(struct childdata, syscall) >= 64,
	"struct childdata: syscallrecord drifted into the hot cacheline");

/*
 * Pin the kcov local-stats staging pointer (a cold field, touched
 * only on the periodic-flush path) outside the leading hot cacheline
 * so a future field reorder that drags it into the per-syscall hot
 * block fails the build instead of silently shrinking the budget the
 * kcov / last_group / op_nr triplet was tuned to fit.
 */
_Static_assert(offsetof(struct childdata, local_stats) >= 64,
	"struct childdata: local_stats drifted into the hot cacheline");

/*
 * Temporarily exempt a child from reaper kills while it is in a critical
 * section that may legitimately exceed the normal timeout, such as lock
 * recovery or crash-log dumping.
 */
void set_dontkillme(struct childdata *child, bool state)
{
	if (child == NULL)	/* possible, we might be the mainpid */
		return;
	child->dontkillme = state;

	/* bump the progress indicator */
	clock_gettime(CLOCK_MONOTONIC, &child->tp);
}

void child_fd_ring_push(struct child_fd_ring *ring, int fd)
{
	ring->fds[ring->head % CHILD_FD_RING_SIZE] = fd;
	ring->head++;
}

/*
 * Sentinel-out any occurrences of `fd` in the ring.  Called from
 * close-like post handlers when the child knows an fd has just been
 * closed, so subsequent get_child_live_fd() picks don't waste an
 * fcntl(F_GETFD) syscall validating a known-dead entry.  Scans all 16
 * slots — bounded constant work; cheaper than the avoided fcntl.
 */
void child_fd_ring_remove(struct child_fd_ring *ring, int fd)
{
	int i;

	if (fd <= 2)
		return;
	for (i = 0; i < CHILD_FD_RING_SIZE; i++) {
		if (ring->fds[i] == fd)
			ring->fds[i] = -1;
	}
}

/*
 * Sentinel-out any ring entries whose fd falls within [lo, hi].
 * For close_range() post handlers — one pass over the ring instead of
 * `hi - lo + 1` calls to child_fd_ring_remove().
 */
void child_fd_ring_remove_range(struct child_fd_ring *ring, int lo, int hi)
{
	int i;

	for (i = 0; i < CHILD_FD_RING_SIZE; i++) {
		int fd = ring->fds[i];

		if (fd > 2 && fd >= lo && fd <= hi)
			ring->fds[i] = -1;
	}
}

/*
 * Single-producer push: extract the structured fields the post-mortem
 * reader consumes into the chronicle slot, then publish the new head
 * with a release-store so the reader observes a fully-written entry
 * when it sees the matching head value.  Field-by-field instead of a
 * struct copy because struct syscallrecord is dominated by the 4 KiB
 * pre-rendered prebuffer the post-mortem path doesn't need.
 */
void child_syscall_ring_push(struct child_syscall_ring *ring,
			     const struct syscallrecord *rec)
{
	struct chronicle_slot *slot;
	uint32_t head;

	head = __atomic_load_n(&ring->head, __ATOMIC_RELAXED);
	slot = &ring->recent[head & (CHILD_SYSCALL_RING_SIZE - 1)];

	slot->tp = rec->tp;
	slot->a1 = rec->a1;
	slot->a2 = rec->a2;
	slot->a3 = rec->a3;
	slot->a4 = rec->a4;
	slot->a5 = rec->a5;
	slot->a6 = rec->a6;
	slot->retval = rec->retval;
	slot->nr = rec->nr;
	slot->errno_post = rec->errno_post;
	slot->do32bit = rec->do32bit;
	slot->valid = true;

	__atomic_store_n(&ring->head, head + 1, __ATOMIC_RELEASE);
}

/*
 * Tweak the oom_score_adj setting for our child so that there's a higher
 * chance that the oom-killer kills our processes rather than something
 * more important.
 */
void oom_score_adj(int adj)
{
	FILE *fp;

	fp = fopen("/proc/self/oom_score_adj", "w");
	if (!fp)
		return;

	fprintf(fp, "%d", adj);
	fclose(fp);
}

#define FD_LEAK_THRESHOLD 50

static void check_fd_leaks(struct childdata *child)
{
	static const char * const group_names[NR_GROUPS] = {
		[GROUP_NONE] = "none",
		[GROUP_VM] = "vm",
		[GROUP_VFS] = "vfs",
		[GROUP_NET] = "net",
		[GROUP_IPC] = "ipc",
		[GROUP_PROCESS] = "process",
		[GROUP_SIGNAL] = "signal",
		[GROUP_IO_URING] = "io_uring",
		[GROUP_BPF] = "bpf",
		[GROUP_SCHED] = "sched",
		[GROUP_TIME] = "time",
		[GROUP_XATTR] = "xattr",
	};
	long delta;
	unsigned int i;

	if (child->fd_created < child->fd_closed)
		return;

	delta = (long)(child->fd_created - child->fd_closed);
	if (delta <= FD_LEAK_THRESHOLD)
		return;

	output(0, "fd leak: child %d created %lu closed %lu (delta %ld, %lu ops)\n",
		child->num, child->fd_created, child->fd_closed,
		delta, child->op_nr);

	for (i = 0; i < NR_GROUPS; i++) {
		if (child->fd_created_by_group[i] > 0)
			output(0, "  group %-10s: %lu fds created\n",
				group_names[i], child->fd_created_by_group[i]);
	}
}

/*
 * This is the child main loop, entered after init_child has completed
 * from the fork_children() loop.
 */
void child_process(struct childdata *child, int childno)
{
	char childname[17];
	int ret;

	/* PR_SET_PDEATHSIG SIGKILL: when the main process dies for any
	 * reason -- a fault, or an external SIGKILL from a wrapper that
	 * gave up on a hung syscall -- the kernel kills this fuzz child
	 * instead of leaving it reparented to init.  The orderly kill_pid
	 * shutdown the supervisor would have driven on a clean exit is
	 * bypassed on a crash; without this, a child wedged in a blocking
	 * syscall (e.g. a fuse poll) outlives the supervisor and needs
	 * manual cleanup.  SIGKILL not SIGTERM because a wedged child
	 * would not respond to a polite signal.
	 *
	 * Race window: if the main process died between fork() returning
	 * here and the prctl above, PDEATHSIG was set too late to fire and
	 * getppid() != mainpid is the only signal we get.  No CLONE_NEWPID
	 * at the spawn fork (init_child enters namespaces later, after the
	 * guard has run), so the host-namespace comparison is reliable. */
	(void)prctl(PR_SET_PDEATHSIG, SIGKILL);
	if (getppid() != mainpid)
		_exit(EXIT_MAIN_DISAPPEARED);

	/* Rename and lower OOM priority before init_child() runs.  init_child
	 * does a lot of mmap-heavy work (init_child_mappings, futex setup,
	 * sibling-childdata mprotect sweeps) which is exactly when memory
	 * pressure peaks.  If we wait until the end of init_child to set the
	 * comm + oom_score_adj, the kernel sees a fresh fork still named
	 * "trinity-main" with adj=0 and may pick it as the OOM victim instead
	 * of the actually-running children at adj=500. */
	memset(childname, 0, sizeof(childname));
	snprintf(childname, sizeof(childname), "trinity-c%d", childno);
	prctl(PR_SET_NAME, (unsigned long) &childname);
	oom_score_adj(500);

	init_child(child, childno);

	/* Whether this child is a dedicated alt-op slot is fixed for the
	 * child's lifetime: alt_op_children is set at startup and childno
	 * is constant per child.  Compute the predicate once instead of
	 * re-deriving it (3 loads + 2 branches) every loop iteration. */
	const bool use_dedicated_op = (alt_op_children != 0 &&
				       childno >= 0 &&
				       (unsigned int)childno < alt_op_children);

	/* kcov_shm is mapped once at startup (init_kcov_shm) and never
	 * reassigned for the child's lifetime, so the per-iteration NULL
	 * tests gating the edges_before snapshot and the post-call
	 * adapt_budget feedback are loop-invariant.  Hoist them once,
	 * mirroring the use_dedicated_op pattern above, to drop 2 loads
	 * + 2 compares per iteration on the dominant 95% syscall path. */
	const bool have_kcov = (kcov_shm != NULL);

	while (__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED) == STILL_RUNNING) {
		/* Fail-closed seal for the signal / longjmp unwind path:
		 * a fault handler that siglongjmps out of a mid-phase
		 * bookkeeping site (e.g. inside cleanup_release_post_state
		 * mid-consume) unwinds back to the loop top with regions
		 * still rw_open under --deferred-free-batch.  Seal every
		 * such leftover here, before the iteration touches any
		 * deferred-free state or dispatches, so the next kernel
		 * entry cannot see a stale window.  No-op with the flag
		 * OFF. */
		if (!deferred_free_seal_all()) {
			__atomic_add_fetch(
				&shm->stats.syscall_dispatch.seal_fail_aborts,
				1, __ATOMIC_RELAXED);
			outputerr("deferred_free: seal failed at loop-top "
				  "chokepoint; aborting child\n");
			goto out;
		}
		deferred_free_debug_assert_sealed();

		/* Catch-up sibling refreeze: a new sibling that ran init_child
		 * since our last sweep bumped shm->sibling_freeze_gen.  Re-run
		 * the mprotect sweep to pull that sibling's childdata into our
		 * PROT_READ set so a stray value-result kernel write of ours
		 * can't land there.  ACQUIRE pairs with the RELEASE bump in
		 * init_child.  No-op (single relaxed-equivalent load) on the
		 * common case where no sibling spawned. */
		unsigned int gen = __atomic_load_n(&shm->sibling_freeze_gen,
						   __ATOMIC_ACQUIRE);
		if (gen != child->last_seen_freeze_gen) {
			struct timespec _rf0, _rf1;
			long _rfns;

			clock_gettime(CLOCK_MONOTONIC, &_rf0);
			freeze_sibling_childdata(childno);
			clock_gettime(CLOCK_MONOTONIC, &_rf1);
			child->last_seen_freeze_gen = gen;
			_rfns = (_rf1.tv_sec - _rf0.tv_sec) * 1000000000L
				+ (_rf1.tv_nsec - _rf0.tv_nsec);
			__atomic_add_fetch(&shm->stats.diag.sibling_refreeze_count, 1,
					   __ATOMIC_RELAXED);
			if (_rfns > 0)
				__atomic_add_fetch(&shm->stats.diag.sibling_refreeze_ns,
						   (unsigned long)_rfns,
						   __ATOMIC_RELAXED);
		}

		if (ctrlc_pending) {
			panic(EXIT_SIGINT);
			break;
		}

		/* SIGALRM: the blocking syscall returned EINTR.
		 * Check for stalled-on-fd, detect stalls, and
		 * count the timeout as an op. */
		if (sigalrm_pending) {
			/* Per-op timeout_observed bump.  pick_op_type() runs
			 * further down the iter, so child->op_type here still
			 * holds the prior iter's pick -- i.e. the op whose
			 * `alarm(1)` is firing.  CHILD_OP_SYSCALL is skipped:
			 * NEED_ALARM syscalls arm their alarm inside
			 * random_syscall(), not at the alt-op site, so they
			 * have no per-op childop_outcome bucket.  Bounds-
			 * checked because op_type lives in shm and a
			 * scribbled-arena writer could land out of range. */
			enum child_op_type armed = child->op_type;
			if ((int)armed >= 0 && armed < NR_CHILD_OP_TYPES &&
			    armed != CHILD_OP_SYSCALL)
				__atomic_add_fetch(
					&shm->stats.childop.timeout_observed[armed],
					1, __ATOMIC_RELAXED);
			sigalrm_pending = 0;
			alarm(0);
			if (check_stall(child))
				goto out;
			if (__atomic_load_n(&child->kill_count, __ATOMIC_RELAXED) > 0) {
				output(1, "[%d] Missed a kill signal, exiting\n", mypid());
				goto out;
			}
		}

		if (xcpu_pending) {
			child->xcpu_count++;
			xcpu_pending = 0;
			if (child->xcpu_count == 100) {
				debugf("Child %d [%d] got 100 XCPUs. Exiting child.\n",
					childno, __atomic_load_n(&pids[childno], __ATOMIC_RELAXED));
				goto out;
			}
		}

		/* If the parent reseeded, we should reflect the latest seed too. */
		if (__atomic_load_n(&shm->seed, __ATOMIC_RELAXED) != child->seed) {
			set_seed(child);
		}

		/* Two back-to-back callsites below (periodic_work and the
		 * iter-start clock_gettime refresh) share the same 16-iter
		 * cadence.  Compute the predicate once and reuse, mirroring
		 * the use_dedicated_op / have_kcov hoists at the top of
		 * child_process(); saves 1 mask + 1 compare + 1 branch on
		 * every iter, not just the 5% alt-op path. */
		const bool tick16 = ((child->op_nr & 15) == 0);

		if (tick16)
			periodic_work(child, child->op_nr);

		/* Per-child storm-containment gate: once every
		 * LOCAL_STORM_CHECK_PERIOD iterations, score the three
		 * local corruption-rate counters against the threshold.
		 * The corruption is a per-child accumulator (a poisoned
		 * OBJ_LOCAL slot or a scribbled libc arena) -- it does
		 * not survive across fork(), so a fresh child re-inherits
		 * clean state and breaks the burn-arg-gen-cycles loop the
		 * storm produces.  Symptom containment, not a root-cause
		 * fix; the upstream scribble source is still active. */
		if ((child->op_nr & (LOCAL_STORM_CHECK_PERIOD - 1)) == 0 &&
		    storm_rate_recycle(child)) {
			stats_ring_enqueue(child->stats_ring,
					   STATS_FIELD_CHILDREN_RECYCLED_ON_STORM,
					   0, 1);
			goto out;
		}

		/* Free any deferred allocations whose TTL has expired.
		 * This runs before the syscall so that freed memory can
		 * be recycled by the allocator for the next sanitise. */
		deferred_free_tick();

		/* Pick an op type for this iteration.  Dedicated alt-op
		 * children (--alt-op-children=N reserves the first N
		 * slots) keep the op_type stamped by the parent at fork
		 * time and skip the random picker entirely; any other
		 * child uses the default 95% syscall / 5% alt-op mix. */
		if (use_dedicated_op == false)
			child->op_type = pick_op_type();

		/* --dry-run only neutralizes the syscall-dispatch path (the
		 * __do_syscall gate synthesizes -1/ENOSYS without entering the
		 * kernel).  Childops issue real syscalls directly and bypass
		 * that gate, so force every iteration -- both the dedicated
		 * alt-op children and the 5% alt-op mix -- onto CHILD_OP_SYSCALL
		 * under dry_run, leaving the mode genuinely syscall-free apart
		 * from the well-formed fd-provider setup. */
		if (dry_run)
			child->op_type = CHILD_OP_SYSCALL;

		/* -c <syscall>, -r <num>, and -g <group> scope the run to a
		 * specific syscall (or a random subset, or a group) for
		 * isolation / bisection runs.  The alt-op childops bypass the
		 * syscall-table gate and issue their own unrelated syscalls;
		 * the 5% leak from pick_op_type (and any dedicated alt-op slot
		 * from --alt-op-children) would contribute coverage, crashes,
		 * and brk/VMA churn that pollute the per-target signal.  Force
		 * CHILD_OP_SYSCALL so the run is actually isolated to the
		 * targeted syscall set; mirrors the dry_run override above and
		 * catches the dedicated alt-op slot same way. */
		if (do_specific_syscall || random_selection ||
		    desired_group != GROUP_NONE)
			child->op_type = CHILD_OP_SYSCALL;

		/* Snapshot op_type once per iter.  child->op_type lives in
		 * shared memory and can be scribbled by a poisoned-arena
		 * write between the picker above and the stats writers
		 * below.  The dispatch path already bounds-checks the field
		 * before indexing op_dispatch[], but the per-op stats arrays
		 * (sized by NR_CHILD_OP_TYPES) were indexed unchecked and a
		 * corrupted index would scribble past their backing store.
		 * Use the local for both dispatch and stats; skip the
		 * per-childop stats writes entirely when the snapshot is out
		 * of range. */
		const enum child_op_type op = child->op_type;
		const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

		/* The alt-op predicate is read three times below (alarm arm,
		 * watch_taint compute, alarm disarm + op_count bump) and the
		 * op_type field cannot change inside the iter body once
		 * stamped above.  Hoist into a single bool, mirroring the
		 * tick16 / use_dedicated_op / have_kcov hoists already in
		 * this loop; saves 2 loads + 2 compares per iter.  Folded in
		 * valid_op so a corrupted op_type both stays out of dispatch
		 * and out of the alt-op-only stats paths below. */
		const bool is_alt_op = valid_op && (op != CHILD_OP_SYSCALL);

		/* SHADOW-ONLY topology-pair latch.
		 * Stamp the most-recent setup childop type + op_nr on this
		 * child before op_fn runs, so productive events fired during
		 * this dispatch attribute to this setup (instead of inheriting
		 * the previous setup's identity).  Stamped only when this iter
		 * actually dispatches an alt-op; CHILD_OP_SYSCALL iters leave
		 * the latch in place so subsequent random-syscall productivity
		 * stays credited to whichever setup last preceded it.  The
		 * NR_CHILD_OP_TYPES sentinel from clean_childdata persists
		 * until the first alt-op iter runs.  Owner-only writes; the
		 * frontier_record_new_edge / _transition_edge readers run on
		 * the same child, so plain stores are sufficient. */
		if (is_alt_op) {
			child->last_setup_op = op;
			child->last_setup_op_nr = child->op_nr;
		}

		/* Refresh the iteration-start timestamp every 16th pass.
		 * vDSO clock_gettime is fast (~20 ns) but at ~700 ops/sec
		 * across 32 children it adds up; rec->tp consumers (taint
		 * ordering, pre_crash_ring) only need second-level
		 * granularity, and the parent-side stall reaper compares
		 * tv_sec with a 30-second threshold (main/loop.c:653).  At 700
		 * iters/sec a 16-iter sample interval is ~23 ms — well
		 * inside the second-level tolerance. */
		if (tick16)
			clock_gettime(CLOCK_MONOTONIC, &child->tp);

		/* Non-debug: hoisted to init_child().  Kept gated under
		 * shm->debug for parity with the existing debug semantics. */
		if (shm->debug == true)
			disable_coredumps();

		/*
		 * Non-syscall ops don't arm their own alarm; set one here so
		 * SIGALRM-based stall detection can fire if the op hangs.
		 * random_syscall() arms alarm internally for NEED_ALARM syscalls.
		 */
		if (is_alt_op) {
			/*
			 * Restore the inner-watchdog handler before arming.
			 * Both SIGALRM and SIGXCPU are in settable_signals[],
			 * so a fuzzed rt_sigaction call in this child can
			 * swap the disposition out for SIG_IGN/SIG_DFL/an
			 * arbitrary stub; without a reinstall the alt-op
			 * then rides the ~30-second outer watchdog instead
			 * of the 1-second inner one.  The helper is
			 * restricted to the two watchdog signals and bumps
			 * the paired clobbered/reinstalled counters so both
			 * the incidence and the repair rate stay measurable.
			 */
			watchdog_reinstall_if_clobbered();
			alarm(1);
		}

		/* Snapshot the global edge counter to feed the diagnostic
		 * childop_edges_discovered[] / childop_calls_with_edges[]
		 * comparator in the post-call block below.  adapt_budget
		 * and the canary queue now consume the clean bracketed
		 * delta (childop_edges_clean[]) instead; the noisy global
		 * counter is kept tracked so operators can diff the two
		 * during the bracket-coverage soak.  Cheap (single relaxed
		 * atomic load) and only meaningful if KCOV is active. */
		unsigned long edges_before = have_kcov
			? __atomic_load_n(&kcov_shm->coverage.edges_found,
					  __ATOMIC_RELAXED)
			: 0UL;

		bool (*op_fn)(struct childdata *) =
			valid_op ? op_dispatch[op] : NULL;

		/* Soft-taint watcher: bracket non-syscall dispatches with a
		 * read of /proc/sys/kernel/tainted so a bit transition (e.g.
		 * lockdep WARN, RCU stall, reckless module load) gets pinned
		 * to the specific childop that triggered it even when the
		 * kernel doesn't escalate to an oops.  Skipped for
		 * CHILD_OP_SYSCALL — the hot 95% path can't afford an extra
		 * pair of read syscalls per iteration, and random_syscall has
		 * its own taint-tracking via the existing pre_crash_ring
		 * record on syscall return. */
		const bool watch_taint = (is_alt_op && child->tainted_fd >= 0);
		unsigned long tainted_before = 0;
		if (watch_taint)
			tainted_before = child->last_tainted;

		/* Per-childop KCOV bracket.  Wraps op_fn (and the
		 * run_sequence_chain fallthrough, which is itself ruled
		 * out by op_uses_outer_bracket for CHILD_OP_SYSCALL) so
		 * the post-call collect attributes only this dispatch's
		 * new edges to childop_edges_clean[].  The is_alt_op
		 * pre-check is implicit: op_uses_outer_bracket gates out
		 * CHILD_OP_SYSCALL, and CHILD_OP_SCHED_CYCLER opts out
		 * because it recurses into per-syscall brackets that
		 * would drain the trace buffer before the outer collect
		 * sees it.  Default --childop-kcov-attribution=off short-
		 * circuits the whole block before kcov_bracket_begin is
		 * called. */
		bool bracketed = false;
		bool cmp_bracketed = false;
		unsigned long edges_this_call = 0;

		if (have_kcov &&
		    childop_kcov_attr_mode != CHILDOP_KCOV_ATTR_OFF &&
		    valid_op &&
		    op_uses_outer_bracket(op)) {
			/* Count one bracket attempt at the op_uses_outer_bracket
			 * gate so the begin-side reject arms in kcov_bracket_begin
			 * (skipped_cmp / skipped_nested / skipped_inactive) and
			 * the success arm (childop_kcov_bracketed) sum back to
			 * this counter -- the smoke-test invariant for this row. */
			__atomic_fetch_add(&kcov_shm->childop_kcov.childop_kcov_attempts,
				1, __ATOMIC_RELAXED);
			/* Per-op mirror.  Sized to KCOV_CHILDOP_NR_MAX;
			 * NR_CHILD_OP_TYPES is asserted to fit inside that
			 * bound in kcov.c, so op is always in range here. */
			__atomic_fetch_add(
				&kcov_shm->childop_kcov.childop_kcov_op_attempts[op],
				1, __ATOMIC_RELAXED);

			/* 1-of-N outer-bracket sampling gate.  With sample_n=1
			 * (the pre-sample default) ONE_IN(1) is always true and
			 * every eligible attempt reaches kcov_bracket_begin -- so
			 * a run with the gate disabled is byte-identical to the
			 * pre-sample codepath.  With sample_n=N>1 (default N=4),
			 * ~1/N attempts pass and the remaining (N-1)/N short-
			 * circuit here, bumping the per-op and aggregate
			 * skipped_sample counters so the invariant
			 *   attempts == bracketed + sum(skipped_*)
			 * closes with the new arm included.  The RNG draw uses
			 * the child's per-process rnd stream (fresh per child at
			 * init) so ordering across concurrent children stays
			 * decorrelated; deterministic modulo counters were
			 * considered but would concentrate every child's brackets
			 * on the same dispatch positions and skew the per-op
			 * sample stream toward whichever ops happen to land on
			 * those positions. */
			const bool sample_skipped =
				(childop_kcov_sample_n > 1U &&
				 !ONE_IN(childop_kcov_sample_n));

			if (sample_skipped) {
				__atomic_fetch_add(
					&kcov_shm->childop_kcov.childop_kcov_skipped_sample,
					1, __ATOMIC_RELAXED);
				__atomic_fetch_add(
					&kcov_shm->childop_kcov.childop_kcov_op_skipped_sample[op],
					1, __ATOMIC_RELAXED);
			} else {
				/* Snapshot the fields kcov_bracket_begin() consults
				 * BEFORE the call so a declined begin can be
				 * classified into the same reject arm the aggregate
				 * skip counter got bumped for.  Order matches the
				 * decision tree in kcov_bracket_begin(); kept in
				 * sync with that function. */
				const bool was_inactive =
					(!child->kcov.active || kcov_shm == NULL);
				const bool was_cmp =
					child->kcov.mode == KCOV_MODE_CMP;
				const bool was_nested = child->kcov.bracket_owned;

				bracketed = kcov_bracket_begin(&child->kcov);

				if (bracketed) {
					__atomic_fetch_add(
						&kcov_shm->childop_kcov.childop_kcov_op_bracketed[op],
						1, __ATOMIC_RELAXED);
				} else if (was_inactive) {
					__atomic_fetch_add(
						&kcov_shm->childop_kcov.childop_kcov_op_skipped_inactive[op],
						1, __ATOMIC_RELAXED);
				} else if (was_cmp) {
					__atomic_fetch_add(
						&kcov_shm->childop_kcov.childop_kcov_op_skipped_cmp[op],
						1, __ATOMIC_RELAXED);
				} else if (was_nested) {
					__atomic_fetch_add(
						&kcov_shm->childop_kcov.childop_kcov_op_skipped_nested[op],
						1, __ATOMIC_RELAXED);
				} else {
					/* Fell past every pre-check but begin still
					 * declined -- kcov_enable_trace() flipped
					 * active to false on ioctl failure, matching
					 * the second skipped_inactive arm inside
					 * kcov_bracket_begin(). */
					__atomic_fetch_add(
						&kcov_shm->childop_kcov.childop_kcov_op_skipped_inactive[op],
						1, __ATOMIC_RELAXED);
				}
			}
		}

		/* Mode-selected CMP-harvest bracket.  kcov_bracket_begin
		 * above unconditionally rejects KCOV_MODE_CMP children
		 * (childop_kcov_skipped_cmp), so on a CMP-mode child the PC
		 * `bracketed` path stays false and this block has exclusive
		 * ownership of the cmp_fd for the duration of the dispatch.
		 *
		 * Gated on the dedicated --childop-cmp-harvest knob (default
		 * off) so the OFF arm is byte-identical to a build without
		 * the harvest path: no KCOV_ENABLE/DISABLE ioctls fire on
		 * cmp_fd, no trinity_cmp_syscall wrapper writes to the
		 * quarantine lane, every childop_cmp_* counter stays at
		 * zero.
		 *
		 * Same op_uses_outer_bracket gate as the PC arm above for
		 * the same reason: CHILD_OP_SYSCALL falls through to
		 * random-syscall's own per-syscall CMP bracket (do_syscall)
		 * and CHILD_OP_SCHED_CYCLER recurses into per-syscall
		 * brackets that would otherwise drain the trace buffer
		 * before this outer collect sees it.  kcov_cmp_bracket_begin
		 * itself enforces mode == KCOV_MODE_CMP + cmp_capable +
		 * !bracket_owned + active, with per-arm reject counters in
		 * kcov_shm so the attempts == opened + sum(skipped)
		 * invariant is directly observable. */
		if (have_kcov &&
		    childop_cmp_harvest_mode != CHILDOP_CMP_HARVEST_OFF &&
		    valid_op &&
		    op_uses_outer_bracket(op)) {
			cmp_bracketed = kcov_cmp_bracket_begin(&child->kcov);
		}

		/* childop_split telemetry: bracket op_fn with a monotonic
		 * sample pair so the elapsed dispatch time can be split into
		 * childop vs random-syscall buckets.  Also set child->in_childop
		 * across the dispatch so a random_syscall() called from inside
		 * an alt-op recipe (e.g. sched_cycler) bumps syscalls_in_childops
		 * at the call-complete enqueue, not syscalls_random.  The flag
		 * is the per-child source of truth for the syscall-count
		 * attribution; the wall-time accumulation below is independent
		 * of it (driven off the is_alt_op snapshot taken at the top of
		 * the iter so a corrupted op_type can't reroute the bucket
		 * after we've already paid the op_fn). */
		struct timespec split_t0, split_t1;
		/* Per-op CPU-time bracket.  Paired with the wall bracket
		 * below and populated with the same is_alt_op gate so on-CPU
		 * work is attributed to the same op_type slot.  Read into
		 * struct childop_outcome's cpu_ns field, which lets the
		 * operator separate "spent N ns of wall time in this op"
		 * (wall_ns) from "burned N ns of CPU in this op" (cpu_ns) --
		 * a blocked-on-futex thread accrues wall time without CPU,
		 * whereas a busy-loop childop's cpu_ns approaches its wall_ns.
		 * CLOCK_THREAD_CPUTIME_ID measures the CALLING THREAD's
		 * user+sys CPU, which is exactly the accounting boundary the
		 * op_fn call site expects. */
		struct timespec cpu_t0, cpu_t1;
		if (is_alt_op)
			clock_gettime(CLOCK_THREAD_CPUTIME_ID, &cpu_t0);
		/* Fd-delta instrumentation: sample the lowest unused fd
		 * number before and after the dispatch so a leaking op
		 * (opens fds and forgets to close some on an error path)
		 * lands a positive delta.  Scoped to is_alt_op — the
		 * CHILD_OP_SYSCALL hot 95% path can't afford two extra
		 * syscalls per iter, and random_syscall's own fd bookkeeping
		 * covers pool-managed fds separately (see check_fd_leaks).
		 * A non-EMFILE probe failure returns -1 and the delta
		 * computation below treats that as "no observation" so
		 * a transient open(/dev/null) error doesn't scribble
		 * negative-cast values into the sum.  EMFILE returns
		 * the RLIMIT_NOFILE ceiling as a sentinel so the leak
		 * IS accounted for at fd-exhaustion time -- see
		 * probe_lowest_free_fd(). */
		bool fd_probe_at_ceiling = false;
		/* Timing temporaries for the fd-probe cost counters.
		 * Re-used for both the before- and after-probe brackets;
		 * declared here so the after-probe site below can
		 * share them without a second declaration inside the
		 * nested is_alt_op block. */
		struct timespec fd_probe_t0, fd_probe_t1;
		if (is_alt_op)
			clock_gettime(CLOCK_MONOTONIC, &fd_probe_t0);
		int fd_probe_before = is_alt_op ?
			probe_lowest_free_fd(&fd_probe_at_ceiling) : -1;
		if (is_alt_op) {
			clock_gettime(CLOCK_MONOTONIC, &fd_probe_t1);
			__atomic_add_fetch(
				&shm->stats.childop.fd_probe_calls,
				1UL, __ATOMIC_RELAXED);
			__atomic_add_fetch(
				&shm->stats.childop.fd_probe_ns_total,
				(unsigned long)((fd_probe_t1.tv_sec
						 - fd_probe_t0.tv_sec)
					       * 1000000000UL
					       + (unsigned long)(fd_probe_t1.tv_nsec
								 - fd_probe_t0.tv_nsec)),
				__ATOMIC_RELAXED);
		}
		clock_gettime(CLOCK_MONOTONIC, &split_t0);
		child->in_childop = is_alt_op;

		/* Childop dispatch is a kernel-entry chokepoint: op_fn
		 * and run_sequence_chain call trinity_raw_syscall and
		 * libc syscall wrappers directly, bypassing do_syscall
		 * (which has its own barrier).  Seal any window left
		 * rw_open by an earlier bookkeeping call in this
		 * iteration BEFORE the childop can hand a syscall to
		 * the kernel, otherwise a copy_to_user aliased to a
		 * deferred-free page silently scribbles instead of
		 * faulting on the PROT_READ/PROT_NONE tripwire.  No-op
		 * with --deferred-free-batch OFF. */
		if (!deferred_free_seal_all()) {
			__atomic_add_fetch(
				&shm->stats.syscall_dispatch.seal_fail_aborts,
				1, __ATOMIC_RELAXED);
			outputerr("deferred_free: seal failed at childop "
				  "dispatch chokepoint; aborting child\n");
			goto out;
		}
		deferred_free_debug_assert_sealed();

		ret = op_fn ? op_fn(child) : run_sequence_chain(child);

		child->in_childop = false;
		clock_gettime(CLOCK_MONOTONIC, &split_t1);
		if (is_alt_op)
			clock_gettime(CLOCK_THREAD_CPUTIME_ID, &cpu_t1);
		if (is_alt_op && fd_probe_before >= 0 && valid_op) {
			clock_gettime(CLOCK_MONOTONIC, &fd_probe_t0);
			int fd_probe_after =
				probe_lowest_free_fd(&fd_probe_at_ceiling);
			clock_gettime(CLOCK_MONOTONIC, &fd_probe_t1);
			__atomic_add_fetch(
				&shm->stats.childop.fd_probe_calls,
				1UL, __ATOMIC_RELAXED);
			__atomic_add_fetch(
				&shm->stats.childop.fd_probe_ns_total,
				(unsigned long)((fd_probe_t1.tv_sec
						 - fd_probe_t0.tv_sec)
					       * 1000000000UL
					       + (unsigned long)(fd_probe_t1.tv_nsec
								 - fd_probe_t0.tv_nsec)),
				__ATOMIC_RELAXED);

			if (fd_probe_after > fd_probe_before) {
				/* At the RLIMIT_NOFILE ceiling the ceiling
				 * value is a sentinel, not a real fd number:
				 * treating (ceiling - before) as the delta
				 * inflates fd_delta_positive_sum by ~rlim_cur
				 * per hit and mis-attributes a single leaked
				 * fd as a giant single-op leak.  Cap the
				 * reported delta to 1 and record the ceiling
				 * hit in a separate counter so operators can
				 * distinguish "op leaked N fds this call" from
				 * "fd table was already saturated". */
				unsigned int delta = fd_probe_at_ceiling ?
					1U :
					(unsigned int)(fd_probe_after - fd_probe_before);

				__atomic_add_fetch(
					&shm->stats.childop.fd_delta_positive_sum[op],
					delta, __ATOMIC_RELAXED);
				__atomic_add_fetch(
					&shm->stats.childop.fd_delta_positive_ops[op],
					1UL, __ATOMIC_RELAXED);
				if (fd_probe_at_ceiling)
					__atomic_add_fetch(
						&shm->stats.childop.fd_leak_at_ceiling[op],
						1UL, __ATOMIC_RELAXED);
			}
		}

		if (bracketed) {
			edges_this_call = kcov_bracket_end(
				&child->kcov,
				CHILDOP_KCOV_NR_BASE + op);
		}
		if (cmp_bracketed)
			kcov_cmp_bracket_end(&child->kcov);

		{
			long ns = (split_t1.tv_sec - split_t0.tv_sec) * 1000000000L
				+ (split_t1.tv_nsec - split_t0.tv_nsec);
			if (ns < 0)
				ns = 0;
			if (is_alt_op) {
				long cpu_ns = (cpu_t1.tv_sec - cpu_t0.tv_sec) * 1000000000L
					+ (cpu_t1.tv_nsec - cpu_t0.tv_nsec);
				if (cpu_ns < 0)
					cpu_ns = 0;
				__atomic_add_fetch(&shm->stats.childop.walltime_ns,
						   (unsigned long)ns, __ATOMIC_RELAXED);
				__atomic_add_fetch(&shm->stats.childop.wall_ns[op],
						   (unsigned long)ns, __ATOMIC_RELAXED);
				__atomic_add_fetch(&shm->stats.childop.cpu_ns[op],
						   (unsigned long)cpu_ns, __ATOMIC_RELAXED);
				/* SHADOW: feed the decaying-recency ring with
				 * the same delta.  No reader on the picker path;
				 * the ring is aged out by childop_window_advance()
				 * from the periodic-surface tick. */
				childop_decay_record_wall(op, (unsigned long)ns);
				/* Untraced dispatch-shape denominator: one
				 * bump per alt-op op_fn call.  Parallel to
				 * random_dispatches on the CHILD_OP_SYSCALL
				 * branch below; unlike childop.invocations[]
				 * this is a fleet-total scalar (no per-op
				 * NR_CHILD_OP_TYPES fan-out) so the child
				 * hot-path dispatch-cost model has a single
				 * denominator per source. */
				__atomic_add_fetch(&shm->stats.syscall_dispatch.childop_dispatches,
						   1UL, __ATOMIC_RELAXED);
			} else if (op == CHILD_OP_SYSCALL) {
				__atomic_add_fetch(&shm->stats.syscall_dispatch.walltime_ns,
						   (unsigned long)ns, __ATOMIC_RELAXED);
				/* Iteration denominator for childop_split.
				 * childop_invocations[] is gated on is_alt_op
				 * upstream, so CHILD_OP_SYSCALL is never counted
				 * there; this is its parallel counter. */
				__atomic_add_fetch(&shm->stats.syscall_dispatch.random_dispatches,
						   1UL, __ATOMIC_RELAXED);
			}
			/* Untraced outer-loop iteration denominator: bumped
			 * once per child_process() dispatch pass regardless of
			 * op_type or valid_op.  Pairs with the per-source
			 * (random_dispatches / childop_dispatches) counters
			 * above so the operator can price iterations-per-
			 * completed-syscall and iterations-per-childop without
			 * inferring the split from the per-op arrays. */
			__atomic_add_fetch(&shm->stats.syscall_dispatch.childop_iterations,
					   1UL, __ATOMIC_RELAXED);
		}

		if (watch_taint) {
			unsigned long tainted_after =
				read_tainted_mask(child->tainted_fd);
			unsigned long delta = tainted_after ^ tainted_before;
			if (delta) {
				pre_crash_ring_record_taint(child, delta,
							    tainted_after,
							    (unsigned int) op,
							    child->op_nr);
				__atomic_add_fetch(
					&shm->stats.childop.taint_transitions[op],
					1, __ATOMIC_RELAXED);
			}
			child->last_tainted = tainted_after;
		}

		if (is_alt_op) {
			/* Per-op timeout_missed bump: the op returned before
			 * the alarm armed above could fire.  sigalrm_pending
			 * is cleared by the iter-top SIGALRM block and only
			 * re-set by the handler, so == 0 here means no fire
			 * inside this iter's arm/disarm window; the fired
			 * case credits timeout_observed at the next iter's
			 * top instead. */
			if (sigalrm_pending == 0)
				__atomic_add_fetch(
					&shm->stats.childop.timeout_missed[op],
					1, __ATOMIC_RELAXED);
			alarm(0);
			stats_ring_enqueue(child->stats_ring,
					   STATS_FIELD_OP_COUNT, 0, 1);
		}

		/* Feed the per-call clean edge delta into the per-op budget
		 * multiplier and the canary-queue input counter
		 * (childop_edges_clean[]).  Both consumers see only the
		 * bracketed contribution from this dispatch -- no sibling
		 * noise -- and skip the ratchet entirely on calls that did
		 * not bracket (mode OFF, op_uses_outer_bracket(op) false,
		 * or kcov_bracket_begin rejected).
		 *
		 * The global edges_found before/after delta is preserved as
		 * a diagnostic so the operator can compare the noisy
		 * discovered counter against the clean counter per op while
		 * the bracket coverage soaks; remaining consumers (plateau
		 * snapshot) still read childop_edges_discovered[].  Skipped
		 * when KCOV is unavailable -- both signals require a live
		 * kcov_shm to be meaningful. */
		if (have_kcov) {
			unsigned long edges_after = __atomic_load_n(
				&kcov_shm->coverage.edges_found, __ATOMIC_RELAXED);
			if (bracketed && valid_op)
				adapt_budget(op, edges_this_call);
			if (is_alt_op) {
				unsigned long delta = (edges_after >= edges_before)
					? (edges_after - edges_before) : 0;
				__atomic_fetch_add(
					&shm->stats.childop.edges_discovered[op],
					delta, __ATOMIC_RELAXED);
				/* Parallel call-count bump for any invocation
				 * that surfaced at least one new edge.  Mirrors
				 * the syscall-path bandit/explorer call counters
				 * so the plateau classifier's Rule 2 can compare
				 * apples-to-apples instead of edge-count vs
				 * call-count. */
				if (delta > 0)
					__atomic_fetch_add(
						&shm->stats.childop.calls_with_edges[op],
						1, __ATOMIC_RELAXED);
			}
			/* dual / on modes only: publish the bracketed per-
			 * call delta to childop_edges_clean[].  off mode
			 * never sets bracketed=true, so this slot stays at
			 * zero and the consumers above degrade to "no
			 * signal this iteration" the same way they do on a
			 * build without KCOV. */
			if (bracketed) {
				__atomic_fetch_add(
					&shm->stats.childop.edges_clean[op],
					edges_this_call, __ATOMIC_RELAXED);
				/* SHADOW: feed the decaying-recency ring with
				 * the bracketed clean-edge delta.  Sibling of
				 * the wall bump above; same shadow contract. */
				childop_decay_record_edges(op, edges_this_call);
			}
		}

		/* Per-op invocation tally for the canary queue's window
		 * measurement.  Bumped per alt-op iteration regardless of
		 * KCOV availability (the canary queue's window-size logic
		 * must work even on builds without kcov), at the same
		 * post-call point so a crash mid-call is not counted.
		 * Skip CHILD_OP_SYSCALL -- parent_stats.op_count already
		 * aggregates that path. */
		if (is_alt_op) {
			__atomic_fetch_add(
				&shm->stats.childop.invocations[op],
				1UL, __ATOMIC_RELAXED);

			/* Per-op "last successful dispatch" timestamp, sampled
			 * from the same fleet-clock source the syscalls_todo
			 * termination check below reads.  Only stamped when the
			 * op returned SUCCESS -- a FAIL return covers throttled
			 * / setup-failed / skipped paths and must not refresh
			 * the timestamp, otherwise the dormancy signal collapses
			 * to "this op was attempted recently" (which the
			 * invocation counter above already encodes) instead of
			 * "this op did useful work recently".  RELAXED store: a
			 * single dispatch is a single writer to its op's slot;
			 * cross-op sibling races are tolerated -- last writer
			 * wins, which is the "most recent observed success"
			 * semantics dump_stats consumes for dormancy detection.
			 * 0 stays "never succeeded" because we only store here
			 * (the create_shm() memset already zeroed the array). */
			if (ret != FAIL && shm_published != NULL) {
				__atomic_store_n(
					&shm->stats.childop.last_success_ts[op],
					__atomic_load_n(
						&shm_published->fleet_op_count,
						__ATOMIC_RELAXED),
					__ATOMIC_RELAXED);
			}
		}

		if (shm->debug == true)
			enable_coredumps();

		__atomic_add_fetch(&child->op_nr, 1, __ATOMIC_RELAXED);

		if (ret == FAIL)
			goto out;

		if (syscalls_todo) {
			/* Read the parent-published mirror page rather than the
			 * canonical aggregate (which is parent-private and not
			 * visible from a child).  Mirror lag is bounded by the
			 * parent's drain cadence (~ms), well inside the
			 * termination granularity callers expect. */
			if (shm_published != NULL &&
			    __atomic_load_n(&shm_published->fleet_op_count,
					    __ATOMIC_RELAXED) >= syscalls_todo) {
				__atomic_store_n(&shm->exit_reason,
						EXIT_REACHED_COUNT, __ATOMIC_RELAXED);
				goto out;
			}
		}
	}

	/* If we're exiting because we tainted, wait here for it to be done.
	 * usleep(1) spins at ~1M syscalls/sec on this loop; 1ms is fine --
	 * postmortem is human-scale and the extra latency is unobservable
	 * next to the postmortem itself. */
	while (__atomic_load_n(&shm->postmortem_in_progress, __ATOMIC_ACQUIRE) == true) {
		/* Make sure the main process is still around. */
		if (pid_alive(mainpid) == false)
			goto out;

		usleep(1000);
	}

out:
	deferred_free_flush();
	check_fd_leaks(child);
	/* Drain any per-child kcov stats staged below the kcov_collect()
	 * cadence threshold before tearing the kcov fd down -- otherwise a
	 * child that exits / is killed / is recycled cold loses up to
	 * KCOV_LOCAL_STATS_FLUSH_SYSCALLS worth of total_calls / remote_calls
	 * / total_pcs.  kcov_cleanup_child() takes struct kcov_child * and
	 * cannot reach child->local_stats, which is why the flush belongs
	 * here on the full childdata.  The flush is gated per-field on
	 * (delta > 0) so it is safe to call with nothing staged. */
	kcov_child_flush_stats(child);
	kcov_cleanup_child(&child->kcov);
	inode_spewer_cleanup();
	psp_key_rotate_cleanup_child();

	if (child->fail_nth_fd != -1) {
		close(child->fail_nth_fd);
		child->fail_nth_fd = -1;
	}

	if (child->tainted_fd != -1) {
		close(child->tainted_fd);
		child->tainted_fd = -1;
	}

	debugf("child %d %d exiting.\n", childno, mypid());
}
