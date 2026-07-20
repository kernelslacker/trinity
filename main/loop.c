#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>


#include "child-api.h"
#include "childops-util.h"
#include "cmp_hints.h"
#include "debug.h"
#include "fd.h"
#include "fd-event.h"
#include "kcov.h"
#include "kmsg-monitor.h"
#include "minicorpus.h"
#include "objects.h"
#include "params.h"
#include "pids.h"
#include "post-mortem.h"
#include "pre_crash_ring.h"
#include "random.h"
#include "self_cgroup.h"
#include "sequence.h"
#include "shm.h"
#include "stats.h"
#include "stats_ring.h"
#include "strategy.h"
#include "syscall.h"
#include "syscall_record.h"
#include "tables.h"
#include "taint.h"
#include "trinity.h"
#include "uid.h"
#include "utils.h"
#include "main-internal.h"

static bool handled_taint = false;

static void taint_check(void)
{
	if (handled_taint == true)
		return;

	if (is_tainted() == true) {
		tainted_postmortem();
		handled_taint = true;
	}
}

/* Catches ring entries published between the last in-loop drain and process exit. */
static void final_ring_drain(void)
{
	fd_event_drain_all();
	stats_ring_drain_all();
}

/* Per-tick block that pulls fresh state from every child: reap zombies,
 * drain the two observation rings (fd_event/stats) into the parent
 * aggregates, then poll the two child-side beacons (hit_bug,
 * fault_beacon) for events a BUG'd or fault-handler-bound child
 * couldn't print itself.  No reorder, no new state. */
static void drain_child_surfaces(void)
{
	handle_children();

	/* Drain fd events from all children's ring buffers.
	 * This processes dup/close events that children couldn't
	 * apply directly (COW heap prevents global pool mutation). */
	fd_event_drain_all();

	/* Drain stats deltas from all children's rings into the
	 * parent-private aggregate.  Republishes the mirror page
	 * inside its own thaw/refreeze bracket. */
	stats_ring_drain_all();

	/* Surface any child-side __BUG() event the BUG'd child
	 * stamped into shared memory but couldn't print itself
	 * (stderr was redirected to /dev/null in init_child).  Cost
	 * is one acquire-load per child per tick; dump_child_bug is
	 * idempotent via its bug_dumped cmpxchg gate, so the
	 * zombie watchdog calling it later (or this loop firing
	 * twice between BUG and reap) doesn't double-print. */
	{
		unsigned int bi;

		for_each_child(bi) {
			struct childdata *bc =
				__atomic_load_n(&children[bi],
						__ATOMIC_ACQUIRE);

			if (bc == NULL)
				continue;
			if (!__atomic_load_n(&bc->hit_bug,
					     __ATOMIC_ACQUIRE))
				continue;
			if (__atomic_load_n(&bc->bug_dumped,
					    __ATOMIC_ACQUIRE))
				continue;
			dump_child_bug(bc);
		}
	}

	/* Surface any signal-time fault beacon stamped by
	 * child_fault_handler.  Sibling poll to the hit_bug block
	 * above with identical shape; cheap acquire-load per child
	 * per tick and dump_child_fault_beacon is idempotent via
	 * its fault_beacon_dumped cmpxchg gate.  The beacon path
	 * exists because the in-handler backtrace_symbols_fd chain
	 * can re-fault on a corrupted ld.so writable segment
	 * before any forensic line lands on disk; without this
	 * poll the SIGSEGV-in-ld.so death class is silent in the
	 * bug corpus. */
	{
		unsigned int fi;

		for_each_child(fi) {
			struct childdata *fc =
				__atomic_load_n(&children[fi],
						__ATOMIC_ACQUIRE);

			if (fc == NULL)
				continue;
			if (__atomic_load_n(&fc->fault_beacon.written,
					    __ATOMIC_ACQUIRE) == 0U)
				continue;
			if (__atomic_load_n(&fc->fault_beacon_dumped,
					    __ATOMIC_ACQUIRE))
				continue;
			dump_child_fault_beacon(fc);
		}
	}
}

/* Per-tick stop-condition checks.  Runs after the child-surface
 * drain so taint and shm-integrity checks see the freshest state.
 * Returns true if main_loop should branch straight to the corrupt
 * shutdown label (shm integrity lost -- pid map can't be trusted).
 * The epoch limit / iteration limit / wall-clock timeout cases
 * trigger panic() instead, which stamps shm->exit_reason and lets
 * the while-loop condition catch the exit on its next pass. */
static bool check_main_loop_stops(const struct timespec *epoch_start)
{
	taint_check();

	self_cgroup_events_check();

	if (shm_is_corrupt() == true)
		return true;

	/* Targeted-run depletion: in -c <syscall> / -r <num> / -g <group>
	 * mode the active set is a fixed subset of the table.  Each entry
	 * can be self-disabled by deactivate_enosys() (ENOSYS return) or
	 * note_validation_failure() (VALIDATE_FAIL_THRESHOLD validation
	 * fails).  When the set empties, the next child that runs
	 * set_syscall_nr() stamps shm->exit_reason and exits clean (0),
	 * but until that observation lands the parent keeps fork-replacing
	 * any slot that races ahead.  Under the wrong scheduling, the
	 * replacement children burn through init_child, hit
	 * no_syscalls_enabled on their first pick, exit, and a sustained
	 * stream of fast (<2s) reaps fills reap_ring[] enough that some
	 * adjacent non-clean exit (a panic-reason _exit from a sibling that
	 * tripped EXIT_REPARENT_PROBLEM / EXIT_KERNEL_TAINTED / similar)
	 * tips reap_ring_fast_die_count to FAST_DIE_RING_SIZE and panics
	 * EXIT_SHM_CORRUPTION.  That alarm is a false positive: the shm is
	 * fine, the targeted set just exhausted itself.  The parent has
	 * authoritative visibility into nr_active_syscalls before the next
	 * round-trip through a child, so detect the depletion here and
	 * stamp the genuine reason before the fast-die circuit fires.  The
	 * gate on do_specific_syscall / random_selection / desired_group is
	 * load-bearing: in default-fuzz mode an unexpected drop to zero
	 * active syscalls IS evidence of corruption and must stay on the
	 * fast-die / shm_is_corrupt path.  Only targeted mode treats
	 * empty-set as expected-and-clean. */
	if ((do_specific_syscall || random_selection ||
	     desired_group != GROUP_NONE) &&
	    no_syscalls_enabled() == true &&
	    __atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED) == STILL_RUNNING) {
		output(0, "targeted syscall set self-disabled (every selected "
			  "syscall hit ENOSYS or VALIDATE_FAIL_THRESHOLD); "
			  "nothing left to fuzz, exiting cleanly\n");
		panic(EXIT_NO_SYSCALLS_ENABLED);
	}

	while (check_all_locks() == true) {
		reap_dead_kids();
		if (__atomic_load_n(&shm->exit_reason, __ATOMIC_ACQUIRE) == EXIT_REACHED_COUNT)
			kill_all_kids();
	}

	unsigned long op = parent_stats.op_count;

	if (syscalls_todo && (op >= syscalls_todo)) {
		output(0, "Reached limit %lu. Telling children to exit.\n", syscalls_todo);
		panic(EXIT_REACHED_COUNT);
	}

	if (epoch_iterations && (op >= epoch_iterations)) {
		output(0, "Epoch iteration limit %lu reached.\n", epoch_iterations);
		panic(EXIT_EPOCH_DONE);
	}

	if (epoch_timeout) {
		struct timespec now;
		clock_gettime(CLOCK_MONOTONIC, &now);
		if ((unsigned int)(now.tv_sec - epoch_start->tv_sec) >= epoch_timeout) {
			output(0, "Epoch timeout %u seconds reached.\n", epoch_timeout);
			final_state_save();
			panic(EXIT_EPOCH_DONE);
		}
	}

	return false;
}

/* Per-tick periodic-surface phase: zombie reaping, anomaly spike
 * detection, the operator-visibility dumps (defense counters, top
 * syscalls, vma count, kcov cmp stats, canary queue summary),
 * coverage-plateau / kcov-bitmap / cmp-hints snapshot triggers,
 * the stats heartbeat, and the canary-queue per-tick window work.
 * Each call is internally rate-limited / self-gated -- this helper
 * is "fire every tick, callees decide if they actually run". */
static void run_periodic_surfaces(void)
{
	check_children_progressing();

	process_zombie_pending();

	corrupt_ptr_spike_check();

	periodic_counter_rates_dump();

	childop_periodic_dump_and_advance();

	cost_pool_periodic_dump();

	top_syscalls_periodic_dump();

	vma_count_periodic_dump();

	kcov_cmp_stats_periodic_dump();

	/* Canary queue summary line (60-s cadence, self-rate-limited
	 * inside the call). */
	canary_queue_summary();

	kcov_plateau_check();

	kcov_bitmap_maybe_snapshot();

	/* Periodic popcount-vs-edges_found audit of bucket_seen[].  Self-
	 * gated on KCOV_BITMAP_CANARY_INTERVAL_SEC so the 8 MB scan only
	 * runs at the snapshot cadence.  Catches wild-writer scribbles
	 * that the guard-shared armour cannot see -- guard pages only
	 * fault on writes that miss the kcov_shm region entirely, not on
	 * writes that land inside it. */
	kcov_bitmap_canary_check();

	/* Periodic walk of the per-op mut_trials/mut_wins (and structured)
	 * pairs verifying the by-construction wins <= trials inequality.
	 * O(MUT_NUM_OPS) and self-gated on MUT_ATTRIB_CANARY_INTERVAL_SEC.
	 * Catches scribbled-counter-word inversions that would silently
	 * mislead the bandit's per-op weighting until the next stats dump
	 * notices. */
	minicorpus_mut_attrib_canary_check();

	cmp_hints_maybe_snapshot();

	/* Same crash-resilience rationale as cmp_hints_maybe_snapshot():
	 * the end-of-run save in trinity.c only fires on a clean shutdown
	 * reason, so a kill / crash mid-run would otherwise drop every
	 * chain admitted since the last successful save.  Cadence gates
	 * (CHAIN_CORPUS_SNAPSHOT_NEW admits + CHAIN_CORPUS_SNAPSHOT_INTERVAL_SEC
	 * seconds) live inside the callee. */
	chain_corpus_maybe_snapshot();

	print_stats();

	/* Canary queue per-tick work: poll the active op's window
	 * progress, fire promote/demote transitions when the window
	 * closes, drain backed-off demotes back into the picker pool.
	 * Cheap when the queue is disabled (single bool check).  The
	 * matching 60-s summary line is emitted from stats.c alongside
	 * the other periodic-surface dumps -- keeping it there means
	 * adding a new periodic visibility surface to the queue does
	 * not require a separate main_loop edit. */
	canary_queue_tick();
}

/* Final operator-visibility line at main_loop shutdown: state why
 * we're bailing.  EXIT_UID_CHANGED carries extra forensic context
 * (the uid we now hold versus the one we started with), so it gets
 * its own format; everything else routes through decode_exit. */
static void log_main_loop_exit(void)
{
	enum exit_reasons reason =
		__atomic_load_n(&shm->exit_reason, __ATOMIC_ACQUIRE);

	switch (reason) {
	case EXIT_UID_CHANGED: {
		uid_t bad = __atomic_load_n(&shm->uid_at_exit,
					    __ATOMIC_ACQUIRE);
		output(0, "Bailing main loop because UID changed (was %u, now %u).\n",
			orig_uid, bad);
		break;
	}
	default:
		output(0, "Bailing main loop because %s.\n",
			decode_exit(reason));
		break;
	}

	/* Pair the bail reason with the operator-set runtime ceiling so the
	 * "hit the limit we were asked to honour" case and an internal
	 * abort that happens to share the same exit_reason cannot be
	 * conflated.  EXIT_EPOCH_DONE on a --max-runtime run is the limit
	 * firing; the same reason without max_runtime_set is the inner
	 * --epoch-iterations / --epoch-timeout cap; EXIT_FORK_FAILURE is
	 * never the limit, regardless of what the operator configured.
	 * Post-mortem grep wants both halves on a single line. */
	{
		char limit[64];

		if (max_runtime_set && epoch_timeout)
			snprintf(limit, sizeof(limit),
				 "max_runtime=%us", epoch_timeout);
		else if (epoch_timeout)
			snprintf(limit, sizeof(limit),
				 "epoch_timeout=%us", epoch_timeout);
		else if (epoch_iterations)
			snprintf(limit, sizeof(limit),
				 "epoch_iterations=%lu", epoch_iterations);
		else if (syscalls_todo)
			snprintf(limit, sizeof(limit),
				 "syscalls_todo=%lu", syscalls_todo);
		else
			snprintf(limit, sizeof(limit), "(none)");

		output(0, "main: exit summary configured_limit:%s"
			  " internal_exit_reason:%s(%d)\n",
			limit, decode_exit(reason), (int)reason);
	}

	{
		unsigned int printed, omitted, sigs;

		dstate_diag_get_counts(&printed, &omitted, &sigs);
		output(0, "D-state diag summary: verbose printed=%u"
			  " omitted=%u sigs=%u\n",
			printed, omitted, sigs);
	}
}

/* Shutdown-tail wait: keep reaping and killing children until the
 * pid map is empty.  Per-invocation counters (last, shutdown_attempts)
 * are scoped to this call so they reset across epochs -- carrying
 * them in file scope would let a prior epoch's count trip the >10
 * cap on the first real wait of a new epoch. */
static void wait_for_children_to_exit(void)
{
	unsigned int last = 0;
	unsigned int shutdown_attempts = 0;

	handle_children();

	/* Are there still children running ? */
	while (pidmap_empty() == false) {
		if (++shutdown_attempts > 10) {
			output(0, "Gave up waiting for children after %u attempts.\n",
				shutdown_attempts);
			panic(EXIT_TIMED_OUT);
			break;
		}

		if (last != __atomic_load_n(&shm->running_childs, __ATOMIC_RELAXED)) {
			last = __atomic_load_n(&shm->running_childs, __ATOMIC_RELAXED);

			output(0, "exit_reason=%d, but %u children still running.\n",
				__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED),
				__atomic_load_n(&shm->running_childs, __ATOMIC_RELAXED));
		}

		/* Wait for all the children to exit. */
		while (__atomic_load_n(&shm->running_childs, __ATOMIC_RELAXED) > 0) {
			taint_check();

			handle_children();
			kill_all_kids();
			/* Give children a chance to exit before retrying. */
			sleep(1);
		}
		reap_dead_kids();
	}
}

/*
 * Close inherited /proc/<pid>/stat fds in a freshly forked child.
 * pidstatfiles[] is parent-only (only get_pid_state and the parent
 * reap/replace paths in this file read or close them), but the fds are
 * opened post-fork as each child is spawned, so every later child
 * inherits the earlier slots' fds.  Without this drop, a fuzzed close()
 * or dup2() in any child blinds the parent's liveness / stuck-detection
 * (get_pid_state then misreads child state via a stale or repointed fd).
 * No CLOEXEC alternative: trinity's children don't exec.
 */
void pidstatfiles_drop_in_child(void)
{
	unsigned int i;

	if (pidstatfiles == NULL)
		return;

	for_each_child(i) {
		if (pidstatfiles[i] >= 0) {
			close(pidstatfiles[i]);
			pidstatfiles[i] = -1;
		}
	}
}

void main_loop(void)
{
	struct timespec epoch_start = { 0 };
	unsigned int i;

	output(1, "phase: entering main_loop\n");

	/* Capture the run-identity baseline (edges_found / distinct_edges
	 * / corpus_entries) on the very first entry into main_loop, which
	 * is the post-warm-load point: trinity.c's warm_start_all() has
	 * already populated kcov_shm->edges_warm_loaded and the per-
	 * syscall corpus rings, so this snapshot is the "where this run
	 * picked up from" baseline that the shutdown render computes
	 * own-start deltas against.  Idempotent inside the function so
	 * epoch_loop's repeated main_loop entries leave the very-first
	 * baseline untouched. */
	stats_runid_snapshot_start();

	/* Sized by max_children, which is fixed before the epoch loop
	 * starts.  Allocate once and reuse across epochs; per-epoch
	 * contents are cleared in reset_epoch_state().  Without the guard,
	 * each epoch leaks a fresh set of arrays into the long-lived
	 * parent. */
	if (pidstatfiles == NULL) {
		pidstatfiles = zmalloc(max_children * sizeof(int));
		zombie_pids = zmalloc(max_children * sizeof(pid_t));
		zombie_since = zmalloc(max_children * sizeof(time_t));
		spawn_times = zmalloc(max_children * sizeof(time_t));
		for_each_child(i) {
			pidstatfiles[i] = -1;
			zombie_pids[i] = EMPTY_PIDSLOT;
		}
	}

	if (epoch_timeout)
		clock_gettime(CLOCK_MONOTONIC, &epoch_start);

	init_altop_dispatch();
	log_alt_op_config();

	/* Dormant-childop canary queue.  Brings the queue up after
	 * init_altop_dispatch() has populated the dense vector from the
	 * static gate, so the queue's startup pass over
	 * dormant_op_disabled[] sees the same state the dispatcher
	 * will.  When --no-canary-queue is in effect, canary_queue_init()
	 * still runs but stays in its disabled-no-op mode. */
	canary_queue_init();

	output(1, "phase: fork_children\n");
	fork_children();

	while (__atomic_load_n(&shm->exit_reason, __ATOMIC_ACQUIRE) == STILL_RUNNING) {

		drain_child_surfaces();

		if (check_main_loop_stops(&epoch_start) == true)
			goto corrupt;

		run_periodic_surfaces();

		/* This should never happen, but just to catch corner cases, like if
		 * fork() failed when we tried to replace a child.
		 */
		if (__atomic_load_n(&shm->running_childs, __ATOMIC_RELAXED) < max_children)
			fork_children();
	}

	/* if the pid map is corrupt, we can't trust that we'll
	 * ever successfully finish pidmap_empty, so skip it */
	if ((__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED) == EXIT_LOST_CHILD) ||
	    (__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED) == EXIT_SHM_CORRUPTION))
		goto dont_wait;

	wait_for_children_to_exit();

corrupt:
	kill_all_kids();

dont_wait:
	log_main_loop_exit();

	final_ring_drain();
}


/*
 * Reset shared state between epochs.  Coverage data (kcov bitmap,
 * cmp_hints, minicorpus) is deliberately preserved so that coverage
 * accumulates across epoch boundaries.
 */
void reset_epoch_state(void)
{
	unsigned int i;

	__atomic_store_n(&shm->exit_reason, STILL_RUNNING, __ATOMIC_RELAXED);
	__atomic_store_n(&shm->spawn_no_more, false, __ATOMIC_RELEASE);
	__atomic_store_n(&shm->ready, false, __ATOMIC_RELEASE);
	__atomic_store_n(&shm->running_childs, 0, __ATOMIC_RELAXED);

	parent_stats.op_count = 0;
	parent_stats.previous_op_count = 0;

	if (shm_published != NULL)
		__atomic_store_n(&shm_published->fleet_op_count, 0UL,
				 __ATOMIC_RELAXED);

	/*
	 * Strategy-rotation window-start snapshots.  maybe_rotate_strategy()
	 * in random-syscall.c computes the window interval as
	 *   (shm_published->fleet_op_count - shm->syscalls_at_last_switch)
	 * with unsigned subtraction.  fleet_op_count is reset above; if we
	 * leave syscalls_at_last_switch holding the previous epoch's final
	 * value, the next maybe_rotate_strategy() call sees (0 - large),
	 * underflows to a huge unsigned, and trips the STRATEGY_WINDOW
	 * threshold immediately -- a bogus forced rotation on the first
	 * syscall of the new epoch.  The per-strategy delta series
	 * (pc_edge_calls/_count, bandit_cmp_new_constants) are cumulative
	 * and intentionally NOT reset.
	 *
	 * The *_at_window_start fields are reseeded from the matching
	 * *_by_strategy[current_strategy] cumulative counters, mirroring the
	 * reseed performed at the end of maybe_rotate_strategy() when an arm
	 * rotates.  Zeroing them instead would make the first window after
	 * the epoch reset compute its delta as (cumulative - 0), absorbing
	 * every reward earned in prior epochs and biasing UCB / EMA state for
	 * the first arm to close a window in the new epoch.
	 *
	 * Bandit arm state (bandit_pulls, bandit_reward_calls, ...) is
	 * intentionally NOT reset -- warm-start across epochs is the desired
	 * UCB1 semantics.  cmp_hints pool, the kcov bitmap, and the
	 * alloc_track ring are also intentionally preserved across epochs
	 * for the same reason.
	 */
	/* fleet_op_count anchor for the next STRATEGY_WINDOW interval */
	__atomic_store_n(&shm->syscalls_at_last_switch, 0UL,
			 __ATOMIC_RELEASE);
	{
		int cur = __atomic_load_n(&shm->current_strategy,
					  __ATOMIC_RELAXED);
		if (cur < 0 || cur >= NR_STRATEGIES)
			cur = STRATEGY_HEURISTIC;

		/* pc_edge_calls_by_strategy[cur] snapshot for next
		 * call-count delta */
		__atomic_store_n(&shm->pc_edge_calls_at_window_start,
				 __atomic_load_n(
					 &shm->pc_edge_calls_by_strategy[cur],
					 __ATOMIC_RELAXED),
				 __ATOMIC_RELAXED);
		/* pc_edge_count_by_strategy[cur] snapshot for next
		 * bucket-count delta */
		__atomic_store_n(&shm->pc_edge_count_at_window_start,
				 __atomic_load_n(
					 &shm->pc_edge_count_by_strategy[cur],
					 __ATOMIC_RELAXED),
				 __ATOMIC_RELAXED);
		/* bandit_cmp_new_constants[cur] snapshot for next
		 * cmp-novelty delta */
		__atomic_store_n(&shm->bandit_cmp_at_window_start,
				 __atomic_load_n(
					 &shm->bandit_cmp_new_constants[cur],
					 __ATOMIC_RELAXED),
				 __ATOMIC_RELAXED);
	}
	for_each_child(i) {
		__atomic_store_n(&pids[i], EMPTY_PIDSLOT, __ATOMIC_RELAXED);
		clean_childdata(children[i]);
		fd_event_ring_init(children[i]->fd_event_ring);

		/* Parent-local per-slot arrays are persistent across epochs
		 * (allocated once in main_loop) -- clear the stale entries
		 * the previous epoch left behind. */
		if (pidstatfiles[i] >= 0) {
			close(pidstatfiles[i]);
			pidstatfiles[i] = -1;
		}
		zombie_pids[i] = EMPTY_PIDSLOT;
		zombie_since[i] = 0;
		spawn_times[i] = 0;
	}

	/* zombie_pids[] is now EMPTY_PIDSLOT across the board; reset the
	 * aggregate gauge in lockstep so process_zombie_pending's gauge != 0
	 * fast-path actually sees zero and short-circuits.  Sibling counters
	 * zombies_reaped / zombies_timed_out are cumulative-by-design and
	 * correctly persist; only the live gauge needs the re-zero. */
	__atomic_store_n(&shm->stats.zombie_reaper.slots_pending, 0, __ATOMIC_RELAXED);

	reseed();
}

/*
 * Something potentially bad happened. Alert all processes by setting appropriate shm vars.
 * (not always 'bad', reaching max count for eg is one example).
 */
void panic(int reason)
{
	__atomic_store_n(&shm->spawn_no_more, true, __ATOMIC_RELEASE);
	__atomic_store_n(&shm->exit_reason, reason, __ATOMIC_RELEASE);
}
