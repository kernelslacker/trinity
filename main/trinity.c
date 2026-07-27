#include <errno.h>
#include <limits.h>
#include <malloc.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "arch.h"
#include "child-api.h"
#include "cmp_hints.h"
#include "fd.h"
#include "files.h"
#include "ioctls.h"
#include "isolation.h"
#include "kcov.h"
#include "kmsg-monitor.h"
#include "maps.h"
#include "minicorpus.h"
#include "numa.h"
#include "objects.h"
#include "pids.h"
#include "params.h"
#include "persist-envelope.h"
#include "domains.h"
#include "random.h"
#include "rlimits.h"
#include "self_cgroup.h"
#include "sequence.h"
#include "signals.h"
#include "shm.h"
#include "stats.h"
#include "stats_ring.h"
#include "strategy.h"
#include "tables.h"
#include "taint.h"
#include "trinity.h"
#include "trinity-internal.h"
#include "uid.h"
#include "utils.h"
#include "version.h"

static int set_exit_code(enum exit_reasons reason)
{
	/* Clean exits return 0; everything else returns the reason
	 * code directly so the parent can distinguish failure modes. */
	switch (reason) {
	case STILL_RUNNING:
	case EXIT_REACHED_COUNT:
	case EXIT_SIGINT:
	case EXIT_USER_REQUEST:
	case EXIT_EPOCH_DONE:
		return EXIT_SUCCESS;

	default:
		return (int)reason;
	}
}

/*
 * Epoch-based wrapper around main_loop().
 *
 * Runs main_loop() for a bounded number of iterations or wall-clock
 * seconds.  When the epoch limit is reached, main_loop() returns with
 * shm->exit_reason == EXIT_EPOCH_DONE; we reset the per-epoch shared
 * state in-place and call main_loop() again.  Coverage data (kcov
 * bitmap, cmp_hints, minicorpus) lives in MAP_SHARED memory
 * and accumulates across epochs.
 *
 * main_loop() runs in-process rather than in an epoch-child so that
 * parent_stats -- a process-private global in stats-ring.c that
 * aggregates running totals -- survives across epochs.  If the epoch
 * body ran in a child, parent_stats would die with the child at epoch
 * end and the outer parent would never see the aggregated numbers.
 * reset_epoch_state() zeroes the per-epoch state that does need
 * clearing between epochs; everything else worth preserving already
 * lives in MAP_SHARED shm pages.  Real wild-write exposure lives in
 * the per-iteration child fork, not here, so running the epoch body
 * in the parent costs no crash isolation.
 */
static void epoch_loop(void)
{
	unsigned int epoch_nr = 0;

	while (1) {
		enum exit_reasons reason;

		epoch_nr++;
		output(0, "Starting epoch %u\n", epoch_nr);

		main_loop();

		reason = __atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED);
		if (reason != EXIT_EPOCH_DONE) {
			output(0, "Epoch %u ended with reason %s, stopping.\n",
				epoch_nr, decode_exit(reason));
			return;
		}

		/*
		 * --max-runtime is a one-shot ceiling, not a recurring epoch.
		 * The parser routes it through epoch_timeout to bound the first
		 * epoch's wall-clock; once that epoch ends we exit instead of
		 * spinning up another.
		 */
		if (max_runtime_set) {
			output(0, "Max runtime reached after epoch %u, exiting.\n", epoch_nr);
			return;
		}

		output(0, "Epoch %u complete, resetting for next epoch.\n", epoch_nr);
		reset_epoch_state();
	}
}

/*
 * Resolve the final slot partition (alt-op / canary / explorer / bandit)
 * from the parsed CLI args and the discovered fleet size.  All inputs
 * and outputs live in globals; the helper runs after parse_args and
 * before any consumer reads the derived values.  The closing print line
 * surfaces the resolved layout (disjoint front-reserved alt-op, then
 * explorer, then whatever remains for the bandit pool) so the operator
 * can confirm what the run will actually do.
 */
static void derive_and_clamp_slot_partition(void)
{
	/* Apply the shared_regions[] / RLIMIT_NPROC / RLIMIT_NOFILE cap
	 * to the default num_online_cpus*4 value when the operator did
	 * not pass -C.  -C path validates against the same cap inside
	 * parse_args, so this is a no-op there. */
	clamp_default_max_children();

	/* Default-fill alt_op_children when --alt-op-children was not
	 * passed.  Runs after clamp_default_max_children() so the derived
	 * value tracks the final fleet size, and before the canary/
	 * explorer derivations below, which both depend on the final
	 * alt_op_children. */
	clamp_default_alt_op_children();

	/* --alt-op-children clamp.  Reserving more slots than the total
	 * fleet would leave zero default syscall children, which defeats
	 * the throughput-preservation rationale.  Cap at max_children-1
	 * so at least one slot still runs the default 95/5 mix. */
	if (alt_op_children >= max_children) {
		unsigned int clamped = max_children > 0 ? max_children - 1 : 0;

		outputerr("warning: --alt-op-children=%u >= --children=%u; clamping to %u so at least one syscall child remains\n",
			alt_op_children, max_children, clamped);
		alt_op_children = clamped;
	}

	/* Auto-couple canary_slots to alt_op_children when the operator
	 * did not pass --canary-slots.  Runs before the clamps below so
	 * the derived value is range-checked alongside an explicit
	 * override. */
	clamp_default_canary_slots();

	/* --canary-slots clamp.  The canary queue carves from the front
	 * of the alt-op pool, so it cannot reserve more slots than the
	 * pool has.  A bigger N here than alt_op_children would be a
	 * silent loss: the queue would think it had N canary slots, but
	 * assign_dedicated_alt_op() walks slots 0..alt_op_children-1.
	 * Clamp loudly.  With the auto-couple above, this warning can
	 * only fire when the operator explicitly set --canary-slots --
	 * the default-derive path zeros canary_slots when alt_op_children
	 * is zero, so it never reaches this state on a default run. */
	if (alt_op_children == 0 && canary_slots > 0 && !canary_queue_disabled && user_specified_canary_slots) {
		outputerr("warning: --canary-slots=%u requested but --alt-op-children=0; canary queue has no slot to canary on, disabling\n",
			canary_slots);
		canary_slots = 0;
	}
	if (canary_slots > alt_op_children) {
		outputerr("warning: --canary-slots=%u > --alt-op-children=%u; clamping to %u\n",
			canary_slots, alt_op_children, alt_op_children);
		canary_slots = alt_op_children;
	}

	/* Compute the default explorer-pool size when the operator did not
	 * pass --explorer-children (max_children/4 under PICKER_BANDIT_UCB1,
	 * zero otherwise), and clamp an explicit value to max_children/2.
	 * Runs after the alt-op clamp so both partitions see the final
	 * max_children. */
	clamp_default_explorer_children();

	/* Surface the resolved slot partition unconditionally so the operator
	 * can confirm what the run will actually do -- the explorer default
	 * is mode-aware, the alt-op range is reserved from the front, and
	 * the bandit pool is whatever remains.  Printing the resolved counts
	 * (not the requested ones) makes the disjoint layout legible without
	 * having to read the source. */
	{
		unsigned int bandit_children = max_children;
		if (bandit_children >= alt_op_children)
			bandit_children -= alt_op_children;
		else
			bandit_children = 0;
		if (bandit_children >= explorer_children)
			bandit_children -= explorer_children;
		else
			bandit_children = 0;
		output(0, "picker_mode=%s slot partition: alt_op=%u explorer=%u bandit=%u (of %u)\n",
		       picker_mode_name(picker_mode_arg),
		       alt_op_children, explorer_children,
		       bandit_children, max_children);
	}
}

/*
 * Final teardown + process exit.  Two distinct shutdown shapes flow
 * through here:
 *
 *   clean_run = true   -- main_loop()/epoch_loop() returned normally
 *   and end-of-run persistence already ran.  Tear down the global
 *   objects table, emit the syscall-totals summary, optionally dump
 *   stats, and re-derive ret from shm->exit_reason via set_exit_code.
 *
 *   clean_run = false  -- a pre-fuzz short-circuit (dump-mode, munge
 *   failure).  Skip the clean-run-only work; ret is whatever the
 *   caller passed in.
 *
 * In both cases, the post-cleanup tail is identical: stop the kmsg
 * monitor, close the stats log, and exit via _exit() on ASAN builds
 * (skipping atexit handlers so libasan's leak-check doesn't tkill
 * the parent mid-reap and orphan surviving fuzz children) or via
 * plain exit() otherwise.  Marked noreturn so the caller (main()
 * only) does not need a trailing return statement.
 */
static void __attribute__((noreturn))
finalize_and_exit(int ret, bool clean_run)
{
	if (clean_run) {
		destroy_global_objects();

		output(0, "Ran %ld syscalls. Successes: %ld  Failures: %ld\n",
			parent_stats.op_count,
			parent_stats.successes, parent_stats.failures);
		if (show_stats == true)
			dump_stats();

		ret = set_exit_code(__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED));
	}

	kmsg_monitor_stop();

	stats_log_close();
	stats_timeseries_close();

	close_parent_tainted_fd();

#ifdef __SANITIZE_ADDRESS__
	/*
	 * ASAN/LSAN build: skip atexit handlers on the parent's normal
	 * shutdown.  Trinity intentionally leaves a number of allocations
	 * unfreed at teardown (per-child mmap pools, sysv_shm regions,
	 * fd-event ring backing, etc.).  Under libasan, exit() runs
	 * __cxa_finalize -> __do_global_dtors_aux -> __lsan::DoLeakCheck(),
	 * which finds those unreachable allocations and tkill()s the parent
	 * with SIGABRT before reaper-of-children completes -- orphaning
	 * surviving fuzz children that then burn CPU indefinitely.  Children
	 * still go through their own _exit()/exit() paths, so LSAN coverage
	 * of real leaks introduced by the fuzz path is unaffected.
	 */
	_exit(ret);
#else
	exit(ret);
#endif
}

int main(int argc, char* argv[])
{
	int ret = EXIT_SUCCESS;

	init_main_process(argv);

	/* Close any fd the launcher (or its parent) handed us before we
	 * open anything of our own.  Keep set is exactly {0,1,2} at this
	 * point; every later open in trinity (kmsg-monitor, kcov probe,
	 * fd-provider init under open_fds, per-child pidstat handles) is
	 * by definition something we want to manage.  Defense-in-depth
	 * against a stuck-fs inherited fd ending up in a watch set and
	 * stalling the parent's reap path. */
	sanitize_inherited_fds();

	parse_args(argc, argv);

	/* Early-exit dump modes share a side-effect-free contract: emit
	 * the requested data and exit before create_shm / self_cgroup_setup /
	 * kmsg_monitor_start / init_pre_fork / generate_filelist.  Each
	 * dump runs on state that init_main_process already populated
	 * (syscall tables via select_syscall_tables; the ioctl-group
	 * table via per-group __attribute__((constructor)) registrations;
	 * argtype[] fields baked in at compile time), so none of them
	 * need the heavier init phases. */

	/* -L (--list): bare syscall names, one per line; pipeable
	 * (`trinity -L | sort -u`). */
	if (show_syscall_list == true) {
		dump_syscall_tables();
		exit(EXIT_SUCCESS);
	}

	/* --show-ioctl-list: dump every registered ioctl group. */
	if (show_ioctl_list == true) {
		dump_ioctls();
		exit(EXIT_SUCCESS);
	}

	/* --show-unannotated: report syscalls with ARG_UNDEFINED entries
	 * in their argtype[].  Biarch-only today; the uniarch branch of
	 * show_unannotated_args() is an intentional no-op. */
	if (show_unannotated == true) {
		show_unannotated_args();
		exit(EXIT_SUCCESS);
	}

	create_shm();

	/* Capture PIE/DSO load bases now, before any fork, so post-mortem
	 * symbolize of a raw IP from a bug log or FAULT! line is a
	 * grep-the-outerr-log operation instead of needing the live
	 * process's /proc/<pid>/maps.  Children inherit the same bases
	 * via fork. */
	log_load_bases();

	init_post_parse_io();

	derive_and_clamp_slot_partition();

	/* Cap NOFILE/NPROC/AS for the whole trinity process tree before
	 * fork_children() runs; child processes inherit rlimits at fork
	 * time, so this is the single point that bounds the fleet's
	 * resource footprint as a defense against OOM cascades.  Runs
	 * after derive_and_clamp_slot_partition() so max_children is
	 * final and the NPROC target reflects the actual fleet size. */
	init_rlimits(max_children);

	/* Register trinity's own .data/.bss + every loaded DSO's writable
	 * PT_LOAD segments with shared_regions[] BEFORE fork_children() so
	 * range_overlaps_shared() refuses fuzzed mm-syscalls that target
	 * trinity's own statics.  All children inherit the populated table
	 * via the COW post-fork copy.  Run after parse_args so -v is
	 * honoured for the per-DSO summary lines. */
	register_loaded_image_segments();

	init_main_early();

	publish_and_persist_seed();

	switch (init_taint_and_handle_disabled_dump()) {
	case INIT_CONTINUE:
		break;
	case INIT_FAILED:
		ret = EXIT_FAILURE;
		/* fallthrough */
	case INIT_DONE:
		finalize_and_exit(ret, false);
	}

	/* Start the kmsg monitor only on the fuzz path -- the early-exit
	 * dump modes (handled above and right after parse_args) and the
	 * --show-disabled-syscalls path all exit before reaching here,
	 * so none of them pay for the pthread_create. */
	kmsg_monitor_start();

	init_pre_fork();

	/* Writer-pinning canary banner.  Both flags are default-off; the
	 * banner only fires when an operator has opted in, so a normal run
	 * stays silent.  Emitting via output(0) so the line lands in the
	 * top-of-log provenance section alongside guard-shared, build_hash
	 * etc.  Heavyweight debug tool -- not for routine fuzzing. */
	if (writer_pin_sweep || writer_watch_addr != 0)
		output(0, "[writer-pin] sweep=%s watch=0x%lx stride=%u"
		       " (debug, perf HW breakpoint)\n",
		       writer_pin_sweep ? "on" : "off",
		       writer_watch_addr,
		       writer_pin_stride);

#ifdef CONFIG_GUARD_SHARED
	/* Announce guard-shared armour state once shared_regions[] has
	 * settled (init_shm + the pool inits inside init_pre_fork have
	 * registered every long-lived region).  Without this line a run
	 * log is silent about whether --guard-shared took effect: the
	 * longopt is always recognised but the handler only flips the
	 * scope when the binary was built with GUARD_SHARED=1, so a
	 * mis-built binary accepts the flag and runs OFF -- exactly the
	 * misattribution the corruption-hunt triages keep hitting.  Emit
	 * via output(0) so the banner reaches the top-of-log section
	 * alongside build_hash and the other startup provenance markers,
	 * and so the "[main] " prefix is added automatically. */
	output(0, "guard-shared armor: scope=%s (%u regions guarded)\n",
	       guard_shared_scope_name(),
	       guard_shared_count_guarded());
#endif

	if (!run_oneshot_passes())
		finalize_and_exit(ret, false);

	warm_start_all();

	if (epoch_iterations || epoch_timeout)
		epoch_loop();
	else
		main_loop();

	persist_state_on_clean_exit();

	finalize_and_exit(ret, true);
}
