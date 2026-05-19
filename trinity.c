#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "arch.h"
#include "child.h"
#include "cmp_hints.h"
#include "effector-map.h"
#include "fd.h"
#include "files.h"
#include "healer.h"
#include "healer_ring.h"
#include "ioctls.h"
#include "kcov.h"
#include "kmsg-monitor.h"
#include "maps.h"
#include "minicorpus.h"
#include "numa.h"
#include "objects.h"
#include "pids.h"
#include "params.h"
#include "domains.h"
#include "random.h"
#include "self_cgroup.h"
#include "signals.h"
#include "shm.h"
#include "stats.h"
#include "stats_ring.h"
#include "strategy.h"
#include "tables.h"
#include "taint.h"
#include "trinity.h"
#include "uid.h"
#include "utils.h"
#include "version.h"

pid_t mainpid;

char *progname = NULL;

unsigned int page_size;
unsigned int num_online_cpus;
bool no_bind_to_cpu;
unsigned int max_children;
struct rlimit max_files_rlimit;

/*
 * Absolute path of trinity's tmp/ directory, resolved once at startup
 * inside change_tmp_dir().  Used by the per-child crash log redirect in
 * signals.c so the path is stable even if a child fuzzes chdir() out
 * from under itself.  Empty string until change_tmp_dir() succeeds;
 * trinity_tmpdir_abs() returns "/tmp" as a safe fallback in that case
 * so a degraded run still puts the log somewhere writable.
 */
static char tmp_dir_abs[PATH_MAX];

const char *trinity_tmpdir_abs(void)
{
	return tmp_dir_abs[0] ? tmp_dir_abs : "/tmp";
}

#ifdef __SANITIZE_ADDRESS__
/*
 * ASAN reads this on init (before main()) to set its default options.
 * Without it, ASAN error reports go to stderr — and init_child() does
 * dup2(devnull, STDERR_FILENO) at child startup so children's fuzzed
 * syscall spew can't pollute the operator's terminal.  Side effect:
 * every ASAN report from a child is silently lost, leaving us blind to
 * exactly the diagnostic we ran ASAN to obtain.  log_path redirects
 * each report to <tmp>/trinity-asan-<PID>.<PID>, sidestepping stderr
 * entirely.  abort_on_error=1 makes ASAN raise SIGABRT after the
 * report so child_fault_handler still runs and a coredump still lands.
 * disable_coredump=0 keeps cores enabled (ASAN's default is 1, which
 * suppresses the core).
 *
 * The tmp/ path is computed at __asan_default_options() time (before
 * main(), before change_tmp_dir()) by appending "tmp/" to the launch
 * cwd — trinity is always run from its source dir per the Makefile
 * test target.  Falls back to /tmp if getcwd() somehow fails.
 */
const char *__asan_default_options(void);
__attribute__((no_sanitize_address))
const char *__asan_default_options(void)
{
	/*
	 * libasan calls this during its own InitializeFlags pass, before
	 * shadow memory is mapped AND before its libc interceptor table is
	 * populated.  no_sanitize_address keeps the compiler from emitting
	 * a function-entry redzone setup, but any libc call from here
	 * (snprintf, getcwd, ...) goes through a still-NULL interceptor
	 * pointer and SEGVs at PC=0.  Return a static string only.
	 *
	 * "trinity-asan-" is a relative path; libasan opens it at
	 * error-write time, when each child's cwd is <source>/tmp/ (set
	 * by change_tmp_dir() in the parent before fork()).  So reports
	 * land in tmp/trinity-asan-<PID>.<PID> alongside the cores.  A
	 * child that fuzzes chdir() would write its report wherever the
	 * fuzzed cwd ended up — acceptable corner case.
	 */
	return "log_path=trinity-asan-:abort_on_error=1:disable_coredump=0";
}
#endif

/*
 * just in case we're not using the test.sh harness, we
 * change to the tmp dir if it exists.
 */
static void change_tmp_dir(void)
{
	struct stat sb;
	const char tmpdir[]="tmp/";
	int ret;

	/* Check if it exists, bail early if it doesn't */
	ret = (lstat(tmpdir, &sb));
	if (ret == -1)
		return;

	/* Just in case a previous run screwed the perms. */
	ret = chmod(tmpdir, 0777);
	if (ret == -1)
		output(0, "Couldn't chmod %s to 0777.\n", tmpdir);

	ret = chdir(tmpdir);
	if (ret == -1) {
		output(0, "Couldn't change to %s\n", tmpdir);
		return;
	}

	/* Resolve tmp/ to an absolute path so the per-child crash log
	 * redirect in signals.c lands in the right place even after a
	 * fuzzed chdir() in the child.  Best-effort -- on failure we fall
	 * back to /tmp via trinity_tmpdir_abs(). */
	if (getcwd(tmp_dir_abs, sizeof(tmp_dir_abs)) == NULL)
		tmp_dir_abs[0] = '\0';
}

/*
 * Trinity assumes the operator can find cores after a crash.  Surface
 * the kernel's core_pattern at startup so the log records exactly where
 * (or to which helper) cores were going to land.  Verbose-only — most
 * runs don't need the noise.  Silent on any failure: a kernel without
 * procfs or with the file removed is a degraded but valid environment.
 */
static void print_core_pattern(void)
{
	char buf[PATH_MAX];
	ssize_t n;
	int fd;

	fd = open("/proc/sys/kernel/core_pattern", O_RDONLY);
	if (fd == -1)
		return;

	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);

	if (n <= 0)
		return;

	buf[n] = '\0';
	if (buf[n - 1] == '\n')
		buf[n - 1] = '\0';

	output(1, "core_pattern: %s\n", buf);
}

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
 * bitmap, cmp_hints, minicorpus, edgepair) lives in MAP_SHARED memory
 * and accumulates across epochs.
 *
 * This used to run main_loop() in a forked epoch-child process, with
 * the outer parent reaping the child between epochs.  That gave the
 * appearance of crash isolation but provided none in practice: the
 * outer parent doesn't run any fuzzed syscalls itself (real wild-write
 * exposure lives in the per-iteration child fork, which is unchanged),
 * and every piece of state the old fork "reset" lived in MAP_SHARED
 * shm pages that were already shared with the outer parent anyway.
 * The one thing the fork did reset -- parent_stats, which is a
 * process-private global in stats-ring.c -- was actually a bug: the
 * aggregating process was the epoch child, so when it exited at epoch
 * end the running totals went with it and the outer parent never saw
 * the aggregated stats.  Running main_loop() in-process keeps
 * parent_stats alive across epochs, and reset_epoch_state() zeroes
 * what we want zeroed.
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

int main(int argc, char* argv[])
{
	int ret = EXIT_SUCCESS;
	const char taskname[13]="trinity-main";

	setlinebuf(stdout);

	progname = argv[0];

	mainpid = getpid();
	cached_pid = mainpid;

    if (getrlimit(RLIMIT_NOFILE, &max_files_rlimit) != 0) {
		max_files_rlimit.rlim_cur = 1024;
		max_files_rlimit.rlim_max = 1024;
	}

	page_size = getpagesize();
	long ncpus = sysconf(_SC_NPROCESSORS_ONLN);
	num_online_cpus = (ncpus > 0) ? (unsigned int)ncpus : 1;
	max_children = num_online_cpus * 4;	/* possibly overridden in params. */

	init_numa_nodes();

	select_syscall_tables();

	create_shm();

	/* Close any fd the launcher (or its parent) handed us before we
	 * open anything of our own.  Keep set is exactly {0,1,2} at this
	 * point; every later open in trinity (kmsg-monitor, kcov probe,
	 * fd-provider init under open_fds, per-child pidstat handles) is
	 * by definition something we want to manage.  Defense-in-depth
	 * against a stuck-fs inherited fd ending up in a watch set and
	 * stalling the parent's reap path. */
	sanitize_inherited_fds();

	parse_args(argc, argv);

	/* --dry-run: validate the argument set and exit before any cgroup,
	 * fork, shm, or init work runs.  Previously the flag only gated the
	 * actual syscall() inside __do_syscall(), so a dry run still spun up
	 * children and burned the full init path before doing nothing — which
	 * defeated the point (cheap parse-validation in CI, reproducer triage)
	 * and silently masked real failures inside open_fds
	 * behind an exit code that looked like a successful no-op.  Honour the
	 * flag at parse-and-exit instead. */
	if (dry_run) {
		output(0, "--dry-run: parse complete, exiting without fuzzing\n");
		exit(EXIT_SUCCESS);
	}

	/* Banner is deferred until after parse_args so --stats-json (which
	 * reserves stdout for the JSON document) can redirect it to stderr.
	 * Without this, the banner would land on stdout before the flag is
	 * known and corrupt the JSON stream consumers expect to parse. */
	if (should_route_to_stdout())
		outputstd("Trinity " VERSION "  Dave Jones <davej@codemonkey.org.uk>\n");
	else
		outputerr("Trinity " VERSION "  Dave Jones <davej@codemonkey.org.uk>\n");

	/* Place ourselves into a dedicated cgroup v2 sub-cgroup with a
	 * memory cap so a runaway allocation triggers a scoped OOM kill of
	 * trinity instead of a host-wide global OOM that takes down the
	 * surrounding shell/tmux.  cgroup v2 process membership is inherited
	 * on plain fork(), so all later children land here automatically.
	 * Failures degrade gracefully: trinity continues without the safety
	 * net rather than refusing to start. */
	self_cgroup_setup();
	atexit(self_cgroup_cleanup);

	/* Open --stats-log-file (if any) before change_tmp_dir() so a
	 * relative PATH is resolved against the operator's launch CWD,
	 * not trinity's tmp/ working directory.  No-op when the flag was
	 * not passed; failure logs a warning and continues without a log. */
	stats_log_open(stats_log_path);

	/* Apply the shared_regions[] / RLIMIT_NPROC / RLIMIT_NOFILE cap
	 * to the default num_online_cpus*4 value when the operator did
	 * not pass -C.  -C path validates against the same cap inside
	 * parse_args, so this is a no-op there. */
	clamp_default_max_children();

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

	/* --canary-slots clamp.  The canary queue carves from the front
	 * of the alt-op pool, so it cannot reserve more slots than the
	 * pool has.  A bigger N here than alt_op_children would be a
	 * silent loss: the queue would think it had N canary slots, but
	 * assign_dedicated_alt_op() walks slots 0..alt_op_children-1.
	 * Clamp loudly. */
	if (alt_op_children == 0 && canary_slots > 0 && !canary_queue_disabled) {
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

	/* Surface the resolved picker/explorer split unconditionally so the
	 * operator can confirm what the run will actually do -- the explorer
	 * default is mode-aware, and an operator passing --strategy without
	 * also setting --explorer-children would otherwise have to read the
	 * source to know whether 25% of children are silently diverted to
	 * STRATEGY_RANDOM. */
	output(0, "picker_mode=%s explorer_children=%u (of %u)\n",
	       picker_mode_name(picker_mode_arg),
	       explorer_children, max_children);

	/* Register trinity's own .data/.bss + every loaded DSO's writable
	 * PT_LOAD segments with shared_regions[] BEFORE fork_children() so
	 * range_overlaps_shared() refuses fuzzed mm-syscalls that target
	 * trinity's own statics.  All children inherit the populated table
	 * via the COW post-fork copy.  Run after parse_args so -v is
	 * honoured for the per-DSO summary lines. */
	register_loaded_image_segments();

	init_uids();

	change_tmp_dir();

	output(1, "phase: init_shm\n");
	init_shm();

	/* Always print mainpid so a gdb-attach round-trip is one line away
	 * instead of needing a separate `ps ax | grep trinity`.  Not gated
	 * on -v: the cost is one line per run, the saving is per-debug. */
	output(0, "mainpid=%d\n", mainpid);

	/*
	 * Print the active post-init shm->seed unconditionally as a canonical
	 * `[main] seed=` anchor for log-grep tooling -- init_seed() already
	 * prints the value, but the line wording differs between the auto
	 * and -s paths.
	 *
	 * Persist only the auto-generated seed: drop the value into
	 * ./last-run-seed (we are already chdir'd into tmp/ via
	 * change_tmp_dir) so a stochastic crash can be re-run with
	 *     trinity --seed=$(cat tmp/last-run-seed) ...
	 * The user-supplied (-s/--seed) path doesn't need persisting -- the
	 * caller already has the value they passed in, and overwriting the
	 * file would lose the last auto-generated seed.
	 *
	 * Write atomically via .tmp + rename (mirrors minicorpus.c) so a
	 * partial write never replaces a previous good value.  Best effort:
	 * all failures are silent, the file is informational.
	 */
	{
		unsigned int active_seed =
			__atomic_load_n(&shm->seed, __ATOMIC_RELAXED);

		output(0, "seed=0x%x\n", active_seed);

		if (user_set_seed == false) {
			FILE *f = fopen("last-run-seed.tmp", "w");

			if (f != NULL) {
				int wrote = fprintf(f, "%u\n", active_seed);
				int closed = fclose(f);

				if (wrote > 0 && closed == 0) {
					if (rename("last-run-seed.tmp",
							"last-run-seed") != 0)
						(void)unlink("last-run-seed.tmp");
				} else {
					(void)unlink("last-run-seed.tmp");
				}
			}
		}
	}

	print_core_pattern();

	kmsg_monitor_start();

	init_taint_checking();

	if (show_disabled_syscalls == true) {
		print_disabled_syscalls();
		goto out;
	}

	if (munge_tables() == false) {
		ret = EXIT_FAILURE;
		goto out;
	}

	if (show_syscall_list == true) {
		dump_syscall_tables();
		goto out;
	}

	if (show_ioctl_list == true) {
		dump_ioctls();
		goto out;
	}

	if (show_unannotated == true) {
		show_unannotated_args();
		goto out;
	}

	init_syscalls();

	do_uid0_check();

	if (do_specific_domain == true)
		find_specific_domain(specific_domain_optarg);

	pids_init();

	fd_hash_init();
	output(1, "phase: init_object_lists\n");
	init_object_lists(OBJ_GLOBAL, NULL);

	output(1, "phase: setup_initial_mappings\n");
	setup_initial_mappings();

	parse_devices();

	output(1, "phase: init_global_objects\n");
	init_global_objects();

	setup_main_signals();

	no_bind_to_cpu = RAND_BOOL();

	prctl(PR_SET_NAME, (unsigned long) &taskname);

	/* Opt the parent out of OOM-killing.  Children carry adj=500 so they
	 * are the kernel's preferred victims under memory pressure; if the
	 * parent dies the whole fuzz session dies (unrecoverable: shared
	 * state, watchdog, reaper, all vanish).  -1000 makes the kernel's
	 * preference structural rather than statistical. */
	oom_score_adj(-1000);

	output(1, "phase: open_fds\n");
	if (open_fds() == false) {
		if (__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED) == STILL_RUNNING)
			panic(EXIT_FD_INIT_FAILURE);

		_exit(EXIT_FD_INIT_FAILURE);
	}

	shared_bitmap_self_check();

	/*
	 * One-shot childop discovery passes that walk large directory trees.
	 * Doing them in the parent before fork lets all children inherit the
	 * results via COW instead of repeating the walk per child.
	 */
	procfs_writer_init();

	/*
	 * --effector-map: one-shot calibration pass that probes per-bit
	 * input significance under KCOV and exits.  Runs after open_fds
	 * so fill_arg() has the full fd, address, and pid pools available,
	 * but before warm-start so the calibration
	 * baseline isn't biased by a replayed corpus snapshot (the
	 * calibration path itself bypasses minicorpus_replay; skipping
	 * warm-start here also avoids loading a corpus we will not use).
	 */
	if (do_effector_map) {
		(void)effector_map_calibrate();
		goto out;
	}

	/*
	 * Warm-start the corpus from the previous run if a persisted file
	 * exists.  Replayed entries take effect once children start fuzzing
	 * via the existing minicorpus_replay() path.  Failures are silent —
	 * a missing or stale file just means we boot cold.
	 */
	if (!no_warm_start) {
		const char *path = warm_start_path ? warm_start_path
						   : minicorpus_default_path();
		if (path != NULL) {
			unsigned int loaded = 0, discarded = 0;
			minicorpus_load_file(path, &loaded, &discarded);
			if (loaded || discarded)
				output(0, "minicorpus: warm-started %u entries from %s (%u discarded)\n",
					loaded, path, discarded);
			/* Wire up periodic mid-run snapshots to the same path.
			 * Done before fork so children inherit snapshot_path COW;
			 * skipped under --no-warm-start since the user has opted
			 * out of on-disk corpus persistence entirely. */
			minicorpus_enable_snapshots(path);
		}

		/* Effector map warm-start runs alongside the corpus warm-start
		 * — both are pre-fork loads of stale-but-still-relevant
		 * calibration data.  Children inherit the populated table via
		 * COW; a missing file just means mutators fall back to uniform
		 * bit selection.  Failures are silent: the loader rejects
		 * dimension or kernel-utsname mismatches, and a stale map
		 * shouldn't degrade fuzzing — it just becomes inert. */
		{
			const char *epath = effector_map_default_path();

			if (epath != NULL) {
				if (effector_map_load_file(epath))
					output(0, "effector-map: loaded from %s\n", epath);
				else
					output(0, "effector-map: no calibrated map found for this kernel — run `trinity --effector-map` once to enable per-bit input-significance picking (boosts coverage-per-iter)\n");
			}
		}
	}

	/*
	 * kcov bucket_seen[] warm-start.  The 8 MB bitmap and edges_found
	 * counter are the dominant carriers of cross-run coverage state;
	 * without persistence, every restart re-discovers the full 50-200k
	 * edge curve at fuzz speed.  Gated independently of --no-warm-start
	 * via --no-kcov-warm-start so an operator can opt out of one without
	 * losing the other.  Done pre-fork, before any child writes to
	 * bucket_seen[], so the memcpy lands without racing the producers.
	 */
	if (!no_kcov_warm_start && kcov_shm != NULL) {
		const char *kpath = kcov_bitmap_default_path();

		if (kpath != NULL) {
			(void)kcov_bitmap_load_file(kpath);
			kcov_bitmap_enable_snapshots(kpath);
		}
	}

	/*
	 * cmp-hints pool warm-start.  Each KCOV CMP record requires a
	 * kernel-side comparison to actually fire on a syscall-derived
	 * input, so the pool grows orders of magnitude slower than the
	 * kcov bitmap and a cold start leaves the first windows after
	 * restart injecting no hints at all.  Gated independently of
	 * --no-kcov-warm-start via --no-cmp-hints-warm-start so an
	 * operator can opt out of one without losing the other.  Done
	 * pre-fork, before any child writes to a pool, so the load lands
	 * without racing the producers.
	 */
	if (!no_cmp_hints_warm_start && cmp_hints_shm != NULL) {
		const char *cpath = cmp_hints_default_path();

		if (cpath != NULL) {
			(void)cmp_hints_load_file(cpath);
			cmp_hints_enable_snapshots(cpath);
		}
	}

	/*
	 * HEALER relation-table warm-start.  Independent of the minicorpus
	 * warm-start gate so an operator can opt out of one without losing
	 * the other (--no-healer-warm-start covers the load, the load is
	 * silent on a missing file because cold-start is the legitimate
	 * first-run state).  Snapshot wiring is gated separately by
	 * --no-healer-snapshot so a read-only "warm-start but don't write"
	 * mode is also expressible.  Both are done before fork so children
	 * inherit the populated shm region and the snapshot path COW.
	 */
	if (!no_healer_warm_start) {
		const char *hpath = healer_default_path();

		if (hpath != NULL && healer_load_file(hpath))
			output(0, "healer: warm-started relation table from %s\n",
				hpath);
	}
	(void)healer_load_static_seed();
	if (!no_healer_snapshot) {
		const char *hpath = healer_default_path();

		if (hpath != NULL)
			healer_enable_snapshots(hpath);
	}

	/* Propagate the warm-started canonical to the mirror pages before
	 * forking so the first child to enter set_syscall_nr_healer sees
	 * the loaded weights instead of an empty mirror.  Drain-all with
	 * no children allocated yet is a no-op for the ring loop and runs
	 * the publish step only. */
	healer_ring_drain_all();

	if (epoch_iterations || epoch_timeout)
		epoch_loop();
	else
		main_loop();

	/*
	 * Persist the minicorpus on graceful exit so the next run starts
	 * warm.  Skip after a corruption or crash — saving from a poisoned
	 * shm could feed garbage back in on restart.
	 */
	if (!no_warm_start) {
		enum exit_reasons er =
			__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED);

		if (er == EXIT_REACHED_COUNT || er == EXIT_SIGINT ||
		    er == EXIT_USER_REQUEST || er == EXIT_EPOCH_DONE) {
			const char *path = warm_start_path ? warm_start_path
							   : minicorpus_default_path();
			if (path != NULL && minicorpus_save_file(path))
				output(0, "minicorpus: persisted to %s\n", path);
		}
	}

	/*
	 * Best-effort end-of-run HEALER snapshot on a clean shutdown.  The
	 * periodic snapshot trigger covers crashes; this captures the trailing
	 * window of observations the trigger window had not yet flushed.
	 * Same exit-reason gate the minicorpus save uses -- a poisoned shm
	 * after a corruption-aborted run could feed garbage into the next
	 * warm-start, so we skip the save unless the shutdown was clean.
	 */
	if (!no_healer_snapshot) {
		enum exit_reasons er =
			__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED);

		if (er == EXIT_REACHED_COUNT || er == EXIT_SIGINT ||
		    er == EXIT_USER_REQUEST || er == EXIT_EPOCH_DONE) {
			const char *hpath = healer_default_path();

			if (hpath != NULL && healer_save_file(hpath))
				output(0, "healer: persisted relation table to %s\n",
					hpath);
		}
	}

	/*
	 * End-of-run kcov bitmap persistence.  Same clean-exit gate as the
	 * minicorpus and healer saves -- a poisoned shm after a corruption-
	 * aborted run could feed garbage back into the next warm-start, so
	 * we skip the save unless the shutdown was clean.  The periodic
	 * snapshot trigger covers crashes; this captures the trailing
	 * window of edges that the periodic cadence had not yet flushed.
	 */
	if (!no_kcov_warm_start && kcov_shm != NULL) {
		enum exit_reasons er =
			__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED);

		if (er == EXIT_REACHED_COUNT || er == EXIT_SIGINT ||
		    er == EXIT_USER_REQUEST || er == EXIT_EPOCH_DONE) {
			const char *kpath = kcov_bitmap_default_path();

			if (kpath != NULL && kcov_bitmap_save_file(kpath))
				output(0, "kcov-bitmap: persisted to %s\n", kpath);
		}
	}

	/*
	 * End-of-run cmp-hints pool persistence.  Same clean-exit gate
	 * the kcov-bitmap save uses -- a poisoned shm after a corruption-
	 * aborted run could feed garbage back into the next warm-start,
	 * so we skip the save unless the shutdown was clean.  The
	 * periodic snapshot trigger covers crashes; this captures the
	 * trailing window of entries the periodic cadence had not yet
	 * flushed.
	 */
	if (!no_cmp_hints_warm_start && cmp_hints_shm != NULL) {
		enum exit_reasons er =
			__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED);

		if (er == EXIT_REACHED_COUNT || er == EXIT_SIGINT ||
		    er == EXIT_USER_REQUEST || er == EXIT_EPOCH_DONE) {
			const char *cpath = cmp_hints_default_path();

			if (cpath != NULL && cmp_hints_save_file(cpath))
				output(0, "cmp-hints: persisted to %s\n", cpath);
		}
	}

	destroy_global_objects();

	output(0, "Ran %ld syscalls. Successes: %ld  Failures: %ld\n",
		parent_stats.op_count,
		parent_stats.successes, parent_stats.failures);
	if (show_stats == true)
		dump_stats();

	ret = set_exit_code(__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED));
out:
	kmsg_monitor_stop();

	stats_log_close();

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
