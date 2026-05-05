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
#include "effector-map.h"
#include "fd.h"
#include "files.h"
#include "ioctls.h"
#include "kmsg-monitor.h"
#include "maps.h"
#include "minicorpus.h"
#include "objects.h"
#include "pids.h"
#include "params.h"
#include "domains.h"
#include "random.h"
#include "signals.h"
#include "shm.h"
#include "stats.h"
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
 * Epoch-based forking wrapper around main_loop().
 *
 * Forks a child process that runs main_loop() for a bounded number of
 * iterations or wall-clock seconds.  When the epoch limit is reached,
 * the child exits cleanly and the parent resets shared state and forks
 * a new epoch child.  Coverage data (kcov bitmap, cmp_hints, minicorpus,
 * edgepair) lives in MAP_SHARED memory and accumulates across epochs.
 *
 * This periodic restart prevents state accumulation (leaked fds, stale
 * mappings, corrupted objects) from degrading fuzzing effectiveness.
 */
static void epoch_loop(void)
{
	unsigned int epoch_nr = 0;
	pid_t epoch_pid;
	int status;

	while (1) {
		epoch_nr++;
		output(0, "Starting epoch %u\n", epoch_nr);

		epoch_pid = fork();
		if (epoch_pid == -1) {
			outputerr("epoch_loop: fork failed: %s\n", strerror(errno));
			return;
		}

		if (epoch_pid == 0) {
			/* Epoch child: become the effective main process. */
			mainpid = getpid();
			setup_main_signals();
			main_loop();
			_exit(set_exit_code(__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED)));
		}

		/* Epoch parent: wait for the epoch child to finish. */
		if (waitpid(epoch_pid, &status, 0) == -1) {
			outputerr("epoch_loop: waitpid failed: %s\n", strerror(errno));
			return;
		}

		if (!WIFEXITED(status) || WEXITSTATUS(status) != EXIT_SUCCESS) {
			output(0, "Epoch %u exited abnormally (status=%d), stopping.\n",
				epoch_nr, status);
			return;
		}

		if (__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED) != EXIT_EPOCH_DONE) {
			output(0, "Epoch %u ended with reason %s, stopping.\n",
				epoch_nr,
				decode_exit(__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED)));
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

	outputstd("Trinity " VERSION "  Dave Jones <davej@codemonkey.org.uk>\n");

	setlinebuf(stdout);

	progname = argv[0];

	mainpid = getpid();

    if (getrlimit(RLIMIT_NOFILE, &max_files_rlimit) != 0) {
		max_files_rlimit.rlim_cur = 1024;
		max_files_rlimit.rlim_max = 1024;
	}

	page_size = getpagesize();
	long ncpus = sysconf(_SC_NPROCESSORS_ONLN);
	num_online_cpus = (ncpus > 0) ? (unsigned int)ncpus : 1;
	max_children = num_online_cpus * 4;	/* possibly overridden in params. */

	select_syscall_tables();

	create_shm();

	parse_args(argc, argv);

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

		output(0, "[main] seed=0x%x\n", active_seed);

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

	/*
	 * After open_fds() returns no caller adds new global objects, and
	 * children are rejected from add_object() anyway.  Lock the global
	 * object metadata and parallel arrays read-only before forking
	 * the first fuzz child so stray writes from children SIGSEGV at
	 * the source instead of corrupting array entries the parent (or a
	 * later child) trips over during init_child_mappings().
	 */
	output(1, "phase: freeze_global_objects\n");
	freeze_global_objects();

	/*
	 * One-shot childop discovery passes that walk large directory trees.
	 * Doing them in the parent before fork lets all children inherit the
	 * results via COW instead of repeating the walk per child.
	 */
	procfs_writer_init();

	/*
	 * --effector-map: one-shot calibration pass that probes per-bit
	 * input significance under KCOV and exits.  Runs after open_fds /
	 * freeze_global_objects so fill_arg() has the full fd, address,
	 * and pid pools available, but before warm-start so the calibration
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

			if (epath != NULL && effector_map_load_file(epath))
				output(0, "effector-map: loaded from %s\n", epath);
		}
	}

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

	destroy_global_objects();

	output(0, "Ran %ld syscalls. Successes: %ld  Failures: %ld\n",
		shm->stats.op_count + sum_local_op_counts(),
		shm->stats.successes, shm->stats.failures);
	if (show_stats == true)
		dump_stats();

	ret = set_exit_code(__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED));
out:
	kmsg_monitor_stop();

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
