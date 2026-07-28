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
#include "rotation_event.h"
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

/*
 * Pre-fork warm-start of every cross-run coverage carrier: the
 * minicorpus replay set, the kcov bucket_seen[] bitmap, and the
 * cmp-hints pool.  Each loader
 * is independently gated by its own --no-*-warm-start flag so the
 * operator can opt out of one without losing the others.  Done before
 * fork so children inherit the populated tables via COW and the
 * memcpys land without racing the producers.  Failures are silent --
 * a missing or stale file just means we boot cold for that carrier.
 */
void warm_start_all(void)
{
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
}

/*
 * Persist every cross-run coverage carrier (minicorpus, kcov bitmap,
 * cmp-hints pool) on a graceful exit so the next run starts warm.
 * Each carrier is independently gated by its own --no-*-warm-start
 * flag, and each save is further conditioned on a clean shutdown
 * reason -- saving from a poisoned shm could feed garbage back in on
 * the next warm-start.  Periodic snapshot triggers cover the crash
 * case; these end-of-run saves capture the trailing window of state
 * that the periodic cadence had not yet flushed.
 */
void persist_state_on_clean_exit(void)
{
	enum trinity_persist_component saved[4];
	uint32_t nr_saved = 0;

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
			if (path != NULL && minicorpus_save_file(path)) {
				output(0, "minicorpus: persisted to %s\n", path);
				saved[nr_saved++] = PERSIST_MINICORPUS;
			}
		}
	}

	/*
	 * End-of-run kcov bitmap persistence.  Same clean-exit gate as the
	 * minicorpus save -- a poisoned shm after a corruption-aborted run
	 * could feed garbage back into the next warm-start, so
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

			if (kpath != NULL && kcov_bitmap_save_file(kpath)) {
				output(0, "kcov-bitmap: persisted to %s\n", kpath);
				saved[nr_saved++] = PERSIST_KCOV;
			}
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

			if (cpath != NULL && cmp_hints_save_file(cpath)) {
				output(0, "cmp-hints: persisted to %s\n", cpath);
				saved[nr_saved++] = PERSIST_CMP_HINTS;
			}
		}
	}

	/*
	 * End-of-run chain corpus persistence.  Same clean-exit gate the
	 * other cross-run carriers use -- a poisoned shm after a corruption-
	 * aborted run could feed garbage back into the next warm-start, so
	 * we skip the save unless the shutdown was clean.  No periodic
	 * snapshot trigger for the chain corpus (unlike minicorpus / kcov
	 * bitmap / cmp-hints, which cover mid-run crashes); this end-of-run
	 * save is the only persistence point.
	 */
	if (!no_chain_warm_start && chain_corpus_shm != NULL) {
		enum exit_reasons er =
			__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED);

		if (er == EXIT_REACHED_COUNT || er == EXIT_SIGINT ||
		    er == EXIT_USER_REQUEST || er == EXIT_EPOCH_DONE) {
			const char *cpath = chain_corpus_default_path();

			if (cpath != NULL && chain_corpus_save_file(cpath)) {
				output(0, "chain corpus: persisted to %s\n",
				       cpath);
				saved[nr_saved++] = PERSIST_CHAIN;
			}
		}
	}

	/*
	 * All four components have finished saving.  Write the manifest
	 * naming this generation and the components that landed, so the
	 * next warm-start can detect a torn coordinated save (e.g. this
	 * process was killed between two _save_file() calls, leaving one
	 * carrier at gen N and another at gen N-1).  Best-effort; missing
	 * manifest just means the load side falls back to per-file
	 * validation.
	 */
	if (nr_saved > 0) {
		(void)persist_write_generation_manifest(
			persist_envelope_current_generation(), saved, nr_saved);
	}
}

/*
 * Publish the run's identification anchors so post-mortem grep
 * tooling can pin down a crashed run from log scrollback.  The
 * mainpid line gives a gdb-attach target without needing `ps`; the
 * seed line is a canonical anchor whose wording matches across the
 * auto and -s code paths (init_seed() already prints the value, but
 * the line text differs between them).  Auto-generated seeds are
 * additionally persisted to ./last-run-seed so a stochastic crash
 * can be re-run with --seed=$(cat tmp/last-run-seed) -- the user-
 * supplied path doesn't persist, since the caller already has the
 * value and overwriting the file would lose the last auto seed.
 */
void publish_and_persist_seed(void)
{
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
}

/*
 * Process bootstrap: stdio buffering, progname/mainpid capture,
 * RLIMIT_NOFILE probe with a 1024 fallback, NUMA enumeration, and
 * syscall table selection.  Runs as the very first work after entry,
 * before parse_args, because every later helper (parser included)
 * depends on at least one of these globals.  Sets the default
 * max_children = num_online_cpus * 4; parse_args may override it,
 * and clamp_default_max_children() applies any caps.  The shm
 * carve-out is deferred to main() so the -L (--list) bare-name
 * dump can run and exit without touching any shared state.
 */
void init_main_process(char *argv[])
{
	setlinebuf(stdout);

	progname = argv[0];

	mainpid = getpid();
	cached_pid = mainpid;
	cached_start_time = pid_start_time(mainpid);

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
}

/*
 * Post-parse process I/O setup: the version banner (routed to stdout
 * or stderr based on whether --stats-json has reserved stdout), the
 * cgroup v2 sub-cgroup placement + atexit cleanup hook, and the
 * --stats-log-file open.  All three steps are gated on parsed args
 * and so cannot run until after parse_args returns; the stats-log
 * open also has to precede change_tmp_dir() so a relative log path
 * is resolved against the operator's launch CWD.
 */
void init_post_parse_io(void)
{
	/* Banner is deferred until after parse_args so --stats-json (which
	 * reserves stdout for the JSON document) can redirect it to stderr.
	 * Without this, the banner would land on stdout before the flag is
	 * known and corrupt the JSON stream consumers expect to parse. */
	if (should_route_to_stdout())
		outputstd("Trinity " VERSION "  Dave Jones <davej@codemonkey.org.uk>\n");
	else
		outputerr("Trinity " VERSION "  Dave Jones <davej@codemonkey.org.uk>\n");

	/* Distinctive single-token build_hash anchor for triage tooling:
	 * `grep build_hash out-*.log | tail -1` pins down which binary
	 * produced a given log without having to parse the banner's
	 * parenthesised `(git ...)` token.  Fleet lands fixes faster than
	 * fuzz runs roll, so triages that try to attribute behaviour to a
	 * specific commit need a self-describing provenance marker in the
	 * log itself.  Build-time (not run-time) hash: the binary is what
	 * was built, regardless of the source tree's state when it ran.
	 * output() auto-prefixes "[main] " when called from mainpid, so
	 * the line on disk reads "[main] build_hash=<sha>". */
	output(0, "build_hash=%s\n", GIT_HASH);

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

	/* Same path-resolution rule as stats_log_open(): open here so the
	 * stats-timeseries-<epoch>.jsonl file lands in the operator's
	 * launch CWD rather than trinity's tmp/ working directory.  No-op
	 * when --stats was not passed. */
	stats_timeseries_open();

	/* Per-rotation-block event sink.  Same pre-fork CWD gating shape
	 * as the timeseries file, so the two --stats-gated JSONL surfaces
	 * land next to each other.  Unlike the timeseries file the fd is
	 * intentionally inherited across fork() and written by the CAS-
	 * winning child of maybe_rotate_strategy(); no drop_in_child
	 * counterpart is called. */
	stats_rotation_event_open();
}

/*
 * Early init that runs after image-segment registration but before
 * the seed publish and the monitor / show-mode dispatch.  Brings up
 * the uid pool used by fault-injection paths, chdir's into trinity's
 * tmp/ working directory (so subsequent ./last-run-seed and ./tmp/
 * paths are relative to a known location), and carves out the
 * per-subsystem shm regions on top of the base shm reserved during
 * process bootstrap.
 */
void init_main_early(void)
{
	init_uids();

	change_tmp_dir();

	output(1, "phase: init_shm\n");
	init_shm();
}

/*
 * Surface core_pattern, init the taint-checker, and dispatch
 * --show-disabled-syscalls before munge_tables() rewrites the active
 * set.  The disabled-syscalls printer is documented as querying the
 * taint-derived deny list, so init_taint_checking() runs first.
 * kmsg_monitor_start() lives at its own call site in main() so the
 * --show-disabled-syscalls path can satisfy the taint contract
 * without spinning up the kmsg pthread.  The other early-exit dump
 * modes (-L / --show-ioctl-list / --show-unannotated) are handled
 * directly in main() right after parse_args because they need
 * nothing beyond the syscall-table selection that init_main_process
 * already performed.  Returned value tells main() whether to fall
 * through to the next init phase or short-circuit to finalize_and_exit,
 * with INIT_FAILED reserved for the munge_tables() error path.
 */
enum init_action init_taint_and_handle_disabled_dump(void)
{
	print_core_pattern();

	init_taint_checking();

	if (show_disabled_syscalls == true) {
		print_disabled_syscalls();
		return INIT_DONE;
	}

	if (munge_tables() == false)
		return INIT_FAILED;

	/*
	 * Freeze the descriptor tables PROT_READ now that every flag-
	 * stamping site inside munge_tables() has run and before
	 * fork_children() carves the fleet.  A later wild write from a
	 * child into a syscallentry field faults at the corruptor
	 * instead of driving downstream code down a corrupted path.
	 */
	protect_syscall_tables();

	return INIT_CONTINUE;
}

/*
 * Pre-fork init that has to complete before fork_children() starts
 * carving up the fleet: syscall table compilation, the uid-0 guard,
 * optional specific-domain restriction, pid + fd + object pool init,
 * the initial address-space mappings, device discovery, the global
 * objects table, main-process signal handlers, the no-bind-to-cpu
 * coin flip, parent prctl name + OOM-immunity, the fd-provider open
 * pass (with its panic path on failure), and the shared-bitmap self-
 * check.  Order matters here -- every later step depends on globals
 * set up by an earlier one -- so the helper is a flat sequence with
 * no internal branches beyond the existing open_fds() failure path.
 */
void init_pre_fork(void)
{
	const char taskname[13]="trinity-main";

	init_syscalls();

	do_uid0_check();

	/*
	 * Parent-side startup-isolation spine: when running as root and
	 * the operator did not pass --no-startup-isolation, unshare the
	 * parent into a private net + mount ns and remount '/' as
	 * MS_REC|MS_PRIVATE so subsequent child mount/net churn cannot
	 * propagate back to the host.  Children inherit the provisioned
	 * ns via fork() and skip their per-child unshare in
	 * init_child_setup_sandbox.  Any failure (non-root, --no-startup-
	 * isolation, EPERM, ENOSYS) leaves shm->isolation.{net,mnt}_ready
	 * false and the children fall back to today's per-child path --
	 * byte-for-byte unchanged from a pre-isolation run.
	 */
	setup_startup_isolation();

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
}

/*
 * One-shot discovery passes that walk large directory trees.  Run in
 * the parent before fork so children inherit the results via COW.
 * procfs_writer_init unconditionally populates the writable-procfs
 * path pool.  Returns a "should main() continue?" boolean to leave
 * room for future calibration-only modes that exit instead of fuzzing.
 */
bool run_oneshot_passes(void)
{
	procfs_writer_init();
	perf_event_chains_init();
	tracefs_fuzzer_init();

	return true;
}
