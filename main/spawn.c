#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>


#include "child-api.h"
#include "cmp_hints.h"
#include "debug.h"
#include "kcov.h"
#include "minicorpus.h"
#include "params.h"
#include "pids.h"
#include "random.h"
#include "self_cgroup.h"
#include "sequence.h"
#include "shm.h"
#include "stats.h"
#include "trinity.h"
#include "utils.h"
#include "main-internal.h"

#include "kernel/fcntl.h"
/* CLOCK_MONOTONIC second past which the canary picker may resume
 * scheduling pid-heavy ops; 0 means no suppression is in effect.
 * Parent-private (the canary picker is parent-only).  Written from
 * fork_children() when consecutive_fork_failures crosses
 * FORK_PRESSURE_DRAIN_THRESHOLD and --fork-pressure-drain is set;
 * read from child-canary.c via fork_pressure_drain_active().  Read
 * RELAXED -- the picker only needs eventual consistency; a one-tick
 * lag in seeing pressure raised or lifted is fine. */
static unsigned long fork_pressure_active_until;

/* Spawn-failure count at which the drain engages.  Picked an order
 * of magnitude below the bail threshold (max_consecutive_fork_failures
 * = 1000) so the drain has room to actually relieve pressure before
 * the parent gives up.  With the inner spawn_child retry's 10-100ms
 * backoff, 100 consecutive failures is roughly the first 1-2 s of a
 * stuck-fork episode -- past any single ENOMEM blip and into
 * sustained pressure. */
#define FORK_PRESSURE_DRAIN_THRESHOLD	100U

/* Seconds the suppression stays in effect after the most recent
 * threshold crossing.  Long enough for the kernel-side resource
 * (process slots, RLIMIT_NPROC, cgroup pids.max) to drain via the
 * fleet's normal reap cadence; short enough that a transient pressure
 * burst does not lock pid-heavy canaries out for a meaningful
 * fraction of the run.  Each new burst re-arms the window. */
#define FORK_PRESSURE_DRAIN_RECOVERY_S	30U

unsigned long fork_pressure_drain_active(void)
{
	return __atomic_load_n(&fork_pressure_active_until, __ATOMIC_RELAXED);
}

static bool spawn_child(int childno)
{
	struct childdata *child;
	int pid = 0;
	int nr_fds;

	if (children == NULL)
		return false;

	child = children[childno];

	/* Wipe any stale spawn timestamp so a slot that fails to spawn
	 * doesn't leave a misleading lifetime in the next reap record. */
	if (spawn_times != NULL)
		spawn_times[childno] = 0;

	/* a new child means a new seed, or the new child
	 * will do the same syscalls as the one in the child it's replacing.
	 * (special case startup, or we reseed unnecessarily)
	 */
	if (__atomic_load_n(&shm->ready, __ATOMIC_ACQUIRE))
		reseed();

	/* Wipe out any state left from a previous child running in this slot. */
	clean_childdata(child);

	/* Commit any staged canary op BEFORE the dedicated-alt-op stamp
	 * below reads canary_active_op().  enter_canarying() stages the
	 * next op in canary_pending_op while leaving the previous op as
	 * the active cell; if assign_dedicated_alt_op() runs first it
	 * would stamp the OLD op into the freshly-spawned child, and the
	 * subsequent pending->active commit would leave the queue
	 * measuring one op while the child is actually running another.
	 * Committing here -- before the stamp -- closes that race: the
	 * new op becomes the slot's running op the moment a fresh child
	 * is forked with it, and straggler iterations of the old op (the
	 * previous canary, killed via kill_pid on transition) cannot
	 * pollute the new op's counters because they belong to a child
	 * that has already exited.  No-op when the queue is disabled or
	 * the slot is not a canary slot. */
	canary_queue_on_child_respawn(childno);

	/* If this slot is reserved for a dedicated alt op (the first
	 * --alt-op-children=N slots), stamp the assigned op_type now so
	 * the freshly-spawned child reads it out of shared memory before
	 * its dispatch loop runs.  No-op when --alt-op-children is 0. */
	assign_dedicated_alt_op(child, childno);

	nr_fds = get_num_fds();
	if (nr_fds < 0) {
		/* Counting /proc/self/fd failed -- can't verify headroom.
		 * Treat conservatively and panic rather than let a negative
		 * value wrap through the unsigned compare below and silently
		 * pass the fd-exhaustion ceiling check. */
		outputerr("get_num_fds() failed (%d); cannot verify fd headroom\n", nr_fds);
		panic(EXIT_NO_FDS);
		return false;
	}
	if ((unsigned long)nr_fds + 3 > max_files_rlimit.rlim_cur) {
		outputerr("current number of fd: %d, please consider ulimit -n xxx to increase fd limition\n", nr_fds);
		panic(EXIT_NO_FDS);
		return false;
	}

	/* Phase 2 self-cgroup back-pressure: when memory.high is being
	 * crossed, the parent ramps fork_throttle_us up so we slow the
	 * spawn rate ahead of the kernel-side throttle.  Zero in the
	 * common no-pressure path. */
	if (fork_throttle_us > 0)
		usleep(fork_throttle_us);

	fflush(stdout);
	pid = self_cgroup_fork_into_workload();

	if (pid == 0) {
		child_process(child, childno);
#ifdef __SANITIZE_ADDRESS__
		/*
		 * Raw exit syscall under ASAN: _exit() is noreturn, so the
		 * compiler emits __asan_handle_no_return, whose
		 * PlatformUnpoisonStacks() CHECK-fails (asan_poisoning.cpp:85)
		 * on children forked via clone3(CLONE_INTO_CGROUP) -- libasan
		 * never registered their stack bounds, so it unpoisons [0,0].
		 * syscall() is not noreturn-attributed, so no unpoison runs;
		 * scrubbing the stack shadow at process exit is pointless.
		 */
		syscall(SYS_exit_group, EXIT_SUCCESS);
		__builtin_unreachable();
#else
		_exit(EXIT_SUCCESS);
#endif
	} else {
		if (pid == -1) {
			debugf("Couldn't fork a new child in pidslot %d. errno:%s\n",
					childno, strerror(errno));
			return false;
		}
	}

	/* Child won't get out of init_child until we write the pid */
	__atomic_store_n(&pids[childno], pid, __ATOMIC_RELEASE);
	/* CLOCK_MONOTONIC seconds -- the fast-die classifier subtracts
	 * this from a monotonic `now` in record_reap(), so a wall-clock
	 * NTP step between spawn and reap cannot drive the computed
	 * lifetime negative and trip a spurious EXIT_SHM_CORRUPTION. */
	if (spawn_times != NULL)
		spawn_times[childno] = (time_t)(mono_ns() / 1000000000ULL);
	if (pidstatfiles[childno] >= 0) {
		close(pidstatfiles[childno]);
		pidstatfiles[childno] = -1;
	}
	pidstatfiles[childno] = open_child_pidstat(pid);
	unsigned int running = __atomic_add_fetch(&shm->running_childs, 1, __ATOMIC_RELAXED);

	debugf("Created child %d (pid:%d) [total:%u/%u]\n",
		childno, pid,
		running,
		max_children);
	return true;
}

/*
 * Read up to bufsz-1 bytes from PATH into BUF, NUL-terminate, strip any
 * trailing newline.  Returns the byte count on success (>=0) or -1 on
 * any open/read failure.  Open is O_CLOEXEC so a fork-failure burst
 * cannot leak the fd to a freshly-forked child.  Backing for the
 * fork-failure diagnostic snapshot whose probes must stay read-only,
 * bounded, and fail-soft against a host whose /proc or /sys layout we
 * do not control.
 */
static ssize_t read_small_file(const char *path, char *buf, size_t bufsz)
{
	int fd;
	ssize_t n;

	if (bufsz == 0)
		return -1;
	buf[0] = '\0';

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	n = read(fd, buf, bufsz - 1);
	close(fd);
	if (n <= 0)
		return -1;
	buf[n] = '\0';
	while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
		buf[--n] = '\0';
	return n;
}

/*
 * Read a single unsigned-long value from PATH (e.g.
 * /proc/sys/kernel/pid_max, cgroup pids.current).  *OUT is set on
 * success.  Returns true on success, false on any open / read / parse
 * failure (with *OUT untouched).  cgroup pids.max etc. may hold the
 * literal "max" instead of a number; treat that as failure so callers
 * can omit the field rather than printing a confusing 0.
 */
static bool read_u64_file(const char *path, unsigned long long *out)
{
	char buf[64];
	char *end;
	unsigned long long val;

	if (read_small_file(path, buf, sizeof(buf)) <= 0)
		return false;
	errno = 0;
	val = strtoull(buf, &end, 10);
	if (end == buf || errno != 0)
		return false;
	*out = val;
	return true;
}

/*
 * Search a "key value\n"-shaped PATH (cgroup memory.events layout) for
 * KEY and put its u64 value in *OUT.  Returns true on success.
 * memory.events lines are short ("oom_kill 0\n") so a 2 KB scratch
 * covers any realistic file; over-long files truncate cleanly because
 * read_small_file uses a fixed-size read.
 */
static bool read_kv_u64(const char *path, const char *key,
			unsigned long long *out)
{
	char buf[2048];
	size_t keylen;
	char *p, *eol;

	if (read_small_file(path, buf, sizeof(buf)) <= 0)
		return false;

	keylen = strlen(key);
	p = buf;
	while (*p != '\0') {
		eol = strchr(p, '\n');
		if (eol != NULL)
			*eol = '\0';
		if (strncmp(p, key, keylen) == 0 && p[keylen] == ' ') {
			char *end;
			unsigned long long val;

			errno = 0;
			val = strtoull(p + keylen + 1, &end, 10);
			if (end == p + keylen + 1 || errno != 0)
				return false;
			*out = val;
			return true;
		}
		if (eol == NULL)
			break;
		p = eol + 1;
	}
	return false;
}

/*
 * Read our own cgroup v2 path from /proc/self/cgroup.  The v2 entry is
 * the line prefixed with "0::".  Writes the path (with leading slash,
 * trailing newline stripped) into BUF; returns true on success.  v1-only
 * systems and an unreadable /proc/self/cgroup both return false so the
 * caller can omit the cgroup section from the snapshot rather than
 * synthesizing a wrong path.
 */
static bool read_self_cgroup_path(char *buf, size_t bufsz)
{
	char raw[4096];
	char *p, *eol;
	size_t len;

	if (read_small_file("/proc/self/cgroup", raw, sizeof(raw)) <= 0)
		return false;

	p = raw;
	while (*p != '\0') {
		eol = strchr(p, '\n');
		if (eol != NULL)
			*eol = '\0';
		if (strncmp(p, "0::", 3) == 0) {
			len = strlen(p + 3);
			if (len == 0 || len >= bufsz)
				return false;
			memcpy(buf, p + 3, len + 1);
			return true;
		}
		if (eol == NULL)
			break;
		p = eol + 1;
	}
	return false;
}

/*
 * One-shot diagnostic snapshot emitted at the first sustained replacement-
 * fork-failure burst.  Latched: at most one snapshot per run, so a wedged
 * fleet cannot drown the log in repeats.  Mirrors the watchdog "record"
 * key:value style from the structured-record landing -- post-run grep on
 * `fork-failure record` pins the bail context to a single log window
 * without having to stitch fields across surrounding lines.
 *
 * Probes are all read-only / bounded / fail-soft: a missing /proc or
 * /sys path drops the corresponding field from the record rather than
 * aborting the snapshot.  No behaviour change to the fork loop itself --
 * the bail decision is upstream of this call.
 */
static void dump_fork_failure_snapshot(void)
{
	static bool emitted = false;
	char cgpath[256];
	char path[512];
	char line[512];
	unsigned int state_R = 0, state_S = 0, state_D = 0;
	unsigned int state_Z = 0, state_T = 0, state_other = 0;
	unsigned int slots_filled = 0;
	unsigned int i;
	struct rlimit rl;
	unsigned long long pid_max = 0, ns_last_pid = 0;
	unsigned long long cg_pids_cur = 0, cg_pids_max = 0;
	unsigned long long mem_low = 0, mem_high = 0, mem_max = 0;
	unsigned long long mem_oom = 0, mem_oom_kill = 0;
	bool have_cg_pids_cur = false, have_cg_pids_max = false;
	bool have_mem_low = false, have_mem_high = false, have_mem_max = false;
	bool have_mem_oom = false, have_mem_oom_kill = false;
	char pid_max_str[32], ns_last_pid_str[32];
	bool have_pid_max, have_ns_last_pid;
	size_t off;

	if (emitted)
		return;
	emitted = true;

	/* Tally child slot state by walking the live pid map.  pids[] lives
	 * in shm and may be NULL if a snapshot somehow fires before the shm
	 * carve-out, but in the documented call sites (fork_children /
	 * replace_child) the array is already populated. */
	if (pids != NULL) {
		for_each_child(i) {
			pid_t pid = __atomic_load_n(&pids[i], __ATOMIC_RELAXED);
			char s;

			if (pid == EMPTY_PIDSLOT)
				continue;
			slots_filled++;
			s = (pidstatfiles != NULL) ? get_pid_state(i) : '?';
			switch (s) {
			case 'R': state_R++; break;
			case 'S': state_S++; break;
			case 'D': state_D++; break;
			case 'Z': state_Z++; break;
			case 'T': case 't': state_T++; break;
			default:  state_other++; break;
			}
		}
	}

	if (getrlimit(RLIMIT_NPROC, &rl) != 0) {
		rl.rlim_cur = 0;
		rl.rlim_max = 0;
	}

	have_pid_max     = read_u64_file("/proc/sys/kernel/pid_max", &pid_max);
	have_ns_last_pid = read_u64_file("/proc/sys/kernel/ns_last_pid",
					 &ns_last_pid);
	if (have_pid_max)
		snprintf(pid_max_str, sizeof(pid_max_str), "%llu", pid_max);
	else
		(void)strcpy(pid_max_str, "-");
	if (have_ns_last_pid)
		snprintf(ns_last_pid_str, sizeof(ns_last_pid_str),
			 "%llu", ns_last_pid);
	else
		(void)strcpy(ns_last_pid_str, "-");

	outputerr("main: fork-failure record"
		  " children_filled:%u children_max:%u"
		  " state_R:%u state_S:%u state_D:%u state_Z:%u state_T:%u"
		  " state_other:%u"
		  " rlimit_nproc_cur:%llu rlimit_nproc_max:%llu"
		  " pid_max:%s ns_last_pid:%s\n",
		  slots_filled, max_children,
		  state_R, state_S, state_D, state_Z, state_T, state_other,
		  (unsigned long long)rl.rlim_cur,
		  (unsigned long long)rl.rlim_max,
		  pid_max_str, ns_last_pid_str);

	if (!read_self_cgroup_path(cgpath, sizeof(cgpath)))
		return;

	/* /sys/fs/cgroup is the canonical v2 mount; an exotic remount (e.g.
	 * a hybrid host with a separate unified mount) renders these probes
	 * unreadable and individual fields drop silently rather than the
	 * whole section. */
	snprintf(path, sizeof(path), "/sys/fs/cgroup%s/pids.current", cgpath);
	have_cg_pids_cur = read_u64_file(path, &cg_pids_cur);
	snprintf(path, sizeof(path), "/sys/fs/cgroup%s/pids.max", cgpath);
	have_cg_pids_max = read_u64_file(path, &cg_pids_max);
	snprintf(path, sizeof(path), "/sys/fs/cgroup%s/memory.events", cgpath);
	have_mem_low      = read_kv_u64(path, "low", &mem_low);
	have_mem_high     = read_kv_u64(path, "high", &mem_high);
	have_mem_max      = read_kv_u64(path, "max", &mem_max);
	have_mem_oom      = read_kv_u64(path, "oom", &mem_oom);
	have_mem_oom_kill = read_kv_u64(path, "oom_kill", &mem_oom_kill);

	off = snprintf(line, sizeof(line), "main: fork-failure cgroup path:%s",
		       cgpath);
	if (have_cg_pids_cur && off < sizeof(line))
		off += snprintf(line + off, sizeof(line) - off,
				" pids_current:%llu", cg_pids_cur);
	if (have_cg_pids_max && off < sizeof(line))
		off += snprintf(line + off, sizeof(line) - off,
				" pids_max:%llu", cg_pids_max);
	if (have_mem_low && off < sizeof(line))
		off += snprintf(line + off, sizeof(line) - off,
				" mem_low:%llu", mem_low);
	if (have_mem_high && off < sizeof(line))
		off += snprintf(line + off, sizeof(line) - off,
				" mem_high:%llu", mem_high);
	if (have_mem_max && off < sizeof(line))
		off += snprintf(line + off, sizeof(line) - off,
				" mem_max:%llu", mem_max);
	if (have_mem_oom && off < sizeof(line))
		off += snprintf(line + off, sizeof(line) - off,
				" mem_oom:%llu", mem_oom);
	if (have_mem_oom_kill && off < sizeof(line))
		/* Last field appended -- no further uses of off afterwards. */
		(void) snprintf(line + off, sizeof(line) - off,
				" mem_oom_kill:%llu", mem_oom_kill);

	outputerr("%s\n", line);
}

/*
 * Per-childop fork-failed counter dump for the stuck-fork bail path.
 * Several childops fork their own short-lived helper workers
 * (sysfs_string_race writers, qrtr_bind_race binders, pfkey_spd_walk
 * walkers, l2tp_ifname_race creators, statmount_idmap carrier helpers)
 * and bump a *_fork_failed counter when their inner fork() returns
 * EAGAIN / ENOMEM / RLIMIT_NPROC.  Those counters are the closest
 * thing the tree has to per-source attribution for pid pressure: if
 * the parent's spawn loop wedged because one specific childop is
 * burning subworker fork budget, the dominant counter here names it.
 *
 * Emitted as a single line (one key:value per source) so log scrapers
 * can lift it out of the surrounding bail block with a fixed prefix
 * match.  Sources with a zero counter are still printed so the
 * absence of a contribution is unambiguous.  Latched via the same
 * one-shot pattern as dump_fork_failure_snapshot(): the bail path
 * touches several dump helpers in sequence; if any of them is reached
 * twice via a future refactor we still emit at most one line per run.
 */
static void dump_fork_failure_subworker_counters(void)
{
	static bool emitted = false;

	if (emitted)
		return;
	emitted = true;

	if (shm == NULL)
		return;

	outputerr("main: fork-failure subworker_fork_failed"
		  " sysfs_string_race:%lu qrtr_bind_race:%lu"
		  " pfkey_spd_walk:%lu l2tp_ifname_race:%lu"
		  " statmount_idmap:%lu\n",
		  __atomic_load_n(&shm->stats.sysfs_string_race_fork_failed,
				  __ATOMIC_RELAXED),
		  __atomic_load_n(&shm->stats.qrtr_bind_race.fork_failed,
				  __ATOMIC_RELAXED),
		  __atomic_load_n(&shm->stats.pfkey_spd_walk.fork_failed,
				  __ATOMIC_RELAXED),
		  __atomic_load_n(&shm->stats.l2tp_ifname_race.fork_failed,
				  __ATOMIC_RELAXED),
		  __atomic_load_n(&shm->stats.statmount_idmap.fork_failed,
				  __ATOMIC_RELAXED));
}

/*
 * Force a save of every cross-run cache (minicorpus, kcov bitmap,
 * cmp-hints pool) at a bail point so the on-disk snapshot reflects the
 * in-memory high-water at the moment we gave up.  Mirrors the cluster
 * of save_file() calls inside persist_state_on_clean_exit() in
 * trinity.c, but without the clean-exit gate: that gate excludes
 * EXIT_FORK_FAILURE, so the fork-pressure bail path would otherwise
 * persist nothing.  Idempotent -- each save_file() is an atomic
 * overwrite, so on the time-limit path (where the trinity.c cleanup
 * will save again) the duplicate is wasted I/O but harmless.  Per-
 * carrier --no-*-warm-start flags still suppress its respective save,
 * matching the trinity.c policy.
 */
void final_state_save(void)
{
	if (!no_warm_start) {
		const char *path = warm_start_path ? warm_start_path
						   : minicorpus_default_path();

		if (path != NULL && minicorpus_save_file(path))
			output(0, "minicorpus: persisted to %s\n", path);
	}
	if (!no_kcov_warm_start && kcov_shm != NULL) {
		const char *kpath = kcov_bitmap_default_path();

		if (kpath != NULL && kcov_bitmap_save_file(kpath))
			output(0, "kcov-bitmap: persisted to %s\n", kpath);
	}
	if (!no_cmp_hints_warm_start && cmp_hints_shm != NULL) {
		const char *cpath = cmp_hints_default_path();

		if (cpath != NULL && cmp_hints_save_file(cpath))
			output(0, "cmp-hints: persisted to %s\n", cpath);
	}
	if (!no_chain_warm_start && chain_corpus_shm != NULL) {
		const char *cpath = chain_corpus_default_path();

		if (cpath != NULL && chain_corpus_save_file(cpath))
			output(0, "chain corpus: persisted to %s\n", cpath);
	}
}

void replace_child(int childno)
{
	unsigned int retries = 0;

	if (__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED) != STILL_RUNNING)
		return;

	/* Don't replace if the fleet has been halted (e.g. a __BUG fired
	 * in some child and we're now keeping the survivors quiescent so
	 * an operator can gdb-attach for inspection).  The slot stays
	 * empty rather than respawning into a known-corrupt environment. */
	if (__atomic_load_n(&shm->spawn_no_more, __ATOMIC_ACQUIRE))
		return;

	while (spawn_child(childno) == false) {
		if (++retries >= 10) {
			outputerr("Failed to replace child %d after %u fork attempts, giving up.\n",
				childno, retries);
			dump_fork_failure_snapshot();
			return;
		}
		usleep(min(retries * 10000u, 20000u));
	}
}

/* Dump /proc/self/status so a stuck-fork bail report shows the parent's
 * thread/process accounting (Threads:, FDSize:, etc.) at the moment we
 * gave up.  Useful for triaging whether the kernel-side resource we ran
 * out of was process slots, pid_max, or something else.
 *
 * Raw open/read/close rather than fopen/getline: this runs from the
 * stuck-fork bail path, exactly the moment heap allocation is most
 * likely to misbehave (we're already out of some kernel resource, and
 * may be on the heel of a flurry of ENOMEM/EAGAIN).  stdio's per-call
 * malloc of the FILE struct and IO buffer, plus getline's malloc'd
 * line buffer, are extra allocation we should not require here.  Use
 * a fixed stack buffer big enough for any realistic /proc/self/status
 * (procfs caps the file at PAGE_SIZE per read but is usually <4KB)
 * and split on '\n' in-place. */
void dump_proc_self_status(void)
{
	char buf[8192];
	ssize_t n;
	char *p, *eol;
	int fd;

	fd = open("/proc/self/status", O_RDONLY);
	if (fd < 0)
		return;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return;
	buf[n] = '\0';

	for (p = buf; *p != '\0'; p = eol + 1) {
		eol = strchr(p, '\n');
		if (eol == NULL) {
			outputerr("/proc/self/status: %s\n", p);
			break;
		}
		*eol = '\0';
		outputerr("/proc/self/status: %s\n", p);
	}
}

/* Generate children*/
void fork_children(void)
{
	/* Bound the outer respawn loop.  The inner spawn_child retry
	 * already caps per-slot attempts at 10, but if every slot keeps
	 * failing (e.g. the process table is full of orphans the parent
	 * cannot reap) the outer while loop will iterate forever, growing
	 * a silent wedge with no exit, no watchdog fire, and no operator
	 * visibility beyond strace.  Track consecutive failed spawn_child
	 * calls and bail once we cross the threshold; with the 10-100ms
	 * inner backoff this caps the stuck window at roughly a minute. */
	unsigned int consecutive_fork_failures = 0;
	const unsigned int max_consecutive_fork_failures = 1000;
	/* Cumulative backoff across all slots in this fork_children call.
	 * Each inner sleep is clamped to 20 ms; once we've burned ~2 s of
	 * backoff total, yield back to main_loop so reap, watchdog and the
	 * deferred-free ring drain run between fork storms instead of being
	 * starved by an endlessly retrying spawn loop. */
	unsigned int total_backoff_us = 0;
	const unsigned int max_total_backoff_us = 2000000u;

	while (__atomic_load_n(&shm->running_childs, __ATOMIC_RELAXED) < max_children) {
		int childno;

		if (__atomic_load_n(&shm->spawn_no_more, __ATOMIC_ACQUIRE))
			return;

		/* Find a space for it in the pid map.  A slot is only
		 * usable when both the live-pid and zombie-pending slots
		 * are empty — see find_free_childno() and the
		 * zombie_pids[] comment at the top of this file. */
		childno = find_free_childno();
		if (childno == CHILD_NOT_FOUND) {
			/* Distinguish a genuinely-full pid map (a fatal
			 * bookkeeping bug) from "every empty slot is in
			 * zombie-pending state" (transient — a future
			 * process_zombie_pending() pass will retire them
			 * and main_loop will call us again). */
			if (find_childno(EMPTY_PIDSLOT) == CHILD_NOT_FOUND) {
				/* Every slot holds a pid, but a watchdog
				 * kill burst can leave slots parked with
				 * dead pids the exit accounting never
				 * cleared -- the "0 active" state. Run the
				 * reconciliation sweep before giving up:
				 * reap_dead_kids' kill(pid,0)==ESRCH pass
				 * reaps those slots to EMPTY_PIDSLOT. Only
				 * a still-full map is a genuine loss. */
				reap_dead_kids();
				if (find_childno(EMPTY_PIDSLOT) == CHILD_NOT_FOUND) {
					outputerr("## Pid map was full!\n");
					dump_childnos();
					exit(EXIT_LOST_CHILD);
				}
			}
			return;
		}

		{
			unsigned int retries = 0;

			while (spawn_child(childno) == false) {
				consecutive_fork_failures++;
				/* Drain mode: at the first crossing of
				 * FORK_PRESSURE_DRAIN_THRESHOLD inside this
				 * burst, arm the recovery window so the canary
				 * picker stops scheduling pid-heavy ops.  Re-
				 * arm on every subsequent failure inside the
				 * burst (cheap, RELAXED store) so a sustained
				 * pressure spell holds the window open instead
				 * of timing out mid-spell.  Guarded by the
				 * opt-in flag -- default behaviour stays
				 * byte-identical. */
				if (fork_pressure_drain &&
				    consecutive_fork_failures >= FORK_PRESSURE_DRAIN_THRESHOLD) {
					struct timespec ts;
					(void)clock_gettime(CLOCK_MONOTONIC, &ts);
					__atomic_store_n(&fork_pressure_active_until,
						(unsigned long)ts.tv_sec +
							FORK_PRESSURE_DRAIN_RECOVERY_S,
						__ATOMIC_RELAXED);
					if (consecutive_fork_failures == FORK_PRESSURE_DRAIN_THRESHOLD)
						output(0, "main: fork-pressure drain engaged (%u consecutive spawn failures); pid-heavy canary picks suppressed for %u s\n",
							consecutive_fork_failures,
							FORK_PRESSURE_DRAIN_RECOVERY_S);
				}
				if (consecutive_fork_failures >= max_consecutive_fork_failures) {
					outputerr("main: fork stuck - %u consecutive spawn failures; bailing (process table likely exhausted)\n",
						consecutive_fork_failures);
					dump_proc_self_status();
					dump_fork_failure_snapshot();
					dump_fork_failure_subworker_counters();
					final_state_save();
					panic(EXIT_FORK_FAILURE);
					return;
				}
				if (++retries >= 10) {
					outputerr("Failed to fork initial child for slot %d after %u attempts, skipping slot.\n",
						childno, retries);
					dump_fork_failure_snapshot();
					break;
				}
				{
					unsigned int sleep_us = min(retries * 10000u, 20000u);
					usleep(sleep_us);
					total_backoff_us += sleep_us;
					if (total_backoff_us >= max_total_backoff_us)
						return;
				}
			}
			if (retries >= 10)
				continue;
			consecutive_fork_failures = 0;
		}

		/* Per-spawn visibility under -v.  Today only the final
		 * "all children running" state is observable; if a fork
		 * silently no-ops or stalls partway through populating the
		 * pidmap there's no way to tell which slot we got stuck
		 * on.  spawn_child has already published the pid into
		 * pids[childno] by this point. */
		output(1, "forked child %u/%u (pid %d)\n",
			__atomic_load_n(&shm->running_childs, __ATOMIC_RELAXED),
			max_children,
			__atomic_load_n(&pids[childno], __ATOMIC_RELAXED));

		if (__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED) != STILL_RUNNING)
			return;

		/* Under cgroup memory.high pressure (fork_throttle_us > 0)
		 * yield back to main_loop after one spawn so periodic work
		 * (zombie reap, ring drain, throttle re-evaluation) runs
		 * between sequential spawns.  At the 1 s sustained cap,
		 * refilling N slots back-to-back would otherwise hold the
		 * main loop for N seconds, blocking reap of children that
		 * are dying in the same pressure window.  No-op in the
		 * common no-pressure path -- the loop just spins back to
		 * the running_childs < max_children check and exits when
		 * the pool is full.  main_loop's existing under-target
		 * branch will re-enter fork_children on the next tick. */
		if (fork_throttle_us > 0)
			return;
	}
	__atomic_store_n(&shm->ready, true, __ATOMIC_RELEASE);
}
