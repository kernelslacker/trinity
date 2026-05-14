#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/sched.h>

#include "child.h"
#include "params.h"
#include "pids.h"
#include "self_cgroup.h"
#include "trinity.h"
#include "utils.h"

#ifndef CLONE_INTO_CGROUP
#define CLONE_INTO_CGROUP 0x200000000ULL
#endif

/*
 * Sub-cgroup layout (all under the v2 cgroup we belong to at startup):
 *
 *   trinity-<pid>/                     container, no procs, no memory.* set
 *     ├── parent/                      memory.oom.group=0, memory.high=<small>
 *     │                                trinity-main lives here
 *     └── children/                    memory.oom.group=1, memory.max=<cap>
 *                                      all worker children live here
 *
 * The split exists so children's OOM doesn't take the parent.  When the
 * children/ cap fires, oom.group=1 kills the entire worker pool atomically
 * and the parent re-spawns from a clean state.  Parent has no memory.max
 * and a generous memory.high so its bandit/HEALER bookkeeping is never
 * the OOM target.
 *
 * Cleanup is best-effort: the kernel reclaims empty cgroups when the last
 * process exits, so rmdir failures during teardown are benign.
 */
static char *cg_container;	/* trinity-<pid>/ */
static char *cg_parent;		/* trinity-<pid>/parent/ */
static char *cg_workload;	/* trinity-<pid>/children/ in split mode,
				 * or the single trinity-<pid>/ in fallback */
static char *cg_original;	/* full /sys/fs/cgroup<parent> path we joined
				 * from at startup; cleanup moves trinity-main
				 * back here so the parent rmdir succeeds.
				 * Populated only in split mode. */
static int  cg_workload_fd = -1;	/* O_DIRECTORY on cg_workload */
static bool cg_split_mode;	/* true if parent/children sub-cgroups are live */
static bool clone3_unavailable;	/* latched on first ENOSYS */

static unsigned long mem_total_bytes(void)
{
	FILE *f;
	char line[256];
	unsigned long kb = 0;

	f = fopen("/proc/meminfo", "re");
	if (f == NULL)
		return 0;
	while (fgets(line, sizeof(line), f) != NULL) {
		if (sscanf(line, "MemTotal: %lu kB", &kb) == 1)
			break;
	}
	fclose(f);
	return kb * 1024UL;
}

/*
 * Parse a size argument and produce a byte-count (out_bytes) plus the
 * canonical string we write into the cgroup file (out_str).  Accepted forms:
 *   "max"          → out_str="max", out_bytes=ULONG_MAX (sentinel for uncapped)
 *   "<n>%"         → percentage of MemTotal (1..100)
 *   "<n>[KMG]"     → bytes, with optional K/M/G binary suffix (1024)
 *
 * On success returns true; *out_str is malloc'd, caller frees.
 * On failure returns false and outputs are untouched.
 */
static bool parse_size_arg(const char *arg, unsigned long mem_total,
			   char **out_str, unsigned long *out_bytes)
{
	char *end;
	unsigned long long val;
	unsigned long long mult = 1;

	if (arg == NULL || *arg == '\0')
		return false;

	if (strcmp(arg, "max") == 0) {
		*out_str = strdup("max");
		if (*out_str == NULL)
			return false;
		*out_bytes = ULONG_MAX;
		return true;
	}

	errno = 0;
	val = strtoull(arg, &end, 10);
	if (end == arg || errno == ERANGE)
		return false;

	if (*end == '%') {
		if (end[1] != '\0')
			return false;
		if (val == 0 || val > 100)
			return false;
		if (mem_total == 0)
			return false;
		val = (unsigned long long)mem_total * val / 100ULL;
	} else if (*end != '\0') {
		if (end[1] != '\0')
			return false;
		switch (*end) {
		case 'k': case 'K': mult = 1024ULL; break;
		case 'm': case 'M': mult = 1024ULL * 1024; break;
		case 'g': case 'G': mult = 1024ULL * 1024 * 1024; break;
		default: return false;
		}
		if (val > ULLONG_MAX / mult)
			return false;
		val *= mult;
	}

	if (asprintf(out_str, "%llu", val) < 0)
		return false;
	*out_bytes = (unsigned long)val;
	return true;
}

/*
 * Read the cgroup v2 path of the calling process from /proc/self/cgroup.
 * The v2 line is the only one prefixed with "0::".  Returns a malloc'd
 * NUL-terminated path (e.g. "/user.slice/user-1000.slice/session-3.scope")
 * with the trailing newline stripped, or NULL if the file is unreadable
 * or no v2 line is present (e.g. pure cgroup v1 systems).
 */
static char *read_self_cg_path(void)
{
	FILE *f;
	char line[PATH_MAX + 32];
	char *result = NULL;

	f = fopen("/proc/self/cgroup", "re");
	if (f == NULL)
		return NULL;
	while (fgets(line, sizeof(line), f) != NULL) {
		if (strncmp(line, "0::", 3) != 0)
			continue;
		char *p = line + 3;
		size_t len = strlen(p);
		while (len > 0 && (p[len - 1] == '\n' || p[len - 1] == '\r'))
			p[--len] = '\0';
		if (len == 0)
			break;
		result = strdup(p);
		break;
	}
	fclose(f);
	return result;
}

static bool write_cg_file(const char *cg_path, const char *name,
			  const char *value)
{
	char path[PATH_MAX];
	int fd;
	ssize_t n;
	size_t len;

	if ((size_t)snprintf(path, sizeof(path), "%s/%s", cg_path, name) >= sizeof(path))
		return false;
	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return false;
	len = strlen(value);
	n = write(fd, value, len);
	close(fd);
	return n == (ssize_t)len;
}

/*
 * Detect a wrapper scope: if our current cgroup already has a non-"max"
 * memory.max, an outer agent (systemd-run, kubelet, the run-trinity.sh
 * stopgap) has already capped us.  Defer to it: nesting our own
 * sub-cgroup inside would just confuse exit accounting and leak rmdir
 * permission errors when the wrapper tears its scope down before us.
 */
static bool already_capped(const char *parent_cg_path)
{
	char path[PATH_MAX];
	FILE *f;
	char buf[64];
	bool capped = false;

	if ((size_t)snprintf(path, sizeof(path), "/sys/fs/cgroup%s/memory.max",
			     parent_cg_path) >= sizeof(path))
		return false;
	f = fopen(path, "re");
	if (f == NULL)
		return false;
	if (fgets(buf, sizeof(buf), f) != NULL) {
		size_t len = strlen(buf);
		while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
			buf[--len] = '\0';
		if (strcmp(buf, "max") != 0)
			capped = true;
	}
	fclose(f);
	return capped;
}

/* Defined below; forward-declared so self_cgroup_setup / _cleanup can
 * call them while keeping the Phase 2 implementation grouped at the
 * bottom of the file. */
static void events_setup(void);
static void events_cleanup(void);

/*
 * Compute the parent's memory.high reservation.  Parent does little work
 * per-iter (waitpid/reap/fork loop, periodic_work bookkeeping, HEALER
 * snapshots), so a small soft limit is plenty.
 *
 *   parent_high = min(200M, total_max / 16)
 *
 * The /16 split keeps the parent's reservation proportional on tiny
 * budgets (e.g. a 256M total cap leaves ~16M for the parent — small but
 * functional) while capping at 200M on large budgets so the operator's
 * --memory-max value mostly goes to children where the work happens.
 *
 * memory.high is a soft limit (kernel throttles allocations above it),
 * not a hard cap.  We deliberately do not set memory.max on the parent —
 * if parent ever genuinely needs more, it should be allowed to allocate.
 */
static unsigned long compute_parent_high(unsigned long total_max_bytes)
{
	const unsigned long PARENT_HIGH_CAP = 200UL * 1024 * 1024;

	if (total_max_bytes == ULONG_MAX)
		return PARENT_HIGH_CAP;
	if (total_max_bytes / 16 < PARENT_HIGH_CAP)
		return total_max_bytes / 16;
	return PARENT_HIGH_CAP;
}

/*
 * Try to enable the memory controller in the container's subtree so the
 * parent/ and children/ sub-cgroups can carry memory.* knobs.  Returns
 * true on success.  Failure (EOPNOTSUPP, EINVAL, EACCES) is the signal to
 * fall back to single-cgroup mode.
 */
static bool enable_memory_subtree(const char *container_path)
{
	return write_cg_file(container_path, "cgroup.subtree_control",
			     "+memory");
}

/*
 * Build sub-cgroups under container/: parent/ and children/.  Sets all
 * memory knobs and moves trinity-main into parent/.  On any failure
 * returns false; caller falls back to single-cgroup mode using the same
 * container directory.
 */
static bool setup_split(const char *container_path,
			const char *children_max_str,
			const char *children_high_str,
			const char *children_swap_str,
			unsigned long children_max_bytes)
{
	char *parent_path = NULL;
	char *children_path = NULL;
	char parent_high_str[32];
	char pidbuf[32];
	int n;
	int wfd = -1;
	unsigned long parent_high;

	if (!enable_memory_subtree(container_path)) {
		outputerr("self-cgroup: enable +memory in subtree_control failed: %s\n",
			  strerror(errno));
		return false;
	}

	if (asprintf(&parent_path, "%s/parent", container_path) < 0) {
		parent_path = NULL;
		goto fail;
	}
	if (asprintf(&children_path, "%s/children", container_path) < 0) {
		children_path = NULL;
		goto fail;
	}

	if (mkdir(parent_path, 0755) != 0) {
		outputerr("self-cgroup: mkdir(%s) failed: %s\n",
			  parent_path, strerror(errno));
		goto fail;
	}
	if (mkdir(children_path, 0755) != 0) {
		outputerr("self-cgroup: mkdir(%s) failed: %s\n",
			  children_path, strerror(errno));
		rmdir(parent_path);
		goto fail;
	}

	/* Children: hard cap + swap cap + back-pressure threshold + group-OOM. */
	if (!write_cg_file(children_path, "memory.max", children_max_str)) {
		outputerr("self-cgroup: write children/memory.max=%s failed: %s\n",
			  children_max_str, strerror(errno));
		goto fail_rmdir;
	}
	if (!write_cg_file(children_path, "memory.high", children_high_str))
		output(1, "self-cgroup: write children/memory.high=%s failed: %s\n",
		       children_high_str, strerror(errno));
	if (!write_cg_file(children_path, "memory.swap.max", children_swap_str))
		output(1, "self-cgroup: write children/memory.swap.max=%s failed: %s\n",
		       children_swap_str, strerror(errno));
	/* memory.oom.group=1: when children's memory.max fires, kill ALL
	 * processes in this cgroup atomically.  Best-effort — older kernels
	 * without the knob silently fall back to per-task OOM. */
	if (!write_cg_file(children_path, "memory.oom.group", "1"))
		output(1, "self-cgroup: write children/memory.oom.group=1 failed: %s\n",
		       strerror(errno));

	/* Parent: small soft limit, no hard cap, never group-killed. */
	parent_high = compute_parent_high(children_max_bytes == ULONG_MAX
					  ? ULONG_MAX
					  : children_max_bytes);
	n = snprintf(parent_high_str, sizeof(parent_high_str), "%lu",
		     parent_high);
	if (n < 0 || (size_t)n >= sizeof(parent_high_str))
		goto fail_rmdir;
	if (!write_cg_file(parent_path, "memory.high", parent_high_str))
		output(1, "self-cgroup: write parent/memory.high=%s failed: %s\n",
		       parent_high_str, strerror(errno));
	if (!write_cg_file(parent_path, "memory.oom.group", "0"))
		output(1, "self-cgroup: write parent/memory.oom.group=0 failed: %s\n",
		       strerror(errno));

	/* Move trinity-main into parent/.  If this fails the split is moot:
	 * trinity-main would be left in container/ alongside the empty
	 * subgroups, which violates v2's "no internal processes" rule. */
	n = snprintf(pidbuf, sizeof(pidbuf), "%d\n", (int)getpid());
	if (n < 0 || (size_t)n >= sizeof(pidbuf) ||
	    !write_cg_file(parent_path, "cgroup.procs", pidbuf)) {
		outputerr("self-cgroup: parent/cgroup.procs write failed: %s\n",
			  strerror(errno));
		goto fail_rmdir;
	}

	/* Open children/ as O_DIRECTORY so spawn_child() can hand the fd to
	 * clone3(CLONE_INTO_CGROUP).  O_PATH would also work but O_DIRECTORY
	 * is what the man page documents for this ABI. */
	wfd = open(children_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (wfd < 0) {
		outputerr("self-cgroup: open(%s) failed: %s\n",
			  children_path, strerror(errno));
		goto fail_rmdir;
	}

	cg_parent = parent_path;
	cg_workload = children_path;
	cg_workload_fd = wfd;
	cg_split_mode = true;

	output(0, "self-cgroup: split mode active "
	       "(parent/memory.high=%s, children/memory.max=%s memory.high=%s memory.swap.max=%s memory.oom.group=1)\n",
	       parent_high_str, children_max_str, children_high_str, children_swap_str);
	return true;

fail_rmdir:
	if (wfd >= 0)
		close(wfd);
	rmdir(children_path);
	rmdir(parent_path);
fail:
	free(parent_path);
	free(children_path);
	return false;
}

/*
 * Single-cgroup fallback: container directory carries memory.* knobs
 * directly and trinity-main + all workers live in it.  This is the
 * Phase 1 behavior and is used when the parent/children split couldn't
 * be set up (older kernel, delegation gap, etc.).  No OOM scope
 * isolation — just the original hard cap.
 */
static bool setup_single(const char *container_path,
			 const char *max_str,
			 const char *high_str,
			 const char *swap_str)
{
	char pidbuf[32];
	int n;

	if (!write_cg_file(container_path, "memory.max", max_str)) {
		outputerr("self-cgroup: write memory.max=%s failed: %s\n",
			  max_str, strerror(errno));
		return false;
	}
	if (!write_cg_file(container_path, "memory.high", high_str))
		output(1, "self-cgroup: write memory.high=%s failed: %s\n",
		       high_str, strerror(errno));
	if (!write_cg_file(container_path, "memory.swap.max", swap_str))
		output(1, "self-cgroup: write memory.swap.max=%s failed: %s\n",
		       swap_str, strerror(errno));

	n = snprintf(pidbuf, sizeof(pidbuf), "%d\n", (int)getpid());
	if (n < 0 || (size_t)n >= sizeof(pidbuf) ||
	    !write_cg_file(container_path, "cgroup.procs", pidbuf)) {
		outputerr("self-cgroup: cgroup.procs write failed: %s\n",
			  strerror(errno));
		return false;
	}

	cg_workload = strdup(container_path);
	if (cg_workload == NULL)
		return false;

	output(0, "self-cgroup: single-cgroup fallback "
	       "(memory.max=%s memory.high=%s memory.swap.max=%s) -- no OOM scope split\n",
	       max_str, high_str, swap_str);
	return true;
}

void self_cgroup_setup(void)
{
	char *parent_cg = NULL;
	unsigned long memtotal;
	char *max_str = NULL;
	char *high_str = NULL;
	char *swap_str = NULL;
	unsigned long max_bytes = 0;
	unsigned long high_bytes = 0;
	unsigned long swap_bytes = 0;

	if (no_cgroup)
		return;

	parent_cg = read_self_cg_path();
	if (parent_cg == NULL) {
		outputerr("self-cgroup: /proc/self/cgroup has no v2 entry; "
			  "running without memory cap\n");
		goto out;
	}

	if (already_capped(parent_cg)) {
		output(1, "self-cgroup: parent cgroup %s already capped; "
		       "deferring to wrapper\n", parent_cg);
		goto out;
	}

	memtotal = mem_total_bytes();
	if (memtotal == 0) {
		outputerr("self-cgroup: cannot read MemTotal; "
			  "running without memory cap\n");
		goto out;
	}

	if (!parse_size_arg(memory_max_arg ? memory_max_arg : "60%",
			    memtotal, &max_str, &max_bytes)) {
		outputerr("self-cgroup: invalid --memory-max '%s'; "
			  "running without memory cap\n",
			  memory_max_arg ? memory_max_arg : "60%");
		goto out;
	}
	if (!parse_size_arg(memory_high_arg ? memory_high_arg : "50%",
			    memtotal, &high_str, &high_bytes)) {
		outputerr("self-cgroup: invalid --memory-high '%s'; "
			  "running without memory cap\n",
			  memory_high_arg ? memory_high_arg : "50%");
		goto out;
	}
	if (!parse_size_arg(memory_swap_max_arg ? memory_swap_max_arg : "20%",
			    memtotal, &swap_str, &swap_bytes)) {
		outputerr("self-cgroup: invalid --memory-swap-max '%s'; "
			  "running without memory cap\n",
			  memory_swap_max_arg ? memory_swap_max_arg : "20%");
		goto out;
	}
	(void)high_bytes;
	(void)swap_bytes;

	if (asprintf(&cg_container, "/sys/fs/cgroup%s/trinity-%d",
		     parent_cg, (int)getpid()) < 0) {
		cg_container = NULL;
		outputerr("self-cgroup: asprintf failed; "
			  "running without memory cap\n");
		goto out;
	}

	if (mkdir(cg_container, 0755) != 0) {
		outputerr("self-cgroup: mkdir(%s) failed: %s; "
			  "running without memory cap\n",
			  cg_container, strerror(errno));
		free(cg_container);
		cg_container = NULL;
		goto out;
	}

	/*
	 * Try the parent/children split first.  On any failure, fall back to
	 * single-cgroup mode (Phase 1 semantics) so the operator still gets
	 * the hard memory cap even on kernels/configs where the split won't
	 * fly.  setup_split() leaves the container directory in place either
	 * way; we then attach memory.* directly to it for the fallback.
	 */
	if (setup_split(cg_container, max_str, high_str, swap_str, max_bytes)) {
		/* split mode established; cg_parent/cg_workload populated.
		 * Save the original /sys/fs/cgroup path so cleanup can move
		 * trinity-main back before tearing down parent/. */
		if (asprintf(&cg_original, "/sys/fs/cgroup%s", parent_cg) < 0)
			cg_original = NULL;
	} else {
		output(1, "self-cgroup: parent/children split unavailable; "
		       "falling back to single-cgroup mode\n");
		if (!setup_single(cg_container, max_str, high_str, swap_str)) {
			outputerr("self-cgroup: single-cgroup fallback also failed; "
				  "running without memory cap\n");
			rmdir(cg_container);
			free(cg_container);
			cg_container = NULL;
			goto out;
		}
	}

	events_setup();

out:
	free(parent_cg);
	free(max_str);
	free(high_str);
	free(swap_str);
}

void self_cgroup_cleanup(void)
{
	events_cleanup();

	if (cg_workload_fd >= 0) {
		close(cg_workload_fd);
		cg_workload_fd = -1;
	}

	/*
	 * rmdir order: workload (children) first, then parent, then
	 * container.  Move trinity-main back to its original cgroup first
	 * so the parent rmdir succeeds — cgroup v2 does not auto-reap
	 * empty directories, so anything we leave behind is a stale
	 * /sys/fs/cgroup/.../trinity-<pid>/ until the next manual sweep.
	 */
	if (cg_original != NULL) {
		char buf[32];
		int n = snprintf(buf, sizeof(buf), "%d\n", (int)getpid());

		if (n > 0 && (size_t)n < sizeof(buf))
			(void)write_cg_file(cg_original, "cgroup.procs", buf);
	}

	if (cg_workload != NULL) {
		rmdir(cg_workload);
		free(cg_workload);
		cg_workload = NULL;
	}
	if (cg_parent != NULL) {
		rmdir(cg_parent);
		free(cg_parent);
		cg_parent = NULL;
	}
	if (cg_container != NULL) {
		rmdir(cg_container);
		free(cg_container);
		cg_container = NULL;
	}
	free(cg_original);
	cg_original = NULL;
	cg_split_mode = false;
}

/*
 * Spawn a worker into the children/ cgroup.  Same return semantics as
 * fork(): pid in parent, 0 in child, -1 on error.
 *
 * Preferred path is clone3(CLONE_INTO_CGROUP) with an O_DIRECTORY fd on
 * children/ — atomic placement, no transient window where the child runs
 * in parent/ and racing allocations could land against the wrong limit.
 *
 * Fallbacks:
 *   - cg_workload_fd < 0 (cgroup setup didn't happen, or single-cgroup
 *     fallback): plain fork(); children inherit whatever cgroup the
 *     parent is in.
 *   - clone3 returns ENOSYS (very old kernel, pre-5.7-ish or stripped):
 *     latch clone3_unavailable, fall through to fork() + post-migrate
 *     by writing the child pid to children/cgroup.procs.  Brief race
 *     window where the child is in parent/ before the write lands.
 *   - clone3 returns any other error (EAGAIN, ENOMEM): return -1 so the
 *     caller's existing retry loop in spawn_child() handles it the same
 *     way it would handle a transient fork() failure.
 */
pid_t self_cgroup_fork_into_workload(void)
{
	pid_t pid;

	if (cg_workload_fd < 0)
		return fork();

	if (!clone3_unavailable) {
		struct clone_args args = {
			.flags = CLONE_INTO_CGROUP,
			.exit_signal = SIGCHLD,
			.cgroup = (uint64_t)(unsigned int)cg_workload_fd,
		};
		long ret = syscall(__NR_clone3, &args, sizeof(args));

		if (ret >= 0)
			return (pid_t)ret;
		if (errno != ENOSYS)
			return -1;
		clone3_unavailable = true;
		output(0, "self-cgroup: clone3 ENOSYS; "
		       "falling back to fork()+post-migrate\n");
	}

	pid = fork();
	if (pid > 0) {
		char buf[32];
		int n = snprintf(buf, sizeof(buf), "%d\n", (int)pid);
		int fd;

		if (n > 0 && (size_t)n < sizeof(buf)) {
			fd = openat(cg_workload_fd, "cgroup.procs",
				    O_WRONLY | O_CLOEXEC);
			if (fd >= 0) {
				ssize_t wn = write(fd, buf, (size_t)n);

				if (wn != n)
					output(1, "self-cgroup: post-fork migrate of pid %d failed: %s\n",
					       (int)pid, strerror(errno));
				close(fd);
			}
		}
	}
	return pid;
}

/*
 * Phase 2: memory.events back-pressure.
 *
 * The Phase 1 cap is reactive: when memory.max is hit the kernel evicts
 * trinity processes, dropping bandit/HEALER convergence state every
 * cycle.  Phase 2 listens to the kernel's memory.events file (rewritten
 * each time low/high/max/oom counters bump) and applies back-pressure
 * before the cap is reached: a doubling fork-rate throttle on
 * memory.high crossings.
 *
 * In split mode the watcher attaches to children/memory.events — that's
 * where the workload's memory pressure shows up.  memory.max crossings
 * are tracked for diagnostics only: with children/memory.oom.group=1 the
 * kernel kills the entire worker pool atomically when the cap fires, the
 * parent re-spawns from a clean state, and any userspace shed-on-top
 * would just race the kernel.
 *
 * The watch is parent-only.  Inotify on cgroupfs delivers IN_MODIFY
 * each time the kernel rewrites memory.events; the parent drains those
 * notifications from its main_loop tick (~25ms cadence at the busiest)
 * and re-reads the file to compare counts against the last snapshot.
 *
 * Failure paths (inotify_init1 EMFILE, watch add denied, file open
 * denied) all degrade silently: the kernel will still scope the OOM kill
 * to children/, just without the proactive throttle.
 */

unsigned int fork_throttle_us;

#define THROTTLE_MIN_US		1000U	/* 1 ms initial step */
#define THROTTLE_MAX_US		100000U	/* 100 ms cap */
#define THROTTLE_DECAY_TICKS	40U	/* ~1s of quiet at 25ms cadence */

static int events_inotify_fd = -1;
static int events_file_fd = -1;
static unsigned long last_high_count;
static unsigned long last_max_count;
static unsigned int high_event_seq;
static unsigned int max_event_seq;
static unsigned int quiet_streak;

/*
 * Re-read the cgroup memory.events file (rewritten in place by the
 * kernel) and pull out the high and max counters.  The file is small
 * (~96 bytes) and uses a stable "key value\n" format documented in
 * cgroup-v2.rst.  Counters increase monotonically across the cgroup's
 * lifetime, so a delta against the prior snapshot is the new-event
 * count for that counter.
 */
static bool read_event_counts(unsigned long *high_out, unsigned long *max_out)
{
	char buf[512];
	ssize_t n;
	char *line, *save = NULL;
	unsigned long high = 0, max = 0;

	if (events_file_fd < 0)
		return false;
	if (lseek(events_file_fd, 0, SEEK_SET) == (off_t)-1)
		return false;
	n = read(events_file_fd, buf, sizeof(buf) - 1);
	if (n <= 0)
		return false;
	buf[n] = '\0';
	for (line = strtok_r(buf, "\n", &save); line != NULL;
	     line = strtok_r(NULL, "\n", &save)) {
		unsigned long v;

		if (sscanf(line, "high %lu", &v) == 1)
			high = v;
		else if (sscanf(line, "max %lu", &v) == 1)
			max = v;
	}
	*high_out = high;
	*max_out = max;
	return true;
}

static void events_setup(void)
{
	char path[PATH_MAX];

	if (cg_workload == NULL)
		return;

	if ((size_t)snprintf(path, sizeof(path), "%s/memory.events",
			     cg_workload) >= sizeof(path))
		return;

	events_inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
	if (events_inotify_fd < 0) {
		outputerr("self-cgroup: inotify_init1 failed: %s; "
			  "memory.events watcher disabled\n",
			  strerror(errno));
		return;
	}

	if (inotify_add_watch(events_inotify_fd, path, IN_MODIFY) < 0) {
		outputerr("self-cgroup: inotify_add_watch(%s) failed: %s; "
			  "memory.events watcher disabled\n",
			  path, strerror(errno));
		close(events_inotify_fd);
		events_inotify_fd = -1;
		return;
	}

	events_file_fd = open(path, O_RDONLY | O_CLOEXEC);
	if (events_file_fd < 0) {
		outputerr("self-cgroup: open(%s) failed: %s; "
			  "memory.events watcher disabled\n",
			  path, strerror(errno));
		close(events_inotify_fd);
		events_inotify_fd = -1;
		return;
	}

	/* Seed the prior-snapshot so a fresh cgroup with non-zero
	 * counters from a previous tenant (shouldn't happen for a
	 * trinity-<pid> dir we just mkdir'd, but be defensive) doesn't
	 * trigger a phantom event on the first tick. */
	read_event_counts(&last_high_count, &last_max_count);

	output(0, "self-cgroup: memory.events watcher armed on %s\n", path);
}

static void events_cleanup(void)
{
	if (events_file_fd >= 0) {
		close(events_file_fd);
		events_file_fd = -1;
	}
	if (events_inotify_fd >= 0) {
		close(events_inotify_fd);
		events_inotify_fd = -1;
	}
}

void self_cgroup_events_check(void)
{
	char drain[4096];
	ssize_t r;
	bool any_event = false;
	unsigned long high, max;

	if (events_inotify_fd < 0)
		return;

	/* Drain the inotify queue.  We don't care which event fired
	 * (memory.events only carries IN_MODIFY for us) — only that
	 * something fired.  EAGAIN on the trailing call is the normal
	 * empty-queue signal under O_NONBLOCK. */
	while ((r = read(events_inotify_fd, drain, sizeof(drain))) > 0)
		any_event = true;

	if (!any_event) {
		if (fork_throttle_us > 0 &&
		    ++quiet_streak >= THROTTLE_DECAY_TICKS) {
			output(0, "self-cgroup: HIGH cleared -- fork throttle off\n");
			fork_throttle_us = 0;
			quiet_streak = 0;
		}
		return;
	}

	quiet_streak = 0;

	if (!read_event_counts(&high, &max))
		return;

	if (high > last_high_count) {
		unsigned int next;

		last_high_count = high;
		high_event_seq++;
		if (fork_throttle_us == 0)
			next = THROTTLE_MIN_US;
		else if (fork_throttle_us >= THROTTLE_MAX_US / 2)
			next = THROTTLE_MAX_US;
		else
			next = fork_throttle_us * 2;
		fork_throttle_us = next;
		output(0, "self-cgroup: HIGH event #%u -- fork throttle now %uus\n",
		       high_event_seq, fork_throttle_us);
	}

	/*
	 * memory.events:max means the kernel has already OOM-killed in the
	 * children/ cgroup.  With memory.oom.group=1 the kill takes the
	 * whole worker pool atomically and the parent (which lives in the
	 * sibling parent/ cgroup with no memory.max) survives untouched —
	 * the existing reap loop in main_loop sees all the SIGCHLDs and
	 * re-spawns the pool from scratch.  No userspace shed required.
	 * The HIGH-event-driven fork throttle above gives back-pressure
	 * before max events fire in the first place.
	 */
	if (max > last_max_count) {
		unsigned long delta = max - last_max_count;

		last_max_count = max;
		max_event_seq++;
		output(0, "self-cgroup: MAX event #%u (delta=%lu) -- "
		       "kernel %s; parent re-spawns worker pool\n",
		       max_event_seq, delta,
		       cg_split_mode ? "group-killed children cgroup atomically"
				     : "OOM-killed in single-cgroup mode");
	}
}
