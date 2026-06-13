#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
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
#include <sys/wait.h>
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
 * and a generous memory.high so its bandit bookkeeping is never the OOM
 * target.
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

static uint64_t mem_total_bytes(void)
{
	FILE *f;
	char line[256];
	uint64_t kb = 0;

	f = fopen("/proc/meminfo", "re");
	if (f == NULL)
		return 0;
	while (fgets(line, sizeof(line), f) != NULL) {
		if (sscanf(line, "MemTotal: %" SCNu64 " kB", &kb) == 1)
			break;
	}
	fclose(f);
	return kb * UINT64_C(1024);
}

/*
 * Parse a size argument and produce a byte-count (out_bytes) plus the
 * canonical string we write into the cgroup file (out_str).  Accepted forms:
 *   "max"          → out_str="max", *out_is_max=true, out_bytes=0 (unused)
 *   "<n>%"         → percentage of MemTotal (1..100)
 *   "<n>[KMG]"     → bytes, with optional K/M/G binary suffix (1024)
 *
 * out_is_max is the explicit "uncapped" flag: callers that need to branch
 * on the "max" sentinel test it directly instead of comparing out_bytes
 * against an in-band magic value.  out_is_max may be NULL when the caller
 * has no interest in the distinction.
 *
 * On success returns true; *out_str is malloc'd, caller frees.
 * On failure returns false and outputs are untouched.
 */
static bool parse_size_arg(const char *arg, uint64_t mem_total,
			   char **out_str, uint64_t *out_bytes,
			   bool *out_is_max)
{
	char *end;
	uint64_t val;
	uint64_t mult = 1;

	if (arg == NULL || *arg == '\0')
		return false;

	if (strcmp(arg, "max") == 0) {
		*out_str = strdup("max");
		if (*out_str == NULL)
			return false;
		*out_bytes = 0;
		if (out_is_max != NULL)
			*out_is_max = true;
		return true;
	}

	/*
	 * strtoull() silently accepts a leading '-' and wraps the result
	 * into ULLONG_MAX-adjacent values that look like enormous byte
	 * counts; '+' is equally surprising in a size context.  Reject
	 * both signs up front, matching parse_unsigned()'s contract in
	 * params.c.
	 */
	if (*arg == '-' || *arg == '+')
		return false;

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
		val = mem_total * val / 100;
	} else if (*end != '\0') {
		if (end[1] != '\0')
			return false;
		switch (*end) {
		case 'k': case 'K': mult = UINT64_C(1024); break;
		case 'm': case 'M': mult = UINT64_C(1024) * 1024; break;
		case 'g': case 'G': mult = UINT64_C(1024) * 1024 * 1024; break;
		default: return false;
		}
		if (val > UINT64_MAX / mult)
			return false;
		val *= mult;
	}

	if (asprintf(out_str, "%" PRIu64, val) < 0)
		return false;
	*out_bytes = val;
	if (out_is_max != NULL)
		*out_is_max = false;
	return true;
}

/*
 * Parse-time validation hook for --memory-max / --memory-high /
 * --memory-swap-max.  parse_args() calls this immediately after
 * strdup'ing the optarg so --dry-run rejects malformed inputs the
 * same way a live run would.  self_cgroup_setup() retains its own
 * parse_size_arg() call as defense-in-depth -- a future code path
 * that mutates the *_arg globals after parse_args() (env override,
 * config file, etc.) still gets caught before being written to
 * memory.max.
 *
 * mem_total=1 is sufficient for a syntactic pass: percentage range
 * (1..100) is enforced before the multiply, and the absolute /
 * suffix branches don't read mem_total.  The canonicalised string
 * is discarded.
 */
bool validate_cgroup_size_arg(const char *flag_name, const char *arg)
{
	char *out_str = NULL;
	uint64_t out_bytes = 0;

	if (parse_size_arg(arg, 1, &out_str, &out_bytes, NULL)) {
		free(out_str);
		return true;
	}

	outputerr("%s: invalid memory-size '%s' "
		  "(accepted: 'max', '<n>%%' with 1..100, '<n>[KMG]')\n",
		  flag_name, arg ? arg : "(null)");
	return false;
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
	int saved_errno;

	if ((size_t)snprintf(path, sizeof(path), "%s/%s", cg_path, name) >= sizeof(path))
		return false;
	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return false;
	len = strlen(value);
	n = write(fd, value, len);
	if (n == (ssize_t)len) {
		close(fd);
		return true;
	}
	/* Preserve write()'s errno across close() so callers' strerror(errno)
	 * reports the real cgroup-write failure cause, not a stray close
	 * errno. */
	if (n >= 0)
		errno = EIO;
	saved_errno = errno;
	close(fd);
	errno = saved_errno;
	return false;
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
 * per-iter (waitpid/reap/fork loop, periodic_work bookkeeping), so a small
 * soft limit is plenty.
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
static uint64_t compute_parent_high(uint64_t total_max_bytes, bool total_is_max)
{
	const uint64_t PARENT_HIGH_CAP = UINT64_C(200) * 1024 * 1024;

	if (total_is_max)
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
 * Decide whether the current scope is ours to carve a memory subtree out
 * of.  True only when the memory controller is available here, the
 * scope's subtree_control is writable, and the scope holds no process
 * other than trinity-main -- i.e. it is trinity's own systemd-run scope,
 * not a shared cgroup whose siblings we must not disturb.  Checked at
 * setup time, before fork_children(), so trinity-main is the only trinity
 * process that can be present.
 */
static bool scope_can_delegate(const char *scope_path)
{
	char path[PATH_MAX];
	char buf[256];
	FILE *f;
	bool has_memory = false;
	bool solo = true;
	pid_t me = mypid();

	if ((size_t)snprintf(path, sizeof(path), "%s/cgroup.controllers",
			     scope_path) >= sizeof(path))
		return false;
	f = fopen(path, "re");
	if (f == NULL)
		return false;
	while (fgets(buf, sizeof(buf), f) != NULL) {
		if (strstr(buf, "memory") != NULL) {
			has_memory = true;
			break;
		}
	}
	fclose(f);
	if (!has_memory)
		return false;

	if ((size_t)snprintf(path, sizeof(path), "%s/cgroup.subtree_control",
			     scope_path) >= sizeof(path))
		return false;
	if (access(path, W_OK) != 0)
		return false;

	if ((size_t)snprintf(path, sizeof(path), "%s/cgroup.procs",
			     scope_path) >= sizeof(path))
		return false;
	f = fopen(path, "re");
	if (f == NULL)
		return false;
	while (fgets(buf, sizeof(buf), f) != NULL) {
		pid_t p = (pid_t)strtol(buf, NULL, 10);

		if (p != 0 && p != me) {
			solo = false;
			break;
		}
	}
	fclose(f);
	return solo;
}

/*
 * Build the parent/children memory split for trinity's own solo scope.
 * cgroup v2 needs the memory controller delegated down to container/
 * before its sub-cgroups can carry memory.* knobs, and a controller can
 * only be enabled in a cgroup's subtree_control while that cgroup has no
 * member processes.  So: create the leaves, vacate the scope by moving
 * trinity-main into container/parent, enable +memory on the scope then on
 * container/, and only then write the knobs.  Returns false (caller falls
 * back) when scope_can_delegate() says no or any step fails; trinity-main
 * may be left in container/parent, still bounded by the scope's outer
 * memory.max and reaped with the scope on exit.
 */
static bool setup_split(const char *container_path,
			const char *scope_path,
			const char *children_max_str,
			const char *children_high_str,
			const char *children_swap_str,
			uint64_t children_max_bytes,
			bool children_max_is_max)
{
	char *parent_path = NULL;
	char *children_path = NULL;
	char parent_high_str[32];
	char pidbuf[32];
	int n;
	int wfd = -1;
	uint64_t parent_high;
	bool main_in_parent = false;
	bool scope_memory = false;
	bool container_memory = false;

	/* Only carve a subtree out of a scope that is ours alone (solo,
	 * writable, memory available) -- trinity's own systemd-run scope.
	 * On a shared cgroup we must not touch the scope's subtree_control. */
	if (!scope_can_delegate(scope_path))
		return false;

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

	/* Vacate the scope: move trinity-main into parent/ before enabling
	 * controllers up the chain.  v2 forbids enabling a controller in a
	 * cgroup's subtree_control while it holds member processes, and
	 * trinity-main starts out directly in the scope. */
	n = snprintf(pidbuf, sizeof(pidbuf), "%d\n", (int)mypid());
	if (n < 0 || (size_t)n >= sizeof(pidbuf) ||
	    !write_cg_file(parent_path, "cgroup.procs", pidbuf)) {
		outputerr("self-cgroup: move trinity-main into parent/ failed: %s\n",
			  strerror(errno));
		goto fail_rmdir;
	}
	main_in_parent = true;

	/* Delegate +memory down the chain now the scope is process-free:
	 * scope -> container -> {parent, children}. */
	if (!write_cg_file(scope_path, "cgroup.subtree_control", "+memory")) {
		outputerr("self-cgroup: enable +memory on scope subtree_control failed: %s\n",
			  strerror(errno));
		goto fail_unwind;
	}
	scope_memory = true;
	if (!enable_memory_subtree(container_path)) {
		outputerr("self-cgroup: enable +memory in container subtree_control failed: %s\n",
			  strerror(errno));
		goto fail_unwind;
	}
	container_memory = true;

	/* Children: hard cap + swap cap + back-pressure threshold + group-OOM. */
	if (!write_cg_file(children_path, "memory.max", children_max_str)) {
		outputerr("self-cgroup: write children/memory.max=%s failed: %s\n",
			  children_max_str, strerror(errno));
		goto fail_unwind;
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
	parent_high = compute_parent_high(children_max_bytes,
					  children_max_is_max);
	n = snprintf(parent_high_str, sizeof(parent_high_str), "%" PRIu64,
		     parent_high);
	if (n < 0 || (size_t)n >= sizeof(parent_high_str))
		goto fail_unwind;
	if (!write_cg_file(parent_path, "memory.high", parent_high_str))
		output(1, "self-cgroup: write parent/memory.high=%s failed: %s\n",
		       parent_high_str, strerror(errno));
	if (!write_cg_file(parent_path, "memory.oom.group", "0"))
		output(1, "self-cgroup: write parent/memory.oom.group=0 failed: %s\n",
		       strerror(errno));

	/* Open children/ as O_DIRECTORY so spawn_child() can hand the fd to
	 * clone3(CLONE_INTO_CGROUP).  O_PATH would also work but O_DIRECTORY
	 * is what the man page documents for this ABI. */
	wfd = open(children_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (wfd < 0) {
		outputerr("self-cgroup: open(%s) failed: %s\n",
			  children_path, strerror(errno));
		goto fail_unwind;
	}

	cg_parent = parent_path;
	cg_workload = children_path;
	cg_workload_fd = wfd;
	cg_split_mode = true;

	output(0, "self-cgroup: split mode active "
	       "(parent/memory.high=%s, children/memory.max=%s memory.high=%s memory.swap.max=%s memory.oom.group=1)\n",
	       parent_high_str, children_max_str, children_high_str, children_swap_str);
	return true;

fail_unwind:
	/* Reverse the state setup_split installed so the single-cgroup
	 * fallback sees a clean topology -- otherwise rmdir below trips on
	 * the still-populated parent/ and the fallback inherits dangling
	 * +memory delegation it can't write through.  cgroup v2 dictates a
	 * strict order: a cgroup distributing controllers can't hold procs,
	 * and a cgroup can't drop a controller from subtree_control while a
	 * child still distributes it.  So:
	 *   1. -memory in container (lets scope drop +memory next),
	 *   2. -memory in scope    (lets scope hold trinity-main again),
	 *   3. move trinity-main back to scope (its original cgroup),
	 *   4. rmdir children/ + parent/ -- both empty now.
	 * Each step is best-effort: on the failure path partial unwind beats
	 * abort, and write_cg_file() failures here have nowhere useful to go. */
	if (container_memory)
		(void)write_cg_file(container_path,
				    "cgroup.subtree_control", "-memory");
	if (scope_memory)
		(void)write_cg_file(scope_path,
				    "cgroup.subtree_control", "-memory");
	if (main_in_parent) {
		n = snprintf(pidbuf, sizeof(pidbuf), "%d\n", (int)mypid());
		if (n > 0 && (size_t)n < sizeof(pidbuf))
			(void)write_cg_file(scope_path,
					    "cgroup.procs", pidbuf);
	}
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
			 const char *scope_path,
			 const char *max_str,
			 const char *high_str,
			 const char *swap_str)
{
	char pidbuf[32];
	int n;

	n = snprintf(pidbuf, sizeof(pidbuf), "%d\n", (int)mypid());
	if (n < 0 || (size_t)n >= sizeof(pidbuf))
		return false;

	/* scope_path != NULL signals "scope is ours to delegate" -- the
	 * caller checked scope_can_delegate().  A setup_split() failure
	 * will have unwound scope's +memory delegation, leaving container
	 * without memory.max; re-enable it here.  v2 won't let us write
	 * +memory to a scope holding procs, so vacate scope first by
	 * moving trinity-main into container (container distributes no
	 * controllers and can hold procs freely). */
	if (scope_path != NULL) {
		if (!write_cg_file(container_path, "cgroup.procs", pidbuf)) {
			outputerr("self-cgroup: cgroup.procs write failed: %s\n",
				  strerror(errno));
			return false;
		}
		if (!write_cg_file(scope_path, "cgroup.subtree_control",
				   "+memory")) {
			outputerr("self-cgroup: re-enable +memory on scope subtree_control failed: %s\n",
				  strerror(errno));
			return false;
		}
	}

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

	/* Shared-scope path: scope_path == NULL means we never touched
	 * scope, so trinity-main is still in it; move it now.  In the
	 * scope_path != NULL path the move happened above and this branch
	 * is skipped. */
	if (scope_path == NULL &&
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
	char *scope_path = NULL;
	bool wrapper_capped = false;
	uint64_t memtotal;
	char *max_str = NULL;
	char *high_str = NULL;
	char *swap_str = NULL;
	uint64_t max_bytes = 0;
	uint64_t high_bytes = 0;
	uint64_t swap_bytes = 0;
	bool max_is_max = false;

	if (no_cgroup)
		return;

	parent_cg = read_self_cg_path();
	if (parent_cg == NULL) {
		outputerr("self-cgroup: /proc/self/cgroup has no v2 entry; "
			  "running without memory cap\n");
		goto out;
	}

	/* A wrapper (run-trinity.sh's systemd-run, kubelet, ...) may have
	 * already set memory.max on our scope.  That stays as the outer
	 * safety net; rather than deferring outright we try to nest our
	 * parent/children OOM split underneath it (so the parent survives a
	 * children-only OOM).  Remember it so a split that can't be set up
	 * falls back to leaving the wrapper cap in place. */
	wrapper_capped = already_capped(parent_cg);

	memtotal = mem_total_bytes();
	if (memtotal == 0) {
		outputerr("self-cgroup: cannot read MemTotal; "
			  "running without memory cap\n");
		goto out;
	}

	if (!parse_size_arg(memory_max_arg ? memory_max_arg : "60%",
			    memtotal, &max_str, &max_bytes, &max_is_max)) {
		outputerr("self-cgroup: invalid --memory-max '%s'; "
			  "running without memory cap\n",
			  memory_max_arg ? memory_max_arg : "60%");
		goto out;
	}
	if (!parse_size_arg(memory_high_arg ? memory_high_arg : "50%",
			    memtotal, &high_str, &high_bytes, NULL)) {
		outputerr("self-cgroup: invalid --memory-high '%s'; "
			  "running without memory cap\n",
			  memory_high_arg ? memory_high_arg : "50%");
		goto out;
	}
	if (!parse_size_arg(memory_swap_max_arg ? memory_swap_max_arg : "20%",
			    memtotal, &swap_str, &swap_bytes, NULL)) {
		outputerr("self-cgroup: invalid --memory-swap-max '%s'; "
			  "running without memory cap\n",
			  memory_swap_max_arg ? memory_swap_max_arg : "20%");
		goto out;
	}
	(void)high_bytes;
	(void)swap_bytes;

	if (asprintf(&scope_path, "/sys/fs/cgroup%s", parent_cg) < 0) {
		scope_path = NULL;
		outputerr("self-cgroup: asprintf failed; "
			  "running without memory cap\n");
		goto out;
	}

	if (asprintf(&cg_container, "%s/trinity-%d",
		     scope_path, (int)mypid()) < 0) {
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
	if (setup_split(cg_container, scope_path, max_str, high_str, swap_str,
			max_bytes, max_is_max)) {
		/* Split mode established; cg_parent/cg_workload populated.  Hand
		 * scope_path to cg_original (in split mode cleanup defers
		 * teardown to systemd, but the field still records the scope we
		 * joined from). */
		cg_original = scope_path;
		scope_path = NULL;
	} else if (wrapper_capped) {
		output(1, "self-cgroup: parent/children split unavailable; "
		       "deferring to the existing wrapper cap on %s\n", parent_cg);
		rmdir(cg_container);
		free(cg_container);
		cg_container = NULL;
		goto out;
	} else {
		const char *scope_for_single = NULL;

		output(1, "self-cgroup: parent/children split unavailable; "
		       "falling back to single-cgroup mode\n");
		/* Hand scope_path to setup_single() only when the scope is
		 * ours alone -- then it can re-enable +memory delegation if
		 * setup_split()'s unwind dropped it.  In a shared scope we
		 * must not touch scope's subtree_control. */
		if (scope_can_delegate(scope_path))
			scope_for_single = scope_path;
		if (!setup_single(cg_container, scope_for_single,
				  max_str, high_str, swap_str)) {
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
	free(scope_path);
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
	 * Split (dance) mode only runs in trinity's own solo systemd-run
	 * scope, where we delegated +memory onto the scope itself.  v2
	 * forbids moving trinity-main back into a scope that now distributes
	 * a controller, and unwinding the nested delegation by hand is
	 * fragile -- systemd reaps the whole scope (and our sub-cgroups with
	 * it) when trinity exits, so leave teardown to it.
	 */
	if (cg_split_mode) {
		free(cg_workload);  cg_workload = NULL;
		free(cg_parent);    cg_parent = NULL;
		free(cg_container); cg_container = NULL;
		free(cg_original);  cg_original = NULL;
		cg_split_mode = false;
		return;
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
		int n = snprintf(buf, sizeof(buf), "%d\n", (int)mypid());

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
		if (errno != ENOSYS && errno != EINVAL)
			return -1;
		clone3_unavailable = true;
		output(0, "self-cgroup: clone3 %s; "
		       "falling back to fork()+post-migrate\n",
		       errno == ENOSYS ? "ENOSYS" : "EINVAL");
	}

	pid = fork();
	if (pid > 0) {
		char buf[32];
		int n = snprintf(buf, sizeof(buf), "%d\n", (int)pid);
		int fd = -1;
		bool migrated = false;

		if (n > 0 && (size_t)n < sizeof(buf)) {
			fd = openat(cg_workload_fd, "cgroup.procs",
				    O_WRONLY | O_CLOEXEC);
			if (fd >= 0) {
				ssize_t wn = write(fd, buf, (size_t)n);

				if (wn == n)
					migrated = true;
				else {
					if (wn >= 0)
						errno = EIO;
					output(0, "self-cgroup: post-fork migrate of pid %d failed: %s\n",
					       (int)pid, strerror(errno));
				}
				close(fd);
			} else {
				output(0, "self-cgroup: openat(cgroup.procs) failed for pid %d: %s\n",
				       (int)pid, strerror(errno));
			}
		} else {
			output(0, "self-cgroup: snprintf failed encoding pid %d\n", (int)pid);
		}

		if (!migrated) {
			/* Kill the child we just forked so it doesn't run outside the
			 * worker memory cap; the caller's spawn-retry path handles the
			 * -1 return. */
			kill(pid, SIGKILL);
			(void)waitpid(pid, NULL, 0);
			return -1;
		}
	}
	return pid;
}

/*
 * Phase 2: memory.events back-pressure.
 *
 * The Phase 1 cap is reactive: when memory.max is hit the kernel evicts
 * trinity processes, dropping bandit convergence state every cycle.
 * Phase 2 listens to the kernel's memory.events file (rewritten each
 * time low/high/max/oom counters bump) and applies back-pressure
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

#define THROTTLE_MIN_US		1000U		/* 1 ms initial step */
#define THROTTLE_MAX_US		1000000U	/* 1 s cap under sustained pressure */
#define THROTTLE_DECAY_TICKS	40U		/* ~1s of quiet at 25ms cadence */

/*
 * The cap and the decay schedule together set how aggressively we back
 * off respawn under memory.high reclaim-throttle pressure.
 *
 *   Cap (THROTTLE_MAX_US = 1 s):
 *     A small cap (e.g. 100 ms) lets per-spawn sleep slow the fork rate
 *     but not enough to keep up with the kernel's reclaim throttle once
 *     children/ memory is sitting at the soft limit.  Each fresh child
 *     immediately hits the same reclaim slowdown in its post-syscall
 *     userspace path, the parent watchdog times it out, kills, respawns
 *     -- positive feedback into a death spiral.  Capping at 1 s gives
 *     the parent room to genuinely pause spawning so the cgroup's
 *     reclaim drains before the next worker lands on it.
 *
 *   Decay (halving per quiet window, not snap-to-zero):
 *     A binary "any quiet window resets the throttle to 0" decay
 *     re-ignites the spiral: pressure subsides briefly, throttle snaps
 *     off, spawn rate slams back to full, pressure returns immediately.
 *     Halving lets the throttle decay over several windows so a transient
 *     dip in memory.high firings doesn't undo the prior backoff.
 */

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

void self_cgroup_drop_fds_in_child(void)
{
	if (events_file_fd >= 0) {
		close(events_file_fd);
		events_file_fd = -1;
	}
	if (events_inotify_fd >= 0) {
		close(events_inotify_fd);
		events_inotify_fd = -1;
	}
	/* The workload-cgroup dirfd is parent-only: the parent uses it for
	 * clone3(CLONE_INTO_CGROUP) (and openat-on-cgroup.procs in the
	 * post-migrate fallback) before the child reaches this hook, and
	 * nothing in the child path needs it.  Leaving it inherited lets a
	 * fuzzed dup2 redirect future spawns into the wrong cgroup
	 * (escaping memory.max + oom.group containment) or a fuzzed close
	 * turn the next spawn into EBADF. */
	if (cg_workload_fd >= 0) {
		close(cg_workload_fd);
		cg_workload_fd = -1;
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

	/* Re-assert O_NONBLOCK before the drain.  A fuzzed
	 * fcntl(fd, F_SETFL, ...) in a pre-fd-drop child (or any other
	 * path that touches the shared OFD) can clear O_NONBLOCK on the
	 * description we set at inotify_init1(IN_NONBLOCK) time.  Without
	 * this re-assert the read() below blocks forever on an empty queue
	 * and the main loop wedges. */
	{
		int fl = fcntl(events_inotify_fd, F_GETFL);

		if (fl >= 0 && !(fl & O_NONBLOCK))
			(void) fcntl(events_inotify_fd, F_SETFL,
				     fl | O_NONBLOCK);
	}

	/* Drain the inotify queue.  We don't care which event fired
	 * (memory.events only carries IN_MODIFY for us) — only that
	 * something fired.  EAGAIN on the trailing call is the normal
	 * empty-queue signal under O_NONBLOCK. */
	while ((r = read(events_inotify_fd, drain, sizeof(drain))) > 0)
		any_event = true;

	if (!any_event) {
		if (fork_throttle_us > 0 &&
		    ++quiet_streak >= THROTTLE_DECAY_TICKS) {
			unsigned int halved = fork_throttle_us / 2;

			if (halved < THROTTLE_MIN_US)
				halved = 0;
			if (halved == 0)
				output(0, "self-cgroup: HIGH cleared -- fork throttle off\n");
			else
				output(0, "self-cgroup: HIGH quiet -- fork throttle halved to %uus\n",
				       halved);
			fork_throttle_us = halved;
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
