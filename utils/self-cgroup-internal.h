#pragma once

/*
 * Private API shared between the utils/self_cgroup_*.c sibling files.
 * Not for use outside utils/self_cgroup*.  Public API lives in
 * include/self_cgroup.h.
 */

#include <stdbool.h>
#include <stdint.h>

/*
 * Shared mutable state.  Defined in utils/self_cgroup.c (which owns
 * setup/cleanup); sibling TUs read/write these through the extern
 * declarations below.
 */
extern char *cg_workload;	/* children/ (split mode) or trinity-<pid>/ */
extern int cg_workload_fd;	/* O_DIRECTORY on cg_workload; -1 if unset */
extern bool cg_split_mode;	/* true iff parent/children sub-cgroups are live */

/*
 * memory.events watcher.  events_setup() is a no-op if cg_workload is
 * unset; events_cleanup() is a no-op if the watcher never armed.  Both
 * are called from self_cgroup_setup / _cleanup respectively.
 */
void events_setup(void);
void events_cleanup(void);

/*
 * Read MemTotal from /proc/meminfo and return it as bytes.  Returns 0
 * on read failure -- callers treat that as "cannot determine host
 * memory" and abort setup.
 */
uint64_t mem_total_bytes(void);

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
bool parse_size_arg(const char *arg, uint64_t mem_total,
		    char **out_str, uint64_t *out_bytes,
		    bool *out_is_max);

/*
 * Read the cgroup v2 path of the calling process from /proc/self/cgroup.
 * The v2 line is the only one prefixed with "0::".  Returns a malloc'd
 * NUL-terminated path (e.g. "/user.slice/user-1000.slice/session-3.scope")
 * with the trailing newline stripped, or NULL if the file is unreadable
 * or no v2 line is present (e.g. pure cgroup v1 systems).
 */
char *read_self_cg_path(void);

/*
 * Write value into <cg_path>/<name>.  Returns true on full write, false
 * on any error (short write, open failure, path overflow); errno is
 * preserved across close() so callers can strerror(errno) the real
 * cgroup-write failure cause.
 */
bool write_cg_file(const char *cg_path, const char *name, const char *value);

/*
 * Detect a wrapper scope: if our current cgroup already has a non-"max"
 * memory.max, an outer agent (systemd-run, kubelet, the run-trinity.sh
 * stopgap) has already capped us.  Defer to it: nesting our own
 * sub-cgroup inside would just confuse exit accounting and leak rmdir
 * permission errors when the wrapper tears its scope down before us.
 */
bool already_capped(const char *parent_cg_path);

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
uint64_t compute_parent_high(uint64_t total_max_bytes, bool total_is_max);

/*
 * Try to enable the memory controller in the container's subtree so the
 * parent/ and children/ sub-cgroups can carry memory.* knobs.  Returns
 * true on success.  Failure (EOPNOTSUPP, EINVAL, EACCES) is the signal to
 * fall back to single-cgroup mode.
 */
bool enable_memory_subtree(const char *container_path);

/*
 * Decide whether the current scope is ours to carve a memory subtree out
 * of.  True only when the memory controller is available here, the
 * scope's subtree_control is writable, and the scope holds no process
 * other than trinity-main -- i.e. it is trinity's own systemd-run scope,
 * not a shared cgroup whose siblings we must not disturb.  Checked at
 * setup time, before fork_children(), so trinity-main is the only trinity
 * process that can be present.
 */
bool scope_can_delegate(const char *scope_path);
