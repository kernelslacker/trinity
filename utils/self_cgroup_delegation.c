#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "pids.h"
#include "self_cgroup.h"

#include "self-cgroup-internal.h"

/*
 * Detect a wrapper scope: if our current cgroup already has a non-"max"
 * memory.max, an outer agent (systemd-run, kubelet, the run-trinity.sh
 * stopgap) has already capped us.  Defer to it: nesting our own
 * sub-cgroup inside would just confuse exit accounting and leak rmdir
 * permission errors when the wrapper tears its scope down before us.
 */
bool already_capped(const char *parent_cg_path)
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
uint64_t compute_parent_high(uint64_t total_max_bytes, bool total_is_max)
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
bool enable_memory_subtree(const char *container_path)
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
bool scope_can_delegate(const char *scope_path)
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
