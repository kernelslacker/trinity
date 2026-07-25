#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#include <linux/sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "child-api.h"
#include "params.h"
#include "pids.h"
#include "self_cgroup.h"
#include "trinity.h"
#include "utils.h"

#include "self-cgroup-internal.h"

#include "kernel/fcntl.h"
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
char *cg_workload;		/* trinity-<pid>/children/ in split mode,
				 * or the single trinity-<pid>/ in fallback */
static char *cg_original;	/* full /sys/fs/cgroup<parent> path we joined
				 * from at startup; cleanup moves trinity-main
				 * back here so the parent rmdir succeeds.
				 * Populated only in split mode. */
int cg_workload_fd = -1;	/* O_DIRECTORY on cg_workload */
bool cg_split_mode;		/* true if parent/children sub-cgroups are live */

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
	char *origin_cg = NULL;
	char *origin_path = NULL;
	bool main_moved = false;
	bool ok = false;

	n = snprintf(pidbuf, sizeof(pidbuf), "%d\n", (int)mypid());
	if (n < 0 || (size_t)n >= sizeof(pidbuf))
		return false;

	/* Record the workload path BEFORE any cgroup mutation: a post-move
	 * strdup-NULL would otherwise return false with trinity-main already
	 * in the capped container and cg_workload still unset, leaving the
	 * caller's rmdir EBUSY and main stranded in an untracked cgroup. */
	cg_workload = strdup(container_path);
	if (cg_workload == NULL) {
		outputerr("self-cgroup: strdup(container_path) failed\n");
		return false;
	}

	/* Capture where main lives BEFORE the move so a post-move failure
	 * (memory.max, subtree_control, ...) can unwind by moving main back.
	 * Re-read /proc/self/cgroup here rather than trusting an earlier
	 * snapshot: a setup_split() failed-unwind may have left main in
	 * container/parent rather than the scope. */
	origin_cg = read_self_cg_path();
	if (origin_cg == NULL) {
		outputerr("self-cgroup: cannot read /proc/self/cgroup; "
			  "aborting before move\n");
		goto fail;
	}
	if (asprintf(&origin_path, "/sys/fs/cgroup%s", origin_cg) < 0) {
		origin_path = NULL;
		outputerr("self-cgroup: asprintf(origin_path) failed; "
			  "aborting before move\n");
		goto fail;
	}

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
			goto fail;
		}
		main_moved = true;
		if (!write_cg_file(scope_path, "cgroup.subtree_control",
				   "+memory")) {
			outputerr("self-cgroup: re-enable +memory on scope subtree_control failed: %s\n",
				  strerror(errno));
			goto fail;
		}
	}

	if (!write_cg_file(container_path, "memory.max", max_str)) {
		outputerr("self-cgroup: write memory.max=%s failed: %s\n",
			  max_str, strerror(errno));
		goto fail;
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
	if (scope_path == NULL) {
		if (!write_cg_file(container_path, "cgroup.procs", pidbuf)) {
			outputerr("self-cgroup: cgroup.procs write failed: %s\n",
				  strerror(errno));
			goto fail;
		}
		main_moved = true;
	}

	output(0, "self-cgroup: single-cgroup fallback "
	       "(memory.max=%s memory.high=%s memory.swap.max=%s) -- no OOM scope split\n",
	       max_str, high_str, swap_str);
	ok = true;

fail:
	if (!ok) {
		/* On any post-move failure, move main back to origin so the
		 * caller's rmdir(container) succeeds and main isn't stranded
		 * in a capped, untracked cgroup.  Best-effort: if the write
		 * fails there is nowhere useful to go. */
		if (main_moved)
			(void)write_cg_file(origin_path, "cgroup.procs", pidbuf);
		free(cg_workload);
		cg_workload = NULL;
	}
	free(origin_cg);
	free(origin_path);
	return ok;
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

