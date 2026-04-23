/*
 * cgroup_churn - rapid mkdir/rmdir of short-lived cgroups under
 * /sys/fs/cgroup/ to exercise the kernel cgroup lifecycle paths.
 *
 * Trinity's normal random_syscall path can issue mkdir(2)/rmdir(2)
 * against arbitrary paths, but the chance that any given path lands
 * under /sys/fs/cgroup/ — let alone names a fresh, never-seen cgroup
 * directory — is vanishingly small.  cgroup_churn closes that gap by
 * driving the cgroup-v2 mkdir/rmdir hot path directly: cgroup_mkdir()
 * (css allocation, css_set linking, kernfs node creation), cgroup_rmdir()
 * (css offline/release, kernfs node removal), and the surrounding
 * css_set rcu/refcount machinery.
 *
 * Per invocation: 1..MAX_CYCLES mkdir/rmdir cycles.  Names are unique
 * per (pid, counter) so concurrent children don't collide on each other's
 * directories — the kernel sees a steady stream of distinct fresh
 * cgroups being created and torn down rather than EEXIST-rejected
 * duplicates.
 *
 * Self-bounding: the inner loop is hard-capped at MAX_CYCLES, every
 * mkdir is matched by an immediate rmdir attempt (or a graceful skip
 * if mkdir failed), and the alarm(1) the parent arms before dispatch
 * bounds wall-clock time even if a syscall blocks.  Best-effort cleanup
 * on bail-out: if mkdir succeeded but a later step bails, the next
 * invocation uses a different name so we don't leak directories with
 * the same path.
 *
 * Many systems run trinity unprivileged or with cgroup-v1 only; in
 * those cases mkdir under /sys/fs/cgroup/ returns EACCES, EROFS, or
 * ENOENT.  We bail gracefully on the first failure and let the parent
 * pick a different op next time — there's no value in spinning on a
 * permission denial.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "child.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"

/* Hard cap on mkdir/rmdir cycles per invocation.  Kept modest so a
 * single op completes well inside the alarm(1) window even when the
 * cgroup subsystem is under contention from sibling churners. */
#define MAX_CYCLES	16

/* Per-process monotonic counter so each cgroup name within a child
 * is distinct.  Doesn't need to be atomic — only this child uses it. */
static unsigned long cgroup_churn_seq;

bool cgroup_churn(struct childdata *child)
{
	unsigned int cycles;
	unsigned int i;
	pid_t pid = getpid();

	(void)child;

	__atomic_add_fetch(&shm->stats.cgroup_churn_runs, 1, __ATOMIC_RELAXED);

	cycles = 1 + (rand() % MAX_CYCLES);

	for (i = 0; i < cycles; i++) {
		char path[64];
		unsigned long seq = ++cgroup_churn_seq;

		snprintf(path, sizeof(path),
			 "/sys/fs/cgroup/trinity-%d-%lu", (int)pid, seq);

		if (mkdir(path, 0755) != 0) {
			__atomic_add_fetch(&shm->stats.cgroup_failed,
					   1, __ATOMIC_RELAXED);
			/* EACCES: unprivileged.  EROFS: cgroup v1 root mounted
			 * read-only at /sys/fs/cgroup.  ENOENT: no cgroupfs at
			 * all.  EEXIST: extremely unlikely with pid+seq names,
			 * but harmless — fall through to the next iteration.
			 * Anything else (ENOMEM, EBUSY, ...) — bail; spinning
			 * won't help. */
			if (errno == EACCES || errno == EROFS ||
			    errno == ENOENT || errno == EPERM)
				return true;
			continue;
		}

		__atomic_add_fetch(&shm->stats.cgroup_mkdirs,
				   1, __ATOMIC_RELAXED);

		if (rmdir(path) == 0) {
			__atomic_add_fetch(&shm->stats.cgroup_rmdirs,
					   1, __ATOMIC_RELAXED);
		} else {
			__atomic_add_fetch(&shm->stats.cgroup_failed,
					   1, __ATOMIC_RELAXED);
			/* EBUSY here means a task entered the cgroup between
			 * mkdir and rmdir (some other churner, or the kernel's
			 * own bookkeeping).  Leave the directory; the next
			 * invocation uses a new name so we don't compound. */
		}
	}

	return true;
}
