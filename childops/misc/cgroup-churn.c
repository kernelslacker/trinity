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
 *
 * PSI race sub-mode (gated ONE_IN(PSI_RACE_GATE) per successful mkdir):
 * open a small pool of fds against one *.pressure file in the freshly-
 * created leaf cgroup, fan out per-fd writer threads firing PSI trigger
 * writes, then rmdir the cgroup out from under them in the main thread.
 * The kernel-side window is between cgroup_kn_unlock() and the matching
 * cgroup_put() inside pressure_write — the cgroup ref pin protects the
 * cgrp pointer itself, but the psi_trigger / cgroup_file_ctx interaction
 * with concurrent css teardown is the bug class this sub-mode targets.
 * pressure_write parses "some <threshold_us> <window_us>" / "full ..."
 * and calls psi_trigger_create which kmallocs a trigger and links it via
 * smp_store_release into ctx->psi.trigger; racing rmdir tears down the
 * css/psi_group state under that allocation+link sequence.
 */

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/types.h>

#include "child.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"
#include "pids.h"

#include "kernel/fcntl.h"
/* Hard cap on mkdir/rmdir cycles per invocation.  Kept modest so a
 * single op completes well inside the alarm(1) window even when the
 * cgroup subsystem is under contention from sibling churners. */
#define MAX_CYCLES	16

/* One in PSI_RACE_GATE successful mkdir cycles enters the PSI race
 * sub-mode instead of an immediate rmdir.  Kept low-frequency so the
 * baseline mkdir/rmdir coverage isn't displaced and the per-invocation
 * thread spawn count stays bounded under sibling load. */
#define PSI_RACE_GATE	4

/* Number of pressure-file fds opened per race sub-mode invocation.
 * Each fd gets its own writer thread.  4 keeps thread spawn pressure
 * modest while still landing multiple concurrent psi_trigger_create
 * calls in the rmdir window. */
#define PSI_RACE_FDS	4

/*
 * PSI trigger write payload.  pressure_write parses
 *   "some <threshold_us> <window_us>" or "full <threshold_us> <window_us>"
 * and calls psi_trigger_create, which validates window in (0, 10s] and
 * (for unprivileged callers) requires window_us % 2_000_000 == 0.  A
 * 500ms threshold over a 10s window satisfies both privileged and
 * unprivileged paths, so we hit psi_trigger_create regardless of how
 * the child is running.  Numeric values are otherwise functionally
 * arbitrary for race purposes — the kmalloc + smp_store_release
 * sequence inside psi_trigger_create runs identically.
 */
static const char psi_payload[] = "some 500000 10000000\n";

static const char * const psi_files[] = {
	"cpu.pressure",
	"memory.pressure",
	"io.pressure",
};
#define NR_PSI_FILES	ARRAY_SIZE(psi_files)

/* Latched once per child if pressure files are absent (CONFIG_PSI=n)
 * or unwritable (no CAP_SYS_RESOURCE and root-owned files).  Saves the
 * open(EACCES|ENOENT) round-trip on subsequent cycles. */
static bool psi_unsupported;

/* Per-process monotonic counter so each cgroup name within a child
 * is distinct.  Doesn't need to be atomic — only this child uses it. */
static unsigned long cgroup_churn_seq;

struct psi_writer_arg {
	int fd;
	unsigned int *writes;
};

/*
 * Writer thread.  One PSI trigger write per invocation: that's the
 * single call that drives pressure_write's full sequence
 * (cgroup_kn_lock_live -> cgroup_get -> cgroup_kn_unlock ->
 * psi_trigger_create -> smp_store_release -> cgroup_put).  Writing
 * a second time on the same fd just bounces off the EBUSY guard
 * inside pressure_write and adds no race coverage, so we exit after
 * one shot and let the join path drop the trigger via .release.
 */
static void *psi_writer(void *arg)
{
	struct psi_writer_arg *a = arg;

	if (write(a->fd, psi_payload, sizeof(psi_payload) - 1) > 0)
		__atomic_add_fetch(a->writes, 1, __ATOMIC_RELAXED);
	return NULL;
}

/*
 * Race the cgroup pressure_write codepath against rmdir.
 *
 * Open PSI_RACE_FDS fds on a single *.pressure file in the freshly-
 * created leaf cgroup, fan out one writer thread per fd, then issue
 * rmdir(cgroup_path) from the main thread while the writers are
 * mid-pressure_write.  After joining, close all fds (drops the
 * psi_trigger refs via the file ->release callback) and re-attempt
 * rmdir to clean up if writers pinned the directory.  The next
 * cgroup_churn cycle uses a fresh seq-suffixed path so a leaked dir
 * from one race doesn't compound across iterations.
 */
static void cgroup_psi_race(const char *cgroup_path)
{
	char file_path[128];
	int fds[PSI_RACE_FDS];
	pthread_t tids[PSI_RACE_FDS];
	struct psi_writer_arg args[PSI_RACE_FDS];
	bool spawned[PSI_RACE_FDS] = { false };
	unsigned int writes = 0;
	unsigned int file_idx = rnd_modulo_u32(NR_PSI_FILES);
	unsigned int i, n_open = 0;

	if (psi_unsupported)
		return;

	snprintf(file_path, sizeof(file_path), "%s/%s",
		 cgroup_path, psi_files[file_idx]);

	for (i = 0; i < PSI_RACE_FDS; i++) {
		fds[i] = open(file_path, O_WRONLY | O_CLOEXEC);
		if (fds[i] < 0) {
			/* ENOENT here on a freshly-created cgroup means
			 * CONFIG_PSI=n; EACCES means pressure files are
			 * root-owned and we lack CAP_SYS_RESOURCE.  Either
			 * way, latch off — won't change for this child. */
			if (i == 0 && (errno == ENOENT || errno == EACCES))
				psi_unsupported = true;
			break;
		}
		n_open++;
	}
	if (n_open == 0) {
		__atomic_add_fetch(&shm->stats.cgroup_churn.psi_race_failed,
				   1, __ATOMIC_RELAXED);
		return;
	}

	__atomic_add_fetch(&shm->stats.cgroup_churn.psi_race_runs,
			   1, __ATOMIC_RELAXED);

	for (i = 0; i < n_open; i++) {
		args[i].fd = fds[i];
		args[i].writes = &writes;
		if (pthread_create(&tids[i], NULL,
				   psi_writer, &args[i]) == 0)
			spawned[i] = true;
	}

	/* The race itself: rmdir while writers are mid-pressure_write.
	 * EBUSY here is expected when a writer happens to be inside the
	 * cgroup_get/cgroup_put window; not a problem — the cleanup
	 * rmdir below catches it once the writer fds are released. */
	(void)rmdir(cgroup_path);

	for (i = 0; i < n_open; i++) {
		if (spawned[i])
			(void)pthread_join(tids[i], NULL);
		close(fds[i]);
	}

	/* Cleanup pass: the close()s above released any psi_trigger
	 * refs that were pinning the cgroup, so a second rmdir cleans
	 * up if the in-race attempt above hit EBUSY. */
	(void)rmdir(cgroup_path);

	__atomic_add_fetch(&shm->stats.cgroup_churn.psi_race_writes,
			   writes, __ATOMIC_RELAXED);
}

bool cgroup_churn(struct childdata *child)
{
	unsigned int cycles;
	unsigned int i;
	pid_t pid = mypid();

	__atomic_add_fetch(&shm->stats.cgroup_churn.runs, 1, __ATOMIC_RELAXED);

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	/* No eligibility gate above the mkdir/rmdir hot loop -- this
	 * invocation has committed to driving the op as soon as it
	 * enters.  Bump setup_accepted here so the per-childop yield
	 * dump attributes the invocation to cgroup_churn. */
	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	cycles = 1 + rnd_modulo_u32(MAX_CYCLES);

	/* Immediately before the mkdir/rmdir loop -- the kernel-exercising
	 * work this childop exists to drive.  NO-setup childop: paired
	 * one-to-one with the setup_accepted bump above (no bail path
	 * between them) so the invariant data_path <= setup_accepted holds
	 * with equality as the healthy baseline. */
	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);

	for (i = 0; i < cycles; i++) {
		char path[64];
		unsigned long seq = ++cgroup_churn_seq;

		snprintf(path, sizeof(path),
			 "/sys/fs/cgroup/trinity-%d-%lu", (int)pid, seq);

		if (mkdir(path, 0755) != 0) {
			__atomic_add_fetch(&shm->stats.cgroup_churn.failed,
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

		__atomic_add_fetch(&shm->stats.cgroup_churn.mkdirs,
				   1, __ATOMIC_RELAXED);

		/* One in PSI_RACE_GATE cycles takes the PSI race sub-mode
		 * branch instead of the simple rmdir.  cgroup_psi_race
		 * handles its own teardown (and a leak-cleanup rmdir on
		 * the way out) so the main loop doesn't need to follow up. */
		if (ONE_IN(PSI_RACE_GATE)) {
			cgroup_psi_race(path);
			continue;
		}

		if (rmdir(path) == 0) {
			__atomic_add_fetch(&shm->stats.cgroup_churn.rmdirs,
					   1, __ATOMIC_RELAXED);
		} else {
			__atomic_add_fetch(&shm->stats.cgroup_churn.failed,
					   1, __ATOMIC_RELAXED);
			/* EBUSY here means a task entered the cgroup between
			 * mkdir and rmdir (some other churner, or the kernel's
			 * own bookkeeping).  Leave the directory; the next
			 * invocation uses a new name so we don't compound. */
		}
	}

	return true;
}
