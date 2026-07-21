/*
 * sysfs_string_race - race two child writers on a curated sysfs
 * string-typed attribute.
 *
 * Pattern: pick one target from a hand-curated allowlist of writable
 * sysfs string attrs, fork two children that each open the attr O_RDWR
 * and tight-loop pwrite(fd, candidate, len, 0) with a different
 * candidate string per child.  The two stores race inside the kernel's
 * kernfs ops .store() callback -- the attribute's parse + apply path
 * sees concurrent writes from two distinct task_structs against the
 * same struct kernfs_open_file, which is the race shape that has
 * surfaced UAFs and torn-string bugs across the sysfs string-attr
 * surface (cve-pattern-corpus/2026-05-22-eafd6f53 et al).
 *
 * The curation deliberately stays generic -- TRANSPARENT HUGEPAGE,
 * KSM, lru_gen, printk module parameters, NUMA demotion knob -- so
 * the op produces coverage on stock kernels rather than only on the
 * DAMON-enabled configs that originally motivated the pattern.
 *
 * Brick-safety: every target is read-mostly admin state with a
 * bounded value space; the candidates list per target only includes
 * legal accepted strings (so a store either succeeds or fails with
 * EINVAL, never wedges the host into a degraded operating mode).
 * Power-management paths (/sys/power/state etc) and SMT control
 * (/sys/devices/system/cpu/smt/control) are deliberately excluded.
 *
 * Containerised hosts will have many of these paths absent or
 * read-only -- a missing path / failed open is treated as silent
 * skip + counter bump, never an error.
 *
 * Bound: 256 iters total per invocation (split evenly between the
 * two child writers).  Each child has a self-armed alarm(2) so a
 * stuck pwrite cannot pin past child.c's per-syscall SIGALRM(1s).
 */

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "child.h"
#include "childops-util.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/fcntl.h"
#define SYSFS_STRING_RACE_ITER_CAP	256U
#define SYSFS_STRING_RACE_ITER_BASE	32U
#define SYSFS_STRING_RACE_CHILD_WATCHDOG_S	2

static const char * const cand_thp_enabled[] = {
	"always", "madvise", "never",
};
static const char * const cand_thp_defrag[] = {
	"always", "defer", "defer+madvise", "madvise", "never",
};
static const char * const cand_thp_shmem_enabled[] = {
	"always", "within_size", "advise", "never", "deny", "force",
};
static const char * const cand_thp_khugepaged_defrag[] = {
	"0", "1",
};
static const char * const cand_thp_use_zero_page[] = {
	"0", "1",
};
static const char * const cand_ksm_run[] = {
	"0", "1", "2",
};
static const char * const cand_numa_demotion_enabled[] = {
	"true", "false", "Y", "N", "1", "0",
};
static const char * const cand_lru_gen_enabled[] = {
	"0x0", "0x1", "0x3", "0x7", "0xf",
};
static const char * const cand_printk_devkmsg[] = {
	"on", "off", "ratelimit",
};
static const char * const cand_printk_param_bool[] = {
	"Y", "N",
};

struct sysfs_string_target {
	const char *path;
	const char * const *candidates;
	unsigned int n_candidates;
};

#define TGT(p, c)	{ (p), (c), ARRAY_SIZE(c) }

static const struct sysfs_string_target targets[] = {
	TGT("/sys/kernel/mm/transparent_hugepage/enabled",
	    cand_thp_enabled),
	TGT("/sys/kernel/mm/transparent_hugepage/defrag",
	    cand_thp_defrag),
	TGT("/sys/kernel/mm/transparent_hugepage/shmem_enabled",
	    cand_thp_shmem_enabled),
	TGT("/sys/kernel/mm/transparent_hugepage/khugepaged/defrag",
	    cand_thp_khugepaged_defrag),
	TGT("/sys/kernel/mm/transparent_hugepage/use_zero_page",
	    cand_thp_use_zero_page),
	TGT("/sys/kernel/mm/ksm/run",
	    cand_ksm_run),
	TGT("/sys/kernel/mm/numa/demotion_enabled",
	    cand_numa_demotion_enabled),
	TGT("/sys/kernel/mm/lru_gen/enabled",
	    cand_lru_gen_enabled),
	TGT("/sys/kernel/printk_devkmsg",
	    cand_printk_devkmsg),
	TGT("/sys/module/printk/parameters/time",
	    cand_printk_param_bool),
	TGT("/sys/module/printk/parameters/ignore_loglevel",
	    cand_printk_param_bool),
	TGT("/sys/module/printk/parameters/always_kmsg_dump",
	    cand_printk_param_bool),
};
#define NR_TARGETS	ARRAY_SIZE(targets)

/*
 * Per-process latch: every target probed at startup returned ENOENT /
 * EACCES.  Containerised images often hide /sys/kernel/mm entirely;
 * once we've confirmed nothing is reachable, every subsequent
 * invocation is a no-op modulo the run counter.
 */
static bool ns_unsupported_sysfs_string_race;
static bool targets_probed;

/*
 * Bitmap of targets that passed open(O_WRONLY) at startup.  Set on
 * first invocation; never mutated after.  A zero bitmap latches the
 * unsupported flag above.
 */
static uint16_t targets_writable_mask;

_Static_assert(NR_TARGETS <= 16,
	"targets_writable_mask must hold one bit per target");

static void probe_targets(struct childdata *child)
{
	unsigned int i;

	targets_probed = true;

	for (i = 0; i < NR_TARGETS; i++) {
		int fd = open(targets[i].path, O_WRONLY | O_CLOEXEC);

		if (fd < 0)
			continue;
		(void)close(fd);
		targets_writable_mask |= (uint16_t)(1U << i);
	}

	if (targets_writable_mask == 0U) {
		ns_unsupported_sysfs_string_race = true;
		/* child->op_type lives in shared memory and can be scribbled
		 * by a poisoned-arena write from a sibling; bounds-check the
		 * snapshot before indexing the NR_CHILD_OP_TYPES-sized stats
		 * arrays, same pattern the child.c dispatch loop uses for the
		 * unguarded write that motivated this guard. */
		{
			const enum child_op_type op = child->op_type;
			if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_NS_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
	}
}

/*
 * Pick a target index whose bit is set in targets_writable_mask.  Caller
 * has already confirmed the mask is non-zero (probe completed without
 * latching unsupported).  Linear scan from a random start so a host
 * that only has one writable target still rotates trivially.
 */
static unsigned int pick_writable_target(void)
{
	unsigned int start = rnd_modulo_u32(NR_TARGETS);
	unsigned int i;

	for (i = 0; i < NR_TARGETS; i++) {
		unsigned int idx = (start + i) % NR_TARGETS;

		if (targets_writable_mask & (uint16_t)(1U << idx))
			return idx;
	}
	/* unreachable: caller checked the mask */
	return 0;
}

/*
 * Child-side writer.  Runs a tight pwrite() loop against the already-
 * opened fd with the given candidate string, up to `iters` iterations
 * or until the self-armed alarm(2) fires.  Uses raw _exit() so the
 * child cannot accidentally drag glibc atexit / stdio flush state
 * inherited from the trinity parent into a sysfs write target.
 */
__attribute__((noreturn))
static void writer_child(int fd, const char *cand, unsigned int iters)
{
	size_t len = strlen(cand);
	unsigned int i;

	(void)prctl(PR_SET_PDEATHSIG, SIGKILL, 0UL, 0UL, 0UL);
	(void)alarm(SYSFS_STRING_RACE_CHILD_WATCHDOG_S);

	/* Re-check parent presence after arming PDEATHSIG, in case the
	 * parent died between fork() and the prctl above. */
	if (getppid() == 1)
		_exit(0);

	for (i = 0; i < iters; i++) {
		ssize_t n = pwrite(fd, cand, len, 0);

		if (n > 0) {
			__atomic_add_fetch(&shm->stats.sysfs_string_race.writes_ok,
					   1, __ATOMIC_RELAXED);
		} else {
			__atomic_add_fetch(&shm->stats.sysfs_string_race.writes_failed,
					   1, __ATOMIC_RELAXED);
		}
	}

	_exit(0);
}

bool sysfs_string_race(struct childdata *child)
{
	unsigned int iters_total, per_child;
	unsigned int tgt_idx;
	const struct sysfs_string_target *tgt;
	const char *cand_a, *cand_b;
	int fd;
	pid_t pa, pb;

	__atomic_add_fetch(&shm->stats.sysfs_string_race.runs,
			   1, __ATOMIC_RELAXED);

	if (ns_unsupported_sysfs_string_race)
		return true;

	if (!targets_probed) {
		probe_targets(child);
		if (ns_unsupported_sysfs_string_race) {
			__atomic_add_fetch(&shm->stats.sysfs_string_race.setup_failed,
					   1, __ATOMIC_RELAXED);
			return true;
		}
	}

	tgt_idx = pick_writable_target();
	tgt = &targets[tgt_idx];

	fd = open(tgt->path, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		/* Permission may have been dropped or the attr file may
		 * have been removed between probe and now -- treat as
		 * silent skip. */
		__atomic_add_fetch(&shm->stats.sysfs_string_race.target_missing,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	iters_total = BUDGETED(CHILD_OP_SYSFS_STRING_RACE,
			       SYSFS_STRING_RACE_ITER_BASE);
	if (iters_total > SYSFS_STRING_RACE_ITER_CAP)
		iters_total = SYSFS_STRING_RACE_ITER_CAP;
	if (iters_total < 2U)
		iters_total = 2U;
	per_child = iters_total / 2U;

	/* Pick two distinct candidates when the target has >1 of them;
	 * otherwise both writers re-write the same string, which still
	 * exercises the .store() race on a single string -- the racing
	 * call sites are the value, not the value diversity. */
	cand_a = tgt->candidates[rnd_modulo_u32(tgt->n_candidates)];
	if (tgt->n_candidates > 1U) {
		unsigned int b_idx;

		do {
			b_idx = rnd_modulo_u32(tgt->n_candidates);
		} while (tgt->candidates[b_idx] == cand_a);
		cand_b = tgt->candidates[b_idx];
	} else {
		cand_b = cand_a;
	}

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	}

	pa = fork();
	if (pa == 0) {
		writer_child(fd, cand_a, per_child);	/* noreturn */
	}
	if (pa < 0) {
		__atomic_add_fetch(&shm->stats.sysfs_string_race.fork_failed,
				   1, __ATOMIC_RELAXED);
		(void)close(fd);
		return true;
	}

	pb = fork();
	if (pb == 0) {
		writer_child(fd, cand_b, per_child);	/* noreturn */
	}
	if (pb < 0) {
		__atomic_add_fetch(&shm->stats.sysfs_string_race.fork_failed,
				   1, __ATOMIC_RELAXED);
		(void)kill(pa, SIGKILL);
		(void)waitpid_eintr(pa, NULL, 0);
		(void)close(fd);
		return true;
	}

	__atomic_add_fetch(&shm->stats.sysfs_string_race.target_used,
			   1, __ATOMIC_RELAXED);

	{
		int sa = 0, sb = 0;

		(void)waitpid_eintr(pa, &sa, 0);
		(void)waitpid_eintr(pb, &sb, 0);
	}

	(void)close(fd);
	return true;
}
