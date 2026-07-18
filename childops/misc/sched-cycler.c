/*
 * sched_cycler - switch scheduling class mid-fuzz to expose races in
 * scheduler-aware kernel paths.
 *
 * Paths like RT priority inheritance, deadline admission control, and
 * CPU migration carry complex locking assumptions about which class a
 * task is in.  Trinity's normal children stay in SCHED_OTHER for their
 * entire lifetime, so class-transition paths — where invariants are
 * most likely to break — never get hit.  This op forces those
 * transitions by switching to a randomly chosen scheduling class,
 * migrating to a different CPU while in that class, running a short
 * burst of random syscalls in the new context, then restoring
 * SCHED_OTHER before returning.
 *
 * sched_setattr() is invoked via syscall() rather than a libc wrapper
 * because the wrapper was only added to glibc 2.35 and struct
 * sched_attr is taken from <linux/sched/types.h> for the same reason.
 *
 * Graceful degradation:
 *   - EPERM on RT/DEADLINE classes (no CAP_SYS_NICE) is counted and
 *     skipped — not fatal.
 *   - DEADLINE admission failures are expected and ignored.
 *   - sched_setaffinity() EINVAL (CPU not in cpuset) is silently
 *     ignored; the syscall burst still runs.
 *   - SCHED_OTHER is always restored before return so the child never
 *     starves the rest of trinity.
 */

#include <errno.h>
#include <sched.h>
#include <stdbool.h>
#include <sys/syscall.h>
#include <linux/sched/types.h>
#include <string.h>

#include "child.h"
#include "syscall-gate.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"

#include "kernel/sched.h"
#define NSEC_PER_MSEC 1000000ULL

static int do_sched_setattr(pid_t pid, struct sched_attr *attr)
{
	return (int)trinity_raw_syscall(__NR_sched_setattr, pid, attr, 0U);
}

bool sched_cycler(struct childdata *child)
{
	static const int classes[] = {
		SCHED_OTHER,
		SCHED_FIFO,
		SCHED_RR,
		SCHED_DEADLINE,
		SCHED_BATCH,
		SCHED_IDLE,
	};
	struct sched_attr attr, restore;
	cpu_set_t set;
	int cls, i;

	__atomic_add_fetch(&shm->stats.sched_cycler.runs, 1, __ATOMIC_RELAXED);

	cls = classes[rnd_modulo_u32(ARRAY_SIZE(classes))];

	memset(&attr, 0, sizeof(attr));
	attr.size = sizeof(attr);
	attr.sched_policy = (unsigned int)cls;

	switch (cls) {
	case SCHED_FIFO:
	case SCHED_RR:
		/* 1-in-RAND_NEGATIVE_RATIO sub the in-range RT priority for
		 * a curated edge value — exercises sched_setattr's priority
		 * range validation against sched_get_priority_min/max for the
		 * chosen class, which the curated 1..3 mix never reaches. */
		attr.sched_priority =
			(unsigned int)RAND_NEGATIVE_OR(1 + rnd_modulo_u32(3));
		break;
	case SCHED_DEADLINE:
		attr.sched_runtime  = 1 * NSEC_PER_MSEC;
		attr.sched_deadline = 10 * NSEC_PER_MSEC;
		attr.sched_period   = 10 * NSEC_PER_MSEC;
		break;
	default:
		attr.sched_priority = 0;
		break;
	}

	if (do_sched_setattr(0, &attr) != 0) {
		if (errno == EPERM)
			__atomic_add_fetch(&shm->stats.sched_cycler.eperm,
					   1, __ATOMIC_RELAXED);
		goto restore_other;
	}

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	/* Migrate to a random CPU while in the new class. */
	CPU_ZERO(&set);
	CPU_SET(rnd_modulo_u32(num_online_cpus), &set);
	(void)sched_setaffinity(0, sizeof(set), &set);

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	/* Short burst of random syscalls in the new scheduling context. */
	for (i = 0; i < 10; i++)
		random_syscall(child);

restore_other:
	memset(&restore, 0, sizeof(restore));
	restore.size = sizeof(restore);
	restore.sched_policy = SCHED_OTHER;
	restore.sched_priority = 0;
	(void)do_sched_setattr(0, &restore);

	return true;
}
