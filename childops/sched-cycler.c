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
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/sched/types.h>

#include "child.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"

#define NSEC_PER_MSEC 1000000ULL

static int do_sched_setattr(pid_t pid, struct sched_attr *attr)
{
	return (int)syscall(__NR_sched_setattr, pid, attr, 0U);
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

	__atomic_add_fetch(&shm->stats.sched_cycler_runs, 1, __ATOMIC_RELAXED);

	cls = classes[rand() % ARRAY_SIZE(classes)];

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
			(unsigned int)RAND_NEGATIVE_OR(1 + rand() % 3);
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
			__atomic_add_fetch(&shm->stats.sched_cycler_eperm,
					   1, __ATOMIC_RELAXED);
		goto restore_other;
	}

	/* Migrate to a random CPU while in the new class. */
	CPU_ZERO(&set);
	CPU_SET(rand() % num_online_cpus, &set);
	(void)sched_setaffinity(0, sizeof(set), &set);

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
