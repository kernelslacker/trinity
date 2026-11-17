/*
 * Self-check for sched_setattr's sanitiser: uclamp_validate()
 * (kernel/sched/syscalls.c) takes a utilization clamp of 0..1024
 * (SCHED_CAPACITY_SCALE), or -1 to reset it, and refuses a min above the
 * max, once user_check_sched_setscheduler() has passed the call, which a
 * child without CAP_SYS_NICE meets only by keeping its own policy and
 * params.  So the clamps drawn are mostly ones it takes, with resets,
 * values past 1024 and inverted pairs among them, and some calls keep
 * policy and params.
 */

#include <stdlib.h>
#include <string.h>

#include "debug.h"			/* BUG */
#include "kernel/sched_attr.h"		/* SCHED_FLAG_*, SCHED_ATTR_SIZE_VER1 */
#include "syscall.h"			/* struct syscallrecord */
#include "syscalls/syscalls.h"		/* syscall_sched_setattr */

#define SETATTR_ROUNDS	20000

/* The flags __sched_setscheduler() takes; a call with another bit set
 * never gets as far as the clamps. */
#define KNOWN_FLAGS	(SCHED_FLAG_RESET_ON_FORK | SCHED_FLAG_RECLAIM | \
			 SCHED_FLAG_DL_OVERRUN | SCHED_FLAG_KEEP_POLICY | \
			 SCHED_FLAG_KEEP_PARAMS | SCHED_FLAG_UTIL_CLAMP_MIN | \
			 SCHED_FLAG_UTIL_CLAMP_MAX)
#define CLAMP_FLAGS	(SCHED_FLAG_UTIL_CLAMP_MIN | SCHED_FLAG_UTIL_CLAMP_MAX)
#define KEEP_FLAGS	(SCHED_FLAG_KEEP_POLICY | SCHED_FLAG_KEEP_PARAMS)
#define UCLAMP_SCALE	1024
#define UCLAMP_RESET	0xffffffffU

void sched_setattr_self_check(void);
void sched_setattr_self_check(void)
{
	unsigned int i, clamps = 0, taken = 0, inside = 0, over = 0;
	unsigned int reset = 0, inverted = 0, kept = 0;

	for (i = 0; i < SETATTR_ROUNDS; i++) {
		struct syscallrecord rec;
		const struct sched_attr *sa;
		unsigned int min, max;

		memset(&rec, 0, sizeof(rec));
		syscall_sched_setattr.sanitise(&rec);
		sa = (const struct sched_attr *) rec.a2;
		if (sa->size < SCHED_ATTR_SIZE_VER1 ||
		    (sa->sched_flags & ~(unsigned long long) KNOWN_FLAGS) ||
		    !(sa->sched_flags & CLAMP_FLAGS)) {
			free((void *) rec.post_state);
			continue;
		}

		clamps++;
		min = sa->sched_util_min;
		max = sa->sched_util_max;
		if ((sa->sched_flags & KEEP_FLAGS) == KEEP_FLAGS)
			kept++;
		if (min == UCLAMP_RESET || max == UCLAMP_RESET)
			reset++;
		if ((min > UCLAMP_SCALE && min != UCLAMP_RESET) ||
		    (max > UCLAMP_SCALE && max != UCLAMP_RESET))
			over++;
		else if (min != UCLAMP_RESET && max != UCLAMP_RESET && min > max)
			inverted++;
		else
			taken++;
		if ((min > 0 && min < UCLAMP_SCALE) || (max > 0 && max < UCLAMP_SCALE))
			inside++;
		free((void *) rec.post_state);
	}

	if (clamps == 0)
		BUG("sched_setattr: no call sets a utilization clamp");
	if (taken < clamps / 2)
		BUG("sched_setattr: the clamps uclamp_validate() takes are rare");
	if (inside == 0)
		BUG("sched_setattr: no clamp falls between 0 and 1024");
	if (over == 0 || reset == 0 || inverted == 0)
		BUG("sched_setattr: no clamp past 1024, reset or inverted pair");
	if (kept == 0)
		BUG("sched_setattr: no clamp call keeps its policy and params");
}
