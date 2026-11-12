/*
 * Self-check for the deadline timerfd_settime's sanitiser gives a
 * TFD_TIMER_ABSTIME call: a second past now on the clock the fd's timer runs
 * on, the base clock for an ALARM one, so the timer fires.  The timerfd pool
 * is a fake holding the one fd, made on each clock in turn.
 */

#include <stdlib.h>
#include <string.h>
#include <sys/timerfd.h>
#include <time.h>

#include "debug.h"		/* BUG */
#include "kernel/time.h"	/* CLOCK_BOOTTIME, CLOCK_*_ALARM */
#include "objects.h"		/* get_objhead */
#include "syscall.h"		/* struct syscallrecord */
#include "syscalls/syscalls.h"	/* syscall_timerfd_settime */
#include "utils-macros.h"	/* ARRAY_SIZE */

extern struct objhead *(*fake_get_objhead)(enum obj_scope scope,
					   enum objecttype type);	/* fake_objects.c */

#define TIMERFD_ROUNDS	400
#define TIMERFD_FD	41

static struct object timerfd_obj;
static struct object *timerfd_array[] = { &timerfd_obj };
static struct objhead timerfd_pool = { .array = timerfd_array, .num_entries = 1 };

static struct objhead *the_pool(enum obj_scope scope, enum objecttype type)
{
	if (scope == OBJ_GLOBAL && type == OBJ_FD_TIMERFD)
		return &timerfd_pool;
	return NULL;
}

void timerfd_settime_self_check(void);
void timerfd_settime_self_check(void)
{
	static const struct {
		int clockid, base;
	} clocks[] = {
		{ CLOCK_REALTIME, CLOCK_REALTIME },
		{ CLOCK_MONOTONIC, CLOCK_MONOTONIC },
		{ CLOCK_BOOTTIME, CLOCK_BOOTTIME },
		{ CLOCK_REALTIME_ALARM, CLOCK_REALTIME },
		{ CLOCK_BOOTTIME_ALARM, CLOCK_BOOTTIME },
	};
	unsigned int c, i;

	fake_get_objhead = the_pool;
	timerfd_obj.timerfdobj.fd = TIMERFD_FD;
	for (c = 0; c < ARRAY_SIZE(clocks); c++) {
		unsigned int absolute = 0;

		timerfd_obj.timerfdobj.clockid = clocks[c].clockid;
		for (i = 0; i < TIMERFD_ROUNDS; i++) {
			struct syscallrecord rec;
			const struct itimerspec *its;
			struct timespec now;

			memset(&rec, 0, sizeof(rec));
			rec.a1 = TIMERFD_FD;
			syscall_timerfd_settime.sanitise(&rec);
			free((void *) rec.post_state);
			its = (const struct itimerspec *) rec.a3;
			if (its == NULL || !(rec.a2 & TFD_TIMER_ABSTIME))
				continue;

			absolute++;
			if (clock_gettime(clocks[c].base, &now) != 0)
				BUG("timerfd_settime: cannot read the clock a timer runs on");
			if (its->it_value.tv_sec < now.tv_sec ||
			    its->it_value.tv_sec > now.tv_sec + 2)
				BUG("timerfd_settime: an absolute deadline far from now on its timer's clock");
		}
		if (absolute == 0)
			BUG("timerfd_settime: no call asks for an absolute deadline");
	}
	fake_get_objhead = NULL;
}
