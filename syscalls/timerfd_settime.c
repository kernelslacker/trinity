/*
 * SYSCALL_DEFINE4(timerfd_settime, int, ufd, int, flags,
	 const struct itimerspec __user *, utmr,
	 struct itimerspec __user *, otmr)
 */
#include <sys/timerfd.h>
#include "objects.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"

#ifndef TFD_TIMER_CANCEL_ON_SET
#define TFD_TIMER_CANCEL_ON_SET (1 << 1)
#endif

static void fill_nonzero_timespec(struct timespec *ts)
{
	switch (rnd_modulo_u32(4)) {
	case 0: ts->tv_sec = 0; ts->tv_nsec = 1; break;
	case 1: ts->tv_sec = 0; ts->tv_nsec = 1 + rnd_modulo_u32(1000000); break;
	case 2: ts->tv_sec = 1 + rnd_modulo_u32(10); ts->tv_nsec = rnd_modulo_u32(1000000000); break;
	default: ts->tv_sec = rand32(); ts->tv_nsec = rnd_modulo_u32(1000000000); break;
	}
}

/*
 * TFD_TIMER_CANCEL_ON_SET only has meaning when paired with
 * TFD_TIMER_ABSTIME on a CLOCK_REALTIME timerfd.  The OBJ_FD_TIMERFD
 * pool publishes the clockid each fd was created with, so look the
 * picked fd up and refuse to set the bit on monotonic/boottime fds
 * where the kernel would just return EINVAL.
 */
static int timerfd_is_realtime(int fd)
{
	struct objhead *head;
	struct object *obj;
	unsigned int idx;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_TIMERFD);
	if (head == NULL)
		return 0;

	for_each_obj(head, obj, idx) {
		if (obj->timerfdobj.fd != fd)
			continue;
		return obj->timerfdobj.clockid == CLOCK_REALTIME;
	}
	return 0;
}

static void sanitise_timerfd_settime(struct syscallrecord *rec)
{
	struct itimerspec *its;
	uint32_t bucket;
	unsigned long flags = 0;

	its = (struct itimerspec *) get_writable_address(sizeof(*its));
	if (its == NULL)
		return;

	its->it_interval.tv_sec = 0;
	its->it_interval.tv_nsec = 0;
	its->it_value.tv_sec = 0;
	its->it_value.tv_nsec = 0;

	bucket = rnd_modulo_u32(100);
	if (bucket < 25) {
		/* disarm */
	} else if (bucket < 55) {
		/* one-shot */
		fill_nonzero_timespec(&its->it_value);
	} else if (bucket < 80) {
		/* periodic */
		fill_nonzero_timespec(&its->it_value);
		fill_nonzero_timespec(&its->it_interval);
	} else {
		/* TFD_TIMER_ABSTIME with a near-now deadline. */
		struct timespec now;

		if (clock_gettime(CLOCK_REALTIME, &now) == 0) {
			its->it_value.tv_sec = now.tv_sec + 1;
			its->it_value.tv_nsec = now.tv_nsec;
		} else {
			fill_nonzero_timespec(&its->it_value);
		}
		flags |= TFD_TIMER_ABSTIME;
	}

	/* CANCEL_ON_SET is only valid on CLOCK_REALTIME timerfds and only
	 * paired with ABSTIME -- gate on both. */
	if ((flags & TFD_TIMER_ABSTIME) &&
	    rnd_modulo_u32(100) < 15 &&
	    timerfd_is_realtime((int) rec->a1))
		flags |= TFD_TIMER_CANCEL_ON_SET;

	rec->a2 = flags;
	rec->a3 = (unsigned long) its;
	avoid_shared_buffer_inout(&rec->a3, sizeof(struct itimerspec));
	avoid_shared_buffer_out(&rec->a4, sizeof(struct itimerspec));
}

struct syscallentry syscall_timerfd_settime = {
	.name = "timerfd_settime",
	.group = GROUP_TIME,
	.num_args = 4,
	.argtype = { [0] = ARG_FD_TIMERFD, [2] = ARG_ADDRESS, [3] = ARG_ADDRESS },
	.argname = { [0] = "ufd", [1] = "flags", [2] = "utmr", [3] = "otmr" },
	.sanitise = sanitise_timerfd_settime,
	.flags = NEED_ALARM,
	.rettype = RET_ZERO_SUCCESS,
};
