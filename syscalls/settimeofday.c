/*
 * SYSCALL_DEFINE2(settimeofday, struct timeval __user *, tv, struct timezone __user *, tz)
 */
#include <sys/time.h>
#include "random.h"
#include "rnd.h"
#include "sanitise.h"

static void sanitise_settimeofday(struct syscallrecord *rec)
{
	struct timezone *tz;

	/* tv (a1) is published by ARG_TIMEVAL: its writable-pool buffer
	 * carries the near-now bias and the invalid-tv_usec bucket so the
	 * kernel's legality validators stay warm. */

	/* timezone is mostly deprecated but exercise it sometimes. */
	if (RAND_BOOL()) {
		tz = (struct timezone *) get_writable_address(sizeof(*tz));
		if (tz == NULL)
			return;
		if (RAND_BOOL()) {
			tz->tz_minuteswest = 0;
			tz->tz_dsttime = 0;
		} else {
			tz->tz_minuteswest =
				(int) (rnd_modulo_u32(1560)) - 780;	/* -13h to +13h */
			tz->tz_dsttime = (int) rnd_modulo_u32(4);
		}
		rec->a2 = (unsigned long) tz;
		avoid_shared_buffer_inout(&rec->a2, sizeof(*tz));
	} else {
		rec->a2 = 0;
	}
}

struct syscallentry syscall_settimeofday = {
	.name = "settimeofday",
	.group = GROUP_TIME,
	.num_args = 2,
	.argname = { [0] = "tv", [1] = "tz" },
	.argtype = { [0] = ARG_TIMEVAL, [1] = ARG_ADDRESS },
	.flags = NEEDS_ROOT,	/* autodrops EPERM on the fleet; type is still correct (mirror clock_settime). */
	.sanitise = sanitise_settimeofday,
	.rettype = RET_ZERO_SUCCESS,
};
