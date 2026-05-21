/*
 * SYSCALL_DEFINE2(settimeofday, struct timeval __user *, tv, struct timezone __user *, tz)
 */
#include <sys/time.h>
#include "random.h"
#include "rnd.h"
#include "sanitise.h"

static void sanitise_settimeofday(struct syscallrecord *rec)
{
	struct timeval *tv;
	struct timezone *tz;

	tv = (struct timeval *) get_writable_address(sizeof(*tv));
	if (tv == NULL)
		return;
	switch (rnd_modulo_u32(4)) {
	case 0:	/* epoch */
		tv->tv_sec = 0;
		tv->tv_usec = 0;
		break;
	case 1: /* near-current */
		tv->tv_sec = time(NULL) + (rnd_modulo_u32(120)) - 60;
		tv->tv_usec = rnd_modulo_u32(1000000);
		break;
	case 2: /* invalid usec (>= 1 million) */
		tv->tv_sec = rand32();
		tv->tv_usec = 1000000 + (rnd_modulo_u32(1000000));
		break;
	default:
		tv->tv_sec = rand32();
		tv->tv_usec = rnd_modulo_u32(1000000);
		break;
	}
	rec->a1 = (unsigned long) tv;

	/* timezone is mostly deprecated but exercise it sometimes. */
	if (RAND_BOOL()) {
		tz = (struct timezone *) get_writable_address(sizeof(*tz));
		if (tz == NULL)
			return;
		tz->tz_minuteswest = (rnd_modulo_u32(1560)) - 780;	/* -13h to +13h */
		tz->tz_dsttime = rnd_modulo_u32(4);
		rec->a2 = (unsigned long) tz;
	}
}

struct syscallentry syscall_settimeofday = {
	.name = "settimeofday",
	.group = GROUP_TIME,
	.num_args = 2,
	.argname = { [0] = "tv", [1] = "tz" },
	.flags = NEEDS_ROOT,
	.sanitise = sanitise_settimeofday,
	.rettype = RET_ZERO_SUCCESS,
};
