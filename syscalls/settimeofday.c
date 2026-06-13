/*
 * SYSCALL_DEFINE2(settimeofday, struct timeval __user *, tv, struct timezone __user *, tz)
 */
#include <sys/time.h>
#include <time.h>
#include "random.h"
#include "rnd.h"
#include "sanitise.h"

static void sanitise_settimeofday(struct syscallrecord *rec)
{
	struct timeval *tv;
	struct timezone *tz;
	struct timespec snap;

	tv = (struct timeval *) get_writable_address(sizeof(*tv));
	if (tv == NULL)
		return;

	/*
	 * Bias 70% near-now / 30% random.  Random tv_sec almost always
	 * EPERMs out before the kernel parses tv_usec, so a uniform random
	 * mix wastes draws.  Bias near-now so the legality validators
	 * (tv_usec < 1e6, monotonic step constraints) actually run.
	 */
	if (rnd_modulo_u32(100) < 70) {
		if (clock_gettime(CLOCK_REALTIME, &snap) == 0) {
			tv->tv_sec = snap.tv_sec +
				(time_t) (rnd_modulo_u32(120)) - 60;
		} else {
			tv->tv_sec = time(NULL) +
				(time_t) (rnd_modulo_u32(120)) - 60;
		}
		tv->tv_usec = rnd_modulo_u32(1000000);
	} else {
		/* Random path: include the invalid-tv_usec validation case. */
		tv->tv_sec = (time_t) rand32();
		if (RAND_BOOL())
			tv->tv_usec = (suseconds_t) rnd_modulo_u32(1000000);
		else
			tv->tv_usec = (suseconds_t) (1000000 +
				rnd_modulo_u32(1000000));
	}

	rec->a1 = (unsigned long) tv;

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
	} else {
		rec->a2 = 0;
	}
}

struct syscallentry syscall_settimeofday = {
	.name = "settimeofday",
	.group = GROUP_TIME,
	.num_args = 2,
	.argname = { [0] = "tv", [1] = "tz" },
	.argtype = { [0] = ARG_ADDRESS, [1] = ARG_ADDRESS },
	.flags = NEEDS_ROOT,
	.sanitise = sanitise_settimeofday,
	.rettype = RET_ZERO_SUCCESS,
};
