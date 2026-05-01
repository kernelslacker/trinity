/*
 * SYSCALL_DEFINE3(setitimer, int, which, struct itimerval __user *, value, struct itimerval __user *, ovalue)
 */
#include <sys/time.h>
#include "random.h"
#include "sanitise.h"

static unsigned long setitimer_which[] = {
	ITIMER_REAL, ITIMER_VIRTUAL, ITIMER_PROF,
};

static void fill_timeval(struct timeval *tv)
{
	switch (rand() % 4) {
	case 0: tv->tv_sec = 0; tv->tv_usec = 0; break;
	case 1: tv->tv_sec = 0; tv->tv_usec = 1 + (rand() % 1000); break;
	case 2: tv->tv_sec = 1 + (rand() % 10); tv->tv_usec = rand() % 1000000; break;
	default: tv->tv_sec = rand32(); tv->tv_usec = rand() % 1000000; break;
	}
}

static void sanitise_setitimer(struct syscallrecord *rec)
{
	struct itimerval *itv;

	itv = (struct itimerval *) get_writable_address(sizeof(*itv));

	fill_timeval(&itv->it_interval);
	fill_timeval(&itv->it_value);

	/* Half the time, disarm the timer. */
	if (RAND_BOOL()) {
		itv->it_value.tv_sec = 0;
		itv->it_value.tv_usec = 0;
	}

	rec->a2 = (unsigned long) itv;

	avoid_shared_buffer(&rec->a3, sizeof(struct itimerval));
}

struct syscallentry syscall_setitimer = {
	.flags = AVOID_SYSCALL,		/* setitimer interferes with alarm() */
	.name = "setitimer",
	.group = GROUP_TIME,
	.num_args = 3,
	.argtype = { [0] = ARG_OP, [2] = ARG_ADDRESS },
	.argname = { [0] = "which", [1] = "value", [2] = "ovalue" },
	.arg_params[0].list = ARGLIST(setitimer_which),
	.sanitise = sanitise_setitimer,
};
