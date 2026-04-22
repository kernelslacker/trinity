/*
 * SYSCALL_DEFINE3(timer_create, const clockid_t, which_clock,
	struct sigevent __user *, timer_event_spec,
	timer_t __user *, created_timer_id)
 */
#include <signal.h>
#include <time.h>

#include "sanitise.h"
#include "random.h"
#include "compat.h"

static void timer_create_sanitise(struct syscallrecord *rec)
{
	struct sigevent *sigev;

	if (RAND_BOOL()) {
		int signo;

		sigev = (struct sigevent *) get_writable_address(sizeof(struct sigevent));

		/* do not let created timer send SIGINT signal */
		do {
			signo = random() % _NSIG;
		} while (signo  == SIGINT);

		sigev->sigev_signo = signo;
	} else
		sigev = NULL;

	rec->a2 = (unsigned long)sigev;

	/*
	 * created_timer_id (a3) is the kernel's output: timer_create writes
	 * the new timer_t there on success.  Random pool can land it inside
	 * an alloc_shared region, so scrub.
	 */
	avoid_shared_buffer(&rec->a3, sizeof(timer_t));
}

static unsigned long clock_ids[] = {
	CLOCK_REALTIME, CLOCK_MONOTONIC, CLOCK_PROCESS_CPUTIME_ID,
	CLOCK_THREAD_CPUTIME_ID, CLOCK_MONOTONIC_RAW, CLOCK_REALTIME_COARSE,
	CLOCK_MONOTONIC_COARSE, CLOCK_BOOTTIME, CLOCK_TAI,
	CLOCK_REALTIME_ALARM, CLOCK_BOOTTIME_ALARM,
};

struct syscallentry syscall_timer_create = {
	.name = "timer_create",
	.group = GROUP_TIME,
	.num_args = 3,
	.argtype = { [0] = ARG_OP, [1] = ARG_ADDRESS, [2] = ARG_ADDRESS },
	.argname = { [0] = "which_clock", [1] = "timer_event_spec", [2] = "create_timer_id" },
	.arg_params[0].list = ARGLIST(clock_ids),
	.sanitise = timer_create_sanitise,
};
