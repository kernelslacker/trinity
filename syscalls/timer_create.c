/*
 * SYSCALL_DEFINE3(timer_create, const clockid_t, which_clock,
	struct sigevent __user *, timer_event_spec,
	timer_t __user *, created_timer_id)
 */
#include <signal.h>

#include "sanitise.h"
#include "random.h"

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
}

struct syscallentry syscall_timer_create = {
	.name = "timer_create",
	.num_args = 3,
	.arg1name = "which_clock",
	.arg2name = "timer_event_spec",
	.arg2type = ARG_ADDRESS,
	.arg3name = "create_timer_id",
	.arg3type = ARG_ADDRESS,
	.sanitise = timer_create_sanitise,
};
