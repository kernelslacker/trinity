/*
 * SYSCALL_DEFINE2(mq_notify, mqd_t, mqdes, const struct sigevent __user *, u_notification)
 */
#include <signal.h>
#include <string.h>
#include "random.h"
#include "sanitise.h"

static void sanitise_mq_notify(struct syscallrecord *rec)
{
	struct sigevent *sev;

	/* Half the time pass NULL to deregister notification. */
	if (RAND_BOOL()) {
		rec->a2 = 0;
		return;
	}

	sev = (struct sigevent *) get_writable_address(sizeof(*sev));
	memset(sev, 0, sizeof(*sev));

	switch (rand() % 3) {
	case 0:
		sev->sigev_notify = SIGEV_NONE;
		break;
	case 1:
		sev->sigev_notify = SIGEV_SIGNAL;
		sev->sigev_signo = 1 + (rand() % 31);
		break;
	default:
		sev->sigev_notify = SIGEV_THREAD;
		sev->sigev_signo = 1 + (rand() % 31);
		break;
	}

	rec->a2 = (unsigned long) sev;
}

struct syscallentry syscall_mq_notify = {
	.name = "mq_notify",
	.group = GROUP_IPC,
	.num_args = 2,
	.argtype = { [0] = ARG_FD_MQ },
	.argname = { [0] = "mqdes", [1] = "u_notification" },
	.flags = NEED_ALARM,
	.sanitise = sanitise_mq_notify,
};
