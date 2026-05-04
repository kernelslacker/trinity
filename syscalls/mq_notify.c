/*
 * SYSCALL_DEFINE2(mq_notify, mqd_t, mqdes, const struct sigevent __user *, u_notification)
 */
#include <mqueue.h>
#include <signal.h>
#include <string.h>
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"

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

static void post_mq_notify(struct syscallrecord *rec)
{
	/*
	 * A successful mq_notify with a non-NULL sevp installs a
	 * notification subscription on the message queue underlying mqdes.
	 * The subscription persists on the queue until it is explicitly
	 * removed (mq_notify with sevp=NULL on the same mqdes) or the queue
	 * itself is destroyed.  The OBJ_FD_MQ pool is OBJ_GLOBAL: queues
	 * are seeded once at init by fds/mq.c and outlive every child, so
	 * unregistered notifications accumulate on those queues for the
	 * full duration of the run.  Mirror the IPC_RMID-in-post pattern
	 * from semget/msgget and the cleanup post handler from
	 * inotify_add_watch: on a successful registering call, issue the
	 * matching deregister so the kernel state does not leak.
	 *
	 * sevp==NULL was already a deregistration; nothing to undo.  Read
	 * rec->a2 at post time without a snapshot: a sibling stomp could
	 * either flip a real registration into a skipped cleanup or trigger
	 * a redundant deregister, both bounded outcomes that do not warrant
	 * the extra post_state plumbing.
	 */
	if (rec->retval != 0)
		return;
	if (rec->a2 == 0)
		return;

	/*
	 * mqdes is an int fd in rec->a1.  looks_like_corrupted_ptr is the
	 * wrong shape here (fds and pointers share no value range), so do
	 * an explicit fd-sanity check: reject negative values and anything
	 * with high bits set, which is the pointer-scribble signature.  PID
	 * scribbles into the small-int fd range are not detectable here,
	 * but the kernel bounces those with EBADF.
	 */
	if ((long) rec->a1 < 0 || (unsigned long) rec->a1 >= 0x10000UL) {
		outputerr("post_mq_notify: rejected suspicious mqdes=%lu (pid-scribbled?)\n",
			  rec->a1);
		__atomic_add_fetch(&shm->stats.post_handler_corrupt_ptr, 1,
				   __ATOMIC_RELAXED);
		return;
	}

	mq_notify((int) rec->a1, NULL);
}

struct syscallentry syscall_mq_notify = {
	.name = "mq_notify",
	.group = GROUP_IPC,
	.num_args = 2,
	.argtype = { [0] = ARG_FD_MQ },
	.argname = { [0] = "mqdes", [1] = "u_notification" },
	.flags = NEED_ALARM,
	.sanitise = sanitise_mq_notify,
	.post = post_mq_notify,
};
