/*
 * SYSCALL_DEFINE3(mq_getsetattr, mqd_t, mqdes,
	const struct mq_attr __user *, u_mqstat,
	struct mq_attr __user *, u_omqstat)
 */
#include <fcntl.h>
#include <mqueue.h>
#include <string.h>
#include "random.h"
#include "sanitise.h"

static void sanitise_mq_getsetattr(struct syscallrecord *rec)
{
	struct mq_attr *mqstat, *omqstat;

	mqstat = (struct mq_attr *) get_writable_address(sizeof(*mqstat));
	memset(mqstat, 0, sizeof(*mqstat));

	/* Only mq_flags is settable: O_NONBLOCK or 0. */
	if (RAND_BOOL())
		mqstat->mq_flags = O_NONBLOCK;

	omqstat = (struct mq_attr *) get_writable_address(sizeof(*omqstat));

	rec->a2 = (unsigned long) mqstat;
	rec->a3 = (unsigned long) omqstat;
}

struct syscallentry syscall_mq_getsetattr = {
	.name = "mq_getsetattr",
	.group = GROUP_IPC,
	.num_args = 3,
	.argtype = { [0] = ARG_FD_MQ },
	.argname = { [0] = "mqdes", [1] = "u_mqstat", [2] = "u_omqstat" },
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.sanitise = sanitise_mq_getsetattr,
};
