/*
 * SYSCALL_DEFINE1(mq_unlink, const char __user *, u_name)
 */
#include <stdlib.h>
#include "sanitise.h"

static void sanitise_mq_unlink(struct syscallrecord *rec)
{
	char *name;

	/* POSIX MQ names must start with '/' */
	name = (char *) get_writable_address(8);
	name[0] = '/';
	name[1] = 't';
	name[2] = 'r';
	name[3] = 'i';
	name[4] = 'n';
	name[5] = '0' + (rand() % 10);
	name[6] = '\0';

	rec->a1 = (unsigned long) name;
}

struct syscallentry syscall_mq_unlink = {
	.name = "mq_unlink",
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_IPC,
	.num_args = 1,
	.argtype = { [0] = ARG_ADDRESS },
	.argname = { [0] = "u_name" },
	.sanitise = sanitise_mq_unlink,
};
