/*
 * SYSCALL_DEFINE4(mq_open, const char __user *, u_name, int, oflag, mode_t, mode, struct mq_attr __user *, u_attr)
 */
#include <fcntl.h>
#include <mqueue.h>
#include <string.h>
#include "random.h"
#include "sanitise.h"

static unsigned long mq_open_flags[] = {
	O_RDONLY, O_WRONLY, O_RDWR,
	O_CREAT, O_EXCL, O_NONBLOCK,
};

static void sanitise_mq_open(struct syscallrecord *rec)
{
	struct mq_attr *attr;
	char *name;

	/* Generate a valid mq name: must start with '/' */
	name = (char *) get_writable_address(32);
	name[0] = '/';
	name[1] = 't';
	name[2] = 'r';
	name[3] = 'i';
	name[4] = 'n';
	name[5] = '0' + (rand() % 10);
	name[6] = '\0';

	attr = (struct mq_attr *) get_writable_address(sizeof(*attr));
	memset(attr, 0, sizeof(*attr));

	switch (rand() % 3) {
	case 0:	/* small queue */
		attr->mq_maxmsg = 1;
		attr->mq_msgsize = 1;
		break;
	case 1: /* typical */
		attr->mq_maxmsg = 10;
		attr->mq_msgsize = 8192;
		break;
	default: /* boundary */
		attr->mq_maxmsg = 1 + (rand() % 256);
		attr->mq_msgsize = 1 + (rand() % 65536);
		break;
	}

	if (RAND_BOOL())
		attr->mq_flags = O_NONBLOCK;

	rec->a1 = (unsigned long) name;
	rec->a4 = (unsigned long) attr;
}

struct syscallentry syscall_mq_open = {
	.name = "mq_open",
	.group = GROUP_IPC,
	.num_args = 4,
	.argtype = { [1] = ARG_LIST, [2] = ARG_MODE_T },
	.argname = { [0] = "u_name", [1] = "oflag", [2] = "mode", [3] = "u_attr" },
	.arg_params[1].list = ARGLIST(mq_open_flags),
	.rettype = RET_FD,
	.sanitise = sanitise_mq_open,
};
