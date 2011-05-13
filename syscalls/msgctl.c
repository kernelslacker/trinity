/*
 * SYSCALL_DEFINE3(msgctl, int, msqid, int, cmd, struct msqid_ds __user *, buf)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_msgctl = {
	.name = "msgctl",
	.num_args = 3,
	.arg1name = "msqid",
	.arg2name = "cmd",
	.arg3name = "buf",
	.arg3type = ARG_ADDRESS,
};
