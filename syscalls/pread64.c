/*
 * SYSCALL_DEFINE(pread64)(unsigned int fd, char __user *buf, size_t count, loff_t pos)
 */
#include "random.h"
#include "sanitise.h"
#include "shm.h"

static void sanitise_pread64(int childno)
{

retry_pos:
	if ((int) shm->syscall[childno].a4 < 0) {
		shm->syscall[childno].a4 = rand64();
		goto retry_pos;
	}
}

struct syscallentry syscall_pread64 = {
	.name = "pread64",
	.num_args = 4,
	.sanitise = sanitise_pread64,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "buf",
	.arg2type = ARG_ADDRESS,
	.arg3name = "count",
	.arg3type = ARG_LEN,
	.arg4name = "pos",
	.flags = NEED_ALARM,
};
