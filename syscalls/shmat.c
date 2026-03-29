/*
 * SYSCALL_DEFINE3(shmat, int, shmid, char __user *, shmaddr, int, shmflg)
 */
#include <sys/shm.h>
#include "sanitise.h"

static unsigned long shmat_flags[] = {
	SHM_RDONLY, SHM_RND,
};

struct syscallentry syscall_shmat = {
	.name = "shmat",
	.group = GROUP_IPC,
	.num_args = 3,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_ADDRESS, [2] = ARG_LIST },
	.argname = { [0] = "shmid", [1] = "shmaddr", [2] = "shmflg" },
	.low1range = 0,
	.hi1range = 65535,
	.arg3list = ARGLIST(shmat_flags),
};
