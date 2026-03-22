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
	.arg1name = "shmid",
	.arg2name = "shmaddr",
	.arg2type = ARG_ADDRESS,
	.arg3name = "shmflg",
	.arg3type = ARG_LIST,
	.arg3list = ARGLIST(shmat_flags),
};
