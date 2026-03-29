/*
 * SYSCALL_DEFINE3(shmat, int, shmid, char __user *, shmaddr, int, shmflg)
 */
#include <sys/shm.h>
#include "arch.h"
#include "random.h"
#include "sanitise.h"

static unsigned long shmat_flags[] = {
	SHM_RDONLY, SHM_RND,
};

static void sanitise_shmat(struct syscallrecord *rec)
{
	/*
	 * shmaddr must be NULL (kernel chooses) or page-aligned.
	 * Non-aligned addresses return EINVAL unless SHM_RND is set.
	 * Use NULL 80% of the time for better success rate.
	 */
	if (rand() % 5 != 0)
		rec->a2 = 0;
	else
		rec->a2 = (unsigned long) get_map() & PAGE_MASK;
}

struct syscallentry syscall_shmat = {
	.name = "shmat",
	.group = GROUP_IPC,
	.num_args = 3,
	.argtype = { [0] = ARG_RANGE, [2] = ARG_LIST },
	.argname = { [0] = "shmid", [1] = "shmaddr", [2] = "shmflg" },
	.low1range = 0,
	.hi1range = 65535,
	.arg3list = ARGLIST(shmat_flags),
	.sanitise = sanitise_shmat,
};
