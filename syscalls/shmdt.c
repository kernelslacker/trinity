/*
 * SYSCALL_DEFINE1(shmdt, char __user *, shmaddr)
 */
#include <sys/shm.h>
#include "sanitise.h"

/*
 * shmdt requires shmaddr to be a return value from a prior shmat call.
 * Attempt shmat with a random shmid; if it succeeds, pass the returned
 * address to shmdt so the kernel actually exercises the detach path.
 */
static void *shmdt_shmat_addr;

static void sanitise_shmdt(struct syscallrecord *rec)
{
	void *addr;

	shmdt_shmat_addr = NULL;
	addr = shmat(rand() % 65536, NULL, 0);
	if (addr != (void *) -1) {
		shmdt_shmat_addr = addr;
		rec->a1 = (unsigned long) addr;
	}
}

static void post_shmdt(struct syscallrecord *rec)
{
	/* If shmdt failed and we attached a segment in sanitise, detach it. */
	if (shmdt_shmat_addr != NULL && rec->retval != 0)
		shmdt(shmdt_shmat_addr);
	shmdt_shmat_addr = NULL;
}

struct syscallentry syscall_shmdt = {
	.name = "shmdt",
	.group = GROUP_IPC,
	.num_args = 1,
	.argtype = { [0] = ARG_ADDRESS },
	.argname = { [0] = "shmaddr" },
	.sanitise = sanitise_shmdt,
	.post = post_shmdt,
};
