/*
 * SYSCALL_DEFINE3(semop, int, semid, struct sembuf __user *, tsops, unsigned, nsops)
 */
#include <sys/sem.h>
#include "random.h"
#include "sanitise.h"

#define MAX_SOPS 8

static void fill_sembuf_array(struct sembuf *sops, unsigned int nsops)
{
	unsigned int i;

	for (i = 0; i < nsops; i++) {
		sops[i].sem_num = rand() % 32;
		switch (rand() % 4) {
		case 0: sops[i].sem_op = 1; break;		/* V (release) */
		case 1: sops[i].sem_op = -1; break;		/* P (acquire) */
		case 2: sops[i].sem_op = 0; break;		/* wait-for-zero */
		default: sops[i].sem_op = (rand() % 20) - 10; break;
		}
		sops[i].sem_flg = 0;
		if (RAND_BOOL())
			sops[i].sem_flg |= IPC_NOWAIT;
		if (RAND_BOOL())
			sops[i].sem_flg |= SEM_UNDO;
	}
}

static void sanitise_semop(struct syscallrecord *rec)
{
	struct sembuf *sops;
	unsigned int nsops;

	nsops = 1 + (rand() % MAX_SOPS);
	sops = (struct sembuf *) get_writable_address(nsops * sizeof(*sops));
	fill_sembuf_array(sops, nsops);

	rec->a2 = (unsigned long) sops;
	rec->a3 = nsops;
}

struct syscallentry syscall_semop = {
	.name = "semop",
	.group = GROUP_IPC,
	.num_args = 3,
	.argtype = { [0] = ARG_RANGE },
	.argname = { [0] = "semid", [1] = "tsops", [2] = "nsops" },
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = 65535,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.sanitise = sanitise_semop,
};
