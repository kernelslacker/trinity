/*
 * SYSCALL_DEFINE4(semtimedop, int, semid, struct sembuf __user *, tsops,
	 unsigned, nsops, const struct timespec __user *, timeout)
 */
#include <sys/sem.h>
#include <time.h>
#include "random.h"
#include "sanitise.h"

#define MAX_SOPS 8

static void fill_sembuf_array(struct sembuf *sops, unsigned int nsops)
{
	unsigned int i;

	for (i = 0; i < nsops; i++) {
		sops[i].sem_num = rand() % 32;
		switch (rand() % 4) {
		case 0: sops[i].sem_op = 1; break;
		case 1: sops[i].sem_op = -1; break;
		case 2: sops[i].sem_op = 0; break;
		default: sops[i].sem_op = (rand() % 20) - 10; break;
		}
		sops[i].sem_flg = 0;
		if (RAND_BOOL())
			sops[i].sem_flg |= IPC_NOWAIT;
		if (RAND_BOOL())
			sops[i].sem_flg |= SEM_UNDO;
	}
}

static void sanitise_semtimedop(struct syscallrecord *rec)
{
	struct sembuf *sops;
	struct timespec *ts;
	unsigned int nsops;

	nsops = 1 + (rand() % MAX_SOPS);
	sops = (struct sembuf *) get_writable_address(nsops * sizeof(*sops));
	fill_sembuf_array(sops, nsops);

	rec->a2 = (unsigned long) sops;
	rec->a3 = nsops;

	/* Short timeout to avoid blocking. */
	ts = (struct timespec *) get_writable_address(sizeof(*ts));
	ts->tv_sec = 0;
	ts->tv_nsec = rand() % 1000000;	/* up to 1ms */
	rec->a4 = (unsigned long) ts;
}

struct syscallentry syscall_semtimedop = {
	.name = "semtimedop",
	.group = GROUP_IPC,
	.num_args = 4,
	.argtype = { [0] = ARG_RANGE },
	.argname = { [0] = "semid", [1] = "tsops", [2] = "nsops", [3] = "timeout" },
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = 65535,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.sanitise = sanitise_semtimedop,
};
