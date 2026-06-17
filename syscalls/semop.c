/*
 * SYSCALL_DEFINE3(semop, int, semid, struct sembuf __user *, tsops, unsigned, nsops)
 */
#include <stdint.h>
#include <sys/sem.h>
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "trinity.h"

#define MAX_SOPS 8

/*
 * Fallback nsems cap used when the producer-side pool entry doesn't
 * carry the chosen set's real nsems.  Matches the value used by
 * sanitise_semctl()'s semnum picker; today every lookup falls back
 * to this cap because sysvsemobj stashes only semid.
 */
#define SEMOP_FALLBACK_NSEMS	32

/*
 * Pool-aware sem_num pick.  The pre-existing rnd_modulo_u32(32) was
 * nsems-blind: it covered the typical small-set case by accident,
 * but split every pick 50/50 between in-range and out-of-range with
 * no oracle telling the fuzzer which side it landed on.  Split the
 * pick explicitly so both the sem_array success path and the EFBIG
 * out-of-range path are exercised in a known ratio.
 *
 *   70% in-range  [0, nsems-1]
 *   30% out-of-range nsems..nsems+63 (EFBIG path)
 *
 * The lookup_sysv_sem_nsems hook stays local to each file rather than
 * exporting a shared helper: the pool entry doesn't carry nsems
 * today, so every caller is on the fallback path -- when a future
 * sysvsemobj extension lands the nsems plumbing can be promoted to
 * a single shared helper at that point.
 */
static unsigned int lookup_sysv_sem_nsems(int semid __unused__)
{
	return SEMOP_FALLBACK_NSEMS;
}

static unsigned short pick_sem_num(int semid)
{
	unsigned int nsems = lookup_sysv_sem_nsems(semid);

	if (rnd_modulo_u32(100) < 70)
		return (unsigned short) rnd_modulo_u32(nsems);
	return (unsigned short) (nsems + rnd_modulo_u32(64));
}

static void fill_sembuf_array(struct sembuf *sops, unsigned int nsops, int semid)
{
	unsigned int i;

	for (i = 0; i < nsops; i++) {
		sops[i].sem_num = pick_sem_num(semid);
		switch (rnd_modulo_u32(4)) {
		case 0: sops[i].sem_op = 1; break;		/* V (release) */
		case 1: sops[i].sem_op = -1; break;		/* P (acquire) */
		case 2: sops[i].sem_op = 0; break;		/* wait-for-zero */
		default: sops[i].sem_op = (rnd_modulo_u32(20)) - 10; break;
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

	nsops = 1 + (rnd_modulo_u32(MAX_SOPS));
	sops = (struct sembuf *) get_writable_address(nsops * sizeof(*sops));
	if (sops == NULL)
		return;
	fill_sembuf_array(sops, nsops, (int) rec->a1);

	rec->a2 = (unsigned long) sops;
	avoid_shared_buffer_inout(&rec->a2, nsops * sizeof(struct sembuf));
	rec->a3 = nsops;
}

struct syscallentry syscall_semop = {
	.name = "semop",
	.group = GROUP_IPC,
	.num_args = 3,
	.argtype = { [0] = ARG_SEM_ID, [1] = ARG_ADDRESS, [2] = ARG_LEN },
	.argname = { [0] = "semid", [1] = "tsops", [2] = "nsops" },
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.sanitise = sanitise_semop,
};
