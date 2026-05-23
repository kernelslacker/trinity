/*
 * SYSCALL_DEFINE4(semtimedop, int, semid, struct sembuf __user *, tsops,
	 unsigned, nsops, const struct timespec __user *, timeout)
 */
#include <stdint.h>
#include <sys/sem.h>
#include <time.h>
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
#define SEMTIMEDOP_FALLBACK_NSEMS	32

/*
 * Pool-aware sem_num pick.  See sanitise_semop() for the rationale --
 * the pre-existing rnd_modulo_u32(32) was nsems-blind, and the split
 * below makes both the success and EFBIG paths reachable in a known
 * ratio (70% in [0, nsems-1], 30% out-of-range).
 */
static unsigned int lookup_sysv_sem_nsems(int semid __unused__)
{
	return SEMTIMEDOP_FALLBACK_NSEMS;
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
		case 0: sops[i].sem_op = 1; break;
		case 1: sops[i].sem_op = -1; break;
		case 2: sops[i].sem_op = 0; break;
		default: sops[i].sem_op = (rnd_modulo_u32(20)) - 10; break;
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
	bool null_timeout;

	nsops = 1 + (rnd_modulo_u32(MAX_SOPS));
	sops = (struct sembuf *) get_writable_address(nsops * sizeof(*sops));

	/*
	 * 25% NULL timeout.  The pre-existing code always handed in a
	 * non-NULL timespec capped at <1ms, which means the kernel
	 * never reached its "timeout == NULL" branch -- that arm has
	 * its own copy_from_user / hrtimer-setup elision and is
	 * worth exercising.  The remaining 75% keeps the short
	 * timeout shape (still <1ms) so the syscall doesn't actually
	 * block on a contended sem -- NEED_ALARM still caps the
	 * NULL-timeout arm if it does block.
	 */
	null_timeout = (rnd_modulo_u32(100) < 25);
	ts = NULL;
	if (!null_timeout) {
		ts = (struct timespec *) get_writable_address(sizeof(*ts));
		if (ts == NULL)
			return;
	}
	if (sops == NULL)
		return;

	fill_sembuf_array(sops, nsops, (int) rec->a1);

	rec->a2 = (unsigned long) sops;
	avoid_shared_buffer_inout(&rec->a2, nsops * sizeof(struct sembuf));
	rec->a3 = nsops;

	if (ts != NULL) {
		ts->tv_sec = 0;
		ts->tv_nsec = rnd_modulo_u32(1000000);	/* up to 1ms */
		rec->a4 = (unsigned long) ts;
		avoid_shared_buffer_inout(&rec->a4, sizeof(struct timespec));
	} else {
		rec->a4 = 0;
	}
}

struct syscallentry syscall_semtimedop = {
	.name = "semtimedop",
	.group = GROUP_IPC,
	.num_args = 4,
	.argtype = { [0] = ARG_SEM_ID },
	.argname = { [0] = "semid", [1] = "tsops", [2] = "nsops", [3] = "timeout" },
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.sanitise = sanitise_semtimedop,
};
