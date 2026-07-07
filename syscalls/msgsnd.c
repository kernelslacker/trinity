/*
 * SYSCALL_DEFINE4(msgsnd, int, msqid, struct msgbuf __user *, msgp, size_t, msgsz, int, msgflg)
 */
#include <stddef.h>
#include <linux/msg.h>
#include "rnd.h"
#include "sanitise.h"
#include "deferred-free.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/socket.h"
static unsigned long msgsnd_flags[] = {
	MSG_NOERROR, MSG_EXCEPT, MSG_COPY, IPC_NOWAIT,
};

/*
 * Payload-size buckets.  A flat rnd_modulo_u32(256) draw piles >99% of
 * sends into the 0..255 byte range, so the empty-message fast path,
 * the page-sized typical case and the near-MSGMAX boundary all stay
 * cold.  The buckets below split sends across those regimes
 * explicitly while keeping a random tail so the validator still sees
 * the full size distribution.
 */
static size_t pick_msgsnd_msgsz(void)
{
	uint32_t pick = rnd_modulo_u32(100);

	if (pick < 15)
		return 0;				/* empty-message fast path */
	if (pick < 40)
		return 1 + rnd_modulo_u32(64);		/* small */
	if (pick < 65)
		return 256 + rnd_modulo_u32(4096 - 256 + 1);	/* page-sized typical */
	if (pick < 85) {
		/* near MSGMAX: last ~1KiB window, clamped to MSGMAX. */
		size_t lo = (MSGMAX > 1024) ? (size_t) MSGMAX - 1024 : 0;
		return lo + rnd_modulo_u32((uint32_t) (MSGMAX - lo + 1));
	}
	return rnd_modulo_u32(MSGMAX + 1);		/* keep the validator warm */
}

static void sanitise_msgsnd(struct syscallrecord *rec)
{
	struct msgbuf *msgp;
	size_t msgsz = pick_msgsnd_msgsz();

	msgp = zmalloc_tracked(sizeof(struct msgbuf) + msgsz);
	msgp->mtype = (rnd_modulo_u32(255)) + 1;	/* mtype must be > 0 */
	rec->a2 = (unsigned long) msgp;
	avoid_shared_buffer_inout(&rec->a2, sizeof(struct msgbuf) + msgsz);
	rec->a3 = msgsz;
	/* Capture the genuine tracked pointer now: a2 may be scribbled by a
	 * sibling syscall before the owned-list drain runs. */
	rec_own(rec, msgp);
}

struct syscallentry syscall_msgsnd = {
	.name = "msgsnd",
	.group = GROUP_IPC,
	.num_args = 4,
	.argtype = { [0] = ARG_MSG_ID, [1] = ARG_ADDRESS, [2] = ARG_LEN, [3] = ARG_LIST },
	.argname = { [0] = "msqid", [1] = "msgp", [2] = "msgsz", [3] = "msgflg" },
	.arg_params[3].list = ARGLIST(msgsnd_flags),
	.flags = NEED_ALARM,
	.sanitise = sanitise_msgsnd,
};
