/*
 * SYSCALL_DEFINE5(msgrcv, int, msqid, struct msgbuf __user *, msgp, size_t, msgsz, long, msgtyp, int, msgflg)
 */
#include <stdint.h>
#include <linux/msg.h>
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "utils.h"

#include "kernel/socket.h"
/*
 * Mirror of msgsnd's payload-size picker (kept local to avoid an
 * msgsnd <-> msgrcv shared-header just for two callers).  Used by the
 * "inherits msgsnd's distribution" tail bucket below so the rcv-side
 * size distribution matches what the snd side actually puts on the
 * queue.
 */
static size_t pick_msgsnd_like_msgsz(void)
{
	uint32_t pick = rnd_modulo_u32(100);

	if (pick < 15)
		return 0;
	if (pick < 40)
		return 1 + rnd_modulo_u32(64);
	if (pick < 65)
		return 256 + rnd_modulo_u32(4096 - 256 + 1);
	if (pick < 85) {
		size_t lo = (MSGMAX > 1024) ? (size_t) MSGMAX - 1024 : 0;
		return lo + rnd_modulo_u32((uint32_t) (MSGMAX - lo + 1));
	}
	return rnd_modulo_u32(MSGMAX + 1);
}

/*
 * msgsz buckets.  msgsnd seeds the queue with mostly small or
 * page-sized payloads (see syscalls/msgsnd.c); a flat rnd_modulo_u32
 * draw rarely matches any of them, so the queue churns through
 * fuzz-discard paths and never exercises a successful receive.
 *
 *  30% exact-sent-size  256..4096 (matches msgsnd's typical bucket)
 *  25% undersized       1..64 with MSG_NOERROR cleared (E2BIG path)
 *  15% zero-length      0
 *  30% inherits msgsnd's full size distribution
 *
 * Returns the chosen msgsz; for the undersized bucket, *flags_out has
 * MSG_NOERROR cleared so the kernel returns -E2BIG instead of silently
 * truncating.
 */
static size_t pick_msgrcv_msgsz(unsigned long *flags_out)
{
	uint32_t pick = rnd_modulo_u32(100);

	if (pick < 30)
		return 256 + rnd_modulo_u32(4096 - 256 + 1);
	if (pick < 55) {
		*flags_out &= ~(unsigned long) MSG_NOERROR;
		return 1 + rnd_modulo_u32(64);
	}
	if (pick < 70)
		return 0;
	return pick_msgsnd_like_msgsz();
}

/*
 * msgtyp buckets.  ARG_RANGE 0..10 gives flat coverage over a tiny
 * window that misses both the any-message (msgtyp=0) fast path and
 * the lowest-mtype-<=|msgtyp| negative path entirely.
 *
 *  30% msgtyp=0             (any message)
 *  30% positive 1..255      (paired with msgsnd's mtype band)
 *  20% negative -1..-255    (lowest mtype <= |msgtyp|)
 *  10% MSG_COPY index 0..7  with msgflg |= MSG_COPY
 *  10% random long
 *
 * Sets *flags_out's MSG_COPY bit when the MSG_COPY bucket fires.
 */
static long pick_msgrcv_msgtyp(unsigned long *flags_out)
{
	uint32_t pick = rnd_modulo_u32(100);

	if (pick < 30)
		return 0;
	if (pick < 60)
		return 1 + (long) rnd_modulo_u32(255);
	if (pick < 80)
		return -(1 + (long) rnd_modulo_u32(255));
	if (pick < 90) {
		*flags_out |= MSG_COPY;
		return (long) rnd_modulo_u32(8);
	}
	return (long) rnd_u64();
}

static void sanitise_msgrcv(struct syscallrecord *rec)
{
	unsigned long flags = rec->a5;

	rec->a3 = pick_msgrcv_msgsz(&flags);
	rec->a4 = (unsigned long) pick_msgrcv_msgtyp(&flags);
	rec->a5 = flags;
	avoid_shared_buffer_out(&rec->a2, rec->a3 + sizeof(long));
}

static unsigned long msgrcv_flags[] = {
	MSG_NOERROR, MSG_EXCEPT, MSG_COPY, IPC_NOWAIT,
};

struct syscallentry syscall_msgrcv = {
	.name = "msgrcv",
	.group = GROUP_IPC,
	.num_args = 5,
	.argtype = { [0] = ARG_MSG_ID, [1] = ARG_NON_NULL_ADDRESS, [2] = ARG_LEN, [3] = ARG_RANGE, [4] = ARG_LIST },
	.argname = { [0] = "msqid", [1] = "msgp", [2] = "msgsz", [3] = "msgtyp", [4] = "msgflg" },
	.arg_params[3].range.low = 0,
	.arg_params[3].range.hi = 10,
	.arg_params[4].list = ARGLIST(msgrcv_flags),
	.flags = IGNORE_ENOSYS | NEED_ALARM,
	.sanitise = sanitise_msgrcv,
	.bound_arg = 3,
};
