/*
 * SYSCALL_DEFINE5(msgrcv, int, msqid, struct msgbuf __user *, msgp, size_t, msgsz, long, msgtyp, int, msgflg)
 */
#include <stdint.h>
#include <linux/msg.h>
#include "output-poison.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"
#include "utils-alloc.h"
#include "utils-mem.h"

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

/*
 * Snapshot of the msgp user pointer plus the fixed poison pattern
 * stamped into its leading 8-byte mtype word, captured at sanitise
 * time and consumed by post_msgrcv.  Lives in rec->post_state, a slot
 * the syscall ABI does not expose, so a sibling scribbling rec->a2
 * between syscall return and post entry cannot redirect the poison
 * check against an unrelated heap page whose residual bytes happen to
 * still match the fixed pattern.  A poison_seed of 0 means the
 * sanitise-time writability check refused to stamp for this call
 * (writable-pool draw no longer provably mapped after
 * avoid_shared_buffer_out) and the post handler no-ops the arm.  addr
 * of 0 signals msgp was NULL and the post handler no-ops that case
 * too since there is nothing to check.
 */
#define MSGRCV_POST_STATE_MAGIC		0x4d534752UL	/* "MSGR" */
#define MSGRCV_POISON_PATTERN		0xC5A7C5A7C5A7C5A7ULL

struct msgrcv_post_state {
	unsigned long magic;
	unsigned long addr;
	uint64_t poison_seed;
};

static void sanitise_msgrcv(struct syscallrecord *rec)
{
	struct msgrcv_post_state *snap;
	unsigned long flags = rec->a5;
	void *buf;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a
	 * stale pointer carried over from an earlier syscall on this
	 * record.
	 */
	rec->post_state = 0;

	rec->a3 = pick_msgrcv_msgsz(&flags);
	rec->a4 = (unsigned long) pick_msgrcv_msgtyp(&flags);
	rec->a5 = flags;
	avoid_shared_buffer_out(&rec->a2, rec->a3 + sizeof(long));

	/*
	 * Stamp a fixed poison pattern into the leading 8-byte mtype
	 * word the kernel writes on success.  The post handler compares
	 * that word byte-for-byte against the same pattern; a match
	 * after a rec->retval >= 0 return means the kernel skipped
	 * copy_to_user() for the mtype word entirely -- the syscall
	 * contract writes the received message's mtype to *msgp on any
	 * success return.  Pattern is a fixed non-zero magic (not
	 * rnd_u64()) so the sanitise pass draws no RNG bytes on this
	 * leg: --dry-run output with a fixed seed stays byte-identical
	 * to a build without this oracle so cross-tree replays and
	 * fixed-seed corpus regeneration are unaffected.  Snapshot
	 * rec->a2 into snap so a sibling scribble of the ABI slot
	 * between syscall return and post entry cannot redirect the
	 * check.  Gate on range_readable_user() so a writable-pool draw
	 * that avoid_shared_buffer_out() moved to an address no longer
	 * provably mapped does not SIGSEGV the sanitiser inside
	 * poison_output_struct's byte-walk; on skip poison_seed stays 0
	 * and the post handler no-ops the arm.  The variable-length
	 * mtext payload after the mtype word is deliberately not
	 * poisoned: msgrcv returns whatever bytes the sender enqueued,
	 * so poisoning it would false-positive whenever the sender's
	 * payload happened to match the pattern.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic       = MSGRCV_POST_STATE_MAGIC;
	snap->addr        = rec->a2;
	snap->poison_seed = 0;

	if (rec->a2 != 0) {
		buf = (void *)(unsigned long) rec->a2;
		if (range_readable_user(buf, sizeof(long)))
			snap->poison_seed =
				poison_output_struct(buf,
						     sizeof(long),
						     MSGRCV_POISON_PATTERN);
	}

	post_state_install(rec, snap);
}

/*
 * Oracle: msgrcv on success returns the number of bytes copied into
 * mtext (>= 0) and always writes the received message's mtype (a
 * leading `long`) to *msgp.  A byte-identical match of that leading
 * 8-byte word against the fixed poison pattern after a success
 * return means the kernel skipped that copy_to_user() entirely; bump
 * the shared post_handler_untouched_out_buf counter.  Error returns
 * (retval < 0) and calls where sanitise refused to stamp
 * (poison_seed == 0) or the msgp pointer was NULL (snap->addr == 0)
 * stay silent.  Only the fixed 8-byte mtype word is checked; the
 * variable mtext payload carries arbitrary sender bytes and would
 * false-positive.  Measure-only: no re-issue, no argument mutation,
 * no oracle output beyond the counter bump.
 */
static void post_msgrcv(struct syscallrecord *rec)
{
	struct msgrcv_post_state *snap;

	snap = post_state_claim_owned(rec, MSGRCV_POST_STATE_MAGIC,
				      __func__);
	if (snap == NULL)
		return;

	if ((long) rec->retval < 0)
		goto out_release;

	if (snap->addr != 0 && snap->poison_seed != 0 &&
	    check_output_struct_user_or_skip((void *)(unsigned long) snap->addr,
					     sizeof(long),
					     snap->poison_seed))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

out_release:
	post_state_release(rec, snap);
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
	.post = post_msgrcv,
	.bound_arg = 3,
};
