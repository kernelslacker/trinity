/*
 * SYSCALL_DEFINE5(mq_timedreceive, mqd_t, mqdes, char __user *, u_msg_ptr,
	size_t, msg_len, unsigned int __user *, u_msg_prio,
	const struct timespec __user *, u_abs_timeout)
 */
#include <stdint.h>
#include "output-poison.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"
#include "utils-alloc.h"
#include "utils-mem.h"

/*
 * Snapshot of the u_msg_prio user pointer plus the fixed poison
 * pattern stamped into it, captured at sanitise time and consumed by
 * post_mq_timedreceive.  Lives in rec->post_state, a slot the syscall
 * ABI does not expose, so a sibling scribbling rec->a4 between the
 * syscall returning and the post handler running cannot redirect the
 * poison check against an unrelated heap page whose residual bytes
 * happen to still match the fixed pattern.  A poison_seed of 0 means
 * the sanitise-time writability check refused to stamp for this call
 * (writable-pool draw no longer provably mapped after
 * avoid_shared_buffer_out) and the post handler must no-op the
 * untouched-buffer arm.  addr == 0 signals u_msg_prio was NULL (the
 * caller opted out of receiving the priority word) -- the post
 * handler no-ops that case too since there is nothing to check.
 */
#define MQ_TIMEDRECEIVE_POST_STATE_MAGIC	0x4d515452UL	/* "MQTR" */
#define MQ_TIMEDRECEIVE_POISON_PATTERN		0xB4E3B4E3B4E3B4E3ULL

struct mq_timedreceive_post_state {
	unsigned long magic;
	unsigned long addr;
	uint64_t poison_seed;
};

static void sanitise_mq_timedreceive(struct syscallrecord *rec)
{
	struct mq_timedreceive_post_state *snap;
	char *msg;
	unsigned int *prio;
	unsigned int len;
	void *buf;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a
	 * stale pointer carried over from an earlier syscall on this
	 * record.
	 */
	rec->post_state = 0;

	/* Provide a receive buffer. */
	len = 1 + (rnd_modulo_u32(8192));
	msg = (char *) get_writable_address(len);

	/* Writable priority output. */
	prio = (unsigned int *) get_writable_address(sizeof(*prio));

	if (msg == NULL || prio == NULL)
		return;

	rec->a2 = (unsigned long) msg;
	rec->a3 = len;
	rec->a4 = (unsigned long) prio;

	avoid_shared_buffer_out(&rec->a2, rec->a3);
	avoid_shared_buffer_out(&rec->a4, sizeof(unsigned int));

	/*
	 * a5 (u_abs_timeout) is typed ARG_TIMESPEC; the generator
	 * publishes a writable pool buffer (or NULL ~10%) for us.
	 * NEED_ALARM caps any blocking arm a large tv_sec bucket
	 * would otherwise produce.
	 */

	/*
	 * Stamp a fixed poison pattern into the unsigned int the kernel
	 * writes u_msg_prio to on success.  The post handler compares
	 * the buffer byte-for-byte against the same pattern; a match
	 * after a rec->retval >= 0 return means the kernel skipped
	 * copy_to_user() for the priority word entirely -- the syscall
	 * contract is to write the received message's priority to
	 * *u_msg_prio on any success return where u_msg_prio is
	 * non-NULL.  Pattern is a fixed non-zero magic (not rnd_u64())
	 * so the sanitise pass draws no RNG bytes on this leg:
	 * --dry-run output with a fixed seed stays byte-identical to a
	 * build without this oracle so cross-tree replays and
	 * fixed-seed corpus regeneration are unaffected.  Snapshot
	 * rec->a4 into snap so a sibling scribble of the ABI slot
	 * between syscall return and post entry cannot redirect the
	 * check.  Gate on range_readable_user() so a writable-pool draw
	 * that avoid_shared_buffer_out() moved to an address no longer
	 * provably mapped does not SIGSEGV the sanitiser inside
	 * poison_output_struct's byte-walk; on skip poison_seed stays 0
	 * and the post handler no-ops the arm.  The msg buffer (a2) is
	 * deliberately not poisoned: its content is variable / arbitrary
	 * (mq_receive returns whatever bytes the sender enqueued), so
	 * poisoning it would false-positive whenever the sender's
	 * payload happened to match the pattern.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic       = MQ_TIMEDRECEIVE_POST_STATE_MAGIC;
	snap->addr        = rec->a4;
	snap->poison_seed = 0;

	buf = (void *)(unsigned long) rec->a4;
	if (range_readable_user(buf, sizeof(unsigned int)))
		snap->poison_seed =
			poison_output_struct(buf,
					     sizeof(unsigned int),
					     MQ_TIMEDRECEIVE_POISON_PATTERN);

	post_state_install(rec, snap);
}

/*
 * Oracle: mq_timedreceive on success returns the number of bytes
 * received (>= 0) and, when u_msg_prio is non-NULL, writes the
 * message priority (an unsigned int) to *u_msg_prio.  A
 * byte-identical match against the fixed poison pattern after a
 * success return means the kernel skipped that copy_to_user()
 * entirely; bump the shared post_handler_untouched_out_buf counter.
 * Error returns (retval < 0) and calls where sanitise refused to
 * stamp (poison_seed == 0) or the u_msg_prio pointer is NULL
 * (snap->addr == 0) stay silent.  Measure-only: no re-issue, no
 * argument mutation, no oracle output beyond the counter bump.
 */
static void post_mq_timedreceive(struct syscallrecord *rec)
{
	struct mq_timedreceive_post_state *snap;

	snap = post_state_claim_owned(rec, MQ_TIMEDRECEIVE_POST_STATE_MAGIC,
				      __func__);
	if (snap == NULL)
		return;

	if ((long) rec->retval < 0)
		goto out_release;

	if (snap->addr != 0 && snap->poison_seed != 0 &&
	    check_output_struct_user_or_skip((void *)(unsigned long) snap->addr,
					     sizeof(unsigned int),
					     snap->poison_seed))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

out_release:
	post_state_release(rec, snap);
}

struct syscallentry syscall_mq_timedreceive = {
	.name = "mq_timedreceive",
	.group = GROUP_IPC,
	.num_args = 5,
	.argtype = { [0] = ARG_FD_MQ, [1] = ARG_ADDRESS, [2] = ARG_LEN, [3] = ARG_ADDRESS, [4] = ARG_TIMESPEC },
	.argname = { [0] = "mqdes", [1] = "u_msg_ptr", [2] = "msg_len", [3] = "u_msg_prio", [4] = "u_abs_timeout" },
	.flags = NEED_ALARM,
	.sanitise = sanitise_mq_timedreceive,
	.post = post_mq_timedreceive,
	.bound_arg = 3,
	.rettype = RET_NUM_BYTES,
};
