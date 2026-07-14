/*
 * SYSCALL_DEFINE4(wait4, pid_t, upid, int __user *, stat_addr,
	 int, options, struct rusage __user *, ru)
 */
#include <stdint.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include "output-poison.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"
#include "utils-alloc.h"
#include "utils-mem.h"

#include "kernel/wait.h"
static unsigned long wait_options[] = {
	WNOHANG, WUNTRACED, WCONTINUED, __WALL, __WCLONE, __WNOTHREAD,
};

/*
 * Snapshot of the sanitise-time stat_addr / ru slots and the poison
 * seeds stamped into each OUT-buffer, captured at sanitise time and
 * consumed by post_wait4.  Lives in rec->post_state so a sibling
 * scribble of rec->a2 / rec->a4 between syscall return and the post
 * handler running cannot redirect either poison check at a foreign
 * heap page.  Per-arm poison_seed of 0 means sanitise refused to
 * stamp that arm (NULL slot or the readable range gate refused after
 * avoid_shared_buffer_out) and the post handler no-ops that arm for
 * this call.
 */
#define WAIT4_POST_STATE_MAGIC		0x574149543400000CUL	/* "WAIT4\0\0\f" */
#define WAIT4_STAT_POISON		0x574149543453544FULL	/* "WAIT4STO" */
#define WAIT4_RU_POISON			0x574149543452554FULL	/* "WAIT4RUO" */

struct wait4_post_state {
	unsigned long magic;
	unsigned long stat_addr;
	unsigned long ru;
	uint64_t stat_poison_seed;
	uint64_t ru_poison_seed;
};

static void sanitise_wait4(struct syscallrecord *rec)
{
	struct wait4_post_state *snap;
	void *stat_addr;
	void *ru;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a
	 * stale pointer carried over from an earlier syscall on this
	 * record.
	 */
	rec->post_state = 0;

	avoid_shared_buffer_out(&rec->a2, sizeof(int));
	avoid_shared_buffer_out(&rec->a4, sizeof(struct rusage));

	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic             = WAIT4_POST_STATE_MAGIC;
	snap->stat_addr         = rec->a2;
	snap->ru                = rec->a4;
	snap->stat_poison_seed  = 0;
	snap->ru_poison_seed    = 0;

	/*
	 * Stamp fixed poison patterns into each OUT-buffer the kernel
	 * writes on a successful reap.  Fixed non-zero magics (not an
	 * RNG draw) keep sanitise's RNG consumption byte-identical
	 * between --dry-run and normal runs so a fixed-seed replay
	 * reproduces the same syscall stream.
	 *
	 * Each arm is independent: stat_addr and ru are both nullable
	 * (wait4 accepts NULL for either), and either buffer's
	 * avoid_shared_buffer_out relocation could land at an address
	 * that has since been munmapped.  Gate each arm separately on
	 * non-NULL slot AND range_readable_user so a failure on one arm
	 * does not disable the other.  On skip that arm's poison_seed
	 * stays 0 and the post handler no-ops it.
	 *
	 * sizeof(struct rusage) is 144 bytes on Linux x86_64, well
	 * under CHECK_OUTPUT_STRUCT_SNAP_MAX (512), so the post-side
	 * snapshot never truncates.
	 */
	stat_addr = (void *)(unsigned long) rec->a2;
	if (stat_addr != NULL && range_readable_user(stat_addr, sizeof(int)))
		snap->stat_poison_seed =
			poison_output_struct(stat_addr, sizeof(int),
					     WAIT4_STAT_POISON);

	ru = (void *)(unsigned long) rec->a4;
	if (ru != NULL && range_readable_user(ru, sizeof(struct rusage)))
		snap->ru_poison_seed =
			poison_output_struct(ru, sizeof(struct rusage),
					     WAIT4_RU_POISON);

	post_state_install(rec, snap);
}

/*
 * Kernel ABI: wait4() returns -1 on error, 0 when WNOHANG is set and no
 * child has changed state, or the reaped child pid in [1, PID_MAX_LIMIT
 * (4194304)] on success. *stat_addr and *ru are separate concerns; only
 * the retval is bound-checked here. Mirrors the pid-bound style used in
 * 547498ccfe16 (getpgrp) / edc0796b4cd7 (gettid) / 108b67820997 (getppid).
 *
 * Poison-writeback oracle: on retval > 0 (a child was reaped) the
 * kernel is contractually required to write *stat_addr and *ru when
 * the caller passed non-NULL for each.  A byte-identical survive of
 * the poison pattern across the checked window on either arm proves
 * the kernel reported a reap yet skipped copy_to_user for that
 * buffer -- a torn write, an early-exit before fill, or a compat
 * wrapper that forgets the store.  Arms are silent when sanitise
 * refused to stamp (poison_seed == 0) or the slot was NULL.
 */
static void post_wait4(struct syscallrecord *rec)
{
	struct wait4_post_state *snap;
	long ret = (long) rec->retval;

	snap = post_state_claim_owned(rec, WAIT4_POST_STATE_MAGIC,
				      __func__);
	if (snap == NULL)
		return;

	if (ret == -1L || ret == 0)
		goto out_release;

	if (ret < 0 || ret > 4194304) {
		output(0, "wait4 oracle: returned pid %ld is out of range (must be -1, 0, or in [1, PID_MAX_LIMIT=4194304])\n",
		       ret);
		post_handler_corrupt_ptr_bump(rec, NULL);
		goto out_release;
	}

	if (snap->stat_addr != 0 && snap->stat_poison_seed != 0 &&
	    check_output_struct_user_or_skip(
			(void *)(unsigned long) snap->stat_addr,
			sizeof(int), snap->stat_poison_seed))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

	if (snap->ru != 0 && snap->ru_poison_seed != 0 &&
	    check_output_struct_user_or_skip(
			(void *)(unsigned long) snap->ru,
			sizeof(struct rusage), snap->ru_poison_seed))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

out_release:
	post_state_release(rec, snap);
}

struct syscallentry syscall_wait4 = {
	.name = "wait4",
	.group = GROUP_PROCESS,
	.num_args = 4,
	.argtype = { [0] = ARG_PID, [1] = ARG_ADDRESS, [2] = ARG_LIST, [3] = ARG_ADDRESS },
	.argname = { [0] = "upid", [1] = "stat_addr", [2] = "options", [3] = "ru" },
	.arg_params[2].list = ARGLIST(wait_options),
	.sanitise = sanitise_wait4,
	.post = post_wait4,
	.flags = NEED_ALARM,
	.rettype = RET_PID_T,
};
