/*
 * SYSCALL_DEFINE3(waitpid, pid_t, pid, int __user *, stat_addr, int, options)
 */
#include <stdint.h>
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
 * Snapshot of the sanitise-time stat_addr slot and the poison seed
 * stamped into the OUT-buffer, captured at sanitise time and consumed
 * by post_waitpid.  Lives in rec->post_state so a sibling scribble of
 * rec->a2 between syscall return and the post handler running cannot
 * redirect the poison check at a foreign heap page.  A poison_seed of
 * 0 means sanitise refused to stamp (stat_addr NULL or the readable
 * range gate refused after avoid_shared_buffer_out) and the post
 * handler no-ops the untouched-buffer arm for that call.
 */
#define WAITPID_POST_STATE_MAGIC	0x574149545049444CUL	/* "WAITPIDL" */
#define WAITPID_STAT_POISON		0x574149545053544FULL	/* "WAITPSTO" */

struct waitpid_post_state {
	unsigned long magic;
	unsigned long stat_addr;
	uint64_t stat_poison_seed;
};

static void sanitise_waitpid(struct syscallrecord *rec)
{
	struct waitpid_post_state *snap;
	void *stat_addr;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a
	 * stale pointer carried over from an earlier syscall on this
	 * record.
	 */
	rec->post_state = 0;

	avoid_shared_buffer_out(&rec->a2, sizeof(int));

	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic             = WAITPID_POST_STATE_MAGIC;
	snap->stat_addr         = rec->a2;
	snap->stat_poison_seed  = 0;

	/*
	 * Stamp a fixed poison word into the int-sized OUT-buffer the
	 * kernel writes on a successful reap.  A fixed non-zero magic
	 * (not an RNG draw) keeps sanitise's RNG consumption byte-
	 * identical between --dry-run and normal runs so a fixed-seed
	 * replay reproduces the same syscall stream.
	 *
	 * Gate on non-NULL stat_addr (waitpid accepts NULL, in which
	 * case there is nothing to write and nothing to check) and
	 * range_readable_user so an avoid_shared_buffer_out relocation
	 * into a pool page that has since been munmapped does not
	 * SIGSEGV the sanitiser inside poison_output_struct's byte-walk.
	 * On skip poison_seed stays 0 and the post handler no-ops the
	 * arm.
	 */
	stat_addr = (void *)(unsigned long) rec->a2;
	if (stat_addr != NULL && range_readable_user(stat_addr, sizeof(int)))
		snap->stat_poison_seed =
			poison_output_struct(stat_addr, sizeof(int),
					     WAITPID_STAT_POISON);

	post_state_install(rec, snap);
}

/*
 * Kernel ABI: waitpid() returns -1 on error, 0 when WNOHANG is set and no
 * child has changed state, or the reaped child pid in [1, PID_MAX_LIMIT
 * (4194304)] on success. Any other retval is a structural ABI regression
 * (e.g. -errno bleeding through the syscall return path, or a pid_ns
 * translation bug). Mirrors the pid-bound style used in 547498ccfe16
 * (getpgrp) / edc0796b4cd7 (gettid) / 108b67820997 (getppid).
 *
 * Poison-writeback oracle: on retval > 0 (a child was reaped) the
 * kernel is contractually required to write *stat_addr when the caller
 * passed non-NULL.  A byte-identical survive of the poison pattern
 * across those four bytes proves the kernel reported a reap yet
 * skipped copy_to_user for the status word -- a torn write, an early-
 * exit before fill, or a compat wrapper that forgets the store.
 * Silent when sanitise refused to stamp (stat_poison_seed == 0) or
 * stat_addr is NULL.
 */
static void post_waitpid(struct syscallrecord *rec)
{
	struct waitpid_post_state *snap;
	long ret = (long) rec->retval;

	snap = post_state_claim_owned(rec, WAITPID_POST_STATE_MAGIC,
				      __func__);
	if (snap == NULL)
		return;

	if (ret == -1L || ret == 0)
		goto out_release;

	if (ret < 0 || ret > 4194304) {
		output(0, "waitpid oracle: returned pid %ld is out of range (must be -1, 0, or in [1, PID_MAX_LIMIT=4194304])\n",
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

out_release:
	post_state_release(rec, snap);
}

struct syscallentry syscall_waitpid = {
	.name = "waitpid",
	.group = GROUP_PROCESS,
	.num_args = 3,
	.argtype = { [0] = ARG_PID, [1] = ARG_ADDRESS, [2] = ARG_LIST },
	.argname = { [0] = "pid", [1] = "stat_addr", [2] = "options" },
	.arg_params[2].list = ARGLIST(wait_options),
	.sanitise = sanitise_waitpid,
	.post = post_waitpid,
	.rettype = RET_PID_T,
	.flags = NEED_ALARM,
};
