/*
 * SYSCALL_DEFINE3(getresuid, uid_t __user *, ruid, uid_t __user *, euid, uid_t __user *, suid)
 */
#include <sys/types.h>
#include "deferred-free.h"
#include "output-poison.h"
#include "proc-status.h"
#include "random.h"
#include "shm.h"
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

/*
 * Magic-cookie + ownership-proof slot consumed by the post oracle, kept
 * in rec->post_state so a sibling stomp of that slot with a heap-shaped
 * pointer to a foreign chunk survives looks_like_corrupted_ptr() but
 * fails the cookie / ownership-table gates.
 *
 * The three OUT-pointers (a1/a2/a3 = ruid/euid/suid) are defended via
 * .arg_snapshot_mask: the dispatch-time arg_shadow capture inside
 * __do_syscall() (after the final blanket_address_scrub, from the
 * locals about to enter the kernel), read in the post oracle via
 * get_arg_snapshot(rec, N).  A sibling stomp of rec->aN between
 * dispatch and post bumps the generic arg_shadow_stomp tripwire from
 * inside the accessor; the returned value is the kernel-visible
 * address, so the uid_t deref still hits the buffer the kernel
 * actually wrote.
 */
#define GETRESUID_POST_STATE_MAGIC	0x47525549UL	/* "GRUI" */
struct getresuid_post_state {
	unsigned long magic;
	/*
	 * Per-slot seeds for the poison pattern stamped into the three
	 * uid_t OUT-buffers (ruid/euid/suid) at sanitise time.  Returned
	 * by poison_output_struct() and fed back into check_output_struct()
	 * in the post handler: a byte-identical match on any slot after a
	 * success return means the kernel wrote zero bytes into that
	 * scalar and left the poison intact.  Snapshot lives in
	 * rec->post_state so a sibling stomp of rec->aN between dispatch
	 * and post cannot redirect the poison check at an unrelated heap
	 * page whose residual bytes happen to match some earlier seed.
	 * A seed of 0 means sanitise chose not to stamp that slot
	 * (unwritable pointer) -- the post handler no-ops that arm rather
	 * than confuse "we could not poison" with "kernel did not write".
	 */
	uint64_t poison_seed[3];
};

static void sanitise_getresuid16(struct syscallrecord *rec)
{
	avoid_shared_buffer_out(&rec->a1, sizeof(uid_t));
	avoid_shared_buffer_out(&rec->a2, sizeof(uid_t));
	avoid_shared_buffer_out(&rec->a3, sizeof(uid_t));
}

static void sanitise_getresuid(struct syscallrecord *rec)
{
	struct getresuid_post_state *snap;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;

	avoid_shared_buffer_out(&rec->a1, sizeof(uid_t));
	avoid_shared_buffer_out(&rec->a2, sizeof(uid_t));
	avoid_shared_buffer_out(&rec->a3, sizeof(uid_t));

	/*
	 * Magic-cookie + ownership entry consumed by the post oracle; the
	 * OUT-pointers themselves are defended via .arg_snapshot_mask, not
	 * a snap field.  The 16-bit getresuid16 path uses
	 * sanitise_getresuid16 instead because it has no .post handler and
	 * would leak the snap.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = GETRESUID_POST_STATE_MAGIC;
	snap->poison_seed[0] = 0;
	snap->poison_seed[1] = 0;
	snap->poison_seed[2] = 0;

	/*
	 * Stamp a per-slot poison pattern into each of the three uid_t
	 * OUT-buffers the kernel is about to fill.  The post handler feeds
	 * each seed back into check_output_struct(); a byte-identical
	 * poison after a success return means the kernel wrote zero bytes
	 * into that scalar and left our stamp intact.  Gate each stamp on
	 * range_readable_user() so a writable-pool draw that
	 * avoid_shared_buffer_out() moved to an address no longer provably
	 * mapped (e.g. sibling munmap between allocation and now) does not
	 * SIGSEGV the sanitiser inside poison_output_struct's byte-walk.
	 * On skip the seed stays 0 and the post handler no-ops that arm
	 * while the existing procfs Uid: divergence oracle keeps running.
	 * Done after avoid_shared_buffer_out() so the poison lands on the
	 * final buffer the kernel will see.
	 */
	{
		unsigned long slots[3] = { rec->a1, rec->a2, rec->a3 };
		unsigned int i;

		for (i = 0; i < 3; i++) {
			void *buf = (void *)(unsigned long) slots[i];

			if (range_readable_user(buf, sizeof(uid_t)))
				snap->poison_seed[i] =
					poison_output_struct(buf,
							     sizeof(uid_t),
							     0);
		}
	}

	/*
	 * post_state_install pairs the rec->post_state assign with the
	 * ownership-table register so the observable window between the
	 * two is closed; post_getresuid() will then gate the snap through
	 * post_state_claim_owned() and prove ownership before
	 * dereferencing any field.
	 */
	post_state_install(rec, snap);
}

/*
 * Oracle: getresuid(&ruid, &euid, &suid) writes this task's real,
 * effective, and saved uids out of current_cred()->uid / euid / suid.
 * The procfs view of the same fact is the "Uid:" line of
 * /proc/self/status, which proc_pid_status() formats from the same
 * task_struct -> real_cred linkage as four whitespace-separated
 * decimals: Real Effective Saved Filesystem.  Both views read the
 * same backing struct cred under rcu, but via different code paths
 * — sys_getresuid copies three fields out via copy_to_user, procfs
 * formats them through a seq_file fill — so a divergence between
 * the two for the same task is its own corruption shape: torn write
 * to cred, stale rcu cred pointer, or anything else that desyncs
 * the cached uids from one another.  fsuid is a separate field and
 * not part of getresuid's contract, so only the first three columns
 * are validated.  Gate on retval == 0 because failures wrote no
 * uids; sample one in a hundred to match the rest of the oracle
 * family.
 */
static void post_getresuid(struct syscallrecord *rec)
{
	struct getresuid_post_state *snap;
	unsigned long ids[4];
	uid_t kruid, keuid, ksuid;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, GETRESUID_POST_STATE_MAGIC, __func__);
	if (snap == NULL)
		return;

	if ((long) rec->retval != 0)
		goto out_free;

	{
		/*
		 * Read the three OUT-pointers via the generic arg_shadow
		 * accessor: it returns the kernel-visible addresses captured
		 * in __do_syscall() after the final blanket_address_scrub,
		 * and bumps arg_shadow_stomp from inside the accessor on any
		 * post-dispatch sibling scribble of rec->aN.  Defense in
		 * depth: a wholesale stomp can rewrite shadow + live in
		 * lock-step, surviving the tripwire; reject pid-scribbled
		 * ruid/euid/suid before deref.
		 */
		uid_t *r = (uid_t *) get_arg_snapshot(rec, 1);
		uid_t *e = (uid_t *) get_arg_snapshot(rec, 2);
		uid_t *s = (uid_t *) get_arg_snapshot(rec, 3);

		if (r == NULL || e == NULL || s == NULL ||
		    looks_like_corrupted_ptr(rec, r) ||
		    looks_like_corrupted_ptr(rec, e) ||
		    looks_like_corrupted_ptr(rec, s)) {
			outputerr("post_getresuid: rejected suspicious ruid=%p euid=%p suid=%p (shadow-scribbled?)\n",
				  r, e, s);
			goto out_free;
		}

		kruid = *r;
		keuid = *e;
		ksuid = *s;
	}

	/*
	 * Untouched-buffer poison check: sanitise stamped a per-slot
	 * poison pattern into each of ruid/euid/suid.  A byte-identical
	 * match on any slot after a success return means the kernel wrote
	 * zero bytes into that scalar and left our stamp intact -- a
	 * short-copy or partial copy_to_user() the field-diff arm below
	 * would also catch, but only after paying for a procfs re-read.
	 * Cheap (three 4-byte compares, no re-issue), so runs on every
	 * success sample; the procfs arm stays rate-limited.  Check
	 * against the local snapshots taken above so a sibling munmap of
	 * the writable-pool page between the deref and here cannot fault
	 * inside a second read.  A seed of 0 means sanitise skipped that
	 * slot -- skip the check too so "we could not poison" is not
	 * confused with "kernel did not write".  Counts against the
	 * shared post_handler_untouched_out_buf slot.
	 */
	if (snap->poison_seed[0] != 0 &&
	    check_output_struct(&kruid, sizeof(kruid), snap->poison_seed[0]))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);
	if (snap->poison_seed[1] != 0 &&
	    check_output_struct(&keuid, sizeof(keuid), snap->poison_seed[1]))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);
	if (snap->poison_seed[2] != 0 &&
	    check_output_struct(&ksuid, sizeof(ksuid), snap->poison_seed[2]))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

	if (!ONE_IN(100))
		goto out_free;

	if (!proc_status_read_id_quad("Uid", ids))
		goto out_free;

	if ((unsigned long) kruid != ids[0] ||
	    (unsigned long) keuid != ids[1] ||
	    (unsigned long) ksuid != ids[2]) {
		output(0, "getresuid oracle: syscall returned "
		       "r=%lu e=%lu s=%lu but /proc/self/status "
		       "Uid: %lu %lu %lu\n",
		       (unsigned long) kruid,
		       (unsigned long) keuid,
		       (unsigned long) ksuid,
		       ids[0], ids[1], ids[2]);
		__atomic_add_fetch(&shm->stats.oracle.getresuid_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}

out_free:
	post_state_release(rec, snap);
}

struct syscallentry syscall_getresuid = {
	.name = "getresuid",
	.num_args = 3,
	.argtype = { [0] = ARG_NON_NULL_ADDRESS, [1] = ARG_NON_NULL_ADDRESS, [2] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "ruid", [1] = "euid", [2] = "suid" },
	.sanitise = sanitise_getresuid,
	.group = GROUP_PROCESS,
	.post = post_getresuid,
	.rettype = RET_ZERO_SUCCESS,
	.flags = REEXEC_SANITISE_OK,
	/* a1/a2/a3 (ruid/euid/suid) are the kernel's OUT-pointers; the
	 * post oracle derefs through them.  Shadow them so a sibling stomp
	 * between dispatch and post bumps arg_shadow_stomp from inside
	 * get_arg_snapshot() and the oracle still sees the addresses the
	 * kernel actually wrote, not the stomped values. */
	.arg_snapshot_mask = (1u << 0) | (1u << 1) | (1u << 2),
};

/*
 * SYSCALL_DEFINE3(getresuid16, old_uid_t __user *, ruid, old_uid_t __user *, euid, old_uid_t __user *, suid)
 */

struct syscallentry syscall_getresuid16 = {
	.name = "getresuid16",
	.num_args = 3,
	.argtype = { [0] = ARG_NON_NULL_ADDRESS, [1] = ARG_NON_NULL_ADDRESS, [2] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "ruid", [1] = "euid", [2] = "suid" },
	.sanitise = sanitise_getresuid16,
	.group = GROUP_PROCESS,
	.rettype = RET_ZERO_SUCCESS,
	.flags = REEXEC_SANITISE_OK,
};
