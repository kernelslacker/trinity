/*
 * SYSCALL_DEFINE3(getresuid, uid_t __user *, ruid, uid_t __user *, euid, uid_t __user *, suid)
 */
#include <sys/types.h>
#include <unistd.h>
#include "deferred-free.h"
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

	if (!ONE_IN(100))
		goto out_free;

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
		__atomic_add_fetch(&shm->stats.getresuid_oracle_anomalies, 1,
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
};
