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
 * Snapshot of the three getresuid input args read by the post oracle,
 * captured at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->aN between the syscall returning and the post
 * handler running cannot redirect the source reads at foreign ruid /
 * euid / suid user buffers.
 */
#define GETRESUID_POST_STATE_MAGIC	0x47525549UL	/* "GRUI" */
struct getresuid_post_state {
	unsigned long magic;
	unsigned long ruid;
	unsigned long euid;
	unsigned long suid;
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
	 * Snapshot the three input args read by the post oracle.  Without
	 * this the post handler reads rec->a1/a2/a3 at post-time, when a
	 * sibling syscall may have scribbled the slots:
	 * looks_like_corrupted_ptr() cannot tell a real-but-wrong heap
	 * address from the original ruid / euid / suid user buffer pointers,
	 * so the source reads would touch foreign allocations that the guard
	 * never inspected.  post_state is private to the post handler.  The
	 * 16-bit getresuid16 path uses sanitise_getresuid16 instead because
	 * it has no .post handler and would leak the snapshot.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = GETRESUID_POST_STATE_MAGIC;
	snap->ruid = rec->a1;
	snap->euid = rec->a2;
	snap->suid = rec->a3;
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
		void *r = (void *) snap->ruid;
		void *e = (void *) snap->euid;
		void *s = (void *) snap->suid;

		/*
		 * Defense in depth: even with the post_state snapshot, a
		 * wholesale stomp could rewrite the snapshot's inner pointer
		 * fields.  Reject pid-scribbled ruid/euid/suid before deref.
		 */
		if (looks_like_corrupted_ptr(rec, r) ||
		    looks_like_corrupted_ptr(rec, e) ||
		    looks_like_corrupted_ptr(rec, s)) {
			outputerr("post_getresuid: rejected suspicious ruid=%p euid=%p suid=%p (post_state-scribbled?)\n",
				  r, e, s);
			goto out_free;
		}
	}

	kruid = *(uid_t *) snap->ruid;
	keuid = *(uid_t *) snap->euid;
	ksuid = *(uid_t *) snap->suid;

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
