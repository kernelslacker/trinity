/*
 * SYSCALL_DEFINE3(getresgid, gid_t __user *, rgid, gid_t __user *, egid, gid_t __user *, sgid)
 */
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include "deferred-free.h"
#include "random.h"
#include "shm.h"
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

/*
 * Snapshot of the three getresgid input args read by the post oracle,
 * captured at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->aN between the syscall returning and the post
 * handler running cannot redirect the source reads at foreign rgid /
 * egid / sgid user buffers.
 */
struct getresgid_post_state {
	unsigned long rgid;
	unsigned long egid;
	unsigned long sgid;
};

static void sanitise_getresgid16(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a1, sizeof(gid_t));
	avoid_shared_buffer(&rec->a2, sizeof(gid_t));
	avoid_shared_buffer(&rec->a3, sizeof(gid_t));
}

static void sanitise_getresgid(struct syscallrecord *rec)
{
	struct getresgid_post_state *snap;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;

	avoid_shared_buffer(&rec->a1, sizeof(gid_t));
	avoid_shared_buffer(&rec->a2, sizeof(gid_t));
	avoid_shared_buffer(&rec->a3, sizeof(gid_t));

	/*
	 * Snapshot the three input args read by the post oracle.  Without
	 * this the post handler reads rec->a1/a2/a3 at post-time, when a
	 * sibling syscall may have scribbled the slots:
	 * looks_like_corrupted_ptr() cannot tell a real-but-wrong heap
	 * address from the original rgid / egid / sgid user buffer pointers,
	 * so the source reads would touch foreign allocations that the guard
	 * never inspected.  post_state is private to the post handler.  The
	 * 16-bit getresgid16 path uses sanitise_getresgid16 instead because
	 * it has no .post handler and would leak the snapshot.
	 */
	snap = zmalloc(sizeof(*snap));
	snap->rgid = rec->a1;
	snap->egid = rec->a2;
	snap->sgid = rec->a3;
	rec->post_state = (unsigned long) snap;
}

/*
 * Oracle: getresgid(&rgid, &egid, &sgid) writes this task's real,
 * effective, and saved gids out of current_cred()->gid / egid / sgid.
 * The procfs view of the same fact is the "Gid:" line of
 * /proc/self/status, which proc_pid_status() formats from the same
 * task_struct -> real_cred linkage as four whitespace-separated
 * decimals: Real Effective Saved Filesystem.  Both views read the
 * same backing struct cred under rcu, but via different code paths
 * — sys_getresgid copies three fields out via copy_to_user, procfs
 * formats them through a seq_file fill — so a divergence between
 * the two for the same task is its own corruption shape: torn write
 * to cred, stale rcu cred pointer, or anything else that desyncs
 * the cached gids from one another.  fsgid is a separate field and
 * not part of getresgid's contract, so only the first three columns
 * are validated.  Gate on retval == 0 because failures wrote no
 * gids; sample one in a hundred to match the rest of the oracle
 * family.
 */
static void post_getresgid(struct syscallrecord *rec)
{
	struct getresgid_post_state *snap =
		(struct getresgid_post_state *) rec->post_state;
	FILE *f;
	char line[256];
	gid_t krgid, kegid, ksgid;
	unsigned long pgid_real, pgid_eff, pgid_saved;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_getresgid: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  snap);
		rec->post_state = 0;
		return;
	}

	if (!ONE_IN(100))
		goto out_free;

	if ((long) rec->retval != 0)
		goto out_free;

	{
		void *r = (void *) snap->rgid;
		void *e = (void *) snap->egid;
		void *s = (void *) snap->sgid;

		/*
		 * Defense in depth: even with the post_state snapshot, a
		 * wholesale stomp could rewrite the snapshot's inner pointer
		 * fields.  Reject pid-scribbled rgid/egid/sgid before deref.
		 */
		if (looks_like_corrupted_ptr(rec, r) ||
		    looks_like_corrupted_ptr(rec, e) ||
		    looks_like_corrupted_ptr(rec, s)) {
			outputerr("post_getresgid: rejected suspicious rgid=%p egid=%p sgid=%p (post_state-scribbled?)\n",
				  r, e, s);
			goto out_free;
		}
	}

	krgid = *(gid_t *) snap->rgid;
	kegid = *(gid_t *) snap->egid;
	ksgid = *(gid_t *) snap->sgid;

	f = fopen("/proc/self/status", "r");
	if (!f)
		goto out_free;
	while (fgets(line, sizeof(line), f)) {
		if (strncmp(line, "Gid:", 4) == 0) {
			if (sscanf(line + 4, "%lu %lu %lu",
				   &pgid_real, &pgid_eff, &pgid_saved) != 3) {
				fclose(f);
				goto out_free;
			}
			fclose(f);

			if ((unsigned long) krgid != pgid_real ||
			    (unsigned long) kegid != pgid_eff ||
			    (unsigned long) ksgid != pgid_saved) {
				output(0, "getresgid oracle: syscall returned "
				       "r=%lu e=%lu s=%lu but /proc/self/status "
				       "Gid: %lu %lu %lu\n",
				       (unsigned long) krgid,
				       (unsigned long) kegid,
				       (unsigned long) ksgid,
				       pgid_real, pgid_eff, pgid_saved);
				__atomic_add_fetch(&shm->stats.getresgid_oracle_anomalies, 1,
						   __ATOMIC_RELAXED);
			}
			goto out_free;
		}
	}
	fclose(f);

out_free:
	deferred_freeptr(&rec->post_state);
}

struct syscallentry syscall_getresgid = {
	.name = "getresgid",
	.num_args = 3,
	.argtype = { [0] = ARG_NON_NULL_ADDRESS, [1] = ARG_NON_NULL_ADDRESS, [2] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "rgid", [1] = "egid", [2] = "sgid" },
	.sanitise = sanitise_getresgid,
	.group = GROUP_PROCESS,
	.post = post_getresgid,
};


/*
 * SYSCALL_DEFINE3(getresgid16, old_gid_t __user *, rgid, old_gid_t __user *, egid, old_gid_t __user *, sgid)
 */

struct syscallentry syscall_getresgid16 = {
	.name = "getresgid16",
	.num_args = 3,
	.argtype = { [0] = ARG_NON_NULL_ADDRESS, [1] = ARG_NON_NULL_ADDRESS, [2] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "rgid", [1] = "egid", [2] = "sgid" },
	.sanitise = sanitise_getresgid16,
	.group = GROUP_PROCESS,
};
