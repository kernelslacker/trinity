/*
 * SYSCALL_DEFINE3(getresgid, gid_t __user *, rgid, gid_t __user *, egid, gid_t __user *, sgid)
 */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
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
#define GETRESGID_POST_STATE_MAGIC	0x47524749UL	/* "GRGI" */
struct getresgid_post_state {
	unsigned long magic;
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
	snap->magic = GETRESGID_POST_STATE_MAGIC;
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
	char buf[2048];
	char *line;
	ssize_t n;
	int fd;
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

	/*
	 * Magic-cookie check: snap survived the heap-shape gate but a
	 * sibling scribble of rec->post_state with a heap-shaped pointer
	 * to a foreign allocation would let the wrong bytes pose as a
	 * getresgid_post_state.  A cookie mismatch means snap does not
	 * point at our struct -- abandon rather than feed wild bytes into
	 * the rgid / egid / sgid inner derefs.
	 */
	if (snap->magic != GETRESGID_POST_STATE_MAGIC) {
		outputerr("post_getresgid: rejected snap with bad magic 0x%lx "
			  "(post_state-stomped to foreign allocation?)\n",
			  snap->magic);
		post_handler_corrupt_ptr_bump(rec, NULL);
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

	/* Raw open/read instead of fopen/fgets/fclose: this post handler runs
	 * many times per second under fuzz, and stdio's per-call malloc of
	 * FILE struct + IO buffer is heap traffic we don't need. */
	fd = open("/proc/self/status", O_RDONLY);
	if (fd < 0)
		goto out_free;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		goto out_free;
	buf[n] = '\0';
	/* Anchor on a newline so a "Gid:" substring inside an earlier field
	 * (e.g. a sibling fuzzer's prctl(PR_SET_NAME) value in Name:) cannot
	 * mis-target the parse. */
	line = strstr(buf, "\nGid:");
	if (line == NULL)
		goto out_free;
	if (sscanf(line + 5, "%lu %lu %lu",
		   &pgid_real, &pgid_eff, &pgid_saved) != 3)
		goto out_free;

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
	.rettype = RET_ZERO_SUCCESS,
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
	.rettype = RET_ZERO_SUCCESS,
};
