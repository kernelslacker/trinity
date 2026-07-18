/*
 * SYSCALL_DEFINE2(getgroups, int, gidsetsize, gid_t __user *, grouplist)
 */
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "output-poison.h"
#include "proc-status.h"
#include "random.h"
#include "shm.h"
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

/*
 * Snapshot of the sanitise-time grouplist address, gidsetsize, and the
 * poison seed stamped into the OUT-buffer, captured at sanitise time and
 * consumed by post_getgroups.  Lives in rec->post_state so a sibling
 * scribble of rec->a1 / rec->a2 between syscall return and the post
 * handler running cannot redirect the poison check at a foreign heap
 * page.  A poison_seed of 0 means sanitise refused to stamp (a1 == 0,
 * grouplist NULL, or the range failed the readability gate) and the
 * post handler no-ops the untouched-buffer arm for that call.
 */
#define GETGROUPS_POST_STATE_MAGIC	0x4747525050554CUL	/* "GGRPPUL" */
#define GETGROUPS_POISON_SEED		0x4747524F55504CULL	/* "GGROUPL" */
struct getgroups_post_state {
	unsigned long magic;
	unsigned long grouplist;
	unsigned long gidsetsize;
	uint64_t poison_seed;
};

/*
 * Shared with the 16-bit getgroups16 variant, which has no .post
 * handler.  Installing a post_state snap in a sanitiser whose companion
 * .post is not registered would leak the snap, so getgroups16 stays on
 * this thin common helper and only sanitise_getgroups below installs a
 * snap.
 */
static void sanitise_getgroups_common(struct syscallrecord *rec)
{
	avoid_shared_buffer_out(&rec->a2, rec->a1 * sizeof(gid_t));
}

static void sanitise_getgroups(struct syscallrecord *rec)
{
	struct getgroups_post_state *snap;
	void *grouplist;
	size_t bytes;

	/*
	 * Clear post_state up front so an early return leaves the post
	 * handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;

	sanitise_getgroups_common(rec);

	/*
	 * Snapshot the two input args for the post oracle.  Reading
	 * rec->a1 / rec->a2 at post-time races a sibling that scribbles
	 * the slots, and looks_like_corrupted_ptr() cannot distinguish a
	 * real-but-wrong heap address from the original grouplist pointer
	 * -- so the poison compare would touch a foreign allocation.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic       = GETGROUPS_POST_STATE_MAGIC;
	snap->grouplist   = rec->a2;
	snap->gidsetsize  = rec->a1;
	snap->poison_seed = 0;

	/*
	 * Stamp a fixed poison pattern into the OUT-buffer the kernel is
	 * about to fill.  A fixed magic (not an RNG-drawn seed) keeps the
	 * sanitiser's RNG consumption byte-identical between --dry-run
	 * and normal runs, so replaying the same command-line seed
	 * reproduces the same syscall stream.
	 *
	 * Gated on gidsetsize > 0, grouplist != 0, and range_readable_user
	 * so an ARG_ADDRESS draw that landed unmapped -- or a caller-visible
	 * 0-length request -- does not SIGSEGV the sanitiser inside the
	 * byte-walk.  On skip, poison_seed stays 0 and the post handler
	 * no-ops the untouched-buffer arm for this call.  Stamped after
	 * avoid_shared_buffer_out so the poison lands on the final buffer
	 * the kernel will see.
	 *
	 * gid_t values are 32-bit non-negative integers; a full 8-byte
	 * poison word will never coincide with a legitimate two-gid
	 * sequence, so a byte-identical survive is unambiguous evidence
	 * the kernel wrote zero bytes despite reporting a positive count.
	 */
	grouplist = (void *)(unsigned long) rec->a2;
	bytes = (size_t) rec->a1 * sizeof(gid_t);
	if (rec->a1 > 0 && grouplist != NULL &&
	    range_readable_user(grouplist, bytes))
		snap->poison_seed = poison_output_struct(grouplist, bytes,
							 GETGROUPS_POISON_SEED);

	post_state_install(rec, snap);
}

/*
 * Oracle: getgroups(0, NULL) returns the supplementary group count for the
 * calling task, sourced from current_cred()->group_info->ngroups.  The
 * procfs view of the same fact is the "Groups:" line of
 * /proc/self/status, which proc_pid_status() / render_cap_t fill from
 * the same task_struct -> real_cred -> group_info linkage by walking
 * group_info->gid[] and emitting each gid as a decimal token.  Both
 * views read the same backing array under rcu, but via different code
 * paths — sys_getgroups returns gi->ngroups directly, procfs counts
 * tokens it formatted itself — so a divergence between the two for the
 * same task is its own corruption shape: torn write to cred, stale rcu
 * cred pointer, or another corruption shape that desyncs the count
 * from the array.  Gate on retval >= 0 because failures returned no
 * count; sample one in a hundred to match the rest of the oracle family.
 */
static void post_getgroups(struct syscallrecord *rec)
{
	struct getgroups_post_state *snap;
	unsigned long retval = rec->retval;
	long ret = (long) retval;
	char *buf, *line, *eol;

	/*
	 * Canonical ownership bracket: shape -> ownership -> magic, in
	 * that order.  post_state_claim_owned() has already cleared
	 * rec->post_state, emitted any outputerr() diagnostic, and bumped
	 * the corruption counter on failure -- just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, GETGROUPS_POST_STATE_MAGIC,
				      __func__);
	if (snap == NULL)
		return;

	/*
	 * Kernel ABI: success retval is the supplementary group count for
	 * the calling task, a non-negative int capped at NGROUPS_MAX =
	 * 65536 (linux/posix_types.h). Failure returns -1UL with EFAULT or
	 * EINVAL on the syscall return path. Anything > NGROUPS_MAX on
	 * success — or any other "negative" value besides -1UL — is a
	 * structural ABI regression: a sign-extension tear, a torn read of
	 * group_info->ngroups, or -errno leaking through the return path.
	 * Reject before the ONE_IN(100) re-read oracle, which would
	 * otherwise miss it 99% of the time.
	 */
	if (retval != (unsigned long)-1L && retval > 65536UL) {
		outputerr("post_getgroups: retval %ld outside [0, NGROUPS_MAX] and != -1UL\n",
			  ret);
		post_handler_corrupt_ptr_bump(rec, NULL);
		goto out_free;
	}

	/*
	 * Untouched-buffer poison arm: sanitise stamped a fixed poison
	 * pattern into the gidsetsize*sizeof(gid_t) grouplist OUT-buffer.
	 * A byte-identical match across the first retval*sizeof(gid_t)
	 * bytes after a positive-count return means the kernel reported
	 * copying `retval` gids out yet wrote zero bytes into the buffer
	 * -- a torn copy_to_user, a "return count before fill" early exit,
	 * or a compat wrapper that forgets the write.  The count-vs-procfs
	 * oracle below cannot catch this: it only compares the returned
	 * count against the parallel /proc/self/status view of the same
	 * ngroups, and both would agree even when the copy is skipped.
	 *
	 * Cheap (a per-byte compare, no syscall re-issue), gated on
	 * retval > 0 (nothing to check on a zero-count) and
	 * retval <= gidsetsize (the kernel cannot claim to have written
	 * more entries than the buffer holds; treat that shape as a
	 * separate ABI violation the ONE_IN(100) count arm handles).
	 * The check helper snapshots the user range under a sigsetjmp
	 * bracket before the compare, so a sibling munmap of the
	 * writable-pool page between syscall return and here degrades to
	 * a skipped sample instead of faulting.  Byte-lengths beyond
	 * CHECK_OUTPUT_STRUCT_SNAP_MAX return false and no-op the arm --
	 * the small-count path (up to 128 gids) is the interesting one
	 * for the "kernel returned success but skipped the copy" shape.
	 */
	if (ret > 0 && snap->grouplist != 0 && snap->poison_seed != 0 &&
	    (unsigned long) ret <= snap->gidsetsize) {
		size_t bytes = (size_t) ret * sizeof(gid_t);

		if (check_output_struct_user_or_skip(
				(void *)(unsigned long) snap->grouplist,
				bytes, snap->poison_seed))
			__atomic_add_fetch(
				&shm->stats.post_handler_untouched_out_buf,
				1, __ATOMIC_RELAXED);
	}

	if (!ONE_IN(100))
		goto out_free;

	if (ret < 0)
		goto out_free;

	/* Dynamically-sized slurp: Groups: at NGROUPS_MAX is several hundred
	 * KB of decimal-plus-space tokens, well past any sensible stack
	 * buffer.  Skip the oracle on read failure rather than risk a false
	 * positive on a partial capture. */
	buf = proc_status_slurp();
	if (buf == NULL)
		goto out_free;

	/* Anchor on a newline so a "Groups:" substring inside an earlier
	 * field cannot mis-target the parse. */
	line = strstr(buf, "\nGroups:");
	if (line != NULL) {
		char *p = line + 8;
		char *tok, *saveptr = NULL;
		int seen = 0;

		/* Bound strtok_r to this single line by NUL-terminating at the
		 * next newline; the original fgets-based code only saw one line
		 * at a time. */
		eol = strchr(p, '\n');
		if (eol != NULL)
			*eol = '\0';

		for (tok = strtok_r(p, " \t", &saveptr); tok;
		     tok = strtok_r(NULL, " \t", &saveptr))
			seen++;

		if (seen != (int) ret) {
			output(0, "groups oracle: /proc/self/status Groups: count %d but rec->retval was %ld\n",
			       seen, ret);
			__atomic_add_fetch(&shm->stats.oracle.getgroups_oracle_anomalies, 1,
					   __ATOMIC_RELAXED);
		}
	}

	free(buf);

out_free:
	post_state_release(rec, snap);
}

struct syscallentry syscall_getgroups = {
	.name = "getgroups",
	.num_args = 2,
	.argtype = { [0] = ARG_LEN, [1] = ARG_ADDRESS },
	.argname = { [0] = "gidsetsize", [1] = "grouplist" },
	.sanitise = sanitise_getgroups,
	.rettype = RET_BORING,
	.flags = REEXEC_SANITISE_OK,
	.group = GROUP_PROCESS,
	.post = post_getgroups,
};


/*
 * SYSCALL_DEFINE2(getgroups16, int, gidsetsize, old_gid_t __user *, grouplist)
 */

struct syscallentry syscall_getgroups16 = {
	.name = "getgroups16",
	.num_args = 2,
	.argtype = { [0] = ARG_LEN, [1] = ARG_ADDRESS },
	.argname = { [0] = "gidsetsize", [1] = "grouplist" },
	.sanitise = sanitise_getgroups_common,
	.rettype = RET_BORING,
	.flags = REEXEC_SANITISE_OK,
	.group = GROUP_PROCESS,
};
