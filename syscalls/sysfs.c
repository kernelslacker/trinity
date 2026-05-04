/*
 * SYSCALL_DEFINE3(sysfs, int, option, unsigned long, arg1, unsigned long, arg2)
 */
#include <stddef.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "arch.h"
#include "deferred-free.h"
#include "maps.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

static unsigned long sysfs_options[] = {
	1, 2, 3,
};

#if defined(SYS_sysfs) || defined(__NR_sysfs)
#ifndef SYS_sysfs
#define SYS_sysfs __NR_sysfs
#endif

/*
 * Snapshot of the three sysfs input args read by the post oracle,
 * captured at sanitise time and consumed by the post handler.  Lives
 * in rec->post_state, a slot the syscall ABI does not expose, so a
 * sibling syscall scribbling rec->aN between the syscall returning
 * and the post handler running cannot redirect us at a foreign user
 * buffer and cannot smear the option discriminator or the index used
 * to seed the re-issue.
 */
struct sysfs_post_state {
	unsigned long option;
	unsigned long idx;
	unsigned long buf;
};
#endif

static void sanitise_sysfs(struct syscallrecord *rec)
{
#if defined(SYS_sysfs) || defined(__NR_sysfs)
	struct sysfs_post_state *snap;

	rec->post_state = 0;
#endif

	switch (rec->a1) {
	case 1:
		/* option 1: arg1 = pointer to fs type name string */
		rec->a2 = (unsigned long) get_address();
		break;
	case 2:
		/* option 2: arg1 = fs type index, arg2 = pointer to buffer */
		rec->a2 = rand() % 32;
		rec->a3 = (unsigned long) get_writable_address(256);
		break;
	case 3:
		/* option 3: returns total number of fs types, no args used */
		break;
	}

#if defined(SYS_sysfs) || defined(__NR_sysfs)
	/*
	 * Snapshot the three input args for the post oracle.  Without
	 * this the post handler reads rec->aN at post-time, when a
	 * sibling syscall may have scribbled the slots:
	 * looks_like_corrupted_ptr() cannot tell a real-but-wrong heap
	 * address from the original user buffer pointer, so the memcpy
	 * / re-issue would touch a foreign allocation.  post_state is
	 * private to the post handler.  Done unconditionally for all
	 * three options -- option 1 and option 3 will short-circuit in
	 * the post handler, but always-allocating keeps the post path
	 * branch-free of option-specific snapshot logic.  Gated to
	 * mirror the .post registration -- on systems without
	 * SYS_sysfs the post handler is not registered and a snapshot
	 * only the post handler can free would leak.
	 */
	snap = zmalloc(sizeof(*snap));
	snap->option = rec->a1;
	snap->idx    = rec->a2;
	snap->buf    = rec->a3;
	rec->post_state = (unsigned long) snap;
#endif
}

#if defined(SYS_sysfs) || defined(__NR_sysfs)

/*
 * Oracle: sysfs(2, fs_index, buf) translates a filesystem registration
 * index into a NUL-terminated filesystem type name copied into a
 * 256-byte user buffer, returning 0 on success.  The kernel
 * filesystem registration table is stable for the runtime of a
 * trinity process -- absent concurrent register_filesystem /
 * unregister_filesystem activity in another thread -- so two
 * back-to-back lookups of the same index from the same task must
 * produce a byte-identical name string.  A divergence between the
 * original syscall payload and an immediate re-call points at one of:
 *
 *   - copy_to_user mis-write into the wrong user slot, leaving the
 *     original receive buffer torn (partial write, wrong-offset fill,
 *     residual stack data) while the re-call lands clean.
 *   - sibling-thread scribble of the user receive buffer between the
 *     original syscall return and our post-hook re-read.
 *   - filesystem registration table mutation handing the second
 *     lookup a different name for the same index, where the swap
 *     completed between the two calls but only the second result
 *     reflects the new state.
 *   - get_filesystem_list internal walk dropping or duplicating an
 *     entry under load and producing an off-by-one index→name map.
 *
 * Only option 2 has a writeback buffer to oracle: option 1 returns an
 * index in the retval (no buffer) and option 3 returns a count (no
 * args).  The three input args (option, idx, buf) are snapshotted at
 * sanitise time into a heap struct in rec->post_state, so a sibling
 * that scribbles rec->aN between syscall return and post entry cannot
 * redirect us at a foreign user buffer and cannot smear the index
 * used to seed the re-issue.  The receive buffer contents are then
 * snapshotted to a stack-local before re-issuing the syscall.  The
 * re-call MUST target a fresh stack buffer, never the snapshot's buf
 * field -- a sibling could mutate the original receive buffer
 * mid-syscall and forge a clean compare.  Drop the sample if the
 * re-call returns < 0 (kernel rejected the index on retry, benign).
 * Compare with a length-bounded memcmp using strnlen on both buffers
 * so a missing NUL terminator does not walk off the stack frame.
 * Sample one in a hundred to stay in line with the rest of the
 * oracle family.
 */
static void post_sysfs(struct syscallrecord *rec)
{
	struct sysfs_post_state *snap =
		(struct sysfs_post_state *) rec->post_state;
	char first[256];
	char recheck_buf[256];
	size_t first_len, recheck_len, cmp_len;
	long rc;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_sysfs: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  snap);
		rec->post_state = 0;
		return;
	}

	if (!ONE_IN(100))
		goto out_free;

	if (snap->option != 2)
		goto out_free;

	if ((long) rec->retval < 0)
		goto out_free;

	if (snap->buf == 0)
		goto out_free;

	{
		void *buf = (void *)(unsigned long) snap->buf;

		/*
		 * Defense in depth: even with the post_state snapshot, a
		 * wholesale stomp could rewrite the snapshot's inner
		 * buf field.  Reject pid-scribbled buf before deref.
		 */
		if (looks_like_corrupted_ptr(rec, buf)) {
			outputerr("post_sysfs: rejected suspicious arg2=%p (post_state-scribbled?)\n",
				  buf);
			goto out_free;
		}
	}

	memcpy(first, (void *)(unsigned long) snap->buf, sizeof(first));

	rc = syscall(SYS_sysfs, 2UL, snap->idx, (unsigned long) recheck_buf);

	if (rc < 0)
		goto out_free;

	first_len = strnlen(first, sizeof(first));
	recheck_len = strnlen(recheck_buf, sizeof(recheck_buf));
	cmp_len = first_len < recheck_len ? first_len : recheck_len;

	if (first_len == recheck_len &&
	    memcmp(first, recheck_buf, cmp_len) == 0)
		goto out_free;

	{
		char first_hex[32 * 2 + 1];
		char recheck_hex[32 * 2 + 1];
		size_t i, dump_first, dump_recheck;

		dump_first = first_len < 32 ? first_len : 32;
		dump_recheck = recheck_len < 32 ? recheck_len : 32;
		for (i = 0; i < dump_first; i++)
			snprintf(first_hex + i * 2, 3, "%02x",
				 (unsigned char) first[i]);
		first_hex[dump_first * 2] = '\0';
		for (i = 0; i < dump_recheck; i++)
			snprintf(recheck_hex + i * 2, 3, "%02x",
				 (unsigned char) recheck_buf[i]);
		recheck_hex[dump_recheck * 2] = '\0';

		output(0,
		       "[oracle:sysfs] idx=%lu first_len=%zu recheck_len=%zu first %s vs recheck %s\n",
		       snap->idx, first_len, recheck_len,
		       first_hex, recheck_hex);
		__atomic_add_fetch(&shm->stats.sysfs_oracle_anomalies,
				   1, __ATOMIC_RELAXED);
	}

out_free:
	deferred_freeptr(&rec->post_state);
}
#endif /* SYS_sysfs || __NR_sysfs */

struct syscallentry syscall_sysfs = {
	.name = "sysfs",
	.num_args = 3,
	.argtype = { [0] = ARG_OP },
	.argname = { [0] = "option", [1] = "arg1", [2] = "arg2" },
	.arg_params[0].list = ARGLIST(sysfs_options),
	.sanitise = sanitise_sysfs,
	.group = GROUP_PROCESS,
#if defined(SYS_sysfs) || defined(__NR_sysfs)
	.post = post_sysfs,
#endif
};
