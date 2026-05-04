/*
 * SYSCALL_DEFINE4(listmount, const struct mnt_id_req __user *, req,
 *		u64 __user *, mnt_ids, size_t, nr_mnt_ids,
 *		unsigned int, flags)
 */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <linux/mount.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <asm/unistd.h>
#include "deferred-free.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "compat.h"
#include "utils.h"

#if defined(SYS_listmount) || defined(__NR_listmount)
#ifndef SYS_listmount
#define SYS_listmount __NR_listmount
#endif
#define HAVE_SYS_LISTMOUNT 1
#endif

#ifndef LISTMOUNT_REVERSE
#define LISTMOUNT_REVERSE	(1 << 0)
#endif

#ifndef LSMT_ROOT
#define LSMT_ROOT 0xffffffffffffffff
#endif

static unsigned long listmount_flags[] = {
	LISTMOUNT_REVERSE,
};

#ifdef HAVE_SYS_LISTMOUNT
/*
 * Snapshot of the three listmount input args read by the post oracle,
 * captured at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->aN between the syscall returning and the post
 * handler running cannot redirect us at a foreign mount-id buffer or
 * smear the size bound used to seed the re-issue.
 */
struct listmount_post_state {
	unsigned long req;
	unsigned long mnt_ids;
	unsigned long nr_mnt_ids;
};
#endif

static void sanitise_listmount(struct syscallrecord *rec)
{
	struct mnt_id_req *req;
	__u64 *mnt_ids;
	unsigned int nr;
#ifdef HAVE_SYS_LISTMOUNT
	struct listmount_post_state *snap;
#endif

	req = (struct mnt_id_req *) get_writable_address(sizeof(*req));
	memset(req, 0, sizeof(*req));

	req->size = MNT_ID_REQ_SIZE_VER0;

	switch (rand() % 3) {
	case 0: req->mnt_id = LSMT_ROOT; break;	/* list all mounts */
	case 1: req->mnt_id = 1; break;		/* root mount */
	default: req->mnt_id = rand32(); break;		/* random mount id */
	}

	nr = 1 + (rand() % 64);
	mnt_ids = (__u64 *) get_writable_address(nr * sizeof(*mnt_ids));

	rec->a1 = (unsigned long) req;
	rec->a2 = (unsigned long) mnt_ids;
	rec->a3 = nr;

#ifdef HAVE_SYS_LISTMOUNT
	/*
	 * Snapshot the three input args for the post oracle.  Without this
	 * the post handler reads rec->aN at post-time, when a sibling
	 * syscall may have scribbled the slots: looks_like_corrupted_ptr()
	 * cannot tell a real-but-wrong heap address from the original user
	 * buffer pointers, so the memcpy / re-issue would touch a foreign
	 * allocation.  post_state is private to the post handler.  Gated on
	 * HAVE_SYS_LISTMOUNT to mirror the .post registration -- on systems
	 * without SYS_listmount the post handler is not registered and a
	 * snapshot only the post handler can free would leak.
	 */
	snap = zmalloc(sizeof(*snap));
	snap->req        = rec->a1;
	snap->mnt_ids    = rec->a2;
	snap->nr_mnt_ids = rec->a3;
	rec->post_state  = (unsigned long) snap;
#endif
}

/*
 * Oracle: listmount(req, mnt_ids, nr_mnt_ids, flags) writes up to nr_mnt_ids
 * u64 mount IDs into the user buffer and returns the count written, with the
 * iteration anchored at req->mnt_id.  For a stable mount set the kernel
 * iteration order is deterministic, so two back-to-back calls with the same
 * request must produce a byte-identical id array.  Mount/umount flux during
 * the sample window is detected by a count mismatch on the re-call and we
 * silently skip -- only true divergence with a matching count is reported.
 *
 * Divergence shapes the oracle catches:
 *   - copy_to_user mis-write: the kernel produced the right answer but a
 *     u64 landed in the wrong slot in the user buffer or arrived torn.
 *   - 32-bit-on-64-bit compat sign-extension on the size_t nr_mnt_ids word.
 *   - struct mnt_id_req layout mismatch between userspace and kernel.
 *   - sibling-thread scribble of the user req struct or ids buffer at
 *     rec->a1/rec->a2 between the original syscall return and our re-issue
 *     via alloc_shared in another trinity child task.
 *
 * TOCTOU defeat: the three input args (req, mnt_ids, nr_mnt_ids) are
 * snapshotted at sanitise time into a heap struct in rec->post_state, so
 * a sibling that scribbles rec->aN between syscall return and post entry
 * cannot redirect us at a foreign mount-id buffer or smear the size
 * bound.  We still snapshot the request struct and the first N ids into
 * stack-locals before re-issuing, with a fresh private stack request and
 * a fresh private stack ids buffer (do NOT pass the snapshot's req /
 * mnt_ids -- a sibling could scribble the user buffers themselves
 * mid-syscall and forge a clean compare).  The flags arg is forced to
 * zero on the re-call since reverse-iteration would change the ordering.
 *
 * Sample one in a hundred to stay in line with the rest of the oracle
 * family.  No early return on first divergence -- multi-field corruption
 * surfaces in a single sample.
 */
static void post_listmount(struct syscallrecord *rec)
{
#ifdef HAVE_SYS_LISTMOUNT
	struct listmount_post_state *snap = (struct listmount_post_state *) rec->post_state;
	struct mnt_id_req first_req;
	u64 first_ids[64];
	u64 recheck_ids[64];
	unsigned long n;
	unsigned long buf_slots;
	long rc;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_listmount: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  snap);
		rec->post_state = 0;
		return;
	}

	if (!ONE_IN(100))
		goto out_free;

	if ((long) rec->retval <= 0)
		goto out_free;

	if (snap->req == 0 || snap->mnt_ids == 0 || snap->nr_mnt_ids == 0)
		goto out_free;

	{
		void *req_p = (void *)(unsigned long) snap->req;
		void *ids_p = (void *)(unsigned long) snap->mnt_ids;

		/*
		 * Defense in depth: even with the post_state snapshot, a
		 * wholesale stomp could rewrite the snapshot's inner pointer
		 * fields.  Reject pid-scribbled req/mnt_ids before deref.
		 */
		if (looks_like_corrupted_ptr(rec, req_p) ||
		    looks_like_corrupted_ptr(rec, ids_p)) {
			outputerr("post_listmount: rejected suspicious req=%p mnt_ids=%p (post_state-scribbled?)\n",
				  req_p, ids_p);
			goto out_free;
		}
	}

	memcpy(&first_req, (void *) snap->req, sizeof(first_req));

	n = ((unsigned long) rec->retval < 64ul)
		? (unsigned long) rec->retval : 64ul;
	memcpy(first_ids, (void *) snap->mnt_ids, n * sizeof(u64));

	{
		struct mnt_id_req recheck_req = first_req;

		buf_slots = ((unsigned long) snap->nr_mnt_ids < 64ul)
			? (unsigned long) snap->nr_mnt_ids : 64ul;
		rc = syscall(SYS_listmount, &recheck_req, recheck_ids,
			     buf_slots, 0u);
	}

	if (rc < 0)
		goto out_free;

	if (rc != (long) rec->retval)
		goto out_free;

	if (memcmp(first_ids, recheck_ids, (size_t) rc * sizeof(u64)) != 0) {
		char first_hex[64 * 17 + 1];
		char recheck_hex[64 * 17 + 1];
		size_t off;
		long i;

		off = 0;
		for (i = 0; i < rc; i++)
			off += snprintf(first_hex + off,
					sizeof(first_hex) - off,
					"%016lx ",
					(unsigned long) first_ids[i]);
		first_hex[off > 0 ? off - 1 : 0] = '\0';

		off = 0;
		for (i = 0; i < rc; i++)
			off += snprintf(recheck_hex + off,
					sizeof(recheck_hex) - off,
					"%016lx ",
					(unsigned long) recheck_ids[i]);
		recheck_hex[off > 0 ? off - 1 : 0] = '\0';

		output(0,
		       "[oracle:listmount] mnt_id=%llx retval=%ld ids [%s] vs [%s]\n",
		       (unsigned long long) first_req.mnt_id,
		       (long) rec->retval, first_hex, recheck_hex);
		__atomic_add_fetch(&shm->stats.listmount_oracle_anomalies,
				   1, __ATOMIC_RELAXED);
	}

out_free:
	deferred_freeptr(&rec->post_state);
#else
	(void) rec;
#endif
}

struct syscallentry syscall_listmount = {
	.name = "listmount",
	.num_args = 4,
	.argtype = { [3] = ARG_LIST },
	.argname = { [0] = "req", [1] = "mnt_ids", [2] = "nr_mnt_ids", [3] = "flags" },
	.arg_params[3].list = ARGLIST(listmount_flags),
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VFS,
	.sanitise = sanitise_listmount,
	.post = post_listmount,
};
