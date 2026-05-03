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

static void sanitise_listmount(struct syscallrecord *rec)
{
	struct mnt_id_req *req;
	__u64 *mnt_ids;
	unsigned int nr;

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
 * TOCTOU defeat: a sibling thread in the same trinity child can scribble
 * either the request struct at rec->a1, the ids payload at rec->a2, or the
 * size word at rec->a3 between the syscall return and our post-hook.
 * Snapshot both the request struct and the first N ids into stack-locals,
 * then re-issue with a fresh private stack request and a fresh private
 * stack ids buffer (do NOT pass rec->a1/rec->a2 -- a sibling could mutate
 * them mid-syscall and we want a clean compare).  The flags arg is forced
 * to zero on the re-call since reverse-iteration would change the ordering.
 *
 * Sample one in a hundred to stay in line with the rest of the oracle
 * family.  No early return on first divergence -- multi-field corruption
 * surfaces in a single sample.
 */
static void post_listmount(struct syscallrecord *rec)
{
#ifdef HAVE_SYS_LISTMOUNT
	struct mnt_id_req first_req;
	u64 first_ids[64];
	u64 recheck_ids[64];
	unsigned long n;
	unsigned long buf_slots;
	long rc;

	if (!ONE_IN(100))
		return;

	if ((long) rec->retval <= 0)
		return;

	if (rec->a1 == 0 || rec->a2 == 0 || rec->a3 == 0)
		return;

	{
		void *req_p = (void *)(unsigned long) rec->a1;
		void *ids_p = (void *)(unsigned long) rec->a2;

		/* Cluster-1/2/3 guard: reject pid-scribbled rec->a1/a2. */
		if (looks_like_corrupted_ptr(req_p) ||
		    looks_like_corrupted_ptr(ids_p)) {
			outputerr("post_listmount: rejected suspicious req=%p mnt_ids=%p (pid-scribbled?)\n",
				  req_p, ids_p);
			shm->stats.post_handler_corrupt_ptr++;
			return;
		}
	}

	memcpy(&first_req, (void *) rec->a1, sizeof(first_req));

	n = ((unsigned long) rec->retval < 64ul)
		? (unsigned long) rec->retval : 64ul;
	memcpy(first_ids, (void *) rec->a2, n * sizeof(u64));

	{
		struct mnt_id_req recheck_req = first_req;

		buf_slots = ((unsigned long) rec->a3 < 64ul)
			? (unsigned long) rec->a3 : 64ul;
		rc = syscall(SYS_listmount, &recheck_req, recheck_ids,
			     buf_slots, 0u);
	}

	if (rc < 0)
		return;

	if (rc != (long) rec->retval)
		return;

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
