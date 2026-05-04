/*
 * SYSCALL_DEFINE4(statmount, const struct mnt_id_req __user *, req,
 *		struct statmount __user *, buf, size_t, bufsize,
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

#if defined(SYS_statmount) || defined(__NR_statmount)
#ifndef SYS_statmount
#define SYS_statmount __NR_statmount
#endif
#define HAVE_SYS_STATMOUNT 1
#endif

#ifndef LSMT_ROOT
#define LSMT_ROOT 0xffffffffffffffff
#endif

#ifndef STATMOUNT_SB_BASIC
#define STATMOUNT_SB_BASIC		0x00000001U
#define STATMOUNT_MNT_BASIC		0x00000002U
#define STATMOUNT_PROPAGATE_FROM	0x00000004U
#define STATMOUNT_MNT_ROOT		0x00000008U
#define STATMOUNT_MNT_POINT		0x00000010U
#define STATMOUNT_FS_TYPE		0x00000020U
#define STATMOUNT_MNT_NS_ID		0x00000040U
#define STATMOUNT_MNT_OPTS		0x00000080U
#define STATMOUNT_FS_SUBTYPE		0x00000100U
#define STATMOUNT_SB_SOURCE		0x00000200U
#define STATMOUNT_OPT_ARRAY		0x00000400U
#define STATMOUNT_OPT_SEC_ARRAY		0x00000800U
#endif
/* statmount() param mask bits added in Linux v6.15. */
#ifndef STATMOUNT_SUPPORTED_MASK
#define STATMOUNT_SUPPORTED_MASK	0x00001000U
#endif
/* statmount() param mask bits added in Linux v7.0. */
#ifndef STATMOUNT_MNT_UIDMAP
#define STATMOUNT_MNT_UIDMAP		0x00002000U
#define STATMOUNT_MNT_GIDMAP		0x00004000U
#endif
/* statmount() syscall flags bit added in Linux v7.0. */
#ifndef STATMOUNT_BY_FD
#define STATMOUNT_BY_FD			0x00000001U
#endif

static unsigned long statmount_params[] = {
	STATMOUNT_SB_BASIC, STATMOUNT_MNT_BASIC, STATMOUNT_PROPAGATE_FROM,
	STATMOUNT_MNT_ROOT, STATMOUNT_MNT_POINT, STATMOUNT_FS_TYPE,
	STATMOUNT_MNT_NS_ID, STATMOUNT_MNT_OPTS,
#ifdef STATMOUNT_FS_SUBTYPE
	STATMOUNT_FS_SUBTYPE, STATMOUNT_SB_SOURCE,
#endif
#ifdef STATMOUNT_OPT_ARRAY
	STATMOUNT_OPT_ARRAY, STATMOUNT_OPT_SEC_ARRAY,
#endif
#ifdef STATMOUNT_SUPPORTED_MASK
	STATMOUNT_SUPPORTED_MASK,
#endif
#ifdef STATMOUNT_MNT_UIDMAP
	STATMOUNT_MNT_UIDMAP, STATMOUNT_MNT_GIDMAP,
#endif
};

#ifdef HAVE_SYS_STATMOUNT
/*
 * Snapshot of the three statmount input args read by the post oracle,
 * captured at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->aN between the syscall returning and the post
 * handler running cannot redirect us at a foreign req / buf and cannot
 * smear the bufsize bound used to seed the re-issue.  bufsize is a
 * scalar but kept in the snap struct for symmetry with the two
 * pointer fields.
 */
struct statmount_post_state {
	unsigned long req;
	unsigned long buffer;
	unsigned long bufsize;
};
#endif

static void sanitise_statmount(struct syscallrecord *rec)
{
	struct mnt_id_req *req;
	unsigned int i, nbits;
	__u64 param;
#ifdef HAVE_SYS_STATMOUNT
	struct statmount_post_state *snap;

	rec->post_state = 0;
#endif

	req = (struct mnt_id_req *) get_writable_struct(sizeof(*req));
	if (!req)
		return;
	memset(req, 0, sizeof(*req));

	req->size = MNT_ID_REQ_SIZE_VER0;

	switch (rand() % 3) {
	case 0: req->mnt_id = LSMT_ROOT; break;
	case 1: req->mnt_id = 1; break;
	default: req->mnt_id = rand32(); break;
	}

	/* Build a random combination of STATMOUNT_* request flags. */
	param = 0;
	nbits = 1 + (rand() % ARRAY_SIZE(statmount_params));
	for (i = 0; i < nbits; i++)
		param |= statmount_params[rand() % ARRAY_SIZE(statmount_params)];
	req->param = param;

	rec->a1 = (unsigned long) req;
	rec->a3 = 4096;	/* reasonable output buffer size */
	rec->a4 = ONE_IN(4) ? STATMOUNT_BY_FD : 0;

	/*
	 * buf (a2) is the kernel's writeback target for struct statmount
	 * plus its variable-length tail (mount opts, fs type strings, etc).
	 * The sanitise above declared a3 = 4096 as the buffer size; mirror
	 * that as the avoid_shared_buffer length.  ARG_ADDRESS draws from
	 * the random pool, so a fuzzed pointer can land inside an
	 * alloc_shared region.
	 */
	avoid_shared_buffer(&rec->a2, rec->a3);

#ifdef HAVE_SYS_STATMOUNT
	/*
	 * Snapshot the three input args for the post oracle.  Without this
	 * the post handler reads rec->aN at post-time, when a sibling
	 * syscall may have scribbled the slots: looks_like_corrupted_ptr()
	 * cannot tell a real-but-wrong heap address from the original user
	 * buffer pointers, so the memcpy / re-issue would touch a foreign
	 * allocation.  post_state is private to the post handler.  Gated on
	 * HAVE_SYS_STATMOUNT to mirror the .post registration -- on systems
	 * without SYS_statmount the post handler is not registered and a
	 * snapshot only the post handler can free would leak.
	 */
	snap = zmalloc(sizeof(*snap));
	snap->req       = rec->a1;
	snap->buffer    = rec->a2;
	snap->bufsize   = rec->a3;
	rec->post_state = (unsigned long) snap;
#endif
}

/*
 * Oracle: statmount(req, buf, bufsize, flags) writes a struct statmount
 * fixed-prefix into the user buffer and returns 0 on success, with the
 * per-mount data anchored at req->mnt_id.  For a stable mount the kernel
 * fields the same struct on a back-to-back re-call, so a byte-identical
 * compare of the fixed-prefix region across two snapshots is the cheapest
 * possible cross-check.  Mount/umount flux or transient -EBUSY/-EINVAL on
 * the re-call is detected via rc < 0 and we silently skip -- only true
 * divergence with a successful re-call is reported.
 *
 * Divergence shapes the oracle catches:
 *   - copy_to_user mis-write: the kernel produced the right answer but a
 *     u64 landed in the wrong slot inside the fixed prefix or arrived torn.
 *   - 32-bit-on-64-bit compat sign-extension on the size_t bufsize word.
 *   - struct layout mismatch between userspace and kernel for the fixed
 *     prefix (a new field inserted in the middle, padding drift).
 *   - sibling-thread scribble of the user req struct or buf payload at
 *     rec->a1/rec->a2 between the original syscall return and our
 *     re-issue via alloc_shared in another trinity child task.
 *
 * TOCTOU defeat: the three input args (req, buffer, bufsize) are
 * snapshotted at sanitise time into a heap struct in rec->post_state, so
 * a sibling that scribbles rec->aN between syscall return and post entry
 * cannot redirect us at a foreign req / buf and cannot smear the bufsize
 * bound used to seed the re-issue.  We still snapshot both the request
 * struct and the buf payload into stack-locals before re-issuing, with a
 * fresh private stack request and a fresh private stack buf (do NOT pass
 * the snapshot's req / buffer -- a sibling could mutate the user buffers
 * themselves mid-syscall and forge a clean compare).  The flags arg is
 * forced to zero on the re-call.
 *
 * Per-audit note: only the FIXED prefix (sizeof(struct statmount)) is
 * compared.  The variable-length string area beyond the fixed struct is
 * also stable but harder to bound -- skip it for this first pass.
 *
 * Sample one in a hundred to stay in line with the rest of the oracle
 * family.  No early return on first divergence -- multi-field corruption
 * surfaces in a single sample.
 */
static void post_statmount(struct syscallrecord *rec)
{
#ifdef HAVE_SYS_STATMOUNT
	struct statmount_post_state *snap =
		(struct statmount_post_state *) rec->post_state;
	struct mnt_id_req first_req;
	struct statmount first_buf;
	struct statmount recheck_buf;
	long rc;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(snap)) {
		outputerr("post_statmount: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  snap);
		__atomic_add_fetch(&shm->stats.post_handler_corrupt_ptr, 1, __ATOMIC_RELAXED);
		rec->post_state = 0;
		return;
	}

	if (!ONE_IN(100))
		goto out_free;

	if ((long) rec->retval != 0)
		goto out_free;

	if (snap->req == 0 || snap->buffer == 0)
		goto out_free;

	if (snap->bufsize < sizeof(struct statmount))
		goto out_free;

	{
		void *req_p = (void *)(unsigned long) snap->req;
		void *buf_p = (void *)(unsigned long) snap->buffer;

		/*
		 * Defense in depth: even with the post_state snapshot, a
		 * wholesale stomp could rewrite the snapshot's inner pointer
		 * fields.  Reject pid-scribbled req/buffer before deref.
		 */
		if (looks_like_corrupted_ptr(req_p) ||
		    looks_like_corrupted_ptr(buf_p)) {
			outputerr("post_statmount: rejected suspicious req=%p buf=%p (post_state-scribbled?)\n",
				  req_p, buf_p);
			__atomic_add_fetch(&shm->stats.post_handler_corrupt_ptr, 1, __ATOMIC_RELAXED);
			goto out_free;
		}
	}

	memcpy(&first_req, (void *) snap->req, sizeof(first_req));
	memcpy(&first_buf, (void *) snap->buffer, sizeof(first_buf));

	{
		struct mnt_id_req recheck_req = first_req;

		rc = syscall(SYS_statmount, &recheck_req, &recheck_buf,
			     sizeof(recheck_buf), 0u);
	}

	if (rc < 0)
		goto out_free;

	if (memcmp(&first_buf, &recheck_buf, sizeof(struct statmount)) != 0) {
		const u64 *first_words = (const u64 *) &first_buf;
		const u64 *recheck_words = (const u64 *) &recheck_buf;
		char first_hex[8 * 17 + 1];
		char recheck_hex[8 * 17 + 1];
		size_t off;
		unsigned int nwords;
		unsigned int i;

		nwords = sizeof(struct statmount) / sizeof(u64);
		if (nwords > 8)
			nwords = 8;

		off = 0;
		for (i = 0; i < nwords; i++)
			off += snprintf(first_hex + off,
					sizeof(first_hex) - off,
					"%016lx ",
					(unsigned long) first_words[i]);
		first_hex[off > 0 ? off - 1 : 0] = '\0';

		off = 0;
		for (i = 0; i < nwords; i++)
			off += snprintf(recheck_hex + off,
					sizeof(recheck_hex) - off,
					"%016lx ",
					(unsigned long) recheck_words[i]);
		recheck_hex[off > 0 ? off - 1 : 0] = '\0';

		output(0,
		       "[oracle:statmount] mnt_id=%llx prefix [%s] vs [%s]\n",
		       (unsigned long long) first_req.mnt_id,
		       first_hex, recheck_hex);
		__atomic_add_fetch(&shm->stats.statmount_oracle_anomalies,
				   1, __ATOMIC_RELAXED);
	}

out_free:
	deferred_freeptr(&rec->post_state);
#else
	(void) rec;
#endif
}

struct syscallentry syscall_statmount = {
	.name = "statmount",
	.num_args = 4,
	.argtype = { [0] = ARG_ADDRESS, [1] = ARG_ADDRESS, [2] = ARG_LEN },
	.argname = { [0] = "req", [1] = "buf", [2] = "bufsize", [3] = "flags" },
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VFS,
	.sanitise = sanitise_statmount,
	.post = post_statmount,
};
