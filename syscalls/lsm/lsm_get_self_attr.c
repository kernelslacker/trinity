/*
 * SYSCALL_DEFINE4(lsm_get_self_attr, unsigned int, attr,
 *		struct lsm_ctx __user *, ctx, u32 __user *, size, u32, flags)
 */
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include "arch.h"
#include "deferred-free.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#ifndef LSM_ATTR_CURRENT
#define LSM_ATTR_CURRENT	100
#define LSM_ATTR_EXEC		101
#define LSM_ATTR_FSCREATE	102
#define LSM_ATTR_KEYCREATE	103
#define LSM_ATTR_PREV		104
#define LSM_ATTR_SOCKCREATE	105
#endif

#ifndef LSM_FLAG_SINGLE
#define LSM_FLAG_SINGLE		0x0001
#endif

#if defined(SYS_lsm_get_self_attr) || defined(__NR_lsm_get_self_attr)
#ifndef SYS_lsm_get_self_attr
#define SYS_lsm_get_self_attr __NR_lsm_get_self_attr
#endif
#define HAVE_SYS_LSM_GET_SELF_ATTR 1
#endif

/*
 * Cap the snapshot/re-call buffer at one page.  The kernel's lsm_ctx output
 * for a single attribute today comfortably fits well below this; the cap
 * keeps the on-stack buffers bounded if a future LSM ever grows the reply.
 */
#define LSM_CTX_BUF_MAX 4096

static unsigned long lsm_attrs[] = {
	LSM_ATTR_CURRENT, LSM_ATTR_EXEC, LSM_ATTR_FSCREATE,
	LSM_ATTR_KEYCREATE, LSM_ATTR_PREV, LSM_ATTR_SOCKCREATE,
};

static unsigned long lsm_get_flags[] = {
	LSM_FLAG_SINGLE,
};

#ifdef HAVE_SYS_LSM_GET_SELF_ATTR
/*
 * Snapshot of the four lsm_get_self_attr input args read by the post
 * oracle, captured at sanitise time and consumed by the post handler.
 * Lives in rec->post_state, a slot the syscall ABI does not expose, so
 * a sibling syscall scribbling rec->aN between the syscall returning
 * and the post handler running cannot redirect us at a foreign ctx /
 * size user buffer or hand the re-call the wrong (attr, flags) tuple.
 *
 * Wired into the post_state ownership table by post_state_install() at
 * sanitise time; post_lsm_get_self_attr() gates the snap through
 * post_state_claim_owned() before any field deref, so a sibling stomp
 * that redirects rec->post_state at a foreign heap chunk is rejected
 * by the ownership lookup before the leading-word magic compare ever
 * runs.
 */
#define LSM_GET_SELF_ATTR_POST_STATE_MAGIC	0x4C534D4753415452UL	/* "LSMGSATR" */
struct lsm_get_self_attr_post_state {
	unsigned long magic;
	unsigned long attr;
	unsigned long ctx;
	unsigned long size;
	unsigned long flags;
};
#endif

static void sanitise_lsm_get_self_attr(struct syscallrecord *rec)
{
	u32 *size;
	void *buf;
	unsigned int sizepick;
	unsigned long buf_len = 0;
#ifdef HAVE_SYS_LSM_GET_SELF_ATTR
	struct lsm_get_self_attr_post_state *snap;
#endif

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;

	/*
	 * Buffer + size variant:
	 *   60% normal: page-sized buf, *size = page_size
	 *   15% undersized: 16-byte buf with *size = 16 (E2BIG path)
	 *   10% oversized: 2*page-sized buf with *size = 2*page_size
	 *   10% NULL size pointer (EFAULT before any copy)
	 *    5% NULL ctx buffer (EFAULT at copy_to_user)
	 *
	 * The post oracle bails when snap->ctx or snap->size is 0 and when
	 * rec->retval != 0, so the EFAULT / E2BIG branches don't trip the
	 * comparison; the post oracle continues to work on the normal path.
	 * Whenever the buffer is real we keep *size <= the allocation so
	 * the kernel can't write past our allocation.
	 */
	sizepick = rnd_modulo_u32(20);

	if (sizepick < 12) {
		buf_len = page_size;
		buf = get_writable_address(buf_len);
		size = (u32 *) get_writable_address(sizeof(*size));
		if (!buf || !size)
			return;
		*size = page_size;
		rec->a2 = (unsigned long) buf;
		rec->a3 = (unsigned long) size;
	} else if (sizepick < 15) {
		buf_len = 16;
		buf = get_writable_address(buf_len);
		size = (u32 *) get_writable_address(sizeof(*size));
		if (!buf || !size)
			return;
		*size = 16;
		rec->a2 = (unsigned long) buf;
		rec->a3 = (unsigned long) size;
	} else if (sizepick < 17) {
		buf_len = 2 * page_size;
		buf = get_writable_address(buf_len);
		size = (u32 *) get_writable_address(sizeof(*size));
		if (!buf || !size)
			return;
		*size = buf_len;
		rec->a2 = (unsigned long) buf;
		rec->a3 = (unsigned long) size;
	} else if (sizepick < 19) {
		buf_len = page_size;
		buf = get_writable_address(buf_len);
		if (!buf)
			return;
		rec->a2 = (unsigned long) buf;
		rec->a3 = 0;
	} else {
		size = (u32 *) get_writable_address(sizeof(*size));
		if (!size)
			return;
		*size = page_size;
		rec->a2 = 0;
		rec->a3 = (unsigned long) size;
	}

	if (rec->a2 != 0)
		avoid_shared_buffer_out(&rec->a2, buf_len);
	if (rec->a3 != 0)
		avoid_shared_buffer_inout(&rec->a3, sizeof(u32));

#ifdef HAVE_SYS_LSM_GET_SELF_ATTR
	/*
	 * Snapshot all four input args for the post oracle.  Without this
	 * the post handler reads rec->aN at post-time, when a sibling
	 * syscall may have scribbled the slots: looks_like_corrupted_ptr()
	 * cannot tell a real-but-wrong heap address from the original user
	 * buffer pointers, so the memcpy / re-call would touch a foreign
	 * allocation.  post_state is private to the post handler.  Gated on
	 * HAVE_SYS_LSM_GET_SELF_ATTR to mirror the .post registration -- on
	 * systems without SYS_lsm_get_self_attr the post handler is not
	 * registered and a snapshot only the post handler can free would
	 * leak.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = LSM_GET_SELF_ATTR_POST_STATE_MAGIC;
	snap->attr  = rec->a1;
	snap->ctx   = rec->a2;
	snap->size  = rec->a3;
	snap->flags = rec->a4;
	post_state_install(rec, snap);
#endif
}

/*
 * Oracle: lsm_get_self_attr(attr, ctx, size, flags) reads the calling task's
 * own LSM attributes (current/exec/fscreate/keycreate/prev/sockcreate) and
 * writes one or more struct lsm_ctx records into the user buffer along with
 * the bytes-actually-written value through *size.  The fields these come
 * from -- task->security via the LSM stack -- only mutate via
 * lsm_set_self_attr(2) (or a parallel exec walking through the bprm hooks),
 * so a same-task re-issue with the same (attr, flags) ~150ms later through
 * the same code path must produce a byte-identical (size, ctx[0..size])
 * pair unless one of:
 *
 *   - copy_to_user mis-write past or before the lsm_ctx user slot.
 *   - 32-on-64 compat sign-extension on the u32 size slot.
 *   - LSM stack ordering bug: different LSMs answer in different order
 *     across calls, so the same attribute serialises to different bytes.
 *   - Stale rcu read of task->security after a parallel security_setprocattr
 *     against a different task that aliases through a stale pointer.
 *   - Sibling-thread scribble of either rec->aN or the user buffers between
 *     syscall return and our post-hook re-read.
 *
 * TOCTOU defeat: all four input args (attr, ctx, size, flags) are
 * snapshotted at sanitise time into a heap struct in rec->post_state, so
 * a sibling that scribbles rec->aN between syscall return and post entry
 * cannot redirect us at a foreign ctx / size buffer or hand the re-call
 * the wrong (attr, flags) tuple.  We still snapshot the size value and
 * ctx payload into stack-locals before re-issuing, with a fresh private
 * stack ctx buffer and size word (NOT the snapshot's ctx / size -- a
 * sibling could scribble the user buffers themselves mid-syscall and
 * forge a clean compare).
 *
 * Sample one in a hundred to stay in line with the rest of the oracle
 * family.  Per-field bumps with no early-return so simultaneous size+ctx
 * corruption surfaces in a single sample.
 *
 * False-positive sources at ONE_IN(100):
 *   - Sibling lsm_set_self_attr(2) between the two reads: rc != 0 path
 *     swallows it (the second call may legitimately differ, but the
 *     swallow keeps it from bumping the counter).
 *   - LSM module load/unload race: extremely rare, rc != 0 path swallows.
 *   - Defensive size cap above protects against future kernel surprises
 *     that grow the lsm_ctx output past a page.
 */
#ifdef HAVE_SYS_LSM_GET_SELF_ATTR
static void post_lsm_get_self_attr(struct syscallrecord *rec)
{
	struct lsm_get_self_attr_post_state *snap;
	u32 size_first;
	u32 size_recall;
	unsigned char ctx_first[LSM_CTX_BUF_MAX];
	unsigned char ctx_recall[LSM_CTX_BUF_MAX];
	long rc;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, LSM_GET_SELF_ATTR_POST_STATE_MAGIC,
				      __func__);
	if (snap == NULL)
		return;

	if (!ONE_IN(100))
		goto out_free;

	if ((long) rec->retval != 0)
		goto out_free;

	if (snap->ctx == 0 || snap->size == 0)
		goto out_free;

	/*
	 * Defense in depth: even with the post_state snapshot, a wholesale
	 * stomp could rewrite the snapshot's inner pointer fields.  Reject
	 * pid-scribbled size before deref.
	 */
	if (looks_like_corrupted_ptr(rec, (void *) snap->size)) {
		outputerr("post_lsm_get_self_attr: rejected suspicious size=%p (post_state-scribbled?)\n",
			  (void *) snap->size);
		goto out_free;
	}

	/*
	 * Copy the size word through the TOCTOU-guarded helper.  The
	 * shape-only guard above lets a non-NULL but stale/unmapped
	 * snap->size through; post_snapshot_or_skip range-proves the
	 * size_first window and recovers from a sibling mprotect/munmap
	 * fault instead of crashing the child mid-sample.
	 */
	if (!post_snapshot_or_skip(&size_first, (const void *) snap->size,
				   sizeof(size_first)))
		goto out_free;
	if (size_first > LSM_CTX_BUF_MAX)
		goto out_free;

	if (!post_snapshot_or_skip(ctx_first, (const void *) snap->ctx,
				   size_first))
		goto out_free;

	size_recall = LSM_CTX_BUF_MAX;
	memset(ctx_recall, 0, sizeof(ctx_recall));
	rc = syscall(SYS_lsm_get_self_attr, snap->attr, ctx_recall,
		     &size_recall, snap->flags);
	if (rc != 0)
		goto out_free;

	if (size_first != size_recall) {
		output(0,
		       "[oracle:lsm_get_self_attr] size %u vs %u (attr=%lu flags=0x%lx)\n",
		       size_first, size_recall, snap->attr, snap->flags);
		__atomic_add_fetch(&shm->stats.oracle.lsm_get_self_attr_oracle_anomalies,
				   1, __ATOMIC_RELAXED);
	}

	if (memcmp(ctx_first, ctx_recall,
		   size_first < size_recall ? size_first : size_recall) != 0) {
		output(0,
		       "[oracle:lsm_get_self_attr] ctx diverged over %u bytes (attr=%lu flags=0x%lx)\n",
		       size_first < size_recall ? size_first : size_recall,
		       snap->attr, snap->flags);
		__atomic_add_fetch(&shm->stats.oracle.lsm_get_self_attr_oracle_anomalies,
				   1, __ATOMIC_RELAXED);
	}

out_free:
	post_state_release(rec, snap);
}
#endif

struct syscallentry syscall_lsm_get_self_attr = {
	.name = "lsm_get_self_attr",
	.num_args = 4,
	.argtype = { [0] = ARG_OP, [1] = ARG_ADDRESS, [2] = ARG_ADDRESS, [3] = ARG_LIST },
	.argname = { [0] = "attr", [1] = "ctx", [2] = "size", [3] = "flags" },
	.arg_params[0].list = ARGLIST(lsm_attrs),
	.arg_params[3].list = ARGLIST(lsm_get_flags),
	.sanitise = sanitise_lsm_get_self_attr,
	.group = GROUP_PROCESS,
	.flags = REEXEC_SANITISE_OK,
#ifdef HAVE_SYS_LSM_GET_SELF_ATTR
	.post = post_lsm_get_self_attr,
#endif
};
