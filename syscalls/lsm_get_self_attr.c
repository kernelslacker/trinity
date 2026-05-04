/*
 * SYSCALL_DEFINE4(lsm_get_self_attr, unsigned int, attr,
 *		struct lsm_ctx __user *, ctx, u32 __user *, size, u32, flags)
 */
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
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
 */
struct lsm_get_self_attr_post_state {
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
	 * The kernel reads *size to find how much space the caller provided.
	 * A zero value causes an immediate E2BIG before any attribute retrieval
	 * happens. Provide a page-sized buffer and tell the kernel about it.
	 */
	buf = get_writable_address(page_size);
	size = (u32 *) get_writable_address(sizeof(*size));
	if (!buf || !size)
		return;
	*size = page_size;
	rec->a2 = (unsigned long) buf;
	rec->a3 = (unsigned long) size;

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
	snap = zmalloc(sizeof(*snap));
	snap->attr  = rec->a1;
	snap->ctx   = rec->a2;
	snap->size  = rec->a3;
	snap->flags = rec->a4;
	rec->post_state = (unsigned long) snap;
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
	struct lsm_get_self_attr_post_state *snap =
		(struct lsm_get_self_attr_post_state *) rec->post_state;
	u32 size_first;
	u32 size_recall;
	unsigned char ctx_first[LSM_CTX_BUF_MAX];
	unsigned char ctx_recall[LSM_CTX_BUF_MAX];
	long rc;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(snap)) {
		outputerr("post_lsm_get_self_attr: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  snap);
		__atomic_add_fetch(&shm->stats.post_handler_corrupt_ptr, 1, __ATOMIC_RELAXED);
		rec->post_state = 0;
		return;
	}

	if (!ONE_IN(100))
		goto out_free;

	if ((long) rec->retval != 0)
		goto out_free;

	if (snap->ctx == 0 || snap->size == 0)
		goto out_free;

	/*
	 * Defense in depth: even with the post_state snapshot, a wholesale
	 * stomp could rewrite the snapshot's inner pointer fields.  Reject
	 * pid-scribbled ctx/size before deref.
	 */
	if (looks_like_corrupted_ptr((void *) snap->ctx) ||
	    looks_like_corrupted_ptr((void *) snap->size)) {
		outputerr("post_lsm_get_self_attr: rejected suspicious ctx=%p size=%p (post_state-scribbled?)\n",
			  (void *) snap->ctx, (void *) snap->size);
		__atomic_add_fetch(&shm->stats.post_handler_corrupt_ptr, 1, __ATOMIC_RELAXED);
		goto out_free;
	}

	memcpy(&size_first, (const void *) snap->size, sizeof(size_first));
	if (size_first > LSM_CTX_BUF_MAX)
		goto out_free;

	memcpy(ctx_first, (const void *) snap->ctx, size_first);

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
		__atomic_add_fetch(&shm->stats.lsm_get_self_attr_oracle_anomalies,
				   1, __ATOMIC_RELAXED);
	}

	if (memcmp(ctx_first, ctx_recall,
		   size_first < size_recall ? size_first : size_recall) != 0) {
		output(0,
		       "[oracle:lsm_get_self_attr] ctx diverged over %u bytes (attr=%lu flags=0x%lx)\n",
		       size_first < size_recall ? size_first : size_recall,
		       snap->attr, snap->flags);
		__atomic_add_fetch(&shm->stats.lsm_get_self_attr_oracle_anomalies,
				   1, __ATOMIC_RELAXED);
	}

out_free:
	deferred_freeptr(&rec->post_state);
}
#endif

struct syscallentry syscall_lsm_get_self_attr = {
	.name = "lsm_get_self_attr",
	.num_args = 4,
	.argtype = { [0] = ARG_OP, [3] = ARG_LIST },
	.argname = { [0] = "attr", [1] = "ctx", [2] = "size", [3] = "flags" },
	.arg_params[0].list = ARGLIST(lsm_attrs),
	.arg_params[3].list = ARGLIST(lsm_get_flags),
	.rettype = RET_ZERO_SUCCESS,
	.sanitise = sanitise_lsm_get_self_attr,
	.group = GROUP_PROCESS,
#ifdef HAVE_SYS_LSM_GET_SELF_ATTR
	.post = post_lsm_get_self_attr,
#endif
};
