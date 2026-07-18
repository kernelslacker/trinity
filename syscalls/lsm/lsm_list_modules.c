/*
 * SYSCALL_DEFINE3(lsm_list_modules, u64 __user *, ids, u32 __user *, size,
 *		u32, flags)
 */
#include <stdbool.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <string.h>
#include "arch.h"
#include "deferred-free.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"
#include "valresult.h"

#if defined(SYS_lsm_list_modules) || defined(__NR_lsm_list_modules)
#ifndef SYS_lsm_list_modules
#define SYS_lsm_list_modules __NR_lsm_list_modules
#endif
#define HAVE_SYS_LSM_LIST_MODULES 1
#endif

#ifdef HAVE_SYS_LSM_LIST_MODULES
/*
 * Snapshot of the two lsm_list_modules input args read by the post
 * oracle, captured at sanitise time and consumed by the post handler.
 * Lives in rec->post_state, a slot the syscall ABI does not expose, so
 * a sibling syscall scribbling rec->aN between the syscall returning
 * and the post handler running cannot redirect us at a foreign LSM-id
 * buffer or smear the size word read out of the user buffer.
 *
 * Wired into the post_state ownership table by post_state_install() at
 * sanitise time; post_lsm_list_modules() gates the snap through
 * post_state_claim_owned() before any field deref, so a sibling stomp
 * that redirects rec->post_state at a foreign heap chunk is rejected
 * by the ownership lookup before the leading-word magic compare ever
 * runs.
 */
#define LSM_LIST_MODULES_POST_STATE_MAGIC	0x4C534D4C4D4F4453UL	/* "LSMLMODS" */
struct lsm_list_modules_post_state {
	unsigned long magic;
	unsigned long ids;
	unsigned long size;
	struct valresult_buf vrb;
};
#endif

static void sanitise_lsm_list_modules(struct syscallrecord *rec)
{
	struct valresult_buf vrb = { 0 };
	unsigned long buf_len = 0;
#ifdef HAVE_SYS_LSM_LIST_MODULES
	struct lsm_list_modules_post_state *snap;
#endif

	/*
	 * Two-axis mutation.
	 *
	 * AXIS A (fault shapes, open-coded, picked first): NULL-size and
	 * NULL-ids each fire on ~1/10 of calls.  These exercise the
	 * EFAULT paths the kernel takes before any copy and stay outside
	 * the value-result shape catalogue because valresult's ZERO shape
	 * already covers "valid pointer, zero length" -- the user-pointer
	 * being NULL is a distinct fault condition.
	 *
	 * AXIS B (size shape, ~80% of calls): the value-result (ids,
	 * *size) pair is routed through valresult_alloc() with a
	 * page_size natural capacity.  The shape catalogue (EXACT /
	 * UNDER / EXACT_PLUS_ONE / HUGE / ZERO) mutates both the ids
	 * buffer capacity and the matching *size word in lockstep so the
	 * kernel can never write past the allocation.  EXACT (~88% of the
	 * AXIS B fraction) keeps the post oracle's stable-equality
	 * comparison firing on the happy path; the other four shapes are
	 * new fuzz coverage for the addrlen-style bounds and short-write
	 * paths and the oracle short-circuits cleanly on them via the
	 * rec->retval != 0 gate.
	 */
	rec->a3 = 0;	/* flags must be zero */

	if (ONE_IN(10)) {
		/* AXIS A: NULL size pointer (EFAULT before any copy) */
		void *buf = get_writable_address(page_size);

		if (!buf)
			return;
		buf_len = page_size;
		rec->a1 = (unsigned long) buf;
		rec->a2 = 0;
		avoid_shared_buffer_out(&rec->a1, buf_len);
	} else if (ONE_IN(9)) {
		/* AXIS A: NULL ids buffer (EFAULT at copy_to_user) */
		u32 *size = (u32 *) get_writable_address(sizeof(*size));

		if (!size)
			return;
		*size = page_size;
		rec->a1 = 0;
		rec->a2 = (unsigned long) size;
		avoid_shared_buffer_inout(&rec->a2, sizeof(u32));
	} else {
		/* AXIS B: size shape via valresult catalogue */
		vrb = valresult_alloc(page_size, valresult_pick_shape());
		buf_len = vrb.cap;
		rec->a1 = (unsigned long) vrb.buf;
		rec->a2 = (unsigned long) vrb.len_io;
		if (rec->a1 != 0)
			avoid_shared_buffer_out(&rec->a1, buf_len);
		if (rec->a2 != 0)
			avoid_shared_buffer_inout(&rec->a2, sizeof(u32));
	}

#ifdef HAVE_SYS_LSM_LIST_MODULES
	/*
	 * Snapshot the two input args for the post oracle.  Without this
	 * the post handler reads rec->a1/a2 at post-time, when a sibling
	 * syscall may have scribbled the slots: looks_like_corrupted_ptr()
	 * cannot tell a real-but-wrong heap address from the original user
	 * buffer pointers, so the memcpy / re-issue would touch a foreign
	 * allocation and a stomped size pointer would smear the buf-size
	 * read that bounds the comparison.  post_state is private to the
	 * post handler.  Gated on HAVE_SYS_LSM_LIST_MODULES to mirror the
	 * .post body -- on systems without SYS_lsm_list_modules the post
	 * handler is a no-op stub and a snapshot only the post handler can
	 * free would leak.
	 *
	 * snap->vrb is by-value: the AXIS A paths leave it zero-initialised
	 * (NULL buf, NULL len_io) and valresult_free() is NULL-safe.  The
	 * AXIS B path stores the helper-returned vrb so post can release
	 * both slots via deferred_free_enqueue() -- closes the prior leak
	 * from the hand-rolled zmalloc(sizeof(*size)) path.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = LSM_LIST_MODULES_POST_STATE_MAGIC;
	snap->ids  = rec->a1;
	snap->size = rec->a2;
	snap->vrb  = vrb;
	post_state_install(rec, snap);
#endif
}

/*
 * Oracle: lsm_list_modules(ids, size, flags) reports the IDs of the LSM
 * modules currently loaded into the kernel's LSM stack as a u64 array,
 * with the byte-count of the array written back through *size.  The LSM
 * stack is fixed at boot -- modules cannot be loaded or unloaded at
 * runtime -- so two back-to-back calls from the same task must produce
 * byte-identical results.  Any divergence between the first call's
 * payload and an immediate re-call points at one of:
 *
 *   - copy_to_user mis-write: the kernel produced the right answer but
 *     it landed in the wrong slot in the user buffer or arrived torn.
 *   - sibling-thread scribble of the user receive buffer or size word
 *     between the syscall return and our post-hook re-read.
 *   - 32-bit-on-64-bit compat sign-extension on the size word.
 *   - LSM-stack accounting drift (a regression that lets the stack
 *     mutate at runtime, which it must never do).
 *
 * TOCTOU defeat: the two input args (ids, size) are snapshotted at
 * sanitise time into a heap struct in rec->post_state, so a sibling
 * that scribbles rec->aN between syscall return and post entry cannot
 * redirect us at a foreign LSM-id buffer or smear the size pointer
 * used to bound the comparison.  We still snapshot both the size word
 * and the first N ids into stack-locals before the re-issue, with a
 * fresh private size word and ids buffer (do NOT pass the snap's
 * ids/size -- a sibling could scribble the user buffers themselves
 * mid-syscall and forge a clean compare).  The flags arg is forced to
 * zero by the sanitiser and is not part of the comparison.
 *
 * Comparison rules (no early return on first mismatch -- multi-field
 * corruption surfaces in a single sample):
 *   - size word must match byte-for-byte across the two calls.
 *   - the u64 IDs payload, of length first_size bytes, must match
 *     byte-for-byte across the two calls.
 *
 * Sample one in a hundred to stay in line with the rest of the oracle
 * family.  Wired only on syscall_lsm_list_modules -- the syscall stands
 * alone with no aliases.
 */
static void post_lsm_list_modules(struct syscallrecord *rec)
{
#ifdef HAVE_SYS_LSM_LIST_MODULES
	struct lsm_list_modules_post_state *snap;
	u32 first_size;
	u64 first_ids[64];
	size_t first_count;
	u64 recheck_ids[64] = { 0 };
	u32 recheck_size = sizeof(recheck_ids);
	size_t recheck_count;
	size_t cmp_count;
	bool size_diverged;
	bool ids_diverged;
	int rc;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, LSM_LIST_MODULES_POST_STATE_MAGIC,
				      __func__);
	if (snap == NULL)
		return;

	if (!ONE_IN(100))
		goto out_free;

	if (rec->retval != 0)
		goto out_free;

	if (snap->ids == 0 || snap->size == 0)
		goto out_free;

	{
		void *size_p = (void *)(unsigned long) snap->size;

		/*
		 * Defense in depth: even with the post_state snapshot, a
		 * wholesale stomp could rewrite the snapshot's inner pointer
		 * fields.  Reject pid-scribbled size before deref.
		 */
		if (looks_like_corrupted_ptr(rec, size_p)) {
			outputerr("post_lsm_list_modules: rejected suspicious size=%p (post_state-scribbled?)\n",
				  size_p);
			goto out_free;
		}
	}

	/*
	 * Copy the size word through the TOCTOU-guarded helper.  The
	 * shape-only guard above lets a non-NULL but stale/unmapped
	 * snap->size through; post_snapshot_or_skip range-proves the
	 * first_size window and recovers from a sibling mprotect/munmap
	 * fault instead of crashing the child mid-sample.
	 */
	if (!post_snapshot_or_skip(&first_size, (void *)(unsigned long) snap->size,
				   sizeof(first_size)))
		goto out_free;
	if (first_size == 0 || first_size > page_size)
		goto out_free;

	first_count = first_size / sizeof(u64);
	if (first_count > 64)
		goto out_free;

	if (!post_snapshot_or_skip(first_ids,
				   (void *)(unsigned long) snap->ids,
				   first_count * sizeof(u64)))
		goto out_free;

	rc = syscall(SYS_lsm_list_modules, recheck_ids, &recheck_size, 0);
	if (rc != 0)
		goto out_free;

	recheck_count = recheck_size / sizeof(u64);
	if (recheck_count > 64)
		recheck_count = 64;

	cmp_count = first_count < recheck_count ? first_count : recheck_count;

	size_diverged = (first_size != recheck_size);
	ids_diverged = (memcmp(first_ids, recheck_ids,
			       cmp_count * sizeof(u64)) != 0);

	if (size_diverged || ids_diverged) {
		size_t i;
		char first_hex[64 * 17 + 1];
		char recheck_hex[64 * 17 + 1];
		size_t off;

		off = 0;
		for (i = 0; i < first_count; i++)
			off += snprintf(first_hex + off,
					sizeof(first_hex) - off,
					"%016lx ",
					(unsigned long) first_ids[i]);
		first_hex[off > 0 ? off - 1 : 0] = '\0';

		off = 0;
		for (i = 0; i < recheck_count; i++)
			off += snprintf(recheck_hex + off,
					sizeof(recheck_hex) - off,
					"%016lx ",
					(unsigned long) recheck_ids[i]);
		recheck_hex[off > 0 ? off - 1 : 0] = '\0';

		if (size_diverged)
			output(0,
			       "[oracle:lsm_list_modules] size divergence %u vs %u\n",
			       first_size, recheck_size);

		output(0,
		       "[oracle:lsm_list_modules] size %u vs %u ids [%s] vs [%s] (cmp_count=%zu)\n",
		       first_size, recheck_size, first_hex, recheck_hex,
		       cmp_count);
		__atomic_add_fetch(&shm->stats.oracle.lsm_list_modules_oracle_anomalies,
				   1, __ATOMIC_RELAXED);
	}

out_free:
	valresult_free(&snap->vrb);
	post_state_release(rec, snap);
#else
	(void) rec;
#endif
}

struct syscallentry syscall_lsm_list_modules = {
	.name = "lsm_list_modules",
	.num_args = 3,
	.argname = { [0] = "ids", [1] = "size", [2] = "flags" },
	.argtype = { [0] = ARG_ADDRESS, [1] = ARG_ADDRESS },
	.sanitise = sanitise_lsm_list_modules,
	.post = post_lsm_list_modules,
	.flags = REEXEC_SANITISE_OK,
	.group = GROUP_PROCESS,
};
