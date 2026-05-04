/*
 * SYSCALL_DEFINE3(lsm_list_modules, u64 __user *, ids, u32 __user *, size,
 *		u32, flags)
 */
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <asm/unistd.h>
#include "arch.h"
#include "deferred-free.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

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
 */
struct lsm_list_modules_post_state {
	unsigned long ids;
	unsigned long size;
};
#endif

static void sanitise_lsm_list_modules(struct syscallrecord *rec)
{
	u32 *size;
	void *buf;
#ifdef HAVE_SYS_LSM_LIST_MODULES
	struct lsm_list_modules_post_state *snap;
#endif

	/*
	 * The kernel reads *size to find how much space is available for the
	 * u64 LSM ID array. A zero causes immediate E2BIG. Provide a
	 * page-sized buffer and initialize the size accordingly.
	 */
	buf = get_writable_address(page_size);
	size = (u32 *) get_writable_address(sizeof(*size));
	if (!buf || !size)
		return;
	*size = page_size;
	rec->a1 = (unsigned long) buf;
	rec->a2 = (unsigned long) size;
	rec->a3 = 0;	/* flags must be zero */

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
	 */
	snap = zmalloc(sizeof(*snap));
	snap->ids  = rec->a1;
	snap->size = rec->a2;
	rec->post_state = (unsigned long) snap;
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
	struct lsm_list_modules_post_state *snap = (struct lsm_list_modules_post_state *) rec->post_state;
	u32 first_size;
	u64 first_ids[64];
	size_t first_count;
	u64 recheck_ids[64];
	u32 recheck_size = sizeof(recheck_ids);
	bool size_diverged;
	bool ids_diverged;
	int rc;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_lsm_list_modules: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  snap);
		rec->post_state = 0;
		return;
	}

	if (!ONE_IN(100))
		goto out_free;

	if (rec->retval != 0)
		goto out_free;

	if (snap->ids == 0 || snap->size == 0)
		goto out_free;

	{
		void *ids_p = (void *)(unsigned long) snap->ids;
		void *size_p = (void *)(unsigned long) snap->size;

		/*
		 * Defense in depth: even with the post_state snapshot, a
		 * wholesale stomp could rewrite the snapshot's inner pointer
		 * fields.  Reject pid-scribbled ids/size before deref.
		 */
		if (looks_like_corrupted_ptr(rec, ids_p) ||
		    looks_like_corrupted_ptr(rec, size_p)) {
			outputerr("post_lsm_list_modules: rejected suspicious ids=%p size=%p (post_state-scribbled?)\n",
				  ids_p, size_p);
			goto out_free;
		}
	}

	memcpy(&first_size, (void *)(unsigned long) snap->size,
	       sizeof(first_size));
	if (first_size == 0 || first_size > page_size)
		goto out_free;

	first_count = first_size / sizeof(u64);
	if (first_count > 64)
		goto out_free;

	memcpy(first_ids, (void *)(unsigned long) snap->ids,
	       first_count * sizeof(u64));

	rc = syscall(SYS_lsm_list_modules, recheck_ids, &recheck_size, 0);
	if (rc != 0)
		goto out_free;

	size_diverged = (first_size != recheck_size);
	ids_diverged = (memcmp(first_ids, recheck_ids,
			       first_count * sizeof(u64)) != 0);

	if (size_diverged || ids_diverged) {
		size_t recheck_count = recheck_size / sizeof(u64);
		size_t i;
		char first_hex[64 * 17 + 1];
		char recheck_hex[64 * 17 + 1];
		size_t off;

		if (recheck_count > 64)
			recheck_count = 64;

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

		output(0,
		       "[oracle:lsm_list_modules] size %u vs %u ids [%s] vs [%s]\n",
		       first_size, recheck_size, first_hex, recheck_hex);
		__atomic_add_fetch(&shm->stats.lsm_list_modules_oracle_anomalies,
				   1, __ATOMIC_RELAXED);
	}

out_free:
	deferred_freeptr(&rec->post_state);
#else
	(void) rec;
#endif
}

struct syscallentry syscall_lsm_list_modules = {
	.name = "lsm_list_modules",
	.num_args = 3,
	.argname = { [0] = "ids", [1] = "size", [2] = "flags" },
	.rettype = RET_ZERO_SUCCESS,
	.sanitise = sanitise_lsm_list_modules,
	.post = post_lsm_list_modules,
	.group = GROUP_PROCESS,
};
