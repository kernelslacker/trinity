/*
 * SYSCALL_DEFINE3(get_robust_list, int, pid,
	struct robust_list_head __user * __user *, head_ptr,
	size_t __user *, len_ptr)
 */
#include <stddef.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/types.h>
#include "output-poison.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#if defined(SYS_get_robust_list) || defined(__NR_get_robust_list)
#ifndef SYS_get_robust_list
#define SYS_get_robust_list __NR_get_robust_list
#endif
#define HAVE_SYS_GET_ROBUST_LIST 1
#endif

#ifdef HAVE_SYS_GET_ROBUST_LIST
/*
 * Snapshot of the three get_robust_list input args read by the post oracle,
 * captured at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->aN between the syscall returning and the post
 * handler running cannot retarget the pid self-filter or redirect the
 * oracle at a foreign head_ptr / len_ptr user buffer.
 */
#define GET_ROBUST_LIST_POST_STATE_MAGIC	0x4752424CUL	/* "GRBL" */
struct get_robust_list_post_state {
	unsigned long magic;
	unsigned long pid;
	unsigned long head_ptr;
	unsigned long len_ptr;
	/*
	 * Per-slot seeds for the poison pattern stamped into the head_ptr
	 * and len_ptr OUT-buffers at sanitise time.  [0] covers the 8-byte
	 * robust_list_head pointer, [1] the 8-byte size_t.  The post
	 * handler feeds each seed back into check_output_struct(): a
	 * byte-identical match on a success return means the kernel wrote
	 * zero bytes into that slot and left our stamp intact.  A seed of
	 * 0 means sanitise chose not to stamp that slot (unwritable
	 * pointer) -- the post handler no-ops that arm so "we could not
	 * poison" is not confused with "kernel did not write".
	 */
	uint64_t poison_seed[2];
};
#endif

static void sanitise_get_robust_list(struct syscallrecord *rec)
{
#ifdef HAVE_SYS_GET_ROBUST_LIST
	struct get_robust_list_post_state *snap;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;
#endif

	/*
	 * The kernel writes a robust_list_head pointer through head_ptr (a2)
	 * and a size_t through len_ptr (a3).  Both args are
	 * ARG_NON_NULL_ADDRESS, so generic_sanitise sources them from the
	 * random pool with no overlap check against the alloc_shared regions.
	 */
	avoid_shared_buffer_out(&rec->a2, sizeof(void *));
	avoid_shared_buffer_out(&rec->a3, sizeof(size_t));

#ifdef HAVE_SYS_GET_ROBUST_LIST
	/*
	 * Snapshot all three input args for the post oracle.  Without this
	 * the post handler reads rec->aN at post-time, when a sibling
	 * syscall may have scribbled the slots: looks_like_corrupted_ptr()
	 * cannot tell a real-but-wrong heap address from the original user
	 * buffer pointers, so the memcpy would touch a foreign allocation,
	 * and the pid self-filter would resolve against a scribbled value.
	 * post_state is private to the post handler.  Gated on
	 * HAVE_SYS_GET_ROBUST_LIST to mirror the .post registration -- on
	 * systems without SYS_get_robust_list the post handler is not
	 * registered and a snapshot only the post handler can free would
	 * leak.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic    = GET_ROBUST_LIST_POST_STATE_MAGIC;
	snap->pid      = rec->a1;
	snap->head_ptr = rec->a2;
	snap->len_ptr  = rec->a3;
	snap->poison_seed[0] = 0;
	snap->poison_seed[1] = 0;

	/*
	 * Stamp a per-slot poison pattern into the two OUT-buffers the
	 * kernel is about to fill on success (head_ptr: 8-byte pointer,
	 * len_ptr: 8-byte size_t).  Gate each stamp on
	 * range_readable_user() so an ARG_NON_NULL_ADDRESS draw at an
	 * address no longer provably mapped skips that slot rather than
	 * SIGSEGVing the sanitiser inside poison_output_struct's byte
	 * walk; on skip the seed stays 0 and the post handler no-ops that
	 * arm.  Done after avoid_shared_buffer_out() so the poison lands
	 * on the final buffer the kernel will see.
	 */
	{
		unsigned long slots[2] = { rec->a2, rec->a3 };
		size_t szs[2] = { sizeof(void *), sizeof(size_t) };
		unsigned int i;

		for (i = 0; i < 2; i++) {
			void *buf = (void *)(unsigned long) slots[i];

			if (range_readable_user(buf, szs[i]))
				snap->poison_seed[i] =
					poison_output_struct(buf, szs[i], 0);
		}
	}

	post_state_install(rec, snap);
#endif
}

/*
 * Oracle: get_robust_list(pid, &head, &len) returns a snapshot of
 * current->robust_list and sizeof(*current->robust_list) for the target
 * task.  Both fields are set once via set_robust_list (called by glibc
 * pthread setup) and stay stable across the lifetime of the task, so
 * re-issuing the same query for self gives a second read of the same
 * field through the same code path — the two copies must agree unless
 * something in between either (a) had copy_to_user write past or before
 * one of the two output slots, (b) the 32-bit-on-64-bit compat copy_to_user
 * truncated the head pointer from 8 bytes to 4, (c) struct-layout mismatch
 * on 32-on-64 emulation landed sizeof(*current->robust_list) (24 on 64-bit,
 * 12 on 32-bit) into the head_ptr slot or vice versa, or (d) a sibling
 * thread scribbled the user receive buffers between syscall return and the
 * post-hook.
 *
 * Restrict to self (pid == 0 or pid == gettid()): cross-target sampling
 * races set_robust_list on the target task and tells us nothing.
 *
 * TOCTOU defeat: the three input args (pid, head_ptr, len_ptr) are
 * snapshotted at sanitise time into a heap struct in rec->post_state, so
 * a sibling that scribbles rec->aN between syscall return and post entry
 * cannot retarget the pid self-filter or redirect the oracle at a foreign
 * head_ptr / len_ptr buffer.  The user buffer payloads are then snapshotted
 * into stack-locals before re-issuing, with a fresh private stack pair for
 * the re-call (NOT the snapshot's head_ptr / len_ptr -- a sibling could
 * mutate the user buffers themselves mid-syscall and forge a clean compare).
 *
 * If the re-call returns nonzero (the original syscall succeeded but the
 * re-call hit a transient failure), give up rather than report a false
 * divergence.  Compare head and len individually with no early-return so a
 * multi-field corruption shows up in a single sample, but bump the anomaly
 * counter only once per sample.  Sample one in a hundred to stay in line
 * with the rest of the oracle family.
 *
 * Known benign sources of divergence (acceptable at the 1/100 sample
 * rate): the calling task itself calling set_robust_list between the two
 * reads (Trinity children don't, but it's worth noting), and a
 * get_robust_list issued from a thread that has not yet set its own
 * robust_list returns (head, len) = (NULL, 0); a sibling thread calling
 * set_robust_list on the target between the two reads would race —
 * mitigated by the self-target gate.
 */
#ifdef HAVE_SYS_GET_ROBUST_LIST
static void post_get_robust_list(struct syscallrecord *rec)
{
	struct get_robust_list_post_state *snap;
	struct robust_list_head *user_head, *kernel_head;
	size_t user_len, kernel_len;
	int rc;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, GET_ROBUST_LIST_POST_STATE_MAGIC, __func__);
	if (snap == NULL)
		return;

	if ((long) rec->retval != 0)
		goto out_free;

	if (snap->head_ptr == 0 || snap->len_ptr == 0)
		goto out_free;

	if (!post_snapshot_or_skip(&user_head,
				   (const void *) snap->head_ptr,
				   sizeof(user_head)))
		goto out_free;
	if (!post_snapshot_or_skip(&user_len,
				   (const void *) snap->len_ptr,
				   sizeof(user_len)))
		goto out_free;

	/*
	 * Untouched-out-buf poison check: sanitise stamped a per-slot
	 * poison pattern into head_ptr and len_ptr.  A byte-identical
	 * match on either slot after a success return means the kernel
	 * wrote zero bytes into that scalar and left our stamp intact --
	 * a short-copy or missing copy_to_user() the divergence arm below
	 * would also catch, but only on the 1/100 self-target sample and
	 * only after paying for a re-issue.  Cheap (two 8-byte compares,
	 * no re-issue), so runs on every success sample against the local
	 * snapshots above so a sibling munmap of the writable-pool page
	 * between the deref and here cannot fault inside a second read.
	 * A seed of 0 means sanitise skipped that slot -- skip the check
	 * too.  Counts against the shared post_handler_untouched_out_buf
	 * slot.
	 */
	{
		const void *bufs[2] = { &user_head, &user_len };
		size_t szs[2] = { sizeof(user_head), sizeof(user_len) };
		unsigned int i;

		for (i = 0; i < 2; i++) {
			if (snap->poison_seed[i] != 0 &&
			    check_output_struct(bufs[i], szs[i],
						snap->poison_seed[i]))
				__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
						   1, __ATOMIC_RELAXED);
		}
	}

	if (!ONE_IN(100))
		goto out_free;

	if ((pid_t) snap->pid != 0 && (pid_t) snap->pid != gettid())
		goto out_free;

	rc = syscall(SYS_get_robust_list, 0, &kernel_head, &kernel_len);
	if (rc != 0)
		goto out_free;

	if (user_head != kernel_head || user_len != kernel_len) {
		output(0,
		       "[oracle:get_robust_list] head %p vs %p len %zu vs %zu\n",
		       user_head, kernel_head, user_len, kernel_len);
		__atomic_add_fetch(&shm->stats.oracle.get_robust_list_oracle_anomalies,
				   1, __ATOMIC_RELAXED);
	}

out_free:
	post_state_release(rec, snap);
}
#endif

struct syscallentry syscall_get_robust_list = {
	.name = "get_robust_list",
	.num_args = 3,
	.argtype = { [0] = ARG_PID, [1] = ARG_NON_NULL_ADDRESS, [2] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "pid", [1] = "head_ptr", [2] = "len_ptr" },
	.sanitise = sanitise_get_robust_list,
#ifdef HAVE_SYS_GET_ROBUST_LIST
	.post = post_get_robust_list,
#endif
	.group = GROUP_PROCESS,
	.rettype = RET_ZERO_SUCCESS,
	.flags = REEXEC_SANITISE_OK,
};
