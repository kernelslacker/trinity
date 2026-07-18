/*
 * SYSCALL_DEFINE5(get_mempolicy, int __user *, policy,
	unsigned long __user *, nmask, unsigned long, maxnode,
	unsigned long, addr, unsigned long, flags)
 */

#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include "arch.h"
#include "deferred-free.h"
#include "output-poison.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#define MPOL_F_NODE     (1<<0)  /* return next IL mode instead of node mask */
#define MPOL_F_ADDR     (1<<1)  /* look up vma using address */
#define MPOL_F_MEMS_ALLOWED (1<<2) /* return allowed memories */

#if defined(SYS_get_mempolicy) || defined(__NR_get_mempolicy)
#ifndef SYS_get_mempolicy
#define SYS_get_mempolicy __NR_get_mempolicy
#endif
#define HAVE_SYS_GET_MEMPOLICY 1
#endif

/*
 * Cap the snapshot/re-call buffers at MAX_NMASK_LONGS unsigned longs.
 * The sanitiser clamps maxnode to 1 << 9 (512 nodes -> 8 longs); the cap
 * here is comfortably above that to absorb future sanitiser drift while
 * keeping the local buffers stack-cheap.
 */
#define MAX_NMASK_LONGS 32
#define MAX_NMASK_BITS  (MAX_NMASK_LONGS * 64)

static unsigned long get_mempolicy_flags[] = {
	MPOL_F_NODE, MPOL_F_ADDR, MPOL_F_MEMS_ALLOWED,
};

#ifdef HAVE_SYS_GET_MEMPOLICY
/*
 * Snapshot of all five get_mempolicy args, captured at sanitise time and
 * consumed by the post oracle.  Lives in rec->post_state, a slot the
 * syscall ABI does not expose, so a sibling syscall scribbling rec->aN
 * between the syscall returning and the post handler running cannot
 * smear the policy/nmask comparison or hand the re-call the wrong
 * (maxnode, addr, flags) tuple.
 */
struct get_mempolicy_post_state {
	unsigned long magic;
	unsigned long policy;
	unsigned long nmask;
	unsigned long maxnode;
	unsigned long addr;
	unsigned long flags;
	uint64_t poison_seed_policy;
	uint64_t poison_seed_nmask;
};
#define GET_MEMPOLICY_POST_STATE_MAGIC	0x474D504CUL	/* "GMPL" */
#define GET_MEMPOLICY_POISON_PATTERN	0xD2B7D2B7D2B7D2B7ULL
#endif

static void sanitise_get_mempolicy(struct syscallrecord *rec)
{
	unsigned long maxnode = rec->a3;
	unsigned long nmask_bytes;
#ifdef HAVE_SYS_GET_MEMPOLICY
	struct get_mempolicy_post_state *snap;
#endif

	/*
	 * The kernel writes an int through policy (a1) and up to maxnode
	 * bits through nmask (a2).  Both args are ARG_ADDRESS, so the
	 * random-address pool sources them with no overlap check against
	 * the alloc_shared regions.  nmask_bytes is BITS_TO_LONGS rounded
	 * up to whole longs; bound it to a sane page in case maxnode came
	 * out at the high end of its range.
	 */
	avoid_shared_buffer_out(&rec->a1, sizeof(int));
	nmask_bytes = ((maxnode + 63) / 64) * sizeof(long);
	if (nmask_bytes == 0)
		nmask_bytes = sizeof(long);
	avoid_shared_buffer_out(&rec->a2, nmask_bytes);

#ifdef HAVE_SYS_GET_MEMPOLICY
	/*
	 * Snapshot all five args for the post oracle.  Without this the
	 * post handler reads rec->aN at post-time, when a sibling syscall
	 * may have scribbled the slots: looks_like_corrupted_ptr() cannot
	 * tell a real-but-wrong heap address from the original user buffer
	 * pointers, so the memcpy / re-call would touch a foreign
	 * allocation.  post_state is private to the post handler.
	 * post_state_install pairs the rec->post_state assign with the
	 * ownership-table register so the observable window between the two
	 * is closed; post_get_mempolicy() will then gate the snap through
	 * post_state_claim_owned() and prove ownership before dereferencing
	 * any field.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic   = GET_MEMPOLICY_POST_STATE_MAGIC;
	snap->policy  = rec->a1;
	snap->nmask   = rec->a2;
	snap->maxnode = rec->a3;
	snap->addr    = rec->a4;
	snap->flags   = rec->a5;
	snap->poison_seed_policy = 0;
	snap->poison_seed_nmask  = 0;

	/*
	 * Stamp fixed poison across the policy int and (when flags == 0)
	 * the nmask bitmap.  The post handler compares the buffers
	 * byte-for-byte against the same pattern; a match after
	 * rec->retval == 0 means the kernel skipped copy_to_user() for
	 * that arm -- get_mempolicy is contracted to write *policy on
	 * every success and to write the task->mempolicy nodes bitmap
	 * through *nmask when flags == 0.  MPOL_F_NODE reshapes *policy
	 * (into the next interleave node) but does not populate nmask,
	 * MPOL_F_MEMS_ALLOWED repurposes the nmask arm to the allowed-
	 * mems bitmap, and MPOL_F_ADDR makes the whole call VMA-scoped
	 * and prone to -EFAULT -- gate the nmask arm on flags == 0 so
	 * the untouched-buffer signal is not diluted by paths where the
	 * kernel legitimately does not write the bitmap.  Pattern is a
	 * fixed non-zero magic (not rnd_u64()) so the sanitise pass
	 * draws no RNG bytes on this leg: --dry-run output with a fixed
	 * seed stays byte-identical to a build without this oracle,
	 * keeping cross-tree replays and fixed-seed corpus regeneration
	 * unaffected.  Gate each stamp on range_readable_user() so a
	 * writable-pool draw that avoid_shared_buffer_out relocated to
	 * an address no longer provably mapped does not SIGSEGV inside
	 * poison_output_struct's byte-walk; on skip poison_seed stays 0
	 * and the post handler no-ops that arm.
	 */
	if (rec->a1 != 0) {
		void *pbuf = (void *)(unsigned long) rec->a1;

		if (range_readable_user(pbuf, sizeof(int)))
			snap->poison_seed_policy =
				poison_output_struct(pbuf, sizeof(int),
						     GET_MEMPOLICY_POISON_PATTERN);
	}

	if (rec->a2 != 0 && rec->a5 == 0) {
		void *nbuf = (void *)(unsigned long) rec->a2;

		if (range_readable_user(nbuf, nmask_bytes))
			snap->poison_seed_nmask =
				poison_output_struct(nbuf, nmask_bytes,
						     GET_MEMPOLICY_POISON_PATTERN);
	}

	post_state_install(rec, snap);
#endif
}

/*
 * Oracle: get_mempolicy(policy, nmask, maxnode, addr, flags) reads the
 * calling task's NUMA memory policy.  With flags == 0 the kernel resolves
 * the target to the task's own task->mempolicy, an under-task_lock read of
 * a field that only mutates via set_mempolicy(2) (or mbind/MPOL_F_RELATIVE
 * variants the caller drives explicitly) -- so a same-task re-issue ~150ms
 * later through the same code path must produce a byte-identical
 * (policy, nmask) pair unless one of:
 *
 *   - copy_to_user mis-write past or before the policy/nmask user slots.
 *   - 32-on-64 compat sign-extension on the int policy slot.
 *   - Stale rcu read of task->mempolicy after a parallel set_mempolicy
 *     against a different task that aliases through a stale pointer.
 *   - Sibling-thread scribble of either user buffer between syscall return
 *     and our post-hook re-read.
 *   - bitmap_to_user / get_nodes mis-pack writing fewer or more longs
 *     than (maxnode + 63) / 64.
 *
 * MPOL_F_ADDR is gated out: with that flag the kernel resolves the policy
 * via the VMA covering `addr`, and a sibling thread is free to munmap that
 * VMA between calls -- the second call will return -EFAULT and the rc != 0
 * give-up path swallows it, but the failure rate is high enough to be a
 * spurious-divergence storm even without an actual bug.  MPOL_F_NODE and
 * MPOL_F_MEMS_ALLOWED both stay in scope: the first re-shapes the int that
 * lands in *policy (returns the next interleave node instead of the mode),
 * the second writes the allowed-mems bitmap into nmask -- both are stable
 * for a same-task read at this sample rate.
 *
 * TOCTOU defeat: all five args are snapshotted at sanitise time into a
 * heap struct in rec->post_state, so a sibling that scribbles rec->aN
 * between syscall return and post entry cannot smear the comparison nor
 * misdirect the re-call.  The re-call uses fresh stack buffers for the
 * policy/nmask payloads (NOT the original user buffers -- a sibling could
 * mutate them mid-syscall and forge a clean compare).
 *
 * Sample one in a hundred to stay in line with the rest of the oracle
 * family.  Per-field bumps with no early-return so simultaneous
 * policy+nmask corruption surfaces in a single sample.
 *
 * False-positive sources at ONE_IN(100):
 *   - MPOL_F_ADDR: gated out (see above).
 *   - Sibling set_mempolicy(2) between the two reads: rc != 0 path or a
 *     legitimate divergence -- swallowed by the rc != 0 give-up.
 *   - Sanitiser drift on the maxnode bound: defensive cap above keeps
 *     the on-stack buffers bounded if a future sanitiser change widens
 *     the maxnode range past MAX_NMASK_BITS.
 */
#ifdef HAVE_SYS_GET_MEMPOLICY
static void post_get_mempolicy(struct syscallrecord *rec)
{
	struct get_mempolicy_post_state *snap;
	int policy_first;
	int policy_recall;
	unsigned long nmask_first[MAX_NMASK_LONGS];
	unsigned long nmask_recall[MAX_NMASK_LONGS];
	size_t nmask_words;
	size_t nmask_bytes;
	long rc;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, GET_MEMPOLICY_POST_STATE_MAGIC,
				      __func__);
	if (snap == NULL)
		return;

	/*
	 * Untouched-buffer arms: get_mempolicy returned 0 but the user
	 * buffer still byte-for-byte matches the fixed poison stamped at
	 * sanitise time -- the kernel never called copy_to_user() on that
	 * arm.  poison_seed == 0 signals sanitise refused to stamp
	 * (writable-pool draw no longer provably mapped, or the nmask arm
	 * was gated out by flags != 0); skip so "we could not poison" is
	 * not confused with "kernel did not write".  Runs on every call
	 * -- not sampled -- so the signal is not diluted by the
	 * ONE_IN(100) gate that throttles the equality re-issue below.
	 * Bounded by MAX_NMASK_LONGS on the nmask arm to match the
	 * on-stack cap the equality arm uses; anything larger would also
	 * exceed CHECK_OUTPUT_STRUCT_SNAP_MAX and be dropped by the
	 * helper regardless.
	 */
	if ((long) rec->retval == 0) {
		if (snap->poison_seed_policy != 0 &&
		    check_output_struct_user_or_skip((void *)(unsigned long) snap->policy,
						     sizeof(int),
						     snap->poison_seed_policy))
			__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
					   1, __ATOMIC_RELAXED);

		if (snap->poison_seed_nmask != 0) {
			size_t words = (snap->maxnode + 63) / 64;

			if (words == 0)
				words = 1;
			if (words <= MAX_NMASK_LONGS &&
			    check_output_struct_user_or_skip((void *)(unsigned long) snap->nmask,
							     words * sizeof(unsigned long),
							     snap->poison_seed_nmask))
				__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
						   1, __ATOMIC_RELAXED);
		}
	}

	if (!ONE_IN(100))
		goto out_free;

	if ((long) rec->retval != 0)
		goto out_free;

	if (snap->policy == 0 || snap->nmask == 0)
		goto out_free;

	if (snap->flags & MPOL_F_ADDR)
		goto out_free;

	nmask_words = (snap->maxnode + 63) / 64;
	if (nmask_words == 0)
		nmask_words = 1;
	if (nmask_words > MAX_NMASK_LONGS)
		goto out_free;
	nmask_bytes = nmask_words * sizeof(unsigned long);

	if (!post_snapshot_or_skip(&policy_first,
				   (const void *)(unsigned long) snap->policy,
				   sizeof(policy_first)))
		goto out_free;
	if (!post_snapshot_or_skip(nmask_first,
				   (const void *)(unsigned long) snap->nmask,
				   nmask_bytes))
		goto out_free;

	memset(&policy_recall, 0, sizeof(policy_recall));
	memset(nmask_recall, 0, nmask_bytes);
	rc = syscall(SYS_get_mempolicy, &policy_recall, nmask_recall,
		     snap->maxnode, snap->addr, snap->flags);
	if (rc != 0)
		goto out_free;

	if (policy_first != policy_recall) {
		output(0,
		       "[oracle:get_mempolicy] policy %d vs %d (maxnode=%lu flags=0x%lx)\n",
		       policy_first, policy_recall, snap->maxnode, snap->flags);
		__atomic_add_fetch(&shm->stats.oracle.get_mempolicy_oracle_anomalies,
				   1, __ATOMIC_RELAXED);
	}

	if (memcmp(nmask_first, nmask_recall, nmask_bytes) != 0) {
		output(0,
		       "[oracle:get_mempolicy] nmask diverged over %zu bytes (maxnode=%lu flags=0x%lx)\n",
		       nmask_bytes, snap->maxnode, snap->flags);
		__atomic_add_fetch(&shm->stats.oracle.get_mempolicy_oracle_anomalies,
				   1, __ATOMIC_RELAXED);
	}

out_free:
	post_state_release(rec, snap);
}
#endif

struct syscallentry syscall_get_mempolicy = {
	.name = "get_mempolicy",
	.num_args = 5,
	.argtype = { [0] = ARG_ADDRESS, [1] = ARG_ADDRESS, [2] = ARG_RANGE, [3] = ARG_MMAP, [4] = ARG_LIST },
	.argname = { [0] = "policy", [1] = "nmask", [2] = "maxnode", [3] = "addr", [4] = "flags" },
	.arg_params[2].range.low = 0,
	.arg_params[2].range.hi = 1 << 9,	/* 1 << CONFIG_NODES_SHIFT */
	.arg_params[4].list = ARGLIST(get_mempolicy_flags),
	.sanitise = sanitise_get_mempolicy,
	.rettype = RET_ZERO_SUCCESS,
	.flags = REEXEC_SANITISE_OK,
	.group = GROUP_VM,
#ifdef HAVE_SYS_GET_MEMPOLICY
	.post = post_get_mempolicy,
#endif
};
