/*
 * SYSCALL_DEFINE5(get_mempolicy, int __user *, policy,
	unsigned long __user *, nmask, unsigned long, maxnode,
	unsigned long, addr, unsigned long, flags)
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
	unsigned long policy;
	unsigned long nmask;
	unsigned long maxnode;
	unsigned long addr;
	unsigned long flags;
};
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
	avoid_shared_buffer(&rec->a1, sizeof(int));
	nmask_bytes = ((maxnode + 63) / 64) * sizeof(long);
	if (nmask_bytes == 0)
		nmask_bytes = sizeof(long);
	avoid_shared_buffer(&rec->a2, nmask_bytes);

#ifdef HAVE_SYS_GET_MEMPOLICY
	/*
	 * Snapshot all five args for the post oracle.  Without this the
	 * post handler reads rec->aN at post-time, when a sibling syscall
	 * may have scribbled the slots: looks_like_corrupted_ptr() cannot
	 * tell a real-but-wrong heap address from the original user buffer
	 * pointers, so the memcpy / re-call would touch a foreign
	 * allocation.  post_state is private to the post handler.
	 */
	snap = zmalloc(sizeof(*snap));
	snap->policy  = rec->a1;
	snap->nmask   = rec->a2;
	snap->maxnode = rec->a3;
	snap->addr    = rec->a4;
	snap->flags   = rec->a5;
	rec->post_state = (unsigned long) snap;
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
	struct get_mempolicy_post_state *snap = (struct get_mempolicy_post_state *) rec->post_state;
	int policy_first;
	int policy_recall;
	unsigned long nmask_first[MAX_NMASK_LONGS];
	unsigned long nmask_recall[MAX_NMASK_LONGS];
	size_t nmask_words;
	size_t nmask_bytes;
	long rc;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(snap)) {
		outputerr("post_get_mempolicy: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  snap);
		__atomic_add_fetch(&shm->stats.post_handler_corrupt_ptr, 1, __ATOMIC_RELAXED);
		rec->post_state = 0;
		return;
	}

	if (!ONE_IN(100))
		goto out_free;

	if ((long) rec->retval != 0)
		goto out_free;

	if (snap->policy == 0 || snap->nmask == 0)
		goto out_free;

	if (snap->flags & MPOL_F_ADDR)
		goto out_free;

	{
		void *policy_p = (void *)(unsigned long) snap->policy;
		void *nmask_p = (void *)(unsigned long) snap->nmask;

		/*
		 * Defense in depth: even with the post_state snapshot, a
		 * wholesale stomp could rewrite the snapshot's inner pointer
		 * fields.  Reject pid-scribbled policy/nmask before deref.
		 */
		if (looks_like_corrupted_ptr(policy_p) ||
		    looks_like_corrupted_ptr(nmask_p)) {
			outputerr("post_get_mempolicy: rejected suspicious policy=%p nmask=%p (post_state-scribbled?)\n",
				  policy_p, nmask_p);
			__atomic_add_fetch(&shm->stats.post_handler_corrupt_ptr, 1, __ATOMIC_RELAXED);
			goto out_free;
		}
	}

	nmask_words = (snap->maxnode + 63) / 64;
	if (nmask_words == 0)
		nmask_words = 1;
	if (nmask_words > MAX_NMASK_LONGS)
		goto out_free;
	nmask_bytes = nmask_words * sizeof(unsigned long);

	memcpy(&policy_first, (const void *)(unsigned long) snap->policy,
	       sizeof(policy_first));
	memcpy(nmask_first, (const void *)(unsigned long) snap->nmask,
	       nmask_bytes);

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
		__atomic_add_fetch(&shm->stats.get_mempolicy_oracle_anomalies,
				   1, __ATOMIC_RELAXED);
	}

	if (memcmp(nmask_first, nmask_recall, nmask_bytes) != 0) {
		output(0,
		       "[oracle:get_mempolicy] nmask diverged over %zu bytes (maxnode=%lu flags=0x%lx)\n",
		       nmask_bytes, snap->maxnode, snap->flags);
		__atomic_add_fetch(&shm->stats.get_mempolicy_oracle_anomalies,
				   1, __ATOMIC_RELAXED);
	}

out_free:
	deferred_freeptr(&rec->post_state);
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
	.group = GROUP_VM,
#ifdef HAVE_SYS_GET_MEMPOLICY
	.post = post_get_mempolicy,
#endif
};
