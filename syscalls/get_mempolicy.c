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
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"

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

static void sanitise_get_mempolicy(struct syscallrecord *rec)
{
	unsigned long maxnode = rec->a3;
	unsigned long nmask_bytes;

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
 * TOCTOU defeat: snapshot all five args plus both buffer payloads into
 * stack-locals BEFORE re-issuing, so a sibling that scribbles either
 * rec->aN or the user buffers between syscall return and the post hook
 * cannot smear the comparison.  The re-call uses fresh stack buffers
 * (NOT rec->a1 / rec->a2 -- a sibling could mutate them mid-syscall and
 * forge a clean compare).
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
	int policy_first;
	int policy_recall;
	unsigned long nmask_first[MAX_NMASK_LONGS];
	unsigned long nmask_recall[MAX_NMASK_LONGS];
	unsigned long maxnode_snap;
	unsigned long addr_snap;
	unsigned long flags_snap;
	size_t nmask_words;
	size_t nmask_bytes;
	long rc;

	if (!ONE_IN(100))
		return;

	if ((long) rec->retval != 0)
		return;

	if (rec->a1 == 0 || rec->a2 == 0)
		return;

	if (rec->a5 & MPOL_F_ADDR)
		return;

	maxnode_snap = rec->a3;
	addr_snap    = rec->a4;
	flags_snap   = rec->a5;

	nmask_words = (maxnode_snap + 63) / 64;
	if (nmask_words == 0)
		nmask_words = 1;
	if (nmask_words > MAX_NMASK_LONGS)
		return;
	nmask_bytes = nmask_words * sizeof(unsigned long);

	memcpy(&policy_first, (const void *)(unsigned long) rec->a1,
	       sizeof(policy_first));
	memcpy(nmask_first, (const void *)(unsigned long) rec->a2,
	       nmask_bytes);

	memset(&policy_recall, 0, sizeof(policy_recall));
	memset(nmask_recall, 0, nmask_bytes);
	rc = syscall(SYS_get_mempolicy, &policy_recall, nmask_recall,
		     maxnode_snap, addr_snap, flags_snap);
	if (rc != 0)
		return;

	if (policy_first != policy_recall) {
		output(0,
		       "[oracle:get_mempolicy] policy %d vs %d (maxnode=%lu flags=0x%lx)\n",
		       policy_first, policy_recall, maxnode_snap, flags_snap);
		__atomic_add_fetch(&shm->stats.get_mempolicy_oracle_anomalies,
				   1, __ATOMIC_RELAXED);
	}

	if (memcmp(nmask_first, nmask_recall, nmask_bytes) != 0) {
		output(0,
		       "[oracle:get_mempolicy] nmask diverged over %zu bytes (maxnode=%lu flags=0x%lx)\n",
		       nmask_bytes, maxnode_snap, flags_snap);
		__atomic_add_fetch(&shm->stats.get_mempolicy_oracle_anomalies,
				   1, __ATOMIC_RELAXED);
	}
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
