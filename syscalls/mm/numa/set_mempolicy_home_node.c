/*
 * SYSCALL_DEFINE4(set_mempolicy_home_node, unsigned long, start, unsigned long, len, unsigned long, home_node, unsigned long, flags)
 *
 * The range stays inside the pool mapping the sanitiser picked, final
 * slots included (vet_final_set_mempolicy_home_node()).
 */
#include <linux/mempolicy.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "maps.h"
#include "random.h"
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

/*
 * The pool mapping the sanitiser picked and the range it built there,
 * captured at sanitise time for the final-slot hook, which has nothing
 * else to name the mapping by: the arg slots hold only an address, and a
 * rewrite after the sanitiser may have moved it.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose.
 */
#define HOME_NODE_POST_STATE_MAGIC	0x484F4D454E4F4445UL	/* "HOMENODE" */
struct home_node_post_state {
	unsigned long magic;
	struct map_range range;
};

/*
 * The kernel reads the final range as munmap() does and rebinds every VMA
 * it reaches whose policy takes a home node, holes and all, up to the
 * first whose policy does not, splitting them at the range's ends
 * (mbind_range()).  So the range has to stay inside the mapping the
 * sanitiser picked (see map_range_vet()); refused rather than repaired.
 * A record with no snapshot of ours passes only a range the kernel acts
 * on nothing of.  Shape, then ownership, then magic, as
 * post_state_claim_owned() orders them.
 */
static int vet_final_set_mempolicy_home_node(struct syscallrecord *rec,
					     const struct syscallentry *entry)
{
	struct home_node_post_state *snap =
		(struct home_node_post_state *) rec->post_state;
	struct map_range *range = NULL;

	if (!is_corrupt_ptr_shape(snap) && post_state_is_owned(snap) &&
	    snap->magic == HOME_NODE_POST_STATE_MAGIC)
		range = &snap->range;
	if (map_range_vet(rec, range))
		return 0;

	outputerr("arg-coupling: %s rejected: the range leaves the mapping sanitise picked\n",
		  entry->name);
	return -1;
}

/*
 * Only a VMA whose policy is MPOL_BIND or MPOL_PREFERRED_MANY takes a
 * home node.  The kernel skips a VMA with no policy, fails with
 * EOPNOTSUPP at one with any other, and fails with ENOENT when the range
 * held no VMA with a policy at all.  A pool mapping has such a policy only
 * if a fuzzed mbind() left one, so half the time the sanitiser binds the
 * range to node 0 itself first.  The policy only steers which node the
 * range's pages come from, which no consumer of the pool mapping minds;
 * a bind that fails, on a kernel without NUMA say, leaves the call to its
 * error paths.
 */
static void sanitise_set_mempolicy_home_node(struct syscallrecord *rec)
{
	struct home_node_post_state *snap;
	struct map *map;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * final-slot hook and the cleanup with no snapshot rather than a
	 * stale pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;

	rec->a4 = 0;	// no flags right now

	map = common_set_mmap_ptr_len(NULL);
	if (map == NULL)
		return;

	/*
	 * A compat call's range has to fit the 32 bits the kernel reads of
	 * each slot, or it is emptied as one over trinity's regions is.
	 */
	if (range_overlaps_shared(rec->a1, rec->a2) ||
	    (rec->do32bit && (rec->a1 > UINT_MAX || rec->a2 > UINT_MAX))) {
		rec->a1 = 0;
		rec->a2 = 0;
	}

	if (rec->a2 != 0 && RAND_BOOL()) {
		unsigned long node0 = 1;

		(void) syscall(__NR_mbind, rec->a1, rec->a2, MPOL_BIND, &node0,
			       8 * sizeof(node0), 0);
	}

	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic      = HOME_NODE_POST_STATE_MAGIC;
	snap->range.map  = map;
	snap->range.addr = rec->a1;
	snap->range.len  = rec->a2;
	post_state_install(rec, snap);
}

/* The snapshot is the final-slot hook's alone, so it goes on every path. */
static void cleanup_set_mempolicy_home_node(struct syscallrecord *rec)
{
	struct home_node_post_state *snap;

	snap = post_state_claim_owned(rec, HOME_NODE_POST_STATE_MAGIC, __func__);
	post_state_release(rec, snap);
}

struct syscallentry syscall_set_mempolicy_home_node = {
	.name = "set_mempolicy_home_node",
	.num_args = 4,
	.argtype = { [0] = ARG_MMAP, [1] = ARG_LEN, [2] = ARG_NUMA_NODE },
	.argname = { [0] = "start", [1] = "len", [2] = "home_node", [3] = "flags" },
	.sanitise = sanitise_set_mempolicy_home_node,
	.vet_final = vet_final_set_mempolicy_home_node,
	.cleanup = cleanup_set_mempolicy_home_node,
	.flags = REEXEC_SANITISE_OK,
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VM,
};
