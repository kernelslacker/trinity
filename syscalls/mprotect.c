/*
 * sys_mprotect(unsigned long start, size_t len, unsigned long prot)
 */
#include <asm/mman.h>
#include "arch.h"
#include "maps.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"

static void sanitise_mprotect(struct syscallrecord *rec)
{
	struct map *map = common_set_mmap_ptr_len();

	if (range_overlaps_shared(rec->a1, rec->a2)) {
		rec->a1 = 0;
		rec->a2 = 0;
	}

	/* Stash map pointer in unused arg slot for post callback.
	 * NULL is fine — post_mprotect checks before dereferencing. */
	rec->a5 = (unsigned long) map;
}

/*
 * If we successfully did an mprotect, update our record of the mappings prot bits.
 */
static void post_mprotect(struct syscallrecord *rec)
{
	struct map *map = (struct map *) rec->a5;

	if (rec->retval != 0 || map == NULL)
		return;

	/*
	 * common_set_mmap_ptr_len() forces rec->a1 = map->ptr but sets
	 * rec->a2 = rand() % map->size & PAGE_MASK, so this path is
	 * effectively always a sub-range mprotect (a2 < map->size).
	 * Blindly overwriting map->prot with rec->a3 leaks the new prot
	 * into the cached invariant — e.g. a sub-range upgrade from
	 * PROT_NONE -> PROT_RW would leave map->prot claiming PROT_WRITE
	 * while most pages are still PROT_NONE.  get_map_with_prot()
	 * trusts m->prot, hands the entry to memory_pressure / iouring_*
	 * / madvise_pattern_cycler, and the per-page write loop SEGV_ACCERRs
	 * on the first un-upgraded page.  Mirror the conservative AND from
	 * mprotect_split (childops/mprotect-split.c): for a whole-mapping
	 * mprotect take the new prot exactly; for any sub-range, intersect
	 * with the existing invariant so we only ever drop bits, never add
	 * them.  False-negatives (skipping a mapping that still has writable
	 * pages somewhere) are acceptable; false-positives crash the child.
	 */
	if (rec->a1 == (unsigned long)map->ptr && rec->a2 == map->size)
		map->prot = rec->a3;
	else
		map->prot &= rec->a3;

	/*
	 * Oracle: 1-in-100 chance — verify /proc/self/maps reflects the prot
	 * change we just applied.  A stale or wrong entry signals that the
	 * kernel's VMA prot state diverged from what mprotect reported back.
	 */
	if (rec->a2 > 0 && ONE_IN(100)) {
		if (!proc_maps_check(rec->a1, rec->a2, rec->a3, true)) {
			output(0, "mmap oracle: mprotect(%lx, %lu, 0x%lx) "
			       "succeeded but prot not in /proc/self/maps\n",
			       rec->a1, rec->a2, rec->a3);
			__atomic_add_fetch(&shm->stats.mmap_oracle_anomalies, 1,
					   __ATOMIC_RELAXED);
		}
	}
}

#ifndef PROT_MTE
#define PROT_MTE	0x20		/* aarch64 MTE (5.10+) */
#endif

static unsigned long mprotect_prots[] = {
	PROT_READ, PROT_WRITE, PROT_EXEC, PROT_SEM,
	PROT_GROWSDOWN, PROT_GROWSUP,
	PROT_MTE,
};

struct syscallentry syscall_mprotect = {
	.name = "mprotect",
	.num_args = 3,
	.argtype = { [0] = ARG_MMAP, [1] = ARG_LEN, [2] = ARG_LIST },
	.argname = { [0] = "start", [1] = "len", [2] = "prot" },
	.arg_params[2].list = ARGLIST(mprotect_prots),
	.sanitise = sanitise_mprotect,
	.group = GROUP_VM,
	.post = post_mprotect,
};

struct syscallentry syscall_pkey_mprotect = {
	.name = "pkey_mprotect",
	.num_args = 4,
	.argtype = { [0] = ARG_MMAP, [1] = ARG_LEN, [2] = ARG_LIST },
	.argname = { [0] = "start", [1] = "len", [2] = "prot", [3] = "key" },
	.arg_params[2].list = ARGLIST(mprotect_prots),
	.sanitise = sanitise_mprotect,
	.group = GROUP_VM,
	.post = post_mprotect,
};
