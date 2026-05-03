/*
 * SYSCALL_DEFINE3(madvise, unsigned long, start, size_t, len_in, int, behavior)
 */
#include <stdlib.h>
#include <sys/mman.h>
#include "maps.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "compat.h"

#ifndef MADV_HWPOISON
#define MADV_HWPOISON		100
#endif
#ifndef MADV_SOFT_OFFLINE
#define MADV_SOFT_OFFLINE	101
#endif

static void sanitise_madvise(struct syscallrecord *rec)
{
	(void) common_set_mmap_ptr_len();

	if (range_overlaps_shared(rec->a1, rec->a2)) {
		rec->a1 = 0;
		rec->a2 = 0;
	}

	/*
	 * MADV_GUARD_INSTALL plants guard PTEs that fault on access without
	 * touching prot. common_set_mmap_ptr_len() above always pins this call
	 * to a sub-range of a pool entry, so range_overlaps_shared() never
	 * fires for it (pool entries aren't tracked in shared_regions[]). The
	 * map's prot stays PROT_READ|PROT_WRITE, so get_map_with_prot() will
	 * later hand the same entry to memory_pressure / iouring_* /
	 * madvise-cycler, which then SEGV on the first per-page write into
	 * the guarded range. Neutralise the call to keep the pool usable.
	 */
	if (rec->a3 == MADV_GUARD_INSTALL) {
		rec->a1 = 0;
		rec->a2 = 0;
	}
}

static unsigned long madvise_advices[] = {
	MADV_NORMAL, MADV_RANDOM, MADV_SEQUENTIAL, MADV_WILLNEED,
	MADV_DONTNEED,
	MADV_FREE, MADV_REMOVE, MADV_DONTFORK, MADV_DOFORK,
	MADV_MERGEABLE, MADV_UNMERGEABLE, MADV_HUGEPAGE, MADV_NOHUGEPAGE,
	MADV_DONTDUMP, MADV_DODUMP,
	MADV_WIPEONFORK, MADV_KEEPONFORK, MADV_COLD, MADV_PAGEOUT,
	MADV_POPULATE_READ, MADV_POPULATE_WRITE, MADV_DONTNEED_LOCKED, MADV_COLLAPSE,
	MADV_HWPOISON, MADV_SOFT_OFFLINE,
	MADV_GUARD_INSTALL, MADV_GUARD_REMOVE,
};

struct syscallentry syscall_madvise = {
	.name = "madvise",
	.num_args = 3,
	.argtype = { [0] = ARG_MMAP, [1] = ARG_LEN, [2] = ARG_OP },
	.argname = { [0] = "start", [1] = "len_in", [2] = "advice" },
	.arg_params[2].list = ARGLIST(madvise_advices),
	.group = GROUP_VM,
	.sanitise = sanitise_madvise,
};
