/*
 * SYSCALL_DEFINE3(madvise, unsigned long, start, size_t, len_in, int, behavior)
 */
#include <stdlib.h>
#include <sys/mman.h>
#include "maps.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"
#include "compat.h"

#ifndef MADV_HWPOISON
#define MADV_HWPOISON		100
#endif
#ifndef MADV_SOFT_OFFLINE
#define MADV_SOFT_OFFLINE	101
#endif

/*
 * Coverage buckets for the advice argument.  The flat random pick from
 * madvise_advices[] below is dominated by the older NORMAL/RANDOM/
 * SEQUENTIAL/WILLNEED/DONTNEED values; the newer thp/migration advices
 * (COLD/PAGEOUT/COLLAPSE/HUGEPAGE/NOHUGEPAGE), the guard-PTE pair
 * (GUARD_INSTALL/REMOVE), and the destructive set
 * (FREE/REMOVE/DONTFORK/WIPEONFORK/KEEPONFORK) rarely get drawn often
 * enough to keep their kernel paths warm.  Override rec->a3 in sanitise
 * with a bucket-weighted pick so each named family gets even attention,
 * and leave a long-tail bucket that keeps the original list-picked value
 * to preserve coverage of MERGEABLE, UNMERGEABLE, DONTDUMP, DODUMP,
 * POPULATE_READ, POPULATE_WRITE, DONTNEED_LOCKED, HWPOISON, SOFT_OFFLINE,
 * and DOFORK.
 */
static const unsigned long madvise_bucket_safe[] = {
	MADV_NORMAL, MADV_RANDOM, MADV_SEQUENTIAL, MADV_WILLNEED,
	MADV_DONTNEED,
};

static const unsigned long madvise_bucket_thp[] = {
	MADV_COLD, MADV_PAGEOUT, MADV_COLLAPSE,
	MADV_HUGEPAGE, MADV_NOHUGEPAGE,
};

static const unsigned long madvise_bucket_guard[] = {
	MADV_GUARD_INSTALL, MADV_GUARD_REMOVE,
};

/*
 * Destructive in the "modifies persistent VMA / page state" sense rather
 * than "crashes the child".  REMOVE punches holes in shmem; FREE marks
 * anon pages lazily reclaimable; DONTFORK/WIPEONFORK/KEEPONFORK toggle
 * VMA inheritance flags that affect future forks.  No sacrificial
 * mapping pool exists yet, so these go through the same get-a-map path
 * as the other buckets; future work will route them to a disposable
 * pool to isolate the side effects from siblings.
 */
static const unsigned long madvise_bucket_destructive[] = {
	MADV_FREE, MADV_REMOVE, MADV_DONTFORK,
	MADV_WIPEONFORK, MADV_KEEPONFORK,
};

static void sanitise_madvise(struct syscallrecord *rec)
{
	struct map *map;

	map = common_set_mmap_ptr_len(NULL);
	if (map == NULL)
		return;

	if (range_overlaps_shared(rec->a1, rec->a2)) {
		rec->a1 = 0;
		rec->a2 = 0;
	}

	/* Bias toward bucket-picked advice; 1-in-5 keeps the ARG_OP draw
	 * so the long-tail values still get exercised. */
	switch (rnd_modulo_u32(5)) {
	case 0:	rec->a3 = RAND_ARRAY(madvise_bucket_safe); break;
	case 1:	rec->a3 = RAND_ARRAY(madvise_bucket_thp); break;
	case 2:	rec->a3 = RAND_ARRAY(madvise_bucket_guard); break;
	case 3:	rec->a3 = RAND_ARRAY(madvise_bucket_destructive); break;
	case 4:	break;	/* keep ARG_OP-picked value for long tail */
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
	 * The bucket draw above can land here, so the check must run after
	 * the override.
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
	.rettype = RET_ZERO_SUCCESS,
};
