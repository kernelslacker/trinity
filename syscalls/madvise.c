/*
 * SYSCALL_DEFINE3(madvise, unsigned long, start, size_t, len_in, int, behavior)
 */
#include <stdlib.h>
#include <sys/mman.h>
#include "deferred-free.h"
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

/*
 * Snapshot of the madvise inputs read by the post handler, captured at
 * sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->aN between the syscall returning and the post
 * handler running cannot retarget invalidate_obj_mmap_in_range() at an
 * address window the madvise call never operated on (which would soft-
 * invalidate live mappings unrelated to the hole-punch and starve the
 * consumer pools) or flip the advice gate to bypass invalidation when
 * the call actually was a hole-punch.  post_state is private to the
 * post handler.
 */
#define MADVISE_POST_STATE_MAGIC	0x4D414456UL	/* "MADV" */
struct madvise_post_state {
	unsigned long magic;
	unsigned long addr;
	unsigned long len;
	unsigned long advice;
};

static void sanitise_madvise(struct syscallrecord *rec)
{
	struct madvise_post_state *snap;
	struct map *map;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;

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

	/*
	 * Snapshot AFTER every rewrite above (range_overlaps_shared zero,
	 * bucket advice override, GUARD_INSTALL zero) so the post handler
	 * sees the final addr/len/advice the syscall actually ran with.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic  = MADVISE_POST_STATE_MAGIC;
	snap->addr   = rec->a1;
	snap->len    = rec->a2;
	snap->advice = rec->a3;
	post_state_install(rec, snap);
}

/*
 * The hole-punch / range-zero / lazy-free family of advices that
 * destroy backing pages out from under a still-mapped VMA.  After any
 * of these succeed, the OBJ_MMAP pool entry overlapping the affected
 * range can still be picked by get_map_with_prot() and handed to a
 * consumer (memory_pressure / iouring_* / madvise_pattern_cycler) that
 * writes through it -- which then SIGBUS / SEGV on the punched-out
 * pages.  Soft-invalidate the overlap via map->prot=0 (mirrors
 * post_munmap's sub-range branch and post_mprotect).
 *
 * The non-destructive advices (NORMAL / RANDOM / SEQUENTIAL /
 * WILLNEED / COLD / PAGEOUT / COLLAPSE / HUGEPAGE / NOHUGEPAGE /
 * MERGEABLE / UNMERGEABLE / DODUMP / DONTDUMP / POPULATE_READ /
 * POPULATE_WRITE / DOFORK / DONTFORK / WIPEONFORK / KEEPONFORK /
 * GUARD_INSTALL / GUARD_REMOVE / HWPOISON / SOFT_OFFLINE) either
 * preserve content or are hint-only; no invalidation needed.
 */
static bool madvise_advice_hole_punches(unsigned long advice)
{
	switch (advice) {
	case MADV_DONTNEED:
	case MADV_DONTNEED_LOCKED:
	case MADV_REMOVE:
	case MADV_FREE:
		return true;
	default:
		return false;
	}
}

static void post_madvise(struct syscallrecord *rec)
{
	struct madvise_post_state *snap;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, MADVISE_POST_STATE_MAGIC, __func__);
	if (snap == NULL)
		return;

	if (rec->retval != 0)
		goto out_free;

	if (snap->len == 0)
		goto out_free;

	if (!madvise_advice_hole_punches(snap->advice))
		goto out_free;

	invalidate_obj_mmap_in_range(snap->addr, snap->len);

out_free:
	post_state_release(rec, snap);
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
	.post = post_madvise,
	.rettype = RET_ZERO_SUCCESS,
};
