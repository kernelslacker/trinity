/*
 * vma_split_storm - hammer the VMA split/merge paths on a private region.
 *
 * The kernel's mm/mprotect.c, mm/mremap.c and mm/madvise.c funnel into
 * the same vma_split / __split_vma / vma_merge / vma_complete machinery
 * (maple tree rebalances, anon_vma chain manipulation, pte locks).
 * Most bugs in those paths only surface when a single address space
 * holds a busy fragmented region whose VMA tree the operator is still
 * actively rearranging — i.e. when split rate dominates merge rate
 * for a sustained window, then merges catch up.  The random_syscall
 * path almost never sustains that shape: each syscall is independent
 * and the mapping picker spreads pressure across the pool.
 *
 * This op owns its region for the duration of one invocation:
 *
 *   1. mmap an 8 MiB private anonymous range up front, page-aligned.
 *   2. Loop bounded by BUDGETED(CHILD_OP_VMA_SPLIT_STORM, ...):
 *        - ~70%: mprotect() a random page-aligned sub-range to an
 *          alternating prot pick (PROT_READ vs PROT_READ|PROT_WRITE).
 *          Each sub-range mprotect that crosses an existing VMA
 *          boundary forces __split_vma + vma_merge on the new edges
 *          and walks the maple tree under the i_mmap/anon_vma locks.
 *        - ~15%: madvise(MADV_DONTNEED) on a random sub-range.
 *          Drops pte mappings without changing VMA shape — exercises
 *          zap_page_range against pages just faulted in by prior
 *          touches, racing the split/merge edges above.
 *        - ~10%: full-range mprotect(PROT_READ|PROT_WRITE) — drives
 *          the recompose path: all sub-VMAs share one prot again, so
 *          vma_merge collapses the fragmentation in one sweep.
 *        - ~5%:  mremap() the whole region with MREMAP_MAYMOVE at the
 *          same length.  Kernel may relocate the mapping, replacing
 *          the VMA tree wholesale; we update `base` to track.
 *   3. munmap() the region.  No state leaks to other ops.
 *
 * Bit faulting:
 *   A trivial volatile write to a random page after each split keeps
 *   ptes hot so DONTNEED has work to do and mprotect actually walks
 *   present ptes rather than empty pgd entries.
 *
 * Self-bounding:
 *   - All work confined to a self-allocated 8 MiB region: nothing
 *     reaches the shared pool / objects ring.
 *   - mprotect lengths capped at 16 pages so a single iteration cannot
 *     re-flatten the whole region.
 *   - mremap MREMAP_MAYMOVE may fail (ENOMEM under address-space
 *     pressure) — ignored, base stays put.
 *   - child.c's SIGALRM(1s) outer cap covers the worst-case loop.
 *
 * No libc rand(): the iter count, offsets, lengths and op choice all
 * route through rnd_u32 / rnd_modulo_u32 from include/rnd.h, matching
 * the project-wide trinity RNG rule.
 */

#include <setjmp.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/mman.h>

#include "arch.h"
#include "child.h"
#include "rnd.h"
#include "shm.h"
#include "signals.h"
#include "trinity.h"
#include "vma-pressure.h"

#define VMA_SPLIT_STORM_REGION_BYTES	(8UL << 20)	/* 8 MiB */
#define VMA_SPLIT_STORM_ITERS_BASE	256U
#define VMA_SPLIT_STORM_MAX_SPAN_PAGES	16U

/*
 * Pick a page-aligned sub-range fully inside [0, region_bytes).
 * *off_out gets the page-aligned byte offset; *len_out gets a length
 * in [page_size, VMA_SPLIT_STORM_MAX_SPAN_PAGES * page_size] clamped
 * so off+len stays inside the region.
 */
static void pick_subrange(unsigned long region_bytes,
			  unsigned long *off_out, unsigned long *len_out)
{
	unsigned long nr_pages = region_bytes / page_size;
	unsigned long start_page, span_pages, max_span;

	start_page = rnd_modulo_u32((uint32_t)nr_pages);
	max_span = nr_pages - start_page;
	if (max_span > VMA_SPLIT_STORM_MAX_SPAN_PAGES)
		max_span = VMA_SPLIT_STORM_MAX_SPAN_PAGES;
	span_pages = 1UL + rnd_modulo_u32((uint32_t)max_span);

	*off_out = start_page * page_size;
	*len_out = span_pages * page_size;
}

/*
 * Touch one byte on a random page of the region.  volatile so the
 * compiler can't elide the store; goal is to keep ptes present so
 * the split / DONTNEED paths have real work.  The touched page may
 * sit in a sub-VMA whose most recent mprotect was PROT_READ, in
 * which case the store faults with SIGSEGV/SEGV_ACCERR -- a
 * sanitiser fault from our own bookkeeping, not a kernel bug.
 *
 * Wrap the store in sigsetjmp/siglongjmp so the fault degrades to
 * a no-op instead of killing the child: child_fault_handler checks
 * vma_split_storm_touch_active first and longjmp's back here when
 * the store faults.  Flag is set ONLY across the single byte write
 * and cleared immediately after on BOTH the normal and the fault-
 * return path, so any unrelated SIGSEGV/SIGBUS the child takes
 * outside this window still reaches the existing diagnostic +
 * _exit path.
 *
 * Locals are marked volatile / hoisted inside the sigsetjmp==0 arm
 * to silence -Wclobbered under gcc: values live from before the
 * sigsetjmp() through the store and are otherwise flagged as
 * potentially clobbered by the longjmp.
 */
static void touch_random_page(void *base, unsigned long region_bytes)
{
	volatile unsigned long nr_pages = region_bytes / page_size;

	if (sigsetjmp(vma_split_storm_touch_recover, 1) == 0) {
		unsigned long pg = rnd_modulo_u32((uint32_t)nr_pages);
		volatile char *p = (volatile char *)base + pg * page_size;

		vma_split_storm_touch_active = 1;
		*p = (char)(rnd_u32() & 0xff);
		vma_split_storm_touch_active = 0;
	} else {
		/*
		 * child_fault_handler caught a real SIGSEGV/SIGBUS
		 * inside the store and longjmp'd back.  Clear the flag
		 * FIRST so any subsequent fault in this child takes the
		 * normal diagnostic + _exit path rather than silently
		 * recovering here.
		 */
		vma_split_storm_touch_active = 0;
	}
}

bool vma_split_storm(struct childdata *child)
{
	void *base;
	unsigned long region_bytes = VMA_SPLIT_STORM_REGION_BYTES;
	unsigned int iters, i;

	base = mmap(NULL, region_bytes, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (base == MAP_FAILED)
		return true;

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	iters = BUDGETED(CHILD_OP_VMA_SPLIT_STORM, VMA_SPLIT_STORM_ITERS_BASE);

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);

	for (i = 0; i < iters; i++) {
		uint32_t pick = rnd_modulo_u32(100U);
		unsigned long off, len;

		/* Global VMA-pressure backoff.  Single BSS load; bails the
		 * remainder of this invocation when the watchdog has latched
		 * the child near max_map_count.  The trailing munmap() below
		 * runs unconditionally so the 8 MiB region returns to the
		 * kernel even when we bailed mid-loop. */
		if (vma_pressure_is_high())
			break;

		if (pick < 70U) {
			/* Split-edge mprotect: alternating prot bits.
			 * The kernel splits whatever VMAs the range
			 * straddles and merges any neighbours that now
			 * share a prot. */
			int prot = (i & 1) ? (PROT_READ | PROT_WRITE)
					   : PROT_READ;

			pick_subrange(region_bytes, &off, &len);
			(void)mprotect((char *)base + off, len, prot);
		} else if (pick < 85U) {
			/* DONTNEED across a random sub-range — drops
			 * ptes without VMA churn, races the split-edge
			 * walker on adjacent pages. */
			pick_subrange(region_bytes, &off, &len);
			(void)madvise((char *)base + off, len,
				      MADV_DONTNEED);
		} else if (pick < 95U) {
			/* Recompose: full-range prot resets every sub-
			 * VMA to a single prot, letting vma_merge collapse
			 * the fragmentation in one sweep. */
			(void)mprotect(base, region_bytes,
				       PROT_READ | PROT_WRITE);
		} else {
			/* Relocate-in-place: same length, MAYMOVE.  On
			 * success the kernel rebuilds the VMA tree at a
			 * fresh address — exercises move_vma + the
			 * maple-tree replace path against a heavily-split
			 * source. */
			void *moved;

			moved = mremap(base, region_bytes, region_bytes,
				       MREMAP_MAYMOVE);
			if (moved != MAP_FAILED)
				base = moved;
		}

		/* Keep ptes hot for the next iteration. */
		if ((i & 3U) == 0U)
			touch_random_page(base, region_bytes);
	}

	(void)munmap(base, region_bytes);
	return true;
}
