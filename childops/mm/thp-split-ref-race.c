/*
 * thp_split_ref_race - deterministic THP split / folio-ref race.
 *
 * Recent MM fixes cluster around folio_split(), folio_try_get(),
 * pagewalk, and deferred-split queues.  The random_syscall path almost
 * never lands a split trigger and a reference walker on the same folio
 * inside a narrow-enough window to reach those paths.
 *
 * What this op does
 * -----------------
 * One invocation:
 *   1. Maps a PMD-aligned 2 MiB anonymous arena (double-map then carve
 *      out the aligned interior so the hint is guaranteed, not hoped).
 *   2. Establishes a THP via MADV_HUGEPAGE + MADV_POPULATE_WRITE and
 *      optionally MADV_COLLAPSE (probed once, latched).
 *   3. Confirms THP via /proc/self/smaps AnonHugePages for the mapping.
 *      If the kernel does not produce a THP (config off, policy "never",
 *      or page pressure cleared it), the op writes CHILDOP_LATCH_UNSUPPORTED
 *      and returns false -- a no-THP fallback that silently succeeds would
 *      manufacture green that means nothing.
 *   4. Runs BUDGETED() bounded rounds.  Each round:
 *        a. Split trigger on a quarter-arena subrange (rotates among
 *           mprotect prot-change, MADV_DONTNEED pte-zap, and mremap
 *           relocation) to force PMD split / folio_split().
 *        b. Reference walkers immediately after the split trigger:
 *           mincore (page-residency walk) and process_vm_readv (cross-
 *           process copy_page_to_iter via folio_try_get()) race the
 *           deferred-split-queue and folio refcount manipulation.
 *        c. Re-collapse for the next round via MADV_HUGEPAGE +
 *           MADV_POPULATE_WRITE.
 *   5. munmaps the arena unconditionally.
 *
 * Oracle: crash/KASAN/SLUB reports on folio split racing a ref.  No
 * synthetic correctness oracle is needed; the kernel's own sanitisers
 * catch the interesting failure modes.
 *
 * Feature latches (probed once, value retained across invocations):
 *   latch_madv_collapse:  -1=unknown  0=absent  1=present
 *   thp_unavail_latched:  true once THP establishment confirmed absent
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include "arch.h"
#include "child.h"
#include "childop-outcome.h"
#include "childops-util.h"
#include "jitter.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"
#include "vma-pressure.h"

#include "kernel/mman.h"

#ifndef MADV_HUGEPAGE
#define MADV_HUGEPAGE		14
#endif
#ifndef MADV_POPULATE_WRITE
#define MADV_POPULATE_WRITE	23
#endif
#ifndef MADV_COLLAPSE
#define MADV_COLLAPSE		25
#endif

/* 2 MiB = one PMD on most architectures. */
#define THP_ARENA_SIZE		(2UL << 20)
#define THP_ARENA_PAGES		(THP_ARENA_SIZE / 4096UL)
#define THP_ROUNDS_BASE		8U
#define THP_BUDGET_NS		200000000L	/* 200 ms */

/* One-time THP unavailability latch and MADV_COLLAPSE feature probe. */
static bool thp_unavail_latched;
static int  latch_madv_collapse = -1;	/* -1=unknown, 0=absent, 1=present */

/*
 * Establish THP on the arena.  Probes MADV_COLLAPSE availability on the
 * first call and latches the verdict for subsequent invocations.
 */
static void thp_establish(void *arena)
{
	(void)madvise(arena, THP_ARENA_SIZE, MADV_HUGEPAGE);
	(void)madvise(arena, THP_ARENA_SIZE, MADV_POPULATE_WRITE);

	if (latch_madv_collapse < 0) {
		int rc = madvise(arena, THP_ARENA_SIZE, MADV_COLLAPSE);
		latch_madv_collapse = (rc == 0 || errno != EINVAL) ? 1 : 0;
	} else if (latch_madv_collapse > 0) {
		(void)madvise(arena, THP_ARENA_SIZE, MADV_COLLAPSE);
	}
}

/*
 * Return true if /proc/self/smaps shows AnonHugePages > 0 for the
 * mapping covering addr.  Walks the file, keying on VMA header lines
 * to scope the AnonHugePages field to the right mapping.
 */
static bool thp_smaps_has_ahp(uintptr_t addr)
{
	char line[256];
	FILE *f;
	bool in_range = false;
	bool found = false;

	f = fopen("/proc/self/smaps", "r");
	if (!f)
		return false;

	while (fgets(line, (int)sizeof(line), f)) {
		uintptr_t lo, hi;

		if (sscanf(line, "%lx-%lx", &lo, &hi) == 2) {
			in_range = (addr >= lo && addr < hi);
		} else if (in_range &&
			   strncmp(line, "AnonHugePages:", 14) == 0) {
			unsigned long kib = 0;

			(void)sscanf(line + 14, " %lu", &kib);
			if (kib > 0) {
				found = true;
				break;
			}
		}
	}
	fclose(f);
	return found;
}

/*
 * One split+ref race round.
 *
 * round % 3 selects the split trigger:
 *   0: mprotect on the first quarter (forces PMD split via prot change)
 *   1: MADV_DONTNEED on first quarter (pte zap, races deferred-split)
 *   2: mremap the first quarter (move_vma + folio_split path)
 *
 * Reference walkers follow immediately after each trigger:
 *   mincore -- page-residency walk races folio_try_get under split
 *   process_vm_readv -- cross-process copy_page_to_iter races refcount
 *
 * Returns the number of direct syscall sites executed in this round.
 */
static unsigned long thp_one_round(void *arena, unsigned int round,
				   unsigned char *vec, size_t vec_sz)
{
	uintptr_t base = (uintptr_t)arena;
	size_t sub = THP_ARENA_SIZE / 4;
	unsigned long calls = 0;

	switch (round % 3U) {
	case 0:
		(void)mprotect((void *)base, sub, PROT_READ);
		(void)mprotect((void *)base, sub, PROT_READ | PROT_WRITE);
		calls += 2;
		break;
	case 1:
		(void)madvise((void *)base, sub, MADV_DONTNEED);
		calls += 1;
		break;
	default: {
		void *moved = mremap((void *)base, sub, sub, MREMAP_MAYMOVE);
		if (moved != MAP_FAILED) {
			(void)*(volatile char *)moved;
			munmap(moved, sub);
			calls += 2;	/* mremap + munmap */
		} else {
			calls += 1;	/* mremap (failed) */
		}
		break;
	}
	}

	/* mincore: races folio_try_get in the pagewalk path. */
	(void)mincore(arena, THP_ARENA_SIZE, vec);
	calls++;

	/* process_vm_readv: copy_page_to_iter under folio split. */
	{
		struct iovec lv = { vec, vec_sz };
		struct iovec rv = { arena, vec_sz };

		(void)process_vm_readv(getpid(), &lv, 1, &rv, 1, 0);
		calls++;
	}

	/* Re-establish THP for the next round. */
	(void)madvise(arena, THP_ARENA_SIZE, MADV_HUGEPAGE);
	(void)madvise(arena, THP_ARENA_SIZE, MADV_POPULATE_WRITE);
	calls += 2;

	return calls;
}

bool thp_split_ref_race(struct childdata *child)
{
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int)op >= 0 && op < NR_CHILD_OP_TYPES);
	unsigned char vec[THP_ARENA_PAGES + 64];	/* mincore + vm_readv buf */
	volatile unsigned int rounds;
	struct timespec start;
	unsigned long direct_calls = 0;
	void *arena;
	uintptr_t base, al;
	unsigned int i;

	if (thp_unavail_latched)
		return false;

	if (vma_pressure_is_high())
		return true;

	/*
	 * Map a PMD-aligned arena via double-map + carve:
	 * 1. Reserve twice the arena size as PROT_NONE.
	 * 2. MAP_FIXED the aligned interior as R/W.
	 * 3. Release prefix and suffix.
	 */
	arena = mmap(NULL, THP_ARENA_SIZE * 2, PROT_NONE,
		     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (arena == MAP_FAILED)
		return true;
	direct_calls += 1;

	base = (uintptr_t)arena;
	al   = (base + THP_ARENA_SIZE - 1) & ~(THP_ARENA_SIZE - 1);

	if (mmap((void *)al, THP_ARENA_SIZE, PROT_READ | PROT_WRITE,
		 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) == MAP_FAILED) {
		munmap(arena, THP_ARENA_SIZE * 2);
		direct_calls += 2;	/* failed mmap + munmap */
		if (valid_op)
			childop_direct_syscalls_add(op, direct_calls);
		return true;
	}
	direct_calls += 1;

	if (al > base) {
		munmap((void *)base, al - base);
		direct_calls++;
	}
	if (al + THP_ARENA_SIZE < base + THP_ARENA_SIZE * 2) {
		munmap((void *)(al + THP_ARENA_SIZE),
		       base + THP_ARENA_SIZE * 2 - (al + THP_ARENA_SIZE));
		direct_calls++;
	}
	arena = (void *)al;

	thp_establish(arena);
	direct_calls += (latch_madv_collapse > 0) ? 3 : 2;	/* madvise calls */

	if (!thp_smaps_has_ahp((uintptr_t)arena)) {
		munmap(arena, THP_ARENA_SIZE);
		direct_calls++;
		thp_unavail_latched = true;
		output(1, "thp_split_ref_race: THP not established -- " /* check-static: child-output-ok */
			  "kernel THP policy or config unavailable; "
			  "op latched unsupported\n");
		if (valid_op) {
			__atomic_store_n(
				&shm->stats.childop.latch_reason[op],
				CHILDOP_LATCH_UNSUPPORTED,
				__ATOMIC_RELAXED);
			childop_direct_syscalls_add(op, direct_calls);
		}
		return false;
	}

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	rounds = BUDGETED(CHILD_OP_THP_SPLIT_REF_RACE,
			  JITTER_RANGE(THP_ROUNDS_BASE));

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);

	clock_gettime(CLOCK_MONOTONIC, &start);

	for (i = 0; i < rounds; i++) {
		if (vma_pressure_is_high())
			break;
		direct_calls += thp_one_round(arena, i, vec, sizeof(vec));
		if (budget_elapsed_ns(&start, THP_BUDGET_NS))
			break;
	}

	munmap(arena, THP_ARENA_SIZE);
	direct_calls++;

	if (valid_op)
		childop_direct_syscalls_add(op, direct_calls);

	return true;
}
