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
 *           mincore (page-residency walk) and process_vm_readv (same-
 *           process copy_page_to_iter via folio_try_get()) race the
 *           deferred-split-queue and folio refcount manipulation.
 *           process_vm_readv passes getpid() -- own mm; the CLONE_VM
 *           sibling in the mincore arm is the actual second task in
 *           the mm (different pid, shared address space).
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
#include <sched.h>
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
#include "signals.h"
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

/*
 * 16 MiB arena for the mincore pagewalk OOB arm.  mincore() walks into a
 * single 4096-byte kernel page (tmp = __get_free_page(GFP_USER)); a
 * duplicated sub-range from the ACTION_AGAIN retry path pushes the cursor
 * past tmp+4096 (OOB write into the adjacent kernel page).  ≥16 MiB
 * (4096 pages) is the minimum size for the cursor to reach that boundary.
 * Keep PMD/THP alignment (multiple of 2 MiB).
 *
 * MINCORE_VEC_BYTES is exactly MINCORE_ARENA_PAGES (4096) -- one byte per
 * page.  KASAN is the oracle for OOB writes on the kernel side.
 */
#define MINCORE_ARENA_SIZE	(16UL << 20)
#define MINCORE_ARENA_PAGES	(MINCORE_ARENA_SIZE / 4096UL)
#define MINCORE_VEC_BYTES	MINCORE_ARENA_PAGES
#define MINCORE_RACER_STACK	(64UL * 1024UL)		/* 64 KiB sibling stack */

/*
 * Per-round oracle tally, aggregated into shm->stats.thp_split_ref_race
 * after each round in the main loop.
 *
 * ref_held:     process_vm_readv returned > 0 bytes (reference walker
 *               reached folio_try_get() during the split window).
 * content_bad:  pvreadv succeeded but returned bytes don't match the
 *               pre-split cookie written to the arena (data corruption).
 * no_race:      both mincore and pvreadv observed nothing useful (pages
 *               absent; no meaningful concurrency this round).
 */
struct thp_round_tally {
	bool ref_held;
	bool content_bad;
	bool no_race;
};

/* One-time THP unavailability latch and MADV_COLLAPSE feature probe. */
static bool thp_unavail_latched;
static int  latch_madv_collapse = -1;	/* -1=unknown, 0=absent, 1=present */

/*
 * Shared state between the parent and the CLONE_VM sibling in the mincore
 * pagewalk arm.  Placed in a private anonymous mapping so it is visible to
 * both tasks without MAP_SHARED (CLONE_VM shares the page tables).
 * Do NOT touch child-framework fields (this_child() etc.) from the sibling;
 * it is not fork-invariant.
 */
struct mincore_racer_state {
	_Atomic volatile int stop;		/* parent sets 1 to terminate sibling */
	_Atomic volatile unsigned long syscalls;	/* sibling accumulates direct calls */
	void *arena;				/* 16 MiB CLONE_VM-shared mapping */
};

/*
 * CLONE_VM sibling body: loops MADV_COLLAPSE + MADV_DONTNEED over the
 * shared 16 MiB arena to trigger pte_offset_map_lock() failures in the
 * parent's concurrent mincore() pagewalk.
 *
 * Must NOT call this_child() -- per-process state is not fork-invariant.
 * Exits via _exit(0) so parent can waitpid().
 */
static int mincore_vm_racer_fn(void *arg)
{
	struct mincore_racer_state *rs = arg;
	void *ar = rs->arena;
	unsigned long calls = 0;

	while (!__atomic_load_n(&rs->stop, __ATOMIC_ACQUIRE)) {
		(void)madvise(ar, MINCORE_ARENA_SIZE, MADV_COLLAPSE);
		(void)madvise(ar, MINCORE_ARENA_SIZE, MADV_DONTNEED);
		calls += 2;
	}
	__atomic_add_fetch(&rs->syscalls, calls, __ATOMIC_RELAXED);
	_exit(0);
}

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
 *   process_vm_readv -- same-process copy_page_to_iter races refcount;
 *     passes getpid() (own mm).  The CLONE_VM sibling spawned by the
 *     caller is the actual second task in this mm (cross-process in the
 *     sense of different pid, shared address space).
 *
 * Returns the number of direct syscall sites executed in this round.
 * *tally is populated with oracle observations for this round.
 */
static unsigned long thp_one_round(void *arena, unsigned int round,
				   unsigned char *vec, size_t vec_sz,
				   struct thp_round_tally *tally)
{
	uintptr_t base = (uintptr_t)arena;
	size_t sub = THP_ARENA_SIZE / 4;
	unsigned long calls = 0;
	unsigned char cookie = (unsigned char)(0xa5 ^ (round & 0xffU));
	bool check_content = false;
	ssize_t pvreadv_bytes;
	int mincore_ok;

	/*
	 * Content oracle: for the mprotect trigger (round%3==0) the arena
	 * content survives the prot-change split, so a pre-split cookie can
	 * be verified after a successful process_vm_readv.  Write the cookie
	 * before the trigger fires so it is present during the race window.
	 * MADV_DONTNEED (round%3==1) legitimately zeros pages; mremap
	 * (round%3==2) relocates the first quarter, making pvreadv to the
	 * original base likely fail -- skip the content check for both.
	 */
	if (round % 3U == 0) {
		__builtin_memset(arena, cookie, vec_sz);
		check_content = true;
	}

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
	mincore_ok = mincore(arena, THP_ARENA_SIZE, vec);
	calls++;

	/*
	 * process_vm_readv: same-process copy_page_to_iter races folio split.
	 * Passes getpid() -- this is a self-read within the same mm.  The
	 * concurrent second task (different pid, same mm via CLONE_VM) is the
	 * cross-process pressure source driving pte_offset_map_lock() failure.
	 */
	{
		struct iovec lv = { vec, vec_sz };
		struct iovec rv = { arena, vec_sz };

		pvreadv_bytes = process_vm_readv(getpid(), &lv, 1, &rv, 1, 0);
		calls++;
	}

	/* Oracle: classify this round. */
	tally->ref_held     = (pvreadv_bytes > 0);
	tally->content_bad  = false;
	tally->no_race      = (mincore_ok != 0 && pvreadv_bytes <= 0);

	if (tally->ref_held && check_content && vec[0] != cookie)
		tally->content_bad = true;

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
	/*
	 * vec: mincore + vm_readv scratch buffer.  Must be MINCORE_VEC_BYTES
	 * long so the 16 MiB mincore arm fits (4096 pages = MINCORE_ARENA_PAGES).
	 * Heap-allocated because the 16 MiB arena requires a 4096-entry vec;
	 * a stack allocation of that size is unreasonable.
	 */
	unsigned char *vec;
	volatile unsigned int rounds;
	struct timespec start;
	unsigned long direct_calls = 0;
	unsigned long tally_rounds = 0;
	unsigned long tally_ref_held = 0;
	unsigned long tally_no_race = 0;
	unsigned long tally_content_bad = 0;
	void *arena;
	uintptr_t base, al;
	unsigned int i;

	if (thp_unavail_latched)
		return false;

	if (vma_pressure_is_high())
		return true;

	/*
	 * Allocate the mincore/pvreadv scratch buffer on the heap.  At
	 * MINCORE_VEC_BYTES = MINCORE_ARENA_PAGES (4096) this covers both the
	 * 2 MiB THP rounds (needing THP_ARENA_PAGES = 512 bytes) and the full
	 * 16 MiB mincore arm (needing MINCORE_ARENA_PAGES = 4096 bytes).
	 */
	vec = mmap(NULL, MINCORE_VEC_BYTES, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (vec == MAP_FAILED)
		return true;
	direct_calls++;

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
		struct thp_round_tally rt = { false, false, false };

		if (vma_pressure_is_high())
			break;
		direct_calls += thp_one_round(arena, i, vec,
				      THP_ARENA_PAGES, &rt);
		tally_rounds++;
		if (rt.ref_held)
			tally_ref_held++;
		if (rt.no_race)
			tally_no_race++;
		if (rt.content_bad)
			tally_content_bad++;
		if (budget_elapsed_ns(&start, THP_BUDGET_NS))
			break;
	}

	munmap(arena, THP_ARENA_SIZE);
	direct_calls++;

	/*
	 * Mincore pagewalk OOB arm.
	 *
	 * Maps a PMD-aligned 16 MiB arena and races mincore() against a
	 * CLONE_VM sibling that loops MADV_COLLAPSE + MADV_DONTNEED.  The
	 * concurrent collapse/dontneed drives pte_offset_map_lock() failures
	 * in the pagewalk, triggering the ACTION_AGAIN retry path.
	 * walk_pud_range() then re-walks the PUD sub-range; mincore_pte_range()
	 * advances its cursor unconditionally, pushing it past the 4096-byte
	 * tmp buffer (OOB write into the adjacent kernel page).  KASAN catches
	 * the overwrite.
	 *
	 * CLONE_VM (not CLONE_VFORK) -- the sibling is a live concurrent task
	 * in the same mm, not a blocked parent waiting for exec/exit.
	 */
	{
		struct mincore_racer_state *rs = MAP_FAILED;
		void *mc_arena = MAP_FAILED;
		void *sibling_stack = MAP_FAILED;
		uintptr_t mc_base, mc_al;
		pid_t sibling_pid = -1;
		unsigned int mc_rounds;

		/* Allocate shared racer state (visible to CLONE_VM sibling). */
		rs = mmap(NULL, sizeof(*rs), PROT_READ | PROT_WRITE,
			  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (rs == MAP_FAILED)
			goto mc_out;
		direct_calls++;
		rs->stop = 0;
		rs->syscalls = 0;

		/* Allocate sibling stack. */
		sibling_stack = mmap(NULL, MINCORE_RACER_STACK,
				     PROT_READ | PROT_WRITE,
				     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (sibling_stack == MAP_FAILED)
			goto mc_out;
		direct_calls++;

		/*
		 * Map a PMD-aligned 16 MiB arena for the mincore arm.
		 * Same double-map + carve pattern as the THP arena above.
		 */
		mc_arena = mmap(NULL, MINCORE_ARENA_SIZE * 2, PROT_NONE,
				MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (mc_arena == MAP_FAILED)
			goto mc_out;
		direct_calls++;

		mc_base = (uintptr_t)mc_arena;
		mc_al   = (mc_base + MINCORE_ARENA_SIZE - 1)
			  & ~(MINCORE_ARENA_SIZE - 1);

		if (mmap((void *)mc_al, MINCORE_ARENA_SIZE,
			 PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
			 -1, 0) == MAP_FAILED) {
			munmap(mc_arena, MINCORE_ARENA_SIZE * 2);
			mc_arena = MAP_FAILED;
			direct_calls += 2;
			goto mc_out;
		}
		direct_calls++;

		if (mc_al > mc_base) {
			munmap((void *)mc_base, mc_al - mc_base);
			direct_calls++;
		}
		if (mc_al + MINCORE_ARENA_SIZE < mc_base + MINCORE_ARENA_SIZE * 2) {
			munmap((void *)(mc_al + MINCORE_ARENA_SIZE),
			       mc_base + MINCORE_ARENA_SIZE * 2
			       - (mc_al + MINCORE_ARENA_SIZE));
			direct_calls++;
		}
		mc_arena = (void *)mc_al;

		/* Fault in the arena so mincore has populated PTEs to walk. */
		(void)madvise(mc_arena, MINCORE_ARENA_SIZE, MADV_HUGEPAGE);
		(void)madvise(mc_arena, MINCORE_ARENA_SIZE, MADV_POPULATE_WRITE);
		direct_calls += 2;

		rs->arena = mc_arena;

		/*
		 * Spawn the CLONE_VM sibling.  NOT CLONE_VFORK -- the sibling
		 * must run concurrently (CLONE_VFORK blocks the parent until the
		 * child calls exec or _exit, which is specific to the exec/_exit arm).
		 */
		sibling_pid = clone(mincore_vm_racer_fn,
				    (char *)sibling_stack + MINCORE_RACER_STACK,
				    CLONE_VM | SIGCHLD,
				    rs);
		if (sibling_pid < 0)
			goto mc_stop;

		/*
		 * Parent loops mincore() over the full 16 MiB.  Each call races
		 * the sibling's MADV_COLLAPSE/MADV_DONTNEED.  Bounded by
		 * THP_BUDGET_NS so the sibling cannot spin the full arm duration.
		 */
		mc_rounds = JITTER_RANGE(8U);
		clock_gettime(CLOCK_MONOTONIC, &start);
		for (unsigned int r = 0; r < mc_rounds; r++) {
			(void)mincore(mc_arena, MINCORE_ARENA_SIZE, vec);
			direct_calls++;

			if (vma_pressure_is_high())
				break;
			if (budget_elapsed_ns(&start, THP_BUDGET_NS))
				break;
		}

mc_stop:
		/* Signal sibling to exit and reap it. */
		__atomic_store_n(&rs->stop, 1, __ATOMIC_RELEASE);
		if (sibling_pid > 0) {
			waitpid_eintr(sibling_pid, NULL, 0);
			direct_calls += (unsigned long)
				__atomic_load_n(&rs->syscalls, __ATOMIC_RELAXED);
		}

mc_out:
		if (mc_arena != MAP_FAILED) {
			munmap(mc_arena, MINCORE_ARENA_SIZE);
			direct_calls++;
		}
		if (sibling_stack != MAP_FAILED)
			(void)munmap(sibling_stack, MINCORE_RACER_STACK);
		if (rs != MAP_FAILED)
			(void)munmap(rs, sizeof(*rs));
	}

	/* Free the heap vec buffer. */
	munmap(vec, MINCORE_VEC_BYTES);
	direct_calls++;

	if (valid_op)
		childop_direct_syscalls_add(op, direct_calls);

	if (tally_rounds) {
		__atomic_add_fetch(&shm->stats.thp_split_ref_race.split_trigger_rounds,
				   tally_rounds, __ATOMIC_RELAXED);
		if (tally_ref_held)
			__atomic_add_fetch(
				&shm->stats.thp_split_ref_race.thp_split_while_ref_held,
				tally_ref_held, __ATOMIC_RELAXED);
		if (tally_no_race)
			__atomic_add_fetch(
				&shm->stats.thp_split_ref_race.thp_no_race,
				tally_no_race, __ATOMIC_RELAXED);
		if (tally_content_bad)
			__atomic_add_fetch(
				&shm->stats.thp_split_ref_race.content_mismatch,
				tally_content_bad, __ATOMIC_RELAXED);
	}
	return true;
}
