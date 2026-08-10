/*
 * mremap_merge_matrix - adjacent anon-VMA merge identities under mremap.
 *
 * Background
 * ----------
 * mremap(2) covers two conceptually separate kernel operations: plain
 * in-place resize (grow/shrink without relocation) and cross-range
 * relocation (move_vma).  When the destination of a move lands adjacent
 * to an existing VMA with the same prot/flags/anon-vma ancestry the
 * kernel must decide whether to merge -- a decision gated by
 * vma_merge_copied_range() and dup_anon_vma().  The merge is only safe
 * when the two VMAs trace back to the same anon_vma root; getting that
 * wrong produces use-after-free crashes in anon_vma_chain_link and in
 * the rmap reverse-mapping walk.  Recent fixes in that area (copy_vma
 * duplication, page-table rollback on merge failure, the per-VMA
 * anon_vma UAF window around fork) all sit in code paths that the
 * random_syscall path almost never reaches because the argument
 * generator rarely constructs the precise adjacent-address+same-prot
 * setup that triggers a merge attempt.
 *
 * What this op does
 * -----------------
 * One invocation owns a 12-slot arena (12 * SLOT_BYTES, default 2 MiB
 * each = 24 MiB), carved into three conceptual rows:
 *
 *   row 0 (slots 0-3):   source VMAs, each with distinct prot/fault history
 *   row 1 (slots 4-7):   destination slots, pre-mapped PROT_NONE holes
 *   row 2 (slots 8-11):  racing region for COW/fork stress
 *
 * Each iteration picks one of several move shapes:
 *
 *   FIXED_MOVE:    mremap(src, len, len, MAYMOVE|FIXED, dst) -- lands dst
 *                  adjacent to a previously-moved VMA to trigger merge.
 *   DONTUNMAP:     mremap(src, len, len, MAYMOVE|FIXED|DONTUNMAP, dst) --
 *                  keeps the source alive and creates a second VMA at dst
 *                  that shares page tables; exercises dup_anon_vma.
 *   GROW:          mremap(src, half, full, MAYMOVE) -- grow into adjacent
 *                  slot, exercising the allocate-new-range path in move_vma.
 *   SHRINK:        mremap(src, full, half, 0) -- in-place truncate, exposes
 *                  the tail as a hole adjacent to the next VMA.
 *   MULTI_VMA:     mprotect() to deliberately split a source slot into two
 *                  VMAs, then mremap the full range -- exercises the
 *                  multi-VMA move path that iterates __split_vma per edge.
 *   GROW_ZERO:     mremap(src, 0, len, MAYMOVE) -- old_len=0 alias for
 *                  "duplicate at new address without unmapping"; kernel
 *                  behaviour varies, exercises the early-EINVAL and the
 *                  (if permitted) zero-len-grow path.
 *
 * After each move we:
 *   1. Verify page content tags: each source page was stamped with a
 *      slot-unique 4-byte cookie before the move.  Post-move we check
 *      that the cookie is readable at the destination (MAYMOVE without
 *      DONTUNMAP) or still readable at both src and dst (DONTUNMAP).
 *   2. Parse /proc/self/maps to check the topology: confirm that
 *      expected merges happened (adjacent equal-prot VMAs collapsed)
 *      and unexpected splits did not appear.
 *
 * Racing
 * ------
 * One fork helper is spawned per invocation, before the move loop.
 * At fork the kernel clones all live VMAs -- including the slot 0-7
 * source/destination arena -- giving the child shared anon_vma and
 * rmap references into those mappings.  The child faults COW pages
 * in the racing region (slots 8-11) and then blocks on a sync pipe.
 * Meanwhile the parent works through its mremap move iterations;
 * the child's live anon_vma references to slots 0-7 overlap with
 * every move_vma() call in the parent, creating genuine shared-
 * metadata lifetime pressure.  After all moves complete the parent
 * writes a byte to the pipe; the child reads it and calls _exit(0),
 * tearing down its cloned VMAs concurrently with any in-progress
 * rmap or anon_vma work in the parent.  The alarm(1) bound in
 * child.c caps wall time; waitpid is matched 1:1 with the fork.
 *
 * Self-bounding
 * -------------
 * The entire arena is munmap'd unconditionally at op exit.  The
 * iter count is bounded by JITTER_RANGE(MAX_ITERS).  Every waitpid is
 * matched 1:1 with its fork.  The alarm(1) in child.c bounds wall time.
 *
 * No libc rand(): all random picks go through rnd_u32()/rnd_modulo_u32().
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
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

/* ------------------------------------------------------------------
 * Geometry constants.
 * ------------------------------------------------------------------ */

#define SLOT_PAGES		512U		/* pages per arena slot */
#define NR_SLOTS		12U		/* total arena slots    */
#define NR_SRC_SLOTS		4U		/* slots 0-3: sources   */
#define NR_DST_SLOTS		4U		/* slots 4-7: dests     */
/* slots 8-11: racing region (NR_RACE_SLOTS = 4, implied) */

#define MAX_ITERS		48U
#define MAPS_LINE_MAX		256

/* 4-byte per-slot page-tag cookie; written to every page of a source
 * slot so we can verify correct data movement after mremap. */
#define SLOT_COOKIE(slot)	((uint32_t)(0xC0DE0000u | ((slot) & 0xFFu)))

/*
 * Per-slot profile: records the protection and fault state assigned at
 * setup so that the per-iteration reset can faithfully restore it,
 * preserving the four-way prot/fault asymmetry across iterations.
 */
enum slot_fault_level {
	SLOT_FAULT_NONE = 0,	/* no pages faulted       (slot 3) */
	SLOT_FAULT_HALF = 1,	/* first half faulted      (slot 1) */
	SLOT_FAULT_FULL = 2,	/* all pages faulted (slot 0, slot 2) */
};

struct slot_profile {
	int prot;
	enum slot_fault_level fault_level;
};

/* ------------------------------------------------------------------
 * Helpers
 * ------------------------------------------------------------------ */

static inline unsigned long slot_off(unsigned int slot,
				     unsigned long slot_bytes)
{
	return (unsigned long)slot * slot_bytes;
}

static inline char *slot_addr(char *arena, unsigned int slot,
			       unsigned long slot_bytes)
{
	return arena + slot_off(slot, slot_bytes);
}

/*
 * stamp_pages - write a 4-byte cookie to the base of every page in
 * [addr, addr+len).  Temporarily upgrades protection to PROT_READ|PROT_WRITE
 * to handle read-only or PROT_NONE slots, then restores orig_prot.
 */
static void stamp_pages(void *addr, unsigned long len, uint32_t cookie,
			int orig_prot)
{
	unsigned long pg;
	unsigned long npages = len / page_size;

	(void)mprotect(addr, len, PROT_READ | PROT_WRITE);
	for (pg = 0; pg < npages; pg++) {
		uint32_t *p = (uint32_t *)((char *)addr + pg * page_size);
		*p = cookie;
	}
	/* Restore the caller's intended protection. */
	(void)mprotect(addr, len, orig_prot);
}

/*
 * verify_pages - check that every page in [addr, addr+len) starts with
 * the expected cookie.  Temporarily upgrades to PROT_READ|PROT_WRITE to
 * tolerate read-only or PROT_NONE slots, then restores orig_prot.
 * Returns false (without faulting) if the mprotect upgrade fails.
 */
static bool verify_pages(void *addr, unsigned long len, uint32_t cookie,
			 int orig_prot)
{
	unsigned long pg;
	unsigned long npages = len / page_size;

	/* Ensure readable; bail cleanly if the upgrade is refused. */
	if (mprotect(addr, len, PROT_READ | PROT_WRITE) != 0)
		return false;

	for (pg = 0; pg < npages; pg++) {
		const uint32_t *p =
			(const uint32_t *)((const char *)addr + pg * page_size);
		if (*p != cookie) {
			(void)mprotect(addr, len, orig_prot);
			return false;
		}
	}
	/* Restore the caller's intended protection. */
	(void)mprotect(addr, len, orig_prot);
	return true;
}

/*
 * Count how many distinct VMA entries in /proc/self/maps overlap the
 * address range [start, start+len).  Used as a quick topology oracle:
 * after a successful merge the count should drop; after a split it
 * should rise.
 */
static unsigned int count_vmas_in_range(unsigned long start,
					unsigned long len)
{
	FILE *f;
	char line[MAPS_LINE_MAX];
	unsigned long end = start + len;
	unsigned int count = 0;

	f = fopen("/proc/self/maps", "r");
	if (!f)
		return 0;

	while (fgets(line, sizeof(line), f)) {
		unsigned long vma_start, vma_end;

		if (sscanf(line, "%lx-%lx", &vma_start, &vma_end) != 2)
			continue;

		/* Any overlap with [start, end) counts. */
		if (vma_start < end && vma_end > start)
			count++;
	}

	fclose(f);
	return count;
}

/*
 * reset_src_slot - re-establish a source slot's prot/fault profile between
 * iterations.  A fresh anonymous VMA is installed (handles the case where the
 * previous shape unmapped src), then pages are stamped and protection is
 * restored to match the original profile built at setup time.  This preserves
 * the four-way asymmetry (slot 0: RW/fully-faulted, slot 1: RW/half-faulted,
 * slot 2: RO/fully-faulted, slot 3: RW/clean) instead of collapsing all
 * slots to RW+fully-faulted after the first reset.
 */
static void reset_src_slot(char *src, unsigned long slot_bytes,
			   unsigned int slot_idx,
			   const struct slot_profile *prof,
			   unsigned long *dc)
{
	/*
	 * Always establish RW first so stamp_pages can write without an
	 * extra mprotect round-trip.  stamp_pages will restore orig_prot.
	 */
	(*dc)++;
	(void)mmap(src, slot_bytes, PROT_READ | PROT_WRITE,
		   MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);

	switch (prof->fault_level) {
	case SLOT_FAULT_FULL:
		/* stamp_pages restores to prof->prot (handles PROT_READ slots). */
		stamp_pages(src, slot_bytes, SLOT_COOKIE(slot_idx), prof->prot);
		break;
	case SLOT_FAULT_HALF:
		stamp_pages(src, slot_bytes / 2, SLOT_COOKIE(slot_idx), prof->prot);
		/* Top half stays clean; set final prot on full slot. */
		if (prof->prot != (PROT_READ | PROT_WRITE)) {
			(*dc)++;
			(void)mprotect(src, slot_bytes, prof->prot);
		}
		break;
	case SLOT_FAULT_NONE:
		/* No pages faulted; just set the correct protection. */
		if (prof->prot != (PROT_READ | PROT_WRITE)) {
			(*dc)++;
			(void)mprotect(src, slot_bytes, prof->prot);
		}
		break;
	}
}

/* ------------------------------------------------------------------
 * Fork-racing COW helper
 *
 * The child faults one byte on each racing slot page to instantiate
 * COW entries, then blocks on sync_rd until the parent signals that
 * all mremap moves for this invocation are done.  Holding cloned
 * VMAs for slots 0-7 (via shared anon_vma references established at
 * fork) while the parent's move_vma() calls are in flight is the
 * actual teardown-vs-move race this helper creates.
 * ------------------------------------------------------------------ */

static void __attribute__((noreturn))
race_cow_helper(char *race_base, unsigned long slot_bytes, int sync_rd)
{
	unsigned int slot;
	char dummy;

	for (slot = 0; slot < 4; slot++) {
		char *p = race_base + slot * slot_bytes;
		/* Fault a page in the middle of each racing slot. */
		volatile char *vp = (volatile char *)(p + slot_bytes / 2);
		*vp = (char)(slot & 0xff);
	}

	/* Block until the parent finishes its moves (or closes the pipe). */
	{
		ssize_t _r __unused__ = read(sync_rd, &dummy, 1);
	}
	_exit(0);
}

/* ------------------------------------------------------------------
 * Move shapes
 * ------------------------------------------------------------------ */

enum merge_shape {
	SHAPE_FIXED_MOVE = 0,
	SHAPE_DONTUNMAP,
	SHAPE_GROW,
	SHAPE_SHRINK,
	SHAPE_MULTI_VMA,
	SHAPE_GROW_ZERO,
	NR_MERGE_SHAPES,
};

/*
 * Execute one mremap move shape.  src_slot/dst_slot are indices into
 * the arena.  Returns true if the oracle checks pass (or are skipped
 * due to MAP_FAILED / expected errors).
 */
static bool do_move(char *arena, unsigned int src_slot, unsigned int dst_slot,
		    unsigned long slot_bytes, enum merge_shape shape,
		    unsigned long *direct_calls_out, int src_prot)
{
	char *src  = slot_addr(arena, src_slot, slot_bytes);
	char *dst  = slot_addr(arena, dst_slot, slot_bytes);
	unsigned long half = slot_bytes / 2;
	void *ret;
	uint32_t cookie = SLOT_COOKIE(src_slot);
	unsigned int pre_vmas, post_vmas;
	bool ok = true;

	switch (shape) {

	case SHAPE_FIXED_MOVE:
		/*
		 * MAYMOVE|FIXED same-size move onto the destination slot.
		 * The destination was mapped PROT_NONE by the arena setup;
		 * mremap replaces it.  If dst is adjacent to a prior moved
		 * VMA with the same prot, vma_merge_copied_range fires.
		 */
		pre_vmas = count_vmas_in_range((unsigned long)dst, slot_bytes);
		(*direct_calls_out)++;
		ret = mremap(src, slot_bytes, slot_bytes,
			     MREMAP_MAYMOVE | MREMAP_FIXED, dst);
		if (ret == MAP_FAILED)
			break;

		/* Page-tag oracle: cookie must be visible at dst. */
		ok = verify_pages(dst, slot_bytes, cookie, src_prot);

		/* Topology oracle: a successful same-prot adjacent landing
		 * must collapse or hold the VMA count (merge reduces it).
		 * post_vmas > pre_vmas means the kernel spuriously split
		 * something rather than merging. */
		post_vmas = count_vmas_in_range((unsigned long)dst, slot_bytes);
		if (post_vmas > pre_vmas)
			__atomic_add_fetch(
				&shm->stats.mremap_merge_matrix.topology_unexpected,
				1, __ATOMIC_RELAXED);

		/* Re-stamp src region as PROT_NONE hole for next round. */
		(*direct_calls_out)++;
		(void)mmap(src, slot_bytes, PROT_NONE,
			   MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
		break;

	case SHAPE_DONTUNMAP:
		/*
		 * MAYMOVE|FIXED|DONTUNMAP: kernel copies the page-table
		 * entries to dst and keeps src alive.  Both VMAs share the
		 * same anon_vma root (dup_anon_vma path in move_vma).
		 */
		(*direct_calls_out)++;
		ret = mremap(src, slot_bytes, slot_bytes,
			     MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP,
			     dst);
		if (ret == MAP_FAILED)
			break;

		/* Both src and dst should hold the original cookie. */
		ok  = verify_pages(src, slot_bytes, cookie, src_prot);
		ok &= verify_pages(dst, slot_bytes, cookie, src_prot);
		break;

	case SHAPE_GROW:
		/*
		 * In-place grow: old_len=half, new_len=slot_bytes.  The
		 * kernel must find a contiguous range past src+half; with
		 * MREMAP_MAYMOVE it may relocate.  If the tail lands
		 * adjacent to a prior equal-prot VMA, vma_merge fires.
		 */
		stamp_pages(src, half, cookie, src_prot);
		(*direct_calls_out)++;
		ret = mremap(src, half, slot_bytes, MREMAP_MAYMOVE);
		if (ret == MAP_FAILED)
			break;

		ok = verify_pages(ret, half, cookie, src_prot);
		/*
		 * Restore arena slot pointer: src may have moved.
		 * If the kernel relocated, ret is outside the arena and
		 * must be freed here; the arena munmap cannot reach it.
		 */
		if (ret != (void *)src) {
			/*
			 * ret now lives outside the arena; release it so
			 * the final munmap(arena) does not miss it.
			 */
			(void)munmap(ret, slot_bytes);
			(*direct_calls_out)++;
			(void)munmap(ret, slot_bytes);
			(*direct_calls_out)++;
			(void)mmap(src, slot_bytes, PROT_NONE,
				   MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,
				   -1, 0);
		}
		break;

	case SHAPE_SHRINK:
		/*
		 * In-place shrink (no MAYMOVE): truncate top half.  Leaves
		 * src[half..slot_bytes) as a PROT_NONE hole adjacent to
		 * src+slot_bytes.  The remaining VMA has new_len == half;
		 * if the neighbour at dst has the same prot the kernel may
		 * extend by merging.
		 */
		(*direct_calls_out)++;
		ret = mremap(src, slot_bytes, half, 0);
		if (ret == MAP_FAILED)
			break;

		/* Tail is now unmapped; plug it back to keep the arena
		 * intact for subsequent iterations. */
		(*direct_calls_out)++;
		(void)mmap(src + half, slot_bytes - half, PROT_NONE,
			   MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
		ok = verify_pages(ret, half, cookie, src_prot);
		break;

	case SHAPE_MULTI_VMA:
		/*
		 * Split src into two VMAs by mprotect-ing the top half to
		 * a different prot, then remap the full range with MAYMOVE.
		 * move_vma must iterate both sub-VMAs.
		 */
		(*direct_calls_out)++;
		(void)mprotect(src + half, half, PROT_READ);

		/* Topology oracle (MULTI_VMA): count VMAs at dst before and
		 * after the move.  After mprotect the src has 2 sub-VMAs;
		 * the destination (a PROT_NONE hole) should absorb both.
		 * Afterwards dst must not have more VMAs than src had (2),
		 * and merging with a same-prot neighbour may reduce that
		 * further.  More VMAs at dst than src had means the move
		 * introduced a spurious split. */
		{
		unsigned int pre_src_mv =
			count_vmas_in_range((unsigned long)src, slot_bytes);

		(*direct_calls_out)++;
		ret = mremap(src, slot_bytes, slot_bytes,
			     MREMAP_MAYMOVE | MREMAP_FIXED, dst);
		if (ret == MAP_FAILED) {
			/* Re-unify prot on failure so arena stays usable. */
			(*direct_calls_out)++;
			(void)mprotect(src, slot_bytes, PROT_READ | PROT_WRITE);
			break;
		}

		/* Restore src hole. */
		(*direct_calls_out)++;
		(void)mmap(src, slot_bytes, PROT_NONE,
			   MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);

		{
			unsigned int post_mv =
				count_vmas_in_range((unsigned long)dst,
						    slot_bytes);
			if (post_mv > pre_src_mv)
				__atomic_add_fetch(
					&shm->stats.mremap_merge_matrix
						.topology_unexpected,
					1, __ATOMIC_RELAXED);
		}
		}
		ok = verify_pages(dst, half, cookie, src_prot);
		break;

	case SHAPE_GROW_ZERO:
		/*
		 * old_len == 0: exercises the early-EINVAL path on most
		 * kernels (mremap returns EINVAL when old_len==0 and
		 * !MREMAP_DONTUNMAP).  On kernels that permit it as a
		 * "duplicate without unmap" alias, verify dst received
		 * the cookie.
		 */
		(*direct_calls_out)++;
		ret = mremap(src, 0, slot_bytes,
			     MREMAP_MAYMOVE | MREMAP_FIXED, dst);
		if (ret == MAP_FAILED)
			break;	/* EINVAL expected — not a fault */

		ok = verify_pages(dst, slot_bytes, cookie, src_prot);
		break;

	case NR_MERGE_SHAPES:
		break;
	}

	return ok;
}

/* ------------------------------------------------------------------
 * Entry point
 * ------------------------------------------------------------------ */

bool mremap_merge_matrix(struct childdata *child)
{
	unsigned long slot_bytes;
	unsigned long arena_bytes;
	char *arena;
	unsigned int iter, iters;
	unsigned long direct_calls = 0;
	int sync_pipe[2];
	pid_t race_pid = -1;

	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (vma_pressure_is_high())
		return true;

	slot_bytes = (unsigned long)SLOT_PAGES * page_size;
	arena_bytes = (unsigned long)NR_SLOTS * slot_bytes;

	/*
	 * Reserve the arena as a contiguous PROT_NONE block.  Each source
	 * slot will be upgraded to RW+faulted; destination slots start as
	 * PROT_NONE holes (mremap FIXED replaces them).
	 */
	arena = mmap(NULL, arena_bytes, PROT_NONE,
		     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (arena == MAP_FAILED)
		return true;

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	/*
	 * Prepare source slots (0-3): each gets a distinct prot/fault mix.
	 *   slot 0: PROT_READ|PROT_WRITE, fully faulted
	 *   slot 1: PROT_READ|PROT_WRITE, half faulted
	 *   slot 2: PROT_READ only
	 *   slot 3: PROT_READ|PROT_WRITE, clean (unfaulted)
	 *
	 * Record each slot's profile in src_profiles[] so the per-iteration
	 * reset can faithfully restore the asymmetry rather than collapsing
	 * all slots to RW+fully-faulted.
	 */
	struct slot_profile src_profiles[NR_SRC_SLOTS] = {
		[0] = { PROT_READ | PROT_WRITE, SLOT_FAULT_FULL },
		[1] = { PROT_READ | PROT_WRITE, SLOT_FAULT_HALF },
		[2] = { PROT_READ,              SLOT_FAULT_FULL },
		[3] = { PROT_READ | PROT_WRITE, SLOT_FAULT_NONE },
	};

	for (unsigned int s = 0; s < NR_SRC_SLOTS; s++) {
		char *p = slot_addr(arena, s, slot_bytes);
		int prot = src_profiles[s].prot;

		direct_calls++;
		(void)mprotect(p, slot_bytes, prot);

		if (s == 0) {
			/* Fully fault and stamp; orig_prot = RW, no-op restore. */
			stamp_pages(p, slot_bytes, SLOT_COOKIE(s),
				    PROT_READ | PROT_WRITE);
		} else if (s == 1) {
			/* Fault and stamp first half only. */
			stamp_pages(p, slot_bytes / 2, SLOT_COOKIE(s),
				    PROT_READ | PROT_WRITE);
		} else if (s == 2) {
			/*
			 * Read-only slot: stamp_pages upgrades temporarily to
			 * RW, writes cookies, then restores to PROT_READ.
			 */
			stamp_pages(p, slot_bytes, SLOT_COOKIE(s), PROT_READ);
		}
		/* slot 3: stay clean (no fault), prot already set above */
	}

	/*
	 * Racing region (slots 8-11): upgrade to RW so the fork helper
	 * can fault COW pages into them.
	 */
	{
		char *race_base = slot_addr(arena, NR_SRC_SLOTS + NR_DST_SLOTS,
					    slot_bytes);
		direct_calls++;
		(void)mprotect(race_base, 4 * slot_bytes,
			       PROT_READ | PROT_WRITE);
	}

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);

	iters = JITTER_RANGE(MAX_ITERS);

	/*
	 * Spawn the racing helper once for this invocation.  The child
	 * holds cloned VMAs (slots 0-7) via shared anon_vma references
	 * and blocks on sync_pipe[0] until we signal it after the move
	 * loop.  Its concurrent _exit() teardown races move_vma() in the
	 * parent.  Close the read end in the parent; if fork fails, close
	 * both ends so nothing leaks.
	 */
	sync_pipe[0] = sync_pipe[1] = -1;
	if (pipe(sync_pipe) == 0) {
		direct_calls++;
		race_pid = fork();
		if (race_pid == 0) {
			CHILDOP_GRANDCHILD_ENTER();
			char *race_base = slot_addr(arena,
						    NR_SRC_SLOTS + NR_DST_SLOTS,
						    slot_bytes);
			close(sync_pipe[1]);
			race_cow_helper(race_base, slot_bytes, sync_pipe[0]);
			/* unreachable */
		}
		close(sync_pipe[0]);
		if (race_pid < 0) {
			close(sync_pipe[1]);
			sync_pipe[1] = -1;
		}
	}

	for (iter = 0; iter < iters; iter++) {
		unsigned int src_slot, dst_slot;
		enum merge_shape shape;

		if (vma_pressure_is_high())
			break;

		src_slot = rnd_modulo_u32(NR_SRC_SLOTS);
		dst_slot = NR_SRC_SLOTS + rnd_modulo_u32(NR_DST_SLOTS);
		shape    = (enum merge_shape)rnd_modulo_u32(NR_MERGE_SHAPES);

		/* Issue the mremap move (src → dst, various shapes). */
		{
			bool move_ok = do_move(arena, src_slot, dst_slot,
					       slot_bytes, shape,
					       &direct_calls,
					       src_profiles[src_slot].prot);

			__atomic_add_fetch(
				&shm->stats.mremap_merge_matrix.checks_run,
				1, __ATOMIC_RELAXED);
			if (!move_ok) {
				__atomic_add_fetch(
					&shm->stats.mremap_merge_matrix
						.tag_mismatch,
					1, __ATOMIC_RELAXED);
				outputerr("mremap_merge_matrix: BUG -- " /* check-static: child-output-ok */
					  "page tag mismatch after shape %d "
					  "src=%u dst=%u\n",
					  (int)shape, src_slot, dst_slot);
			}
		}

		/*
		 * Re-establish the source slot with its original prot/fault
		 * profile so the asymmetry is preserved across iterations.
		 * reset_src_slot() installs a fresh anon VMA, stamps the
		 * appropriate pages, and restores the assigned protection.
		 */
		{
			char *src = slot_addr(arena, src_slot, slot_bytes);

			reset_src_slot(src, slot_bytes, src_slot,
				       &src_profiles[src_slot], &direct_calls);
		}

		/*
		 * Re-establish the destination as a PROT_NONE hole so the
		 * next FIXED move has a clean landing zone.
		 */
		{
			char *dst = slot_addr(arena, dst_slot, slot_bytes);

			direct_calls++;
			(void)mmap(dst, slot_bytes, PROT_NONE,
				   MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,
				   -1, 0);
		}
	}

	/*
	 * Signal the racing helper that all moves are done, then reap it.
	 * Closing sync_pipe[1] (write end) delivers EOF to the child if
	 * we exited the loop early (vma_pressure bail), ensuring the child
	 * is not left wedged.
	 */
	if (sync_pipe[1] >= 0) {
		ssize_t _w __unused__ = write(sync_pipe[1], "x", 1);
		close(sync_pipe[1]);
		sync_pipe[1] = -1;
	}
	if (race_pid > 0) {
		int status;

		direct_calls++;
		(void)waitpid_eintr(race_pid, &status, 0);
	}

	/* Release the entire arena unconditionally. */
	direct_calls++;
	(void)munmap(arena, arena_bytes);

	if (valid_op)
		childop_direct_syscalls_add(op, direct_calls);

	return true;
}
