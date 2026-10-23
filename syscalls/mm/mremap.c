/*
 * asmlinkage unsigned long sys_mremap(unsigned long addr,
 *   unsigned long old_len, unsigned long new_len,
 *   unsigned long flags, unsigned long new_addr)
 *
 * The old range stays inside the pool mapping the sanitiser picked, and a
 * fixed move goes where it vetted, final slots included (vet_final_mremap()).
 */

#include <sys/mman.h>
#include <sys/stat.h>
#include "arch.h"
#include "maps.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/mman.h"
static const unsigned long alignments[] = {
	MB(1), MB(2), MB(4), MB(4),
	MB(10), MB(100),
	GB(1), GB(2), GB(4),
};

/*
 * Flag-combo coverage for rec->a4.  ARG_LIST's bitmask draw across
 * { MAYMOVE, FIXED, DONTUNMAP } leaves the in-place-resize combo (0)
 * unreachable and routinely produces invalid combos (FIXED without
 * MAYMOVE, DONTUNMAP without MAYMOVE) that bounce off -EINVAL.
 * Override with a bias-weighted pick: ~70% valid combos so the
 * success paths get exercised, ~20% keep the ARG_LIST draw for
 * long-tail invalids, ~10% explicit invalids so the validation
 * path stays warm.
 */
static const unsigned long mremap_valid_combos[] = {
	0,
	MREMAP_MAYMOVE,
	MREMAP_MAYMOVE | MREMAP_FIXED,
	MREMAP_MAYMOVE | MREMAP_DONTUNMAP,
	MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP,
};

static const unsigned long mremap_invalid_combos[] = {
	MREMAP_FIXED,
	MREMAP_DONTUNMAP,
	MREMAP_FIXED | MREMAP_DONTUNMAP,
};

/*
 * Snapshot of the mremap call the sanitiser built: the old range in the
 * mapping it picked and the new length, which the post handler reads, and
 * the flags and target, which vet_final_mremap() holds a fixed move to.
 * Captured at sanitise time, its range and new length moved to the final
 * slots at dispatch, and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->aN between the syscall returning and the post
 * handler running cannot smear the new_len value that gets cached into
 * map->size and map->tracked_size, or retarget the trinity-tracked map
 * pointer the post handler updates.
 *
 * Unlike the readlink/statfs family, post_mremap does not memcpy out of
 * a kernel-written user buffer; it writes the kernel's returned address
 * and the requested new length back into trinity's map bookkeeping.
 * The snap exists to defend the bookkeeping write itself: a stomped
 * new_len would cache the wrong size into map->size and let later pool
 * consumers walk off the actual mapping; a stomped map slot points the
 * same write at an unrelated heap allocation that the existing
 * corruption guard cannot tell apart from a real-but-wrong map pointer.
 */
#define MREMAP_POST_STATE_MAGIC	0x4D52454D5F4D4147UL	/* "MREM_MAG" */
struct mremap_post_state {
	unsigned long magic;
	struct map_range range;
	unsigned long new_len;
	unsigned long flags;
	unsigned long new_addr;
};

/*
 * The kernel acts on the old range first: a shrink unmaps its tail across
 * holes (shrink_vma()), a move takes every VMA in it (remap_move()).  So
 * it has to stay inside the mapping the sanitiser picked (see
 * map_range_vet()), which also keeps it off trinity's regions and the libc
 * heap: the sanitiser empties a range on them, and nothing rewrites a1
 * after it, as ARG_MMAP takes no substitute and the entry is never
 * re-executed.
 *
 * MREMAP_FIXED unmaps whatever lies at the target before it moves anything
 * there (mremap_to()), so a final call carrying it has to be the one the
 * sanitiser vetted, flags, new_len and new_addr alike; MREMAP_DONTUNMAP
 * alone only hints at the target (vrm_set_new_addr()).  A FIXED or MAYMOVE
 * bit the sanitiser did not draw is refused too, and a record with no
 * snapshot of ours drew none.  Refused rather than repaired, each slot
 * read once, as the kernel reads it: the low 32 bits for a compat call.  A
 * pass moves that new_len to the snapshot, which the post handler caches.
 * Shape, then ownership, then magic, as post_state_claim_owned() orders
 * them.
 */
static int vet_final_mremap(struct syscallrecord *rec)
{
	struct mremap_post_state *snap =
		(struct mremap_post_state *) rec->post_state;
	unsigned long mask = rec->do32bit ? UINT_MAX : ULONG_MAX;
	unsigned long new_len = rec->a3 & mask, flags = rec->a4 & mask;
	unsigned long drawn = 0;
	struct map_range *range = NULL;

	if (!is_corrupt_ptr_shape(snap) && post_state_is_owned(snap) &&
	    snap->magic == MREMAP_POST_STATE_MAGIC) {
		range = &snap->range;
		drawn = snap->flags & mask;
	}

	/* A FIXED bit past the first test was drawn, so snap is ours. */
	if ((flags & ~drawn & (MREMAP_FIXED | MREMAP_MAYMOVE)) ||
	    ((flags & MREMAP_FIXED) &&
	     (flags != drawn || new_len != (snap->new_len & mask) ||
	      ((rec->a5 ^ snap->new_addr) & mask))) ||
	    !map_range_vet(rec, range)) {
		outputerr("arg-coupling: mremap rejected: the old range leaves the mapping sanitise picked, or the move is not one it vetted\n");
		return -1;
	}

	if (range != NULL)
		snap->new_len = new_len;
	return 0;
}

static void sanitise_mremap(struct syscallrecord *rec)
{
	struct mremap_post_state *snap;
	struct map *map;
	unsigned long newaddr = 0;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;

	map = common_set_mmap_ptr_len(NULL);
	if (map == NULL) {
		/* No mapping available; stash NULL for post_mremap to skip.
		 * With no snapshot, vet_final_mremap() refuses a move, so
		 * the move bits ARG_LIST drew go too: a refusal is left to
		 * mean a rewrite happened. */
		rec->a4 &= ~(unsigned long) (MREMAP_FIXED | MREMAP_MAYMOVE);
		rec->a6 = 0;
		return;
	}

	/* A compat call's old range has to fit the 32 bits the kernel reads
	 * of each slot, or it is emptied as one over trinity's regions is. */
	if (RANGE_OVERLAPS_SHARED_AUDITED("mremap-old", rec->a1, rec->a2) ||
	    range_overlaps_libc_heap(rec->a1, rec->a2) ||
	    (rec->do32bit && (rec->a1 > UINT_MAX || rec->a2 > UINT_MAX))) {
		rec->a1 = 0;
		rec->a2 = 0;
	}

	rec->a3 = map->size;

	/* Sometimes request a different size */
	switch (rnd_modulo_u32(4)) {
	case 0: break;	/* same size */
	case 1: rec->a3 /= 2; break;	/* shrink */
	case 2: rec->a3 *= 2; break;	/* grow */
	case 3: rec->a3 = page_size * (1 + rnd_modulo_u32(16)); break;	/* random pages */
	}

	/*
	 * Page-align new_len.  An odd-page map->size makes the shrink case
	 * land on 1.5 * page_size and mremap returns -EINVAL before any
	 * interesting split/merge logic runs.  Round up so we still ask for
	 * at least the selected size.
	 */
	rec->a3 = (rec->a3 + page_size - 1) & PAGE_MASK;

	{
		unsigned int r = rnd_modulo_u32(10);

		if (r < 7)
			rec->a4 = RAND_ARRAY(mremap_valid_combos);
		else if (r < 9)
			;	/* keep ARG_LIST-picked value for long tail */
		else
			rec->a4 = RAND_ARRAY(mremap_invalid_combos);
	}

	if (rec->a4 & MREMAP_FIXED) {
		unsigned long align = RAND_ARRAY(alignments);
		unsigned int shift = (WORD_BIT / 2) - 1;
		unsigned long huge, unmapped;

		newaddr = RAND_BYTE();
		newaddr <<= shift;
		newaddr |= align;
		newaddr &= ~(align - 1);

		/*
		 * A hugetlb source has the kernel round new_len up to its
		 * huge page size before the target is unmapped, and refuse
		 * a target that size does not divide (align_hugetlb()).
		 * For a source that is one mapping, the largest power of
		 * two dividing newaddr bounds that size, so the target is
		 * checked as far as new_len rounded up to it.  A move-only
		 * call whose old range runs from an ordinary VMA into a
		 * hugetlb one escapes the bound: each VMA moves to its own
		 * offset from newaddr (remap_move()), which the huge page
		 * size has to divide rather than newaddr.  But the old range
		 * is built inside one pool entry, so that takes an entry
		 * that no longer describes its mapping.
		 */
		huge = newaddr & -newaddr;
		unmapped = rec->a3 > ULONG_MAX - (huge - 1) ? ULONG_MAX :
			   (rec->a3 + huge - 1) & ~(huge - 1);

		/* MREMAP_FIXED unmaps any prior mapping at [newaddr,
		 * newaddr + unmapped) before placing the relocated
		 * mapping there.  Reject if that range overlaps a
		 * trinity-owned shared region — otherwise we silently
		 * unmap our own bookkeeping — or trinity's own image,
		 * whose text a non-PIE build loads at these low
		 * addresses.  A compat call's kernel would truncate a
		 * target its slots cannot carry to one nobody checked. */
		if (RANGE_OVERLAPS_SHARED_AUDITED("mremap-new", newaddr, unmapped) ||
		    range_overlaps_libc_heap(newaddr, unmapped) ||
		    range_overlaps_image(newaddr, unmapped) ||
		    (rec->do32bit && (newaddr > UINT_MAX || rec->a3 > UINT_MAX))) {
			rec->a4 &= ~MREMAP_FIXED;
			newaddr = 0;
		}
	}

	rec->a5 = newaddr;

	/* Stash map pointer in unused arg slot for post callback. */
	rec->a6 = (unsigned long) map;

	/*
	 * Diagnostic: pin slips where range_overlaps_libc_heap() passed
	 * either the old addr or the MREMAP_FIXED new addr but a fresh
	 * sbrk(0) right here proves the addr lies inside the live brk
	 * arena.  Pure observability.
	 */
	log_mm_syscall_post_gate_heap_slip("mremap-old", rec->a1, rec->a2,
					   rec->a4);
	if (rec->a4 & MREMAP_FIXED)
		log_mm_syscall_post_gate_heap_slip("mremap-new", newaddr,
						   rec->a3, rec->a4);

	/*
	 * Snapshot the two inputs the post handler reads.  Without this
	 * the post handler reads rec->a3 and rec->a6 at post-time, when
	 * a sibling syscall may have scribbled the slots.  rec->a6 is
	 * already corruption-guarded against pid scribbles, but
	 * looks_like_corrupted_ptr() cannot tell a real-but-wrong heap
	 * address from a real map pointer, so a foreign-heap stomp slips
	 * the guard and the bookkeeping write lands in someone else's
	 * allocation.  rec->a3 is unguarded entirely; a stomped value
	 * caches the wrong size into map->size and a later consumer that
	 * trusts m->size walks off the actual mapping.  The flags and the
	 * target are kept as vetted for vet_final_mremap().  post_state
	 * is private to the post handler and that hook.
	 * post_state_install pairs the rec->post_state assign with the
	 * ownership-table register so the observable window between the
	 * two is closed; post_mremap() will then gate the snap through
	 * post_state_claim_owned() and prove ownership before
	 * dereferencing any field.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic      = MREMAP_POST_STATE_MAGIC;
	snap->range.map  = map;
	snap->range.addr = rec->a1;
	snap->range.len  = rec->a2;
	snap->new_len    = rec->a3;
	snap->flags      = rec->a4;
	snap->new_addr   = rec->a5;
	post_state_install(rec, snap);
}

/*
 * If we successfully remapped a range, we need to update our record of it
 * so we don't re-use the old address.
 */
static void post_mremap(struct syscallrecord *rec)
{
	struct mremap_post_state *snap;
	struct map *map;
	void *ptr = (void *) rec->retval;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, MREMAP_POST_STATE_MAGIC, __func__);
	if (snap == NULL)
		return;

	map = snap->range.map;

	if (ptr == MAP_FAILED || map == NULL)
		goto out_free;

	/*
	 * Defense in depth: even with the post_state snapshot, a wholesale
	 * stomp could rewrite the snapshot's inner map field.  Reject a
	 * pid-scribbled map before deref.
	 */
	if (looks_like_corrupted_ptr(rec, map)) {
		outputerr("post_mremap: rejected suspicious map=%p (post_state-scribbled?)\n",
			  (void *) map);
		goto out_free;
	}

	/*
	 * Oracle: a successful mremap return must be page-aligned.
	 * mremap may return the same address it received (no MREMAP_FIXED,
	 * no resize-to-move) or a freshly placed address; either way the
	 * kernel ABI requires a PAGE_SIZE-aligned base.  Caching a
	 * misaligned ptr into map->ptr would corrupt every subsequent
	 * consumer that trusts the bookkeeping pointer is a real VMA base.
	 */
	if ((unsigned long) ptr & (page_size - 1)) {
		output(0, "mremap oracle: returned addr %p is not page-aligned (page_size=%u)\n",
		       ptr, page_size);
		__atomic_add_fetch(&shm->stats.oracle.mmap_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
		goto out_free;
	}

	map->ptr = ptr;
	map->size = snap->new_len;
	/*
	 * The VMA the entry now describes was made new_len long, and
	 * tracked_size is that extent: map_destructor() and a whole-mapping
	 * munmap unmap it, and map_range_vet() holds a later range to it.
	 * Left at the old length, a shrink or a move has them reach past the
	 * VMA into whatever is mapped there since.  The clamp below lowers
	 * only size, as post_mmap()'s does.  The shared-region tracker never
	 * sees the change: the entries over tracked regions are clones that
	 * do not own their VMA, which map_destructor() never untracks, and
	 * the sanitiser empties the old range of every one of them.
	 */
	map->tracked_size = snap->new_len;

	/*
	 * Invalidate the get_writable_address() known_rw skip-cache.  The
	 * slot's VMA was just moved/shrunk/grown out from under any prior
	 * whole-mapping mprotect upgrade -- the cached "this slot is RW and
	 * resident" claim no longer covers what's at map->ptr.  Letting it
	 * persist would let the hot path return a pointer into a relocated
	 * or hole-punched arena page and SEGV_MAPERR the consumer on first
	 * store.  Covers all mremap arms (shrink in place, grow, MAYMOVE
	 * relocate, MREMAP_DONTUNMAP); clearing unconditionally on any
	 * successful mremap is correct and simplest.  Mirrors the clear in
	 * post_munmap / post_mprotect.
	 */
	map->known_rw = false;

	/*
	 * For file-backed maps, an mremap grow can produce a VMA covering
	 * pages past the file's backing extent — accessing those pages
	 * SIGBUSes BUS_ADRERR and burns the child before it contributes
	 * coverage, the same crash class post_mmap clamps against.  Mirror
	 * that clamp here: fstat the backing fd and shrink map->size to
	 * the page-aligned in-bounds extent.  Anonymous maps (CHILD_ANON,
	 * INITIAL_ANON) are kernel-backed across the grow and stay at the
	 * requested length.  The original mmap offset is not preserved
	 * across the mremap path, so be conservative and treat offset as
	 * zero (clamp to st_size).  st_size == 0 covers /dev/zero,
	 * /dev/mem, hugetlb fds, memfd_secret, kcov and friends whose
	 * mappable extent is not reflected in stat — leave the requested
	 * size alone for those, matching post_mmap.
	 */
	if (map->type == MMAPED_FILE && map->fd != -1) {
		struct stat st;

		if (fstat(map->fd, &st) == 0) {
			if (st.st_size > 0) {
				if ((unsigned long) st.st_size < map->size)
					map->size = (unsigned long) st.st_size & PAGE_MASK;

				if (map->size != snap->new_len)
					__atomic_add_fetch(&shm->stats.diag.mmap_size_clamped,
							   1, __ATOMIC_RELAXED);
			}
		} else {
			/*
			 * fstat failed -- the fd was closed or replaced
			 * between the mremap return and the post handler.
			 * Backed extent is unknown, so zero the size to
			 * gate dirty_mapping off rather than walking past
			 * EOF.  Mirrors the post_mmap fstat-failure stance.
			 */
			map->size = 0;
			__atomic_add_fetch(&shm->stats.diag.mmap_size_clamped,
					   1, __ATOMIC_RELAXED);
		}
	}

out_free:
	post_state_release(rec, snap);
}

static unsigned long mremap_flags[] = {
	MREMAP_MAYMOVE, MREMAP_FIXED, MREMAP_DONTUNMAP,
};

struct syscallentry syscall_mremap = {
	.name = "mremap",
	.num_args = 5,
	.sanitise = sanitise_mremap,
	.vet_final = vet_final_mremap,
	.argtype = { [0] = ARG_MMAP, [1] = ARG_LEN, [2] = ARG_LEN, [3] = ARG_LIST },
	.argname = { [0] = "addr", [1] = "old_len", [2] = "new_len", [3] = "flags", [4] = "new_addr" },
	.arg_params[3].list = ARGLIST(mremap_flags),
	.group = GROUP_VM,
	.post = post_mremap,
	.rettype = RET_ADDRESS,
	.flags = AVOID_REEXEC | REEXEC_SANITISE_OK,
};
