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
#include "utils.h"

#include "kernel/mman.h"
/*
 * Snapshot of the mprotect inputs read by the post handler, captured at
 * sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->aN between the syscall returning and the post
 * handler running cannot smear the addr/len/prot/map the post handler
 * uses to update the trinity-tracked map->prot invariant or to drive
 * the proc-maps oracle.  pkey is captured for the pkey_mprotect entry
 * that shares this sanitise/post pair (key arrives at rec->a4); plain
 * mprotect ignores the field.
 *
 * A stomped rec->a3 caches the wrong prot bits into map->prot and a
 * later get_map_with_prot() consumer (memory_pressure / iouring_* /
 * madvise_pattern_cycler) trusts the lie and SEGV_ACCERRs on the first
 * un-upgraded page or, mirror-image, skips a mapping that is still
 * writable.  A stomped rec->a1/rec->a2 retargets the proc-maps oracle
 * at an address window the syscall never operated on -- forging either
 * a clean compare against an unrelated /proc/self/maps slice or an
 * "mprotect did not land" anomaly that never happened.
 *
 * map is snapshotted for the same heap-shape-spoofing defence the
 * munmap and mremap post handlers already document:
 * looks_like_corrupted_ptr() cannot tell a real-but-wrong heap address
 * from a real map pointer, so a foreign-heap stomp of rec->a5 would
 * slip the guard and cache prot bits into the wrong tracked map.
 */
/* Forward declaration so sanitise_mprotect() can disambiguate the
 * shared sanitise hook by entry-pointer comparison (the pkey_mprotect
 * entry takes a fourth pkey argument that plain mprotect ignores). */
extern struct syscallentry syscall_pkey_mprotect;

#define MPROTECT_POST_STATE_MAGIC	0x4D505254UL	/* "MPRT" */
struct mprotect_post_state {
	unsigned long magic;
	unsigned long addr;
	unsigned long len;
	unsigned long prot;
	unsigned long pkey;
	unsigned long map;
};

static void sanitise_mprotect(struct syscallrecord *rec)
{
	struct mprotect_post_state *snap;
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

	if (RANGE_OVERLAPS_SHARED_AUDITED("mprotect", rec->a1, rec->a2) ||
	    range_overlaps_libc_heap(rec->a1, rec->a2)) {
		rec->a1 = 0;
		rec->a2 = 0;
	}

	/* Stash map pointer in unused arg slot for post callback.
	 * NULL is fine — post_mprotect checks before dereferencing. */
	rec->a5 = (unsigned long) map;

	/*
	 * pkey_mprotect's fourth argument is a pkey id allocated by
	 * pkey_alloc().  Generic argument generation feeds rec->a4 a
	 * fully random ulong, which almost never hits a live key — the
	 * kernel's per-mm pkey bitmap has 16 slots and the unknown-key
	 * reject path collapses the call to EINVAL on miss.  Pull from
	 * the OBJ_PKEY pool (populated by post_pkey_alloc()) 60% of the
	 * time when the pool is non-empty so the call lands on a live
	 * key.  The remaining 40% (and the empty-pool fallback) stay
	 * random so the unknown-key reject path keeps getting coverage.
	 */
	if (rec->entry == &syscall_pkey_mprotect) {
		if (rnd_modulo_u32(100) < 60) {
			int id = get_random_pkey_id();

			if (id >= 0)
				rec->a4 = (unsigned long) id;
		}
	}

	/*
	 * Diagnostic: pin slips where range_overlaps_libc_heap() passed
	 * the addr but a fresh sbrk(0) right here proves it lies inside
	 * the live brk arena.  Pure observability.  Covers both mprotect
	 * and pkey_mprotect via the shared sanitiser.
	 */
	log_mm_syscall_post_gate_heap_slip(
		rec->entry == &syscall_pkey_mprotect
			? "pkey_mprotect" : "mprotect",
		rec->a1, rec->a2, rec->a3);

	/*
	 * Snapshot the inputs the post handler reads.  Without this the
	 * post handler reads rec->a1/a2/a3 at post-time, when a sibling
	 * syscall may have scribbled the slots: a stomped prot caches the
	 * wrong bits into the cached map->prot invariant, and a stomped
	 * addr/len mis-aims the proc-maps oracle.  post_state is private
	 * to the post handler.  post_state_install pairs the rec->post_state
	 * assign with the ownership-table register so the observable window
	 * between the two is closed; post_mprotect() will then gate the snap
	 * through post_state_claim_owned() and prove ownership before
	 * dereferencing any field.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = MPROTECT_POST_STATE_MAGIC;
	snap->addr = rec->a1;
	snap->len  = rec->a2;
	snap->prot = rec->a3;
	snap->pkey = rec->a4;
	snap->map  = (unsigned long) map;
	post_state_install(rec, snap);
}

/*
 * If we successfully did an mprotect, update our record of the mappings prot bits.
 */
static void post_mprotect(struct syscallrecord *rec)
{
	struct mprotect_post_state *snap;
	struct map *map;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, MPROTECT_POST_STATE_MAGIC, __func__);
	if (snap == NULL)
		return;

	map = (struct map *) snap->map;

	if (rec->retval != 0 || map == NULL)
		goto out_free;

	/*
	 * Defense in depth: even with the post_state snapshot, a wholesale
	 * stomp could rewrite the snapshot's inner map field.  Reject a
	 * pid-scribbled map before deref.
	 */
	if (looks_like_corrupted_ptr(rec, map)) {
		outputerr("post_mprotect: rejected suspicious map=%p (pid-scribbled?)\n",
			  (void *) map);
		goto out_free;
	}

	/*
	 * common_set_mmap_ptr_len() forces rec->a1 = map->ptr but sets
	 * rec->a2 = rnd_modulo_u32(map->size) & PAGE_MASK, so this path is
	 * effectively always a sub-range mprotect (a2 < map->size).
	 * Blindly overwriting map->prot with the new prot leaks it into
	 * the cached invariant — e.g. a sub-range upgrade from PROT_NONE
	 * -> PROT_RW would leave map->prot claiming PROT_WRITE while most
	 * pages are still PROT_NONE.  get_map_with_prot() trusts m->prot,
	 * hands the entry to memory_pressure / iouring_* /
	 * madvise_pattern_cycler, and the per-page write loop SEGV_ACCERRs
	 * on the first un-upgraded page.  Mirror the conservative AND from
	 * mprotect_split (childops/mm/mprotect-split.c): for a whole-mapping
	 * mprotect take the new prot exactly; for any sub-range, intersect
	 * with the existing invariant so we only ever drop bits, never add
	 * them.  False-negatives (skipping a mapping that still has writable
	 * pages somewhere) are acceptable; false-positives crash the child.
	 */
	if (snap->addr == (unsigned long)map->ptr && snap->len == map->size)
		map->prot = snap->prot;
	else
		map->prot &= snap->prot;

	/*
	 * Invalidate the get_writable_address() known_rw skip-cache.  The
	 * cache assumes nobody has touched the slot's prot since the last
	 * whole-mapping RW upgrade; we just stomped that assumption.  A
	 * sub-range downgrade leaves the cached bit lying about pages that
	 * are no longer writable, and even a whole-mapping mprotect to
	 * something that still contains PROT_WRITE is safer cleared --
	 * get_writable_address() will re-upgrade and reset the bit on its
	 * next miss.  Clearing here is the simpler half of the contract
	 * documented on struct map::known_rw.
	 */
	map->known_rw = false;

	/*
	 * Oracle: 1-in-100 chance — verify /proc/self/maps reflects the prot
	 * change we just applied.  A stale or wrong entry signals that the
	 * kernel's VMA prot state diverged from what mprotect reported back.
	 */
	if (snap->len > 0 && ONE_IN(100)) {
		if (!proc_maps_check(snap->addr, snap->len, snap->prot, true)) {
			output(0, "mmap oracle: mprotect(%lx, %lu, 0x%lx) "
			       "succeeded but prot not in /proc/self/maps\n",
			       snap->addr, snap->len, snap->prot);
			__atomic_add_fetch(&shm->stats.oracle.mmap_oracle_anomalies, 1,
					   __ATOMIC_RELAXED);
		}
	}

out_free:
	post_state_release(rec, snap);
}

#ifndef PROT_MTE
#define PROT_MTE	0x20		/* aarch64 MTE (5.10+) */
#endif

#ifndef PROT_BTI
#define PROT_BTI	0x10		/* aarch64 BTI */
#endif

static unsigned long mprotect_prots[] = {
	PROT_READ, PROT_WRITE, PROT_EXEC, PROT_SEM,
	PROT_GROWSDOWN, PROT_GROWSUP,
	PROT_MTE, PROT_BTI,
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
	.rettype = RET_ZERO_SUCCESS,
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
	.rettype = RET_ZERO_SUCCESS,
};
