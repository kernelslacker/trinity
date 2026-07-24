#include <stdbool.h>
#include <sys/mman.h>
#include <asm/mman.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include "arch.h"
#include "child.h"
#include "deferred-free.h"
#include "maps.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "utils.h"

#include "kernel/mman.h"
#include "maps-internal.h"
/*
 * Trigger threshold for the OBJ_LOCAL ANON lazy refill in
 * get_map_handle().  Post fork-time seed (init_child_mappings) the
 * pool starts populated, so steady-state exhaustion should be rare;
 * 64 leaves headroom for short bursts without re-walking the global
 * snapshot on every drained pick.
 */
#define MAPS_LOCAL_REFILL_PERIOD	64u

/*
 * SAMPLED pick-cost telemetry.  A per-child function-local static
 * counter gates 1-in-2^MAPS_PICK_SAMPLE_SHIFT calls of
 * get_map_handle() to bracket its retry loop with rdtsc.  Sampling,
 * not per-call: an unconditional rdtsc pair on the arg-gen hot path
 * would show up in profiles.  The counter is deterministic and
 * consumes no RNG entropy so the emitted arg stream stays byte-
 * identical to the untelemetered build (verified via --dry-run
 * shadow-identity gate).  N=64 is a compromise between sample noise
 * (want more) and hot-path cost (want less).
 */
#define MAPS_PICK_SAMPLE_SHIFT	6u
#define MAPS_PICK_SAMPLE_MASK	((1u << MAPS_PICK_SAMPLE_SHIFT) - 1u)

/*
 * Read a monotonic cycle counter.  x86 uses rdtsc directly; aarch64
 * uses the EL0-readable virtual counter (cntvct_el0); other targets
 * fall back to 0, which collapses the sampled sum to 0 and lets the
 * dump-time render skip the row via the standard count==0 guard.
 * Volatile asm keeps the compiler from hoisting the read out of the
 * measurement bracket.
 */
static inline unsigned long maps_pick_read_cycles(void)
{
#if defined(__x86_64__) || defined(__i386__)
	unsigned int lo, hi;

	__asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
	return ((unsigned long)hi << 32) | (unsigned long)lo;
#elif defined(__aarch64__)
	unsigned long v;

	__asm__ volatile("mrs %0, cntvct_el0" : "=r"(v));
	return v;
#else
	return 0UL;
#endif
}

/*
 * Bucket the loop-exit index `i` into a log2 histogram slot that
 * mirrors fd_live_remove_scan_histogram exactly: slot 0 for i==0
 * (first-iteration hit), slot k for i in [2^(k-1), 2^k) up to a
 * saturating tail slot for i >= 2^(N-1).  RELAXED add-fetch on the
 * shared shm counter matches the shm->stats convention used
 * elsewhere in the file.
 */
static void maps_pick_bump_scan_histogram(unsigned int i)
{
	unsigned int bucket;

	if (i == 0) {
		bucket = 0;
	} else {
		unsigned int lz = (unsigned int)__builtin_clz(i);
		unsigned int hi_bit = 31u - lz;

		bucket = hi_bit + 1u;
		if (bucket >= ARRAY_SIZE(shm->stats.maps.pick_scan_histogram))
			bucket = ARRAY_SIZE(shm->stats.maps.pick_scan_histogram) - 1u;
	}
	__atomic_add_fetch(&shm->stats.maps.pick_scan_histogram[bucket],
			   1, __ATOMIC_RELAXED);
}

/*
 * Restrict the per-iteration pool pick to OBJ_LOCAL pools the
 * owning child has marked nonempty.  Without the mask, type was
 * chosen uniformly from all three regardless of occupancy, so
 * each empty pool burnt one in three iterations on a
 * get_random_object() == NULL reject -- a steady-state cost
 * paid every draw post-fork until FILE/TESTFILE picked up
 * entries via lazy mmap shapes.  The mask filters those
 * guaranteed misses out entirely; the post-1000-iter refill
 * arm below still runs on real exhaustion (mask==0).
 *
 * The pick is uniform across the SET bits in popmask, not
 * weighted by num_entries -- intentionally preserves the
 * pre-mask equal-pool bias (each nonempty pool sampled at
 * 1/popcount) so consumer mix over {ANON, FILE, TESTFILE}
 * stays unchanged for the common all-nonempty case and
 * collapses sensibly to the surviving subset when one or two
 * pools drain.  Weighting by num_entries would change the mix
 * and is explicitly out of scope.
 *
 * OBJ_GLOBAL keeps the uniform 1-of-3 pick: the mask lives in
 * childdata and is owner-only; the parent-side path through
 * this function (child == NULL) has no per-pool occupancy
 * shadow and just picks across all three pool types as before.
 */
static enum objecttype pick_mmap_pool_type(struct childdata *child,
					   enum obj_scope scope,
					   bool *all_empty)
{
	static const enum objecttype map_pool_types[3] = {
		OBJ_MMAP_ANON, OBJ_MMAP_FILE, OBJ_MMAP_TESTFILE
	};
	unsigned int popmask, popcount, pick, bit;
	enum objecttype type;

	*all_empty = false;

	if (scope == OBJ_LOCAL && child != NULL) {
		popmask = child->mmap_pool_nonempty_mask & 0x7u;
		if (popmask == 0) {
			*all_empty = true;
			return map_pool_types[0];
		}
	} else {
		popmask = 0x7u;
	}

	popcount = (unsigned int) __builtin_popcount(popmask);
	pick = rnd_modulo_u32(popcount);
	type = map_pool_types[0];
	for (bit = 0; bit < 3; bit++) {
		if ((popmask & (1u << bit)) == 0)
			continue;
		if (pick == 0) {
			type = map_pool_types[bit];
			break;
		}
		pick--;
	}
	return type;
}

static void account_pool_empty_reject(enum objecttype type)
{
	__atomic_add_fetch(&shm->stats.maps.reject_pool_empty, 1, __ATOMIC_RELAXED);
	/* Per-type sub-attribution.  The aggregate
	 * above is bumped per NULL-pool iteration without
	 * recording which OBJ_MMAP_* pool returned NULL; the
	 * three counters below split it so the TESTFILE-share
	 * of interest post-fork is directly visible. */
	switch (type) {
	case OBJ_MMAP_ANON:
		__atomic_add_fetch(&shm->stats.maps.reject_pool_empty_anon,
				   1, __ATOMIC_RELAXED);
		break;
	case OBJ_MMAP_FILE:
		__atomic_add_fetch(&shm->stats.maps.reject_pool_empty_file,
				   1, __ATOMIC_RELAXED);
		break;
	case OBJ_MMAP_TESTFILE:
		__atomic_add_fetch(&shm->stats.maps.reject_pool_empty_testfile,
				   1, __ATOMIC_RELAXED);
		break;
	default:
		break;
	}
}

/*
 * Defend against stale or corrupted slot pointers leaking
 * out of the OBJ_MMAP pool.  Heap pointers land at
 * >= 0x10000 and below the 47-bit user/kernel boundary;
 * any obj pointer outside that window can't be a real obj
 * struct, and dereferencing it via &obj->map then map->ptr
 * scribbles garbage into whatever syscall arg buffer the
 * caller is filling (alloc_iovec via the iovec generator
 * was the trigger — its iov_base ended up at sub-page
 * addresses like 0x1d8).  Skip the slot and try again.
 */
static bool obj_ptr_in_user_va_band(struct object *obj,
				    enum objecttype type,
				    enum obj_scope scope)
{
	if ((uintptr_t)obj < 0x10000UL ||
	    (uintptr_t)obj >= 0x800000000000UL) {
		__atomic_add_fetch(&shm->stats.maps.reject_bogus_obj_ptr, 1, __ATOMIC_RELAXED);
		outputerr("get_map_handle: bogus obj %p in OBJ_MMAP "
			  "pool (type %u, scope %d)\n",
			  obj, type, scope);
		return false;
	}
	return true;
}

/*
 * Ground-truth check before the first deref: validate that the pool
 * slot still names a live obj of the expected type.  objpool_check()
 * reads obj->obj_type -- the authoritative pool-slot state -- and
 * catches the two failure modes get_map_handle would otherwise
 * dereference through: (a) a stomped slot that survived the VA-band
 * guard but points at bytes whose obj_type does not match, and
 * (b) a recycled chunk where the slot pointer is heap-shaped but no
 * longer a struct object of `type`.  Symmetric with the sibling
 * addr_in_local_runtime_map / invalidate_mmap_pool_range walks that
 * gate on the same objpool_check() before touching &obj->map.
 *
 * Replaces an older alloc_track_lookup() gate that was OBJ_LOCAL-only
 * and false-rejected long-lived pool entries whenever they rotated
 * out of the 4096-entry alloc-track ring under arg-buffer churn: a
 * single child accumulated 12k+ rejects on live slots.  alloc_track
 * is an allocation-provenance ring, not a live-object registry, and
 * overloading it as the latter is what produced the flood.
 *
 * The stats.maps.reject_alloc_track_miss[_anon|_file|_testfile]
 * counters retain their historical names for dashboard continuity;
 * they now count objpool_check() rejects (bogus obj_type / VA-band
 * mismatch that survived the earlier obj_ptr_in_user_va_band guard).
 * The reject log is rate-limited to one line per second per child
 * -- counters carry the exact aggregate; the log line names the
 * attributed culprit syscall via log_self_corrupt_culprit(), matching
 * the sibling walks' reject-path convention.
 */
static bool obj_pool_slot_check(struct object *obj, enum objecttype type)
{
	static struct timespec last_warn;
	struct timespec now;
	struct childdata *cc;

	if (objpool_check(obj, type))
		return true;

	__atomic_add_fetch(&shm->stats.maps.reject_alloc_track_miss, 1, __ATOMIC_RELAXED);
	switch (type) {
	case OBJ_MMAP_ANON:
		__atomic_add_fetch(&shm->stats.maps.reject_alloc_track_miss_anon,
				   1, __ATOMIC_RELAXED);
		break;
	case OBJ_MMAP_FILE:
		__atomic_add_fetch(&shm->stats.maps.reject_alloc_track_miss_file,
				   1, __ATOMIC_RELAXED);
		break;
	case OBJ_MMAP_TESTFILE:
		__atomic_add_fetch(&shm->stats.maps.reject_alloc_track_miss_testfile,
				   1, __ATOMIC_RELAXED);
		break;
	default:
		break;
	}

	clock_gettime(CLOCK_MONOTONIC, &now);
	if (now.tv_sec != last_warn.tv_sec) {
		last_warn = now;
		cc = this_child();
		log_self_corrupt_culprit("mm:get_map_handle:objpool",
					 (unsigned long)obj,
					 cc != NULL ? &cc->syscall : NULL);
	}
	return false;
}

/*
 * Even when the obj pointer is sane, the map struct itself
 * may have been stomped on by a stray syscall write, leaving
 * a believable ptr but a wildly wrong size.  Consumers like
 * gen_xattr_name's snprintf, generate_syscall_args, and
 * alloc_iovec then read/write past the real mapping and we
 * SEGV/SIGBUS at fixed-pattern addresses.
 *
 * Legitimate allocations top out at GB(1) (mapping_sizes[8]
 * in maps-initial.c, pick_size in mmap-lifecycle.c).  Cap at
 * GB(4) so the live 1GB tier passes cleanly while ASCII
 * patterns and stomped pointers (which land in the TB+ range)
 * are rejected.  Zero is also bogus — a real mapping always
 * has at least one page.
 */
static bool map_size_in_range(struct object *obj,
			      enum objecttype type,
			      enum obj_scope scope)
{
	if (obj->map.size == 0) {
		/*
		 * Legitimate post-clamp state from mmap_fd:
		 * empty file, fstat failure, or offset past EOF.
		 * mmap_fd now drops these at seed time, but a
		 * pre-clamp pool entry from an earlier startup
		 * may still surface here.  Skip silently.
		 */
		__atomic_add_fetch(&shm->stats.maps.reject_size_zero, 1, __ATOMIC_RELAXED);
		return false;
	}
	if (obj->map.size > GB(4UL)) {
		__atomic_add_fetch(&shm->stats.maps.reject_size_too_large, 1, __ATOMIC_RELAXED);
		outputerr("get_map_handle: bogus map->size %lu for "
			  "obj %p (type %u, scope %d)\n",
			  obj->map.size, obj, type, scope);
		return false;
	}
	return true;
}

/* Pick-cost + per-type pool-chosen
 * accounting.  `i + 1` is the 1-indexed retry count
 * that landed this successful pick; attempts_sum /
 * successes is the realised average attempts-per-pick
 * the 1000-iter budget exists to amortise.  The
 * per-type pool_chosen split lets the dispatch mix be
 * cross-checked against pool occupancy. */
static void account_pool_pick_success(enum objecttype type, int retry_index)
{
	__atomic_add_fetch(&shm->stats.maps.pick_attempts_sum,
			   (unsigned long)(retry_index + 1), __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.maps.pick_successes,
			   1, __ATOMIC_RELAXED);
	switch (type) {
	case OBJ_MMAP_ANON:
		__atomic_add_fetch(&shm->stats.maps.pool_chosen_anon,
				   1, __ATOMIC_RELAXED);
		break;
	case OBJ_MMAP_FILE:
		__atomic_add_fetch(&shm->stats.maps.pool_chosen_file,
				   1, __ATOMIC_RELAXED);
		break;
	case OBJ_MMAP_TESTFILE:
		__atomic_add_fetch(&shm->stats.maps.pool_chosen_testfile,
				   1, __ATOMIC_RELAXED);
		break;
	default:
		break;
	}
}

/*
 * Lazy top-up.  Under sustained ARG_ADDRESS pressure the per-
 * child OBJ_LOCAL ANON pool can drain entries faster than
 * post_mmap refills it (entries leave on every munmap that hits
 * an INITIAL_ANON or CHILD_ANON slot).  Re-cloning the
 * OBJ_GLOBAL ANON snapshot here gives the next draw live
 * entries to pick from instead of the consumer falling through
 * to its NULL/EFAULT path on every ARG_ADDRESS slot.
 *
 * Rate-limited to once per MAPS_LOCAL_REFILL_PERIOD exhaustion
 * events per child so the (re-walk-the-global-pool, strdup
 * every name) cost stays bounded.  FILE/TESTFILE are
 * deliberately not topped up here: their OBJ_GLOBAL sources
 * can also drain (mmap_fd is the only producer for FILE; the
 * testfiles seed runs once at startup for TESTFILE), so the
 * fork-time seed is the right warm-up for those pools.
 */
static void maybe_refill_local_anon_pool(struct childdata *child,
					 enum obj_scope scope)
{
	if (scope == OBJ_LOCAL && child != NULL) {
		if (++child->maps_local_refill_credit >= MAPS_LOCAL_REFILL_PERIOD) {
			child->maps_local_refill_credit = 0;
			clone_global_mmap_pool(OBJ_MMAP_ANON);
		}
	}
}

/*
 * Populate a handle for a randomly-picked entry in the
 * OBJ_MMAP_ANON / OBJ_MMAP_FILE / OBJ_MMAP_TESTFILE pools.  Same
 * pick-and-deref flow as get_map() (heap-range guard, size guard);
 * post-Stage-5 the pools live in private heap so there is no
 * concurrent destroyer racing the consumer's deref of map->ptr /
 * map->size / map->prot.
 */
bool get_map_handle(struct map_handle *h)
{
	struct childdata *child = this_child();
	enum obj_scope scope;
	enum objecttype type = 0;
	/*
	 * Per-child sample counter.  Function-local static so each
	 * fork'd child gets its own copy via copy-on-write; no cross-
	 * child coherence needed and no RNG entropy consumed.
	 */
	static unsigned int pick_sample_ctr;
	unsigned long t0 = 0, t1;
	bool sampled;
	int i;

	if (h == NULL)
		return false;

	h->map = NULL;

	if (child == NULL)
		scope = OBJ_GLOBAL;
	else
		scope = OBJ_LOCAL;

	sampled = ((pick_sample_ctr++ & MAPS_PICK_SAMPLE_MASK) == 0);
	if (sampled)
		t0 = maps_pick_read_cycles();

	for (i = 0; i < 1000; i++) {
		struct object *obj;
		bool all_empty;

		type = pick_mmap_pool_type(child, scope, &all_empty);
		if (all_empty) {
			/*
			 * All three OBJ_LOCAL mmap pools are empty.
			 * Further draws this call cannot succeed; exit
			 * the retry loop early and let the post-loop
			 * lazy refill arm decide whether to top up.
			 */
			break;
		}

		obj = get_random_object(type, scope);
		if (obj == NULL) {
			account_pool_empty_reject(type);
			continue;
		}

		if (!obj_ptr_in_user_va_band(obj, type, scope))
			continue;

		if (!obj_pool_slot_check(obj, type))
			continue;

		if (!map_size_in_range(obj, type, scope))
			continue;

		h->map = &obj->map;
		h->type = type;
		h->scope = scope;

		if (sampled) {
			t1 = maps_pick_read_cycles();
			__atomic_add_fetch(&shm->stats.maps.pick_cycles_sampled_sum,
					   t1 - t0, __ATOMIC_RELAXED);
			__atomic_add_fetch(&shm->stats.maps.pick_cycles_sampled_count,
					   1, __ATOMIC_RELAXED);
		}
		maps_pick_bump_scan_histogram((unsigned int)i);
		account_pool_pick_success(type, i);
		return true;
	}

	if (sampled) {
		t1 = maps_pick_read_cycles();
		__atomic_add_fetch(&shm->stats.maps.pick_cycles_sampled_sum,
				   t1 - t0, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.maps.pick_cycles_sampled_count,
				   1, __ATOMIC_RELAXED);
	}
	maps_pick_bump_scan_histogram((unsigned int)i);

	maybe_refill_local_anon_pool(child, scope);

	__atomic_add_fetch(&shm->stats.maps.pool_draw_exhausted, 1, __ATOMIC_RELAXED);
	return false;
}

/*
 * Post-Stage-5 every pool is private-heap; the handle stays valid for
 * the consumer's lifetime.  The check collapses to a NULL guard so
 * callers that always re-validate before dereferencing still have a
 * cheap canonical entry point and don't need to special-case scope.
 */
bool validate_map_handle(struct map_handle *h)
{
	return h != NULL && h->map != NULL;
}

/*
 * Walk the current child's OBJ_LOCAL OBJ_MMAP_* pools and report
 * whether [addr, addr+len) lies entirely inside a runtime mapping
 * the child created (CHILD_ANON / MMAPED_FILE).  Runtime mmap() results
 * land in the per-child object pool via post_mmap() but are not added
 * to shared_regions[] -- that tracker exists to defend trinity's own
 * bookkeeping from fuzzed kernel writes, not to enumerate every VMA
 * the child legitimately owns.  Without this helper the post-mprotect
 * tracked-shared gate in get_writable_address() drops every runtime
 * mapping as if it were a scribbled slot.
 *
 * INITIAL_ANON entries copied in by init_child_mappings() share their
 * ptr with the OBJ_GLOBAL entry seeded by setup_initial_mappings(),
 * which IS registered with track_shared_region().  range_in_tracked_
 * shared() already accepts those, so we deliberately skip them here
 * to keep the two acceptance paths from masking double-tracking bugs.
 *
 * Overflow defense: a wild write into map->size could fabricate a
 * (ptr, size) pair that wraps past ULONG_MAX, which would otherwise
 * make the containment test vacuously true for any addr.  Reject the
 * slot rather than accepting on wrap.
 */
bool addr_in_local_runtime_map(unsigned long addr, unsigned long len)
{
	static const enum objecttype map_pool_types[3] = {
		OBJ_MMAP_ANON, OBJ_MMAP_FILE, OBJ_MMAP_TESTFILE,
	};
	unsigned int i;

	if (len == 0)
		return false;

	for (i = 0; i < 3; i++) {
		struct objhead *head;
		struct object *obj;
		unsigned int idx;

		head = get_objhead(OBJ_LOCAL, map_pool_types[i]);
		if (head == NULL || head->array == NULL)
			continue;

		for_each_obj(head, obj, idx) {
			struct map *m;
			unsigned long base, end;

			/*
			 * Defence-in-depth against a sibling wild write that
			 * scribbled our childdata->objects[OBJ_MMAP_*] array:
			 * a garbled slot can hold a wild obj pointer, a wild
			 * obj_type tag, or a wild m->ptr/m->size that would
			 * otherwise be dereferenced or arithmetic'd here.
			 * objpool_check() rejects the two cheap fatal cases
			 * (out-of-userspace-VA pointer, wrong obj_type) using
			 * the same bracket the fds/ hot paths use before
			 * dereferencing pool slots.  Bumps the global-obj UAF
			 * stat on the reject path so the incidence is visible
			 * in the periodic dump alongside the other pool
			 * cold-recycle counters.  A reject additionally logs
			 * the just-dispatched syscall's SREC to stderr so the
			 * culprit whose arg-gen produced the wild pointer is
			 * captured in the child bug-log before the SIGSEGV
			 * that the same scribble typically causes elsewhere.
			 */
			if (!objpool_check(obj, map_pool_types[i])) {
				struct childdata *cc = this_child();

				log_self_corrupt_culprit(
					"mm:runtime-map:objpool",
					(unsigned long)obj,
					cc != NULL ? &cc->syscall : NULL);
				continue;
			}

			m = &obj->map;

			if (m->type != CHILD_ANON && m->type != MMAPED_FILE)
				continue;
			if (m->ptr == NULL || m->size == 0)
				continue;

			base = (unsigned long) m->ptr;
			end = base + m->size;
			if (end < base)
				continue;

			if (addr >= base && addr + len <= end &&
			    addr + len >= addr)
				return true;
		}
	}

	return false;
}

/*
 * Return a pointer a previous mmap() that we did, either during startup,
 * or from a fuzz result.  Thin wrapper around get_map_handle() for
 * callers that don't need to re-validate the slot at deref time.
 */
struct map * get_map(void)
{
	struct map_handle h;

	if (!get_map_handle(&h))
		return NULL;
	return h.map;
}

/*
 * Like get_map(), but only return entries whose protection bits include
 * every bit set in required_prot.  Pool entries (mm/maps-initial.c) are
 * created with EVERY combination of PROT_READ / PROT_WRITE / PROT_EXEC /
 * PROT_NONE — including PROT_NONE and write-less mappings — so consumers
 * that touch the region with a specific access pattern (e.g. a dirty-each-
 * page loop, or io_uring opcodes that direct the kernel to read or write
 * the user buffer) MUST filter, otherwise drawing a PROT_READ-only or
 * PROT_NONE entry will SEGV_ACCERR on the first incompatible access.
 *
 * The most common need is PROT_WRITE (the consumer writes to the region);
 * PROT_READ alone is also reasonable for read-only consumers.  Returns
 * NULL if no matching entry is drawn within the same retry budget as
 * get_map().
 */
struct map * get_map_with_prot(int required_prot)
{
	/* Low-three-bit mask index for the per-mask
	 * prot-reject counter array.  The interesting prot bits at
	 * the rejection-sample sites are PROT_READ|WRITE|EXEC;
	 * PROT_SEM and other higher bits fold harmlessly into the
	 * RWX overlap because the rejection signal we're after is
	 * "which RWX combination is paying the rejection-sample
	 * cost", not the full prot space. */
	unsigned int mask_idx = (unsigned int)required_prot & 0x7u;

	for (int i = 0; i < 1000; i++) {
		struct map *m = get_map();

		if (m == NULL)
			return NULL;

		if ((m->prot & required_prot) == required_prot) {
			/* with_prot pick-cost.  Same
			 * shape as the inner get_map_handle()
			 * pair but tracks the outer prot-filter
			 * retry loop.  attempts_sum / successes
			 * compounds the inner pool-pick reject
			 * with the prot-filter reject — the
			 * higher of the two ratios identifies
			 * which side of the loop dominates the
			 * cost a per-prot map index
			 * would amortise. */
			__atomic_add_fetch(&shm->stats.maps.pick_with_prot_attempts_sum,
					   (unsigned long)(i + 1), __ATOMIC_RELAXED);
			__atomic_add_fetch(&shm->stats.maps.pick_with_prot_successes,
					   1, __ATOMIC_RELAXED);
			return m;
		}

		/* Per-required-mask reject attribution. */
		__atomic_add_fetch(&shm->stats.maps.prot_reject_by_mask[mask_idx],
				   1, __ATOMIC_RELAXED);
	}

	return NULL;
}

/*
 * Like get_map_with_prot(), but additionally restricts the draw to the
 * OBJ_MMAP_ANON pool.  Required by consumers that store to the region
 * synchronously (no fault guard) before issuing the syscall under test:
 * a FILE/TESTFILE-backed entry can be prot-RW yet have an un-faultable
 * first page when a sibling syscall (truncate / hole-punch / fallocate
 * range-zero) has left a hole behind a still-RW VMA, and the store then
 * SIGBUSes BUS_ADRERR before the syscall is reached.  Anon-pool entries
 * are zero-fill with no backing file (tracked_size == size), so every
 * page inside [ptr, ptr+size) is always faultable.
 *
 * Same retry budget as get_map_with_prot(); get_map_handle() supplies
 * the alloc-track / bogus-ptr armor on each pick.  Returns NULL if no
 * matching entry is drawn within the budget.
 */
struct map * get_anon_map_with_prot(int required_prot)
{
	for (int i = 0; i < 1000; i++) {
		struct map_handle h;

		if (!get_map_handle(&h))
			return NULL;

		if (h.type != OBJ_MMAP_ANON)
			continue;

		if ((h.map->prot & required_prot) == required_prot)
			return h.map;
	}

	return NULL;
}

