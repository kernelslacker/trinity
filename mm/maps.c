#include <stdbool.h>
#include <sys/mman.h>
#include <asm/mman.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "arch.h"
#include "child.h"
#include "deferred-free.h"
#include "maps.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "utils.h"

#include "kernel/mman.h"
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

static void clone_global_mmap_pool(enum objecttype type);

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
 * Ground-truth check before the first deref: obj pointers
 * for OBJ_LOCAL pools come back through __zmalloc(), which
 * registers them in the alloc-track ring.  A stomped slot
 * can hand back a value that passes the heap-range guard
 * above (8-byte aligned, inside user VA) yet doesn't match
 * any allocation we ever made -- the first obj->map.size
 * read then returns garbage and downstream consumers
 * (gen_xattr_name, generate_syscall_args, alloc_iovec)
 * walk into unmapped memory.  Skip the slot when the obj
 * isn't in the live malloc-result set.  This guard is gated
 * on OBJ_LOCAL: those live pointers belong to this child's
 * own tracked malloc set.  OBJ_GLOBAL objs are the parent's
 * pre-fork allocations inherited via COW (or cloned into the
 * child), so they aren't in this child's alloc-track ring and
 * need a separate validity rule.
 */
static bool obj_alloc_track_check(struct object *obj,
				  enum objecttype type,
				  enum obj_scope scope)
{
	if (scope == OBJ_LOCAL && !alloc_track_lookup(obj)) {
		__atomic_add_fetch(&shm->stats.maps.reject_alloc_track_miss, 1, __ATOMIC_RELAXED);
		/*
		 * Per-type sub-attribution of the alloc-track-miss
		 * reject.  Aggregate above stays bumped for historical
		 * comparability; these tell which OBJ_MMAP_* pool's
		 * slots are the dominant false-rejected source so a
		 * 153M-class miss spike can be attributed to one pool
		 * instead of pooled across all three.  `type` is the
		 * pool the draw landed on this iteration and is the
		 * only contextual axis available at this site without
		 * new plumbing; `scope` is gated to OBJ_LOCAL by the
		 * if-condition above so splitting on it would be inert.
		 */
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
		outputerr("get_map_handle: obj %p not in alloc_track "
			  "(stomped slot, type %u, scope %d)\n",
			  obj, type, scope);
		return false;
	}
	return true;
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

		if (!obj_alloc_track_check(obj, type, scope))
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

/*
 * Destructor for OBJ_LOCAL mmap entries (init_child_mappings copies and
 * the children's own runtime mmaps).  The obj struct and the name string
 * both live on the calling process's private heap, so we use the regular
 * libc free path.
 */
void map_destructor(struct object *obj)
{
	struct map *map;
	size_t extent;

	map = &obj->map;
	/*
	 * clone_global_mmap_pool() propagates tracked_size onto OBJ_LOCAL
	 * FILE/TESTFILE entries cloned from a clamped mmap_fd() source, so
	 * the local-pool destructor sees the same map->size < VMA extent
	 * asymmetry as map_destructor_shared().  Release both the
	 * shared_regions[] slot and the VMA against the pre-clamp extent
	 * so the two halves stay in lock step; legacy callers that never
	 * clamped leave tracked_size == 0 and fall back to map->size.
	 */
	extent = map->tracked_size ? map->tracked_size : map->size;
	/*
	 * Range-validate map->ptr and cap extent before untrack+munmap.
	 * The alloc_track armor at get_map_handle (maps.c:103) only
	 * validates the obj pointer; an in-place scribble of the map body
	 * via a fuzzed value-result syscall whose user buffer aliases a
	 * real, pool-resident obj can leave .ptr / .tracked_size wild while
	 * the obj-pointer gate still vouches for the slot.  munmap() on a
	 * wild (ptr, len) pair can collateral-unmap trinity's own
	 * bookkeeping (the armored deferred-free ring, shm regions);
	 * untrack_shared_region() with the same pair would also corrupt
	 * shared_regions[] bookkeeping by chance-matching an unrelated
	 * slot.  Mirror the existing get_map_handle guards: user VA band
	 * [0x10000, 0x800000000000) (maps.c:78-79) and the GB(4) cap on
	 * size (maps.c:137).  Skip the whole untrack+munmap pair on miss
	 * -- leaking the VA for the rest of the run is strictly safer
	 * than a wild unmap, and the name-free gate below still runs so
	 * the proven-ours name buffer is recycled.
	 */
	if (map->ptr != NULL &&
	    (uintptr_t)map->ptr >= 0x10000UL &&
	    (uintptr_t)map->ptr < 0x800000000000UL &&
	    extent != 0 && extent <= GB(4UL)) {
		untrack_shared_region((unsigned long)map->ptr, extent);
		munmap(map->ptr, extent);
	}
	/*
	 * Free the name via tracked_free_now(), not a bare free().  A bare
	 * free() releases the buffer to glibc but leaves its pointer in
	 * alloc_track[] -- the alloc_track_lookup() gate only tests
	 * membership, it does not consume the entry.  A later
	 * alloc_track_consume() (the deferred-free ring drain, or after
	 * glibc reuses the freed chunk for a new tracked allocation) then
	 * still returns true and free()s it a second time -- the ASAN
	 * bad-free observed at deferred-free.c:697.  tracked_free_now()
	 * consumes the alloc_track entry as it frees, skips ring-owned
	 * pointers so the ring's drain stays authoritative, and still
	 * leaks an unproven (scribbled) name because the consume gate
	 * rejects any pointer __zmalloc never produced -- "release what we
	 * own, leak the unproven".
	 */
	tracked_free_now(map->name);
	map->name = NULL;
}

/*
 * Destructor for OBJ_GLOBAL mmap entries created via mmap_fd() and
 * setup_initial_mappings().  The obj struct itself is freed by
 * release_obj() (which zeroes the chunk and routes it through
 * deferred-free); we only need to release the name string and
 * unmap the actual mapping here.
 */
void map_destructor_shared(struct object *obj)
{
	struct map *map;
	size_t extent;

	map = &obj->map;
	/*
	 * Both untrack_shared_region() and munmap() need the full VMA extent,
	 * not the consumer-walkable extent in map->size.
	 *
	 * untrack_shared_region() matches the (addr, len) pair recorded at
	 * track_shared_region() time exactly; a shorter len would leave the
	 * shared_regions[] slot in place and the bitmap bits past `len' would
	 * outlive the munmap below, blocking any subsequent VA recycle into
	 * legitimate fuzzed mm-syscalls.  munmap() with a shorter len under-
	 * unmaps the VMA: the past-clamp tail pages stay mapped until process
	 * exit, leaking address space and keeping the file's page-cache pin
	 * alive for entries the destructor is supposed to be releasing.
	 *
	 * mmap_fd() may clamp map->size down to the fstat-backed extent after
	 * the kernel mapped a wider VMA; the pre-clamp length lives in
	 * map->tracked_size for exactly these two calls.  Legacy callsites
	 * that pre-date the field leave tracked_size == 0; fall back to
	 * map->size for those (they set size to the real VMA extent because
	 * they never clamped).
	 */
	extent = map->tracked_size ? map->tracked_size : map->size;
	/*
	 * Same destructor-munmap gate as map_destructor() above: range-
	 * validate map->ptr and cap extent before untrack+munmap so an
	 * in-place .ptr / .tracked_size scribble cannot drive a wild
	 * unmap of trinity's own bookkeeping.  See map_destructor() for
	 * the full rationale.
	 */
	if (map->ptr != NULL &&
	    (uintptr_t)map->ptr >= 0x10000UL &&
	    (uintptr_t)map->ptr < 0x800000000000UL &&
	    extent != 0 && extent <= GB(4UL)) {
		untrack_shared_region((unsigned long)map->ptr, extent);
		munmap(map->ptr, extent);
	}
	/*
	 * Gate the name free on shared-heap residency BEFORE strlen
	 * touches the bytes.  The local destructor uses alloc_track_lookup
	 * (libc heap); this variant's names live in the shared str heap
	 * (alloc_shared_pool, registered via shared_regions[]), so
	 * range_in_tracked_shared() is the matching ownership check.
	 * Without the pre-strlen gate, a scribbled .name pointing outside
	 * any tracked region drives strlen into unmapped memory before the
	 * free_shared_str call is reached -- a wild read on the way to a
	 * bad free.  Skip-and-leak on miss, mirror of map_destructor's
	 * alloc_track_lookup gate.
	 */
	if (map->name != NULL &&
	    range_in_tracked_shared((unsigned long)map->name, 1)) {
		/*
		 * INITIAL_ANON names are alloc_shared_str(80) fixed-size
		 * slots, not alloc_shared_strdup(name).  Releasing them with
		 * strlen+1 lands in a smaller free-bucket than the allocator
		 * carved, stranding the 80-byte slot in the shared str heap.
		 * Match the alloc with a literal 80; MMAPED_FILE keeps the
		 * strlen+1 pairing its alloc_shared_strdup expects.
		 */
		if (map->type == INITIAL_ANON)
			free_shared_str(map->name, 80);
		else
			free_shared_str(map->name, strlen(map->name) + 1);
	}
	map->name = NULL;
}

void map_dump(struct object *obj, enum obj_scope scope)
{
	struct map *m;
	char buf[32];

	m = &obj->map;

	sizeunit(m->size, buf, sizeof(buf));
	output(2, " start: %p size:%s  flags:%s%s  name: %s scope:%d\n",
		m->ptr, buf,
		(m->flags & MAP_SHARED) ? "shared" : "private",
		(m->flags & MAP_HUGETLB) ? ",hugetlb" : "",
		m->name, scope);
}

/*
 * Seed an OBJ_LOCAL OBJ_MMAP_* pool from the matching OBJ_GLOBAL
 * snapshot.  Used for the FILE / TESTFILE pools at fork; ANON has
 * its own open-coded loop because it hardcodes INITIAL_ANON on the
 * cloned entry (every ANON source is INITIAL_ANON anyway, but the
 * explicit assignment documents the post-fork lifecycle expected
 * by mprotect/mremap/munmap).  This helper instead propagates the
 * source map type so MMAPED_FILE entries stay tagged as such.
 */
static void clone_global_mmap_pool(enum objecttype type)
{
	struct objhead *globalhead, *localhead;
	struct object *globalobj, *localobj;
	unsigned int idx, lidx;

	globalhead = get_objhead(OBJ_GLOBAL, type);
	if (globalhead == NULL || globalhead->array == NULL)
		return;

	/*
	 * localhead may be NULL on the very first call before
	 * init_child_mappings() ran; treat that as "nothing to dedup
	 * against" and append every entry.
	 */
	localhead = get_objhead(OBJ_LOCAL, type);

	for_each_obj(globalhead, globalobj, idx) {
		struct map *m = &globalobj->map;
		struct object *newobj;
		bool dup = false;

		if (m->name == NULL) {
			outputerr("clone_global_mmap_pool: skipping global map with NULL name (type %u)\n",
				  type);
			continue;
		}

		/*
		 * Dedup by ptr against the local head.  Global ANON ptrs
		 * are stable (set once at setup_initial_mappings, never
		 * replaced) and child-added post_mmap entries return
		 * unique mmap'd ptrs that cannot collide with a global
		 * slot, so a ptr match means we have already cloned this
		 * global entry on a prior refill.  Without this guard
		 * each refill appends N copies of every global entry,
		 * bloating per-child memory (leaked strdup'd names) and
		 * skewing future uniform draws.
		 */
		if (localhead != NULL && localhead->array != NULL) {
			for_each_obj(localhead, localobj, lidx) {
				if (localobj->map.ptr == m->ptr) {
					dup = true;
					/* Refresh the local obj in alloc_track[] so the validator
					 * LRU lookup at get_map_handle (mm/maps.c:103) stays warm
					 * even when dedup skips a fresh __zmalloc_tracked.  Without
					 * this, dedup starves alloc_track and pool entries rotate
					 * out under churn (the 256->4096 alloc_track widen was outpaced 100x
					 * at full throughput). */
					alloc_track_refresh(localobj);
					break;
				}
			}
		}
		if (dup)
			continue;

		newobj = alloc_object();
		newobj->map.ptr = m->ptr;
		newobj->map.name = strdup(m->name);
		if (!newobj->map.name) {
			tracked_free_now(newobj);
			continue;
		}
		newobj->map.size = m->size;
		newobj->map.tracked_size = m->tracked_size;
		newobj->map.prot = m->prot;
		newobj->map.flags = m->flags;
		newobj->map.fd = m->fd;
		newobj->map.type = m->type;
		add_object(newobj, OBJ_LOCAL, type);
	}
}

/*
 * Cap each child's LOCAL mmap pools so the otherwise-dormant prune path
 * (prune_objects -> __prune_objects -> map_destructor -> munmap) runs.
 * With max_entries left at 0 the pool never prunes: every successful
 * fuzzed mmap()/memfd map adds an OBJ_LOCAL entry that is not reclaimed
 * until the child exits, so a long-lived child (canary / D-state-wedged)
 * pins gigabytes of resident shmem and OOMs a small box.  64 matches the
 * self-limit mmap_lifecycle already enforces (MAX_LIFECYCLE_MAPS) and
 * keeps plenty of pool diversity for mm coverage.  GLOBAL pools are
 * separately hard-capped at OBJ_GLOBAL_MAX; this is the missing LOCAL cap.
 */
#define MMAP_LOCAL_MAX_ENTRIES 64U

/*
 * Set up a childs local mapping list.
 * A child inherits the initial mappings, and will add to them
 * when it successfully completes mmap() calls.
 */
void init_child_mappings(void)
{
	struct objhead *head, *globalhead;
	struct object *globalobj;
	unsigned int idx;

	/*
	 * init_object_lists(OBJ_LOCAL, child) copies head->destroy from
	 * the matching OBJ_GLOBAL head into every OBJ_LOCAL head.  The
	 * OBJ_GLOBAL OBJ_MMAP_* heads are wired to map_destructor_shared
	 * (setup_initial_mappings for ANON, mmap_fd for FILE/TESTFILE),
	 * which calls free_shared_str() -- the shared-heap allocator --
	 * on map->name.  But OBJ_LOCAL entries created by post_mmap and
	 * by the global-pool clone in this routine allocate map->name
	 * with libc strdup(), so the inherited destructor would feed a
	 * libc-malloc'd pointer to free_shared_str() and corrupt the
	 * shared-heap metadata for every other child.
	 *
	 * Override the inherited destructor on ALL three local mmap
	 * pools to the libc-allocator destructor.  The ANON path was
	 * the only one already covered; FILE and TESTFILE were latent
	 * until the post_munmap pool-type fix landed and started
	 * routing those entries to destroy_object() with their real
	 * head.  Both must land together: fixing one without the other
	 * turns a latent bug into a live crash class.
	 */
	head = get_objhead(OBJ_LOCAL, OBJ_MMAP_ANON);
	if (head == NULL)
		return;
	head->destroy = &map_destructor;
	head->dump = &map_dump;
	head->max_entries = MMAP_LOCAL_MAX_ENTRIES;

	head = get_objhead(OBJ_LOCAL, OBJ_MMAP_FILE);
	if (head != NULL) {
		head->destroy = &map_destructor;
		head->dump = &map_dump;
		head->max_entries = MMAP_LOCAL_MAX_ENTRIES;
	}

	head = get_objhead(OBJ_LOCAL, OBJ_MMAP_TESTFILE);
	if (head != NULL) {
		head->destroy = &map_destructor;
		head->dump = &map_dump;
		head->max_entries = MMAP_LOCAL_MAX_ENTRIES;
	}

	globalhead = get_objhead(OBJ_GLOBAL, OBJ_MMAP_ANON);
	if (globalhead == NULL || globalhead->array == NULL)
		return;

	/* Copy the initial mapping list to the child.
	 * Note we're only copying pointers here, the actual mmaps
	 * will be faulted into the child when they get accessed.
	 *
	 * Skip entries whose name pointer is bogus.  See child #9 spawn
	 * crash where m->name had been overwritten with 0x610000.  The
	 * iteration bound is provided by for_each_obj (array_capacity);
	 * no additional cap is needed.
	 */
	for_each_obj(globalhead, globalobj, idx) {
		struct map *m = &globalobj->map;
		struct object *newobj;

		if (m->name == NULL) {
			outputerr("init_child_mappings: skipping global map with NULL name\n");
			continue;
		}

		newobj = alloc_object();
		newobj->map.ptr = m->ptr;
		newobj->map.name = strdup(m->name);
		if (!newobj->map.name) {
			tracked_free_now(newobj);
			continue;
		}
		newobj->map.size = m->size;
		newobj->map.tracked_size = m->tracked_size;
		newobj->map.prot = m->prot;
		newobj->map.flags = m->flags;
		newobj->map.fd = m->fd;
		/* We leave type as 'INITIAL' until we change the mapping
		 * by mprotect/mremap/munmap etc..
		 */
		newobj->map.type = INITIAL_ANON;
		add_object(newobj, OBJ_LOCAL, OBJ_MMAP_ANON);
	}

	/*
	 * Seed the OBJ_LOCAL FILE and TESTFILE pools from their
	 * OBJ_GLOBAL snapshots too.  get_map_handle() picks the sub-pool
	 * uniformly from {ANON, FILE, TESTFILE}; without these clones
	 * two thirds of OBJ_LOCAL draws return NULL until lazy mmap
	 * shapes happen to add entries, which only the 1/8 file-fd path
	 * does for FILE and nothing does for TESTFILE.  Propagate the
	 * source m->type (MMAPED_FILE for both pools today) rather than
	 * forcing INITIAL_ANON so consumers can tell file mappings apart.
	 */
	clone_global_mmap_pool(OBJ_MMAP_FILE);
	clone_global_mmap_pool(OBJ_MMAP_TESTFILE);
}

/* used in several sanitise_* functions. */
struct map * common_set_mmap_ptr_len(enum objecttype *out_type)
{
	struct syscallrecord *rec;
	struct map *map;
	struct childdata *child = this_child();

	if (out_type != NULL)
		*out_type = OBJ_NONE;

	rec = &child->syscall;
	map = (struct map *) rec->a1;
	if (map == NULL) {
		rec->a1 = 0;
		rec->a2 = 0;
		return NULL;
	}

	/*
	 * ARG_MMAP plumbed a struct map * into rec->a1 at args-generation
	 * time, but a sibling kernel-write to childdata.syscall.a1 can
	 * replace it with a fuzzed value before we get here.  Validate the
	 * shape before the map->ptr / map->size derefs below; an unmapped
	 * or non-canonical pointer would SEGV the consumer (mincore,
	 * mremap, madvise, mlock, munlock, mbind, getrandom, ...).  Mirror
	 * the failure mode of the NULL path so existing callers' NULL
	 * short-circuits handle it cleanly.
	 */
	if (looks_like_corrupted_ptr(rec, map)) {
		outputerr("common_set_mmap_ptr_len: rejected suspicious map=%p (pid-scribbled?)\n",
			  map);
		rec->a1 = 0;
		rec->a2 = 0;
		return NULL;
	}

	rec->a1 = (unsigned long) map->ptr;
	if (map->size == 0) {
		rec->a2 = 0;
	} else {
		rec->a2 = rnd_modulo_u64(map->size);
		rec->a2 &= PAGE_MASK;
	}

	/*
	 * Resolve which OBJ_LOCAL OBJ_MMAP_* pool this obj actually lives
	 * in.  destroy_object() in post_munmap's WHOLE branch needs the
	 * matching head to satisfy its head->array[idx] == obj invariant
	 * -- a hard-coded OBJ_MMAP_ANON destroys nothing when the entry
	 * came from FILE/TESTFILE, leaving an obj that points at unmapped
	 * memory in the pool for the next consumer to walk into.
	 *
	 * obj->obj_type is stamped by add_object() and would be a faster
	 * read, but a wild rec->a1 that passes looks_like_corrupted_ptr
	 * could still point at the embedded map field of a non-mmap obj
	 * whose stamped tag would then mislead us.  Walking the three
	 * mmap pools and matching the obj pointer is the ground-truth
	 * check: a no-match leaves *out_type at OBJ_NONE so the caller
	 * declines to destroy.
	 */
	if (out_type != NULL) {
		struct object *want = container_of(map, struct object, map);
		static const enum objecttype map_pool_types[3] = {
			OBJ_MMAP_ANON, OBJ_MMAP_FILE, OBJ_MMAP_TESTFILE,
		};
		unsigned int i;
		/* Cumulative objects visited across the
		 * three-pool walk this call.  Bumped per-iteration
		 * inside for_each_obj, accumulated locally so the
		 * shared counter pays exactly one RELAXED add per
		 * call instead of one per object visited. */
		unsigned long scanned = 0;

		for (i = 0; i < 3; i++) {
			struct objhead *head;
			struct object *obj;
			unsigned int idx;

			head = get_objhead(OBJ_LOCAL, map_pool_types[i]);
			if (head == NULL || head->array == NULL)
				continue;

			for_each_obj(head, obj, idx) {
				scanned++;
				if (obj == want) {
					*out_type = map_pool_types[i];
					goto type_resolved;
				}
			}
		}
type_resolved:
		/* Bump even on a miss: the walk still cost the
		 * objects it visited, and the miss-rate (1 - hits /
		 * calls) is itself a signal that the slot was
		 * scribbled / pre-clamped / from a non-MMAP pool. */
		__atomic_add_fetch(&shm->stats.maps.type_resolution_calls,
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.maps.type_resolution_scan_length_sum,
				   scanned, __ATOMIC_RELAXED);
		if (*out_type != OBJ_NONE)
			__atomic_add_fetch(&shm->stats.maps.type_resolution_hits,
					   1, __ATOMIC_RELAXED);
	}

	return map;
}

/*
 * Routine to perform various kinds of write operations to a mapping
 * that we created.
 */
void dirty_mapping(struct map *map)
{
	switch (map->prot) {
	case PROT_WRITE:
	case PROT_WRITE|PROT_READ:
	case PROT_WRITE|PROT_EXEC:
	case PROT_WRITE|PROT_READ|PROT_EXEC:
		random_map_writefn(map);
		break;
	case PROT_READ:
	case PROT_READ|PROT_EXEC:
	case PROT_EXEC:
		random_map_readfn(map);
		break;
	case PROT_SEM:
	case PROT_NONE:
	default:
		break;
	}
}

/*
 * Pick a random mapping, and perform some r/w op on it.
 * Called from child on child init, and also periodically
 * from periodic_work()
 */
void dirty_random_mapping(void)
{
	struct map_handle h;
	struct map local;

	if (!get_map_handle(&h))
		return;

	/*
	 * Cheap defense-in-depth NULL re-check right before the deref-
	 * heavy dirty_mapping path (it reads map->prot to dispatch and
	 * then map->ptr / map->size inside random_map_writefn /
	 * random_map_readfn).  Pools are per-child private heap, so there
	 * is no concurrent destroyer to race with; this only guards
	 * against the handle being clobbered across the call gap above.
	 * It is a plain NULL check -- no counters are bumped here.
	 */
	if (!validate_map_handle(&h))
		return;

	/*
	 * The mmap_fd post-mmap fstat clamp pins obj->map.size to the file's
	 * backed extent at allocation time, but a sibling syscall can
	 * ftruncate() the underlying fd down between then and now.  Walking
	 * the stale stored size SIGBUSes BUS_ADRERR on the first page past
	 * the new EOF.
	 *
	 * Snapshot the map into a stack-local, re-fstat the fd, and clamp
	 * a local-effective walk extent using the same min / page-aligned
	 * down arithmetic as the mmap_fd clamp.  obj->map.size itself is
	 * left untouched -- other consumers reuse the stored value and a
	 * different walker may race with us; mutating it would leak the
	 * narrowed view to anyone holding the same handle.
	 *
	 * fstat failure (EBADF after a sibling close, etc.) is treated as
	 * "no walkable extent" and the dirty walk is dropped entirely
	 * rather than falling back to the stale stored size.  Anonymous
	 * mappings (INITIAL_ANON, CHILD_ANON) carry no underlying file
	 * extent and pass through unchanged.
	 */
	local = *h.map;

	if (local.type == MMAPED_FILE && local.fd >= 0) {
		struct stat st;

		if (fstat(local.fd, &st) != 0)
			return;
		if (st.st_size == 0)
			return;
		if ((unsigned long) st.st_size < local.size)
			local.size = (unsigned long) st.st_size & PAGE_MASK;
	}

	if (local.size == 0)
		return;

	dirty_mapping(&local);
}

/*
 * Set up a mmap object for an fd we already opened.
 */
void mmap_fd(int fd, const char *name, size_t len, int prot, enum obj_scope scope, enum objecttype type)
{
	struct objhead *head;
	struct object *obj;
	off_t offset;
	int retries = 0;

	/*
	 * Create an MMAP of the same fd.  OBJ_GLOBAL entries are added to
	 * shm-visible lists that children walk, so the obj struct AND the
	 * name string MUST live in shared memory — otherwise children
	 * dereference parent-private pointers and SEGV in libc string
	 * functions when they read the name (the bug class the rest of
	 * the OBJ_GLOBAL sweep closed).
	 */
	if (scope == OBJ_GLOBAL) {
		obj = alloc_object();
		if (obj == NULL)
			return;
		obj->map.name = alloc_shared_strdup(name);
		if (obj->map.name == NULL) {
			deferred_free_enqueue(obj);
			return;
		}
	} else {
		obj = alloc_object();
		obj->map.name = strdup(name);
		if (!obj->map.name) {
			deferred_free_enqueue(obj);
			return;
		}
	}
	obj->map.size = len;

retry_mmap:
	if (len == 0) {
		offset = 0;
		obj->map.size = page_size;
	} else
		offset = (obj->map.size > 0 ? rnd_modulo_u64(obj->map.size) : 0) & PAGE_MASK;

	obj->map.prot = prot;
	obj->map.fd = fd;
	obj->map.type = MMAPED_FILE;
	/*
	 * Capture the flags word into a local before mmap() so the actual
	 * flags used for this mapping are stored on the obj.  Calling
	 * get_rand_mmap_flags() inline as the mmap() arg threw the bits
	 * away, leaving obj->map.flags at zero for every entry seeded
	 * through this path -- map_dump() and any flag-aware consumer
	 * then saw shared / hugetlb mappings as plain private ones.
	 * Mirrors the alloc_zero_map() pattern in mm/maps-initial.c. */
	{
		int mmap_flags = (int) get_rand_mmap_flags();

		obj->map.flags = mmap_flags;
		obj->map.ptr = mmap(NULL, obj->map.size, prot, mmap_flags,
				    fd, offset);
	}
	if (obj->map.ptr == MAP_FAILED) {
		retries++;
		if (retries == 100) {
			if (scope == OBJ_GLOBAL) {
				free_shared_str(obj->map.name,
						strlen(obj->map.name) + 1);
				obj->map.name = NULL;
				deferred_free_enqueue(obj);
			} else {
				free(obj->map.name);
				obj->map.name = NULL;
				deferred_free_enqueue(obj);
			}
			obj = NULL;
			return;
		} else
			goto retry_mmap;
	}

	/*
	 * obj->map.size currently records the length passed to mmap():
	 * for len > 0 the caller-supplied length, for len == 0 a forced
	 * page_size used only to give the obj a non-NULL ptr for type
	 * tracking.  Neither value is bounded against the chosen fd's
	 * actual backing extent.
	 *
	 * For len > 0 the offset above is a random page-aligned multiple
	 * in [0, len); the kernel happily creates a VMA covering pages
	 * past EOF when offset + len > st_size, but accessing those pages
	 * SIGBUSes with BUS_ADRERR.  For len == 0 we have no walkable
	 * extent at all -- the one-page mmap exists only as a handle.
	 *
	 * dirty_random_mapping (and other consumers that walk obj->map.size
	 * bytes from obj->map.ptr) burn the child on the first unbacked
	 * page, so clamp the recorded size to the in-bounds extent.  fstat
	 * failure or an empty regular file leaves no walkable pages -- gate
	 * downstream walkers off with size 0.  mmap_fd is reached only from
	 * regular-file paths, so st_size == 0 means a genuinely empty file
	 * (the special-fd carve-out used by post_mmap does not apply here).
	 */
	if (len == 0) {
		obj->map.size = 0;
	} else {
		struct stat st;

		if (fstat(fd, &st) != 0 || st.st_size == 0) {
			obj->map.size = 0;
		} else {
			off_t backed = (off_t) st.st_size - (off_t) offset;

			if (backed <= 0)
				obj->map.size = 0;
			else if ((unsigned long) backed < obj->map.size)
				obj->map.size = (unsigned long) backed & PAGE_MASK;
		}
	}

	/*
	 * A zero-clamped entry has no walkable extent and would only be
	 * rejected by every get_map_handle() consumer.  Drop it at the
	 * seed site instead of polluting the pool.
	 */
	if (obj->map.size == 0) {
		munmap(obj->map.ptr, len > 0 ? len : page_size);
		if (scope == OBJ_GLOBAL) {
			free_shared_str(obj->map.name,
					strlen(obj->map.name) + 1);
			obj->map.name = NULL;
			deferred_free_enqueue(obj);
		} else {
			free(obj->map.name);
			obj->map.name = NULL;
			deferred_free_enqueue(obj);
		}
		return;
	}

	/*
	 * Record the actual VMA extent the kernel mapped (len), not the
	 * fstat-clamped consumer-walkable extent in obj->map.size.  The clamp
	 * above shrinks map->size to the in-bounds backed region so dirty
	 * walkers stay inside real backing, but the kernel's VMA still covers
	 * the full `len' the mmap() call requested.  Defensive bookkeeping
	 * needs to know about the VMA extent: fuzzed kernel writes that land
	 * anywhere inside the VMA (past the backed tail included, where they
	 * SIGBUS rather than corrupt) must be recognised by
	 * range_overlaps_shared(), and the matching untrack at destroy time
	 * must release the same extent or the bitmap bits the tail claimed
	 * survive past munmap.  Length parity between this track call and the
	 * untrack in map_destructor_shared is enforced by both reading from
	 * obj->map.tracked_size.
	 */
	obj->map.tracked_size = len;
	track_shared_region((unsigned long)obj->map.ptr, len);

	head = get_objhead(scope, type);
	if (head != NULL) {
		head->dump = &map_dump;
		if (scope == OBJ_GLOBAL) {
			head->destroy = &map_destructor_shared;
		}
	}

	add_object(obj, scope, type);
	return;
}

/*
 * Read /proc/self/maps and verify a VMA invariant about [addr, addr+len).
 *
 * expect_present=true: at least one entry overlapping the range must exist
 * with rwx prot bits matching expected_prot.
 * expect_present=false: no entry may overlap the range at all.
 *
 * Returns true when the invariant holds, false when it is violated.
 * Returns true on I/O errors to avoid false positives.
 */
bool proc_maps_check(unsigned long addr, unsigned long len,
		     int expected_prot, bool expect_present)
{
	FILE *f;
	char line[256];
	unsigned long start, end;
	char perms[5];
	bool found = false;

	f = fopen("/proc/self/maps", "r");
	if (!f)
		return true;

	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) != 3)
			continue;
		if (end <= addr || start >= addr + len)
			continue;

		if (expect_present) {
			int map_prot = 0;

			if (perms[0] == 'r')
				map_prot |= PROT_READ;
			if (perms[1] == 'w')
				map_prot |= PROT_WRITE;
			if (perms[2] == 'x')
				map_prot |= PROT_EXEC;

			if ((map_prot & (PROT_READ | PROT_WRITE | PROT_EXEC)) ==
			    (expected_prot & (PROT_READ | PROT_WRITE | PROT_EXEC))) {
				found = true;
				break;
			}
		} else {
			found = true;
			break;
		}
	}

	fclose(f);
	return expect_present ? found : !found;
}

/*
 * Soft-invalidate every entry in one OBJ_LOCAL OBJ_MMAP_* pool whose
 * mapped extent overlaps [addr, addr+end_excl).  Clears map->prot so
 * get_map_with_prot() will skip the entry on subsequent picks and
 * drops the known_rw skip-cache bit for the same reason post_munmap's
 * sub-range branch documents -- letting either survive across a
 * hole-punch hands a writer a pointer into a SIGBUS-on-access region.
 * Returns the number of entries touched.  Pool iteration is a plain
 * forward walk: this is a soft invalidate, no swap-with-last happens,
 * so num_entries is stable for the duration.
 */
static unsigned int
invalidate_mmap_pool_range(enum objecttype type,
			   unsigned long addr, unsigned long end_excl)
{
	struct objhead *head;
	struct object *obj;
	unsigned int idx, touched = 0;

	head = get_objhead(OBJ_LOCAL, type);
	if (head == NULL || head->array == NULL)
		return 0;

	for_each_obj(head, obj, idx) {
		struct map *m;
		unsigned long m_start, m_end;

		/*
		 * Same sibling-scribble defence as addr_in_local_runtime_map:
		 * reject wild obj / obj_type before touching &obj->map or
		 * m->ptr / m->size.  Bad-slot stat bump happens inside;
		 * log_self_corrupt_culprit() on the reject path attributes
		 * the wild obj to the syscall that just ran.
		 */
		if (!objpool_check(obj, type)) {
			struct childdata *cc = this_child();

			log_self_corrupt_culprit(
				"mm:invalidate-range:objpool",
				(unsigned long)obj,
				cc != NULL ? &cc->syscall : NULL);
			continue;
		}

		m = &obj->map;

		if (m->ptr == NULL || m->size == 0)
			continue;

		m_start = (unsigned long) m->ptr;
		m_end = m_start + m->size;

		if (m_end <= addr || m_start >= end_excl)
			continue;

		m->prot = 0;
		m->known_rw = false;
		touched++;
	}

	return touched;
}

unsigned int invalidate_obj_mmap_in_range(unsigned long addr, unsigned long len)
{
	static const enum objecttype map_pool_types[3] = {
		OBJ_MMAP_ANON, OBJ_MMAP_FILE, OBJ_MMAP_TESTFILE,
	};
	unsigned long end_excl;
	unsigned int i, touched = 0;

	if (len == 0)
		return 0;

	/*
	 * Wraparound guard: a stomped addr/len whose sum overflows would
	 * make every interval test trivially true and blanket-clear the
	 * pool.  Reject silently; the caller already snapshotted from a
	 * cookie-validated post_state, so a wraparound here means the
	 * caller's own snapshot was junk.
	 */
	end_excl = addr + len;
	if (end_excl < addr)
		return 0;

	for (i = 0; i < 3; i++)
		touched += invalidate_mmap_pool_range(map_pool_types[i],
						      addr, end_excl);

	return touched;
}

unsigned int invalidate_obj_mmap_by_fd(int fd)
{
	static const enum objecttype map_pool_types[2] = {
		OBJ_MMAP_FILE, OBJ_MMAP_TESTFILE,
	};
	unsigned int i, touched = 0;

	if (fd < 0)
		return 0;

	for (i = 0; i < 2; i++) {
		struct objhead *head;
		struct object *obj;
		unsigned int idx;

		head = get_objhead(OBJ_LOCAL, map_pool_types[i]);
		if (head == NULL || head->array == NULL)
			continue;

		for_each_obj(head, obj, idx) {
			struct map *m;

			/*
			 * Same sibling-scribble defence as
			 * addr_in_local_runtime_map: reject wild obj /
			 * obj_type before touching &obj->map or m->fd.
			 * Bad-slot stat bump happens inside; the culprit
			 * logger attributes the reject to the just-run
			 * syscall so the wild-write producer is named in
			 * the child bug-log.
			 */
			if (!objpool_check(obj, map_pool_types[i])) {
				struct childdata *cc = this_child();

				log_self_corrupt_culprit(
					"mm:invalidate-fd:objpool",
					(unsigned long)obj,
					cc != NULL ? &cc->syscall : NULL);
				continue;
			}

			m = &obj->map;

			if (m->fd != fd)
				continue;

			m->prot = 0;
			m->known_rw = false;
			touched++;
		}
	}

	return touched;
}
