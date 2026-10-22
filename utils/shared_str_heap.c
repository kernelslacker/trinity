/*
 * Shared-string heap allocator: a size-classed slab in one MAP_SHARED
 * region, so a string pointer reachable from an OBJ_GLOBAL object stays
 * walkable in every forked child (the obj struct is private; only its
 * payload lives here).  Freed slots up to 1024 B recycle through the
 * freelists in shared_freelist.c, larger ones bump-and-leak, and
 * free_shared_str() trusts only the out-of-band slot_state record.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "pids.h"
#include "shared_freelist.h"
#include "shared_str_heap.h"
#include "trinity.h"
#include "utils-mem.h"

/*
 * 1 MiB.  Slots up to 1024 B are returned to the size-bucketed
 * freelists on free, so steady-state occupancy tracks the live
 * working set under OBJ_LOCAL churn (post_*_fd callbacks plus
 * per-child fanout).  Above-bucket frees bump-and-leak -- they lose
 * a slot apiece -- and the 1 MiB ceiling sizes the headroom that
 * path needs over a sustained fuzz run.
 */
#define SHARED_STR_HEAP_SIZE (1U * 1024U * 1024U)

/*
 * Freelist tokens are (offset+1) and must fit in the low 32 bits of
 * the head word; offset 0 is legal, so the token can be up to
 * SHARED_STR_HEAP_SIZE.  Bounding at UINT32_MAX (not 1U << 32 -- that
 * shift is a width-of-type UB) keeps the encoding lossless for any
 * future heap growth.
 */
_Static_assert(SHARED_STR_HEAP_SIZE <= UINT32_MAX,
	       "shared string heap offset+1 must fit in uint32_t");

/*
 * Cross-process state.  Lives in its own alloc_shared_pool region so
 * children inherit a pointer to the same mapping; the mapping is set
 * up in the parent before any fork.  Kept off shm_s so this TU is
 * standalone and unit-testable without dragging the shm.h include
 * pyramid into the test binary.
 */
struct shared_str_state {
	/*
	 * Bump cursor.  Advanced with a RELAXED CAS: OBJ_GLOBAL alloc
	 * is refused post-fork by add_object_validate(), so at
	 * allocation time the payload the cursor names is process-
	 * private and needs no inter-process publish barrier.
	 */
	size_t heap_used __attribute__((aligned(64)));

	/*
	 * Per-bucket freelist heads.  Each 64-bit head is a
	 * (version, offset+1) tuple manipulated by
	 * shared_freelist_pop / shared_freelist_push (see
	 * utils/shared_freelist.c for the head-word packing and the
	 * bounds+provenance armour applied on every deref).
	 */
	uint64_t freelist[SHARED_FREELIST_NUM_BUCKETS];

	/*
	 * Per-slot state, indexed by slot_offset / SHARED_FREELIST_SLOT_STRIDE
	 * (all bucket sizes and slot offsets are multiples of the stride).
	 * See shared_freelist.h for the encoding: 0 == UNCARVED / interior,
	 * 1..N == FREE(bucket_idx = v - 1), N+1..2N == LIVE(bucket_idx =
	 * v - 1 - N).  free_shared_str() and the freelist primitives trust
	 * nothing but this record, for two reasons.
	 *
	 * Bucket: payload bytes, a strdup's NUL included, live in MAP_SHARED
	 * memory that fuzzed syscalls can be handed as a user pointer.  A
	 * bucket re-derived with strlen() would let a scribbled NUL put the
	 * slot in a LARGER bucket than alloc carved: the push's memset(slot,
	 * 0, bucket_size) then runs past the slot end and the next pop hands
	 * out a too-small chunk.  So the bucket is recorded at alloc time and
	 * free_shared_str() takes no size.
	 *
	 * Provenance: a bounds check on a freelist token only proves the
	 * address is in the slab, not that it names a live, non-interior,
	 * same-bucket slot.  A forged in-bounds token can alias a live slot,
	 * cross buckets or land inside a slot (silent payload corruption),
	 * and a double free links one address into two chains.  So
	 * shared_freelist_pop/push make the atomic FREE<->LIVE transition the
	 * sole gate for handing out or reclaiming a slot: every provenance
	 * failure is a failed state CAS, and the slot is leaked without
	 * touching slab memory.  The array sits in its own alloc_shared_pool
	 * region, not inside shared_str_heap and not registered as a fuzz
	 * target, so a fuzzed syscall cannot rewrite it.
	 */
	uint8_t slot_state[SHARED_STR_HEAP_SIZE /
			   SHARED_FREELIST_SLOT_STRIDE];
};

/*
 * Compile-time cross-check: uint8_t is enough to hold every state
 * encoding.  The highest legal value is LIVE(NUM_BUCKETS - 1) which
 * is 2 * NUM_BUCKETS.  If a future refactor grows NUM_BUCKETS past
 * 127, LIVE and FREE ranges would collide the sign bit / need a
 * wider table.
 */
_Static_assert(2 * SHARED_FREELIST_NUM_BUCKETS <= 254,
	       "state encoding must fit in slot_state's uint8_t");

/*
 * Base pointer of the shared string heap.  Freelist tokens encode an
 * offset+1 into this region; both push and pop translate between
 * tokens and pointers via this base, so it is passed down to the
 * shared_freelist primitives with every call.  The actual mapping is
 * created lazily in shared_str_heap_init() below.
 */
static char *shared_str_heap;
static size_t shared_str_heap_capacity;
static struct shared_str_state *sss;

static void shared_str_heap_init(void)
{
	/* Same pre-fork-mapping requirement as the obj heap: the first
	 * caller must run in the parent before any child forks, which
	 * holds for all current callers (init_*_fds via open_fds()
	 * before fork_children()).  Assert it so a future child-context
	 * caller cannot silently map a private heap behind the shared
	 * cursor, which would dangle string pointers across processes. */
	if (getpid() != mainpid) {
		outputerr("alloc_shared_str: heap init from child context "
			  "(pid %d, parent %d) -- would dangle shm pointers\n",
			  getpid(), mainpid);
		abort();
	}
	shared_str_heap_capacity = SHARED_STR_HEAP_SIZE;
	shared_str_heap = alloc_shared_pool(shared_str_heap_capacity);
	sss = alloc_shared_pool(sizeof(*sss));
	/* __alloc_shared() poisons the region with random bytes to
	 * expose uninitialised reads.  Zero the state block explicitly:
	 * the bump cursor and freelist heads read as 0 only if we
	 * clear it, and slot_state must start at 0 (== UNCARVED) so
	 * the free path treats a not-yet-allocated slot correctly
	 * (skip freelist push, fall through to the leak path) and the
	 * freelist pop primitive correctly rejects a forged token that
	 * names an uncarved offset. */
	memset(sss, 0, sizeof(*sss));
}

void * alloc_shared_str(size_t size)
{
	size_t old_used, new_used;
	void *p;
	int bucket;

	if (size == 0)
		return NULL;

	if (shared_str_heap == NULL)
		shared_str_heap_init();

	/* Round up so each allocation starts pointer-aligned.  The
	 * primitive is generic -- strings don't need it, but the
	 * empty-buffer callers (perf_event_attr) do, and one rule keeps
	 * the accounting simple. */
	size = (size + sizeof(void *) - 1) & ~(sizeof(void *) - 1);

	/* Try the freelist before touching the bump cursor. */
	bucket = shared_freelist_bucket(size);
	if (bucket >= 0) {
		p = shared_freelist_pop(&sss->freelist[bucket],
					sss->slot_state,
					(unsigned int)bucket,
					shared_str_heap,
					shared_str_heap_capacity,
					shared_freelist_bucket_sizes[bucket]);
		if (p != NULL) {
			/* Primitive already installed LIVE(bucket) at
			 * slot_state[off / SHARED_FREELIST_SLOT_STRIDE]
			 * via the FREE->LIVE state CAS, so no local
			 * post-fixup is needed here. */
			return p;
		}
		/* Round bump to bucket size so the first free of a bump
		 * slot doesn't overrun the next slot via the freelist
		 * push's bucket-size memset. */
		size = shared_freelist_bucket_sizes[bucket];
	}

	/* Lock-free bump via CAS on the shared-state cursor.  RELAXED
	 * is sufficient because OBJ_GLOBAL additions are refused
	 * post-fork by add_object_validate()'s guard, so objheads (and
	 * any shared_str pointer they carry) are process-private at
	 * allocation time.  With no concurrent cross-process reader,
	 * plain accesses within the allocating process are correctly
	 * ordered by program order; no inter-process publish barrier is
	 * needed on the bump cursor. */
	old_used = __atomic_load_n(&sss->heap_used, __ATOMIC_RELAXED);
	do {
		new_used = old_used + size;
		if (new_used > shared_str_heap_capacity) {
			outputerr("alloc_shared_str: heap exhausted "
				  "(cap %zu, used %zu, req %zu)\n",
				  shared_str_heap_capacity, old_used, size);
			return NULL;
		}
	} while (!__atomic_compare_exchange_n(&sss->heap_used,
					      &old_used, new_used,
					      false,
					      __ATOMIC_RELAXED,
					      __ATOMIC_RELAXED));

	p = shared_str_heap + old_used;
	memset(p, 0, size);
	if (bucket >= 0) {
		/* Bucketed bump slot: publish LIVE(bucket) into
		 * slot_state so a subsequent free_shared_str() finds
		 * the correct bucket and passes the primitive's
		 * LIVE->FREE state CAS.  The bump CAS above guaranteed
		 * this offset is uniquely owned by us, so the transition
		 * is UNCARVED (0) -> LIVE(bucket); a plain atomic store
		 * with RELEASE ordering suffices.  Above-bucket bump
		 * slots leave the record at UNCARVED and free them via
		 * the leak-with-capped-memset path. */
		__atomic_store_n(&sss->slot_state[old_used /
						  SHARED_FREELIST_SLOT_STRIDE],
				 SHARED_FREELIST_STATE_LIVE(
					 (unsigned int)bucket),
				 __ATOMIC_RELEASE);
	}
	return p;
}

char * alloc_shared_strdup(const char *src)
{
	size_t len;
	char *dst;

	if (src == NULL)
		return NULL;

	len = strlen(src) + 1;
	dst = alloc_shared_str(len);
	if (dst == NULL)
		return NULL;

	memcpy(dst, src, len);
	return dst;
}

void free_shared_str(void *p)
{
	size_t off;
	uint8_t recorded;

	if (p == NULL)
		return;

	/* Slot must live inside the heap.  A wild pointer -- fuzzed
	 * scribble into an obj->name field, or an above-heap alloc that
	 * escaped a caller-side range check -- has no recorded state
	 * for us to trust; skip and leak rather than dereference an
	 * out-of-heap pointer or scribble a random address.  This is
	 * the same "release what we own, leak the unproven" invariant
	 * the map destructor's alloc_track_lookup gate encodes. */
	if (shared_str_heap == NULL || sss == NULL)
		return;
	if ((char *)p < shared_str_heap ||
	    (char *)p >= shared_str_heap + shared_str_heap_capacity)
		return;

	off = (size_t)((char *)p - shared_str_heap);

	/* Slot starts are STRIDE-aligned by construction (bucket sizes
	 * are all multiples of STRIDE, initial cursor is 0, bump rounds
	 * to bucket size for bucketed slots).  A misaligned pointer
	 * means either a corrupt caller or a poisoned pointer that
	 * happened to land in the heap band -- skip and leak. */
	if ((off & (SHARED_FREELIST_SLOT_STRIDE - 1U)) != 0)
		return;

	/* Authoritative state lookup: recorded at alloc time in memory
	 * the fuzzer cannot reach.  A LIVE(bucket) record is the only
	 * input that picks the bucket to push to; see slot_state in
	 * struct shared_str_state. */
	recorded = __atomic_load_n(&sss->slot_state[off /
						    SHARED_FREELIST_SLOT_STRIDE],
				   __ATOMIC_ACQUIRE);
	if (recorded > SHARED_FREELIST_NUM_BUCKETS &&
	    recorded <= 2 * SHARED_FREELIST_NUM_BUCKETS) {
		unsigned int bucket = (unsigned int)recorded - 1U -
				      SHARED_FREELIST_NUM_BUCKETS;

		/* Primitive owns the LIVE->FREE state transition
		 * atomically (see shared_freelist.c).  A double-free,
		 * cross-bucket push, or interior-address push all fail
		 * the CAS inside the primitive and the slot is leaked;
		 * we don't need to pre-clear state here. */
		shared_freelist_push(&sss->freelist[bucket],
				     sss->slot_state, bucket, p,
				     shared_str_heap,
				     shared_str_heap_capacity,
				     shared_freelist_bucket_sizes[bucket]);
		return;
	}

	/* No LIVE record -- above-bucket bump-and-leak slot, an
	 * already-freed slot (state == FREE(bucket)), an interior
	 * stride unit of a live slot, or a never-carved in-heap
	 * address.  Leak without touching any slab bytes:
	 *
	 *   FREE(bucket): slot's link bytes hold the next-token for
	 *     the freelist chain; a memset would truncate the chain
	 *     (duplicate-free corruption).
	 *
	 *   UNCARVED / interior: the bytes belong to a live
	 *     allocation; a memset scribbles payload (interior-
	 *     pointer corruption).
	 *
	 * Only an exact LIVE(bucket) provenance match earns the
	 * LIVE->FREE transition, and that transition must go through
	 * shared_freelist_push() as the sole authorised path.
	 * Above-bucket bump allocations and all other unproven
	 * pointers are leaked here. */
	return;
}

void shared_str_heap_reset_for_test(void)
{
	/* Test-only re-init hook: drops the current heap + state
	 * mapping references so the next alloc_shared_str() call
	 * re-runs shared_str_heap_init() and carves a fresh MAP_SHARED
	 * region.  Never call this from production trinity -- see the
	 * header for the fork-safety reason.
	 *
	 * The previous mappings are deliberately leaked: the test
	 * binary is single-shot and short-lived, and threading a
	 * matching free_shared() through this hook would drag the full
	 * shared-region unregister path (locks, bitmap, guard-page
	 * layout) into the test binary's link graph. */
	shared_str_heap = NULL;
	shared_str_heap_capacity = 0;
	sss = NULL;
}
