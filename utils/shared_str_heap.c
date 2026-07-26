/*
 * Shared-string heap allocator.
 *
 * A size-classed slab that carves variable-length string payloads out
 * of a single MAP_SHARED region so that any string pointer reachable
 * from an OBJ_GLOBAL object stays walkable in every forked child.  The
 * owning obj struct is on the private per-process heap; only the
 * variable-length payload it points at lives in this slab.
 *
 * Layout:
 *
 *   +-------------------------- shared_str_heap (1 MiB, MAP_SHARED)
 *   | slot | slot | slot | ... | bump cursor -> ...
 *
 *   Each carved slot belongs to exactly one size bucket
 *   (shared_freelist_bucket_sizes[]: 8..1024, powers of two).  Slots
 *   up to 1024 bytes are recycled through per-bucket freelists on
 *   free; slots above bucket-1024 are bump-and-leak.
 *
 * Free-size authority (the reason the metadata table exists):
 *
 *   Payload bytes -- including the terminating NUL of a strdup-style
 *   allocation -- live in a MAP_SHARED region that can be handed to
 *   fuzzed syscalls as a user pointer.  A syscall that scribbles the
 *   NUL turns any strlen()-derived free size into an attacker-
 *   controlled quantity.  If free_shared_str picked its target bucket
 *   by re-strlen()'ing the payload, a NUL stomp would push the slot
 *   into a LARGER bucket than alloc carved -- the next pop from that
 *   larger bucket then hands the caller a too-small chunk that
 *   the push's memset(slot, 0, bucket_size) already scribbled past
 *   the slot end.
 *
 *   Fix: record the bucket at alloc time in an out-of-band table
 *   (slot_bucket, indexed by slot_offset / 8; all bucket sizes and
 *   slot offsets are multiples of 8), and gate free_shared_str's
 *   bucket choice on that record instead of on any quantity a fuzz
 *   scribble can influence.  The size parameter to free_shared_str is
 *   kept for API stability but is advisory only when the slot has a
 *   recorded bucket -- which is every bucketed slot.  Above-bucket
 *   bump-and-leak slots have no record and still consult the
 *   caller-supplied size for the poison memset, capped to the
 *   heap-remaining extent so a fuzzable size cannot drive a scribble
 *   past the heap.
 *
 *   The metadata table lives in its own alloc_shared_pool region --
 *   NOT inside shared_str_heap and NOT registered as a fuzz target --
 *   so a fuzzed syscall cannot rewrite the authoritative bucket the
 *   free path reads.
 *
 * Freelist primitives:
 *
 *   The per-bucket lock-free freelist heads (ABA-safe, bounds-checked)
 *   live in utils/shared_freelist.c.  This TU owns the heap base, the
 *   per-bucket head words, and the per-slot bucket record; it calls
 *   shared_freelist_pop / shared_freelist_push to move slots on and
 *   off each head.
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

#define NUM_SHM_FREELIST_BUCKETS	8

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
	 * bounds-check armour applied on every deref).
	 */
	uint64_t freelist[NUM_SHM_FREELIST_BUCKETS];

	/*
	 * Per-slot bucket record.  Indexed by slot_offset / 8 (all
	 * bucket sizes and slot offsets are multiples of 8); each entry
	 * is bucket_index + 1, with 0 == unrecorded (either uncarved or
	 * an above-bucket bump-and-leak slot).  free_shared_str reads
	 * this to pick the target bucket instead of recomputing size
	 * from the slot's own (fuzzable) payload bytes.
	 */
	uint8_t slot_bucket[SHARED_STR_HEAP_SIZE / 8];
};

/*
 * Compile-time cross-check: uint8_t is enough to encode every
 * bucket index + 1 plus the "unrecorded" sentinel.  If a future
 * refactor grows NUM_SHM_FREELIST_BUCKETS past 254, the recording
 * would silently truncate and the free-path lookup would land in
 * the wrong bucket.
 */
_Static_assert(NUM_SHM_FREELIST_BUCKETS <= 254,
	       "bucket index + 1 must fit in slot_bucket's uint8_t");

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
	 * clear it, and slot_bucket must start at 0 (== unrecorded)
	 * so the free path treats a not-yet-allocated slot correctly
	 * (skip freelist push, fall through to the leak path). */
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
					shared_str_heap,
					shared_str_heap_capacity,
					shared_freelist_bucket_sizes[bucket]);
		if (p != NULL) {
			size_t off = (size_t)((char *)p - shared_str_heap);
			sss->slot_bucket[off / 8U] = (uint8_t)(bucket + 1);
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
		/* Bucketed bump slot: record the bucket so free lands
		 * in the right freelist even if the payload NUL is
		 * later stomped.  Above-bucket bump slots leave the
		 * record at 0 (unrecorded) and free them via the
		 * leak-with-capped-memset path. */
		sss->slot_bucket[old_used / 8U] = (uint8_t)(bucket + 1);
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

void free_shared_str(void *p, size_t size)
{
	size_t off;
	uint8_t recorded;

	if (p == NULL)
		return;

	/* Slot must live inside the heap.  A wild pointer -- fuzzed
	 * scribble into an obj->name field, or an above-heap alloc that
	 * escaped a caller-side range check -- has no recorded bucket
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

	/* Slot starts are 8-byte aligned by construction (bucket sizes
	 * are all multiples of 8, initial cursor is 0, bump rounds to
	 * bucket size for bucketed slots).  A misaligned pointer means
	 * either a corrupt caller or a poisoned pointer that happened
	 * to land in the heap band -- skip and leak. */
	if ((off & 7U) != 0)
		return;

	/* Authoritative bucket lookup: recorded at alloc time in
	 * memory the fuzzer cannot reach.  A non-zero record wins over
	 * whatever the caller passed as `size' (which for the maps
	 * strdup path is a strlen()-derived quantity computed from a
	 * payload the kernel can scribble via a fuzzed syscall).  See
	 * the block comment at the top of this file. */
	recorded = sss->slot_bucket[off / 8U];
	if (recorded != 0 && recorded <= NUM_SHM_FREELIST_BUCKETS) {
		unsigned int bucket = (unsigned int)recorded - 1U;

		/* Clear the record BEFORE push: the slot is about to
		 * be handed to the next popper, and stale metadata
		 * would then misattribute a future free of an
		 * unrelated (untracked) pointer that happened to land
		 * on this offset.  Reset here so the invariant "record
		 * == 0 iff slot is not currently live" holds across
		 * the alloc-free cycle. */
		sss->slot_bucket[off / 8U] = 0;
		shared_freelist_push(&sss->freelist[bucket], p,
				     shared_str_heap,
				     shared_str_heap_capacity,
				     shared_freelist_bucket_sizes[bucket]);
		return;
	}

	/* No record -- above-bucket bump-and-leak slot, or an alloc
	 * that predates any record (there are none at HEAD, but be
	 * conservative).  Poison and leak, capping the memset to the
	 * heap-remaining extent so a fuzzable `size' cannot drive a
	 * scribble past the heap end. */
	if (size == 0)
		return;
	if (size > shared_str_heap_capacity - off)
		size = shared_str_heap_capacity - off;
	memset(p, 0, size);
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
