#include <stdbool.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "child.h"
#include "debug.h"
#include "deferred-free.h"
#include "locks.h"
#include "objects.h"
#include "params.h"
#include "pc_format.h"
#include "pids.h"
#include "random.h"
#include "shm.h"
#include "stats.h"
#include "stats_ring.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"

/*
 * Use this allocator if you have an object a child writes to that you want
 * all other processes to see.
 *
 * Every allocation is tracked so that VM syscalls (munmap, madvise, mremap,
 * mprotect) can avoid clobbering trinity's own shared state.
 */

static struct {
	unsigned long addr;
	unsigned long size;
} shared_regions[MAX_SHARED_ALLOCS];
unsigned int nr_shared_regions;

/*
 * Bounded overflow tail for registrations that arrive once
 * shared_regions[] is full.  Exists so range_overlaps_shared() (via the
 * bitmap, which is still updated) and range_in_tracked_shared() (via the
 * linear walk extension below) keep protecting fuzzed mm syscalls from
 * clobbering the untracked region instead of silently failing open.
 *
 * Intentionally small: 256 slots is "absorb a moderately over-budget
 * fleet host long enough to fail loudly and tell the operator to raise
 * MAX_SHARED_ALLOCS or move to dynamic resize", not "a second pool to
 * keep growing into".  Exhausting the tail BUG()s in both debug and
 * release; under-protection of a writable shared mapping is the failure
 * class the whole tracker exists to prevent and is never preferable to
 * a loud abort.
 */
#define SHARED_REGIONS_OVERFLOW_TAIL 256

static struct {
	unsigned long addr;
	unsigned long size;
} shared_regions_overflow[SHARED_REGIONS_OVERFLOW_TAIL];
static unsigned int nr_shared_regions_overflow;

/*
 * Bitmap accelerator for range_overlaps_shared().  One bit per
 * SHARED_BITMAP_GRANULARITY-byte chunk of user VA; a set bit means at
 * least one byte in that chunk belongs to a registered shared region.
 *
 * The mm-syscall sanitisers (madvise/mremap/mprotect/munmap/mseal/mbind/
 * process_madvise/remap_file_pages/...) call range_overlaps_shared()
 * once per fuzzed call, often many times per child per second.  The
 * original linear scan over shared_regions[] is O(N) per query with N
 * easily reaching 100+ on a 32-child fleet (per-child childdata,
 * fd_event ring, kcov ring, plus the global reserve).  Replacing the
 * scan with this bitmap turns the hot path into one or two word loads
 * for the common single-page query.
 *
 * Granularity 2 MiB is the natural unit for the conservative
 * over-reject guarantee: any 2 MiB chunk that touches a shared region
 * gets its bit set, and a query whose footprint hits that chunk
 * rejects.  False positives are possible at chunk boundaries (a
 * non-shared page co-located in the same 2 MiB chunk as a shared
 * region rejects too), which is the SAFETY direction -- under-reject
 * would let a fuzzed mmap call clobber trinity's own shared state.
 *
 * Span 1<<47 covers the canonical x86_64 user VA on default
 * (4-level page table) kernels.  Regions registered outside the span
 * trip the BUG_ON in shared_bitmap_mark(); queries entirely outside
 * the span return false (no tracked region can live there because the
 * BUG_ON would have fired).  At 1 bit per 2 MiB, the bitmap is
 * 1<<26 bits = 8 MiB of BSS, but it is mostly zero pages: only the
 * 4 KiB pages that cover actually-set bits ever fault in, so true
 * resident growth is in the kilobytes for a typical fleet host where
 * shared regions cluster in the mmap arena near 0x7f000000....
 */
#define SHARED_BITMAP_GRANULARITY_LOG2	21UL	/* 2 MiB per bit */
#define SHARED_BITMAP_VA_LOG2		47UL	/* 128 TiB user VA span */
#define SHARED_BITMAP_VA_SPAN		(1UL << SHARED_BITMAP_VA_LOG2)
#define SHARED_BITMAP_NBITS		(SHARED_BITMAP_VA_SPAN >> SHARED_BITMAP_GRANULARITY_LOG2)
#define SHARED_BITMAP_BITS_PER_WORD	(8UL * sizeof(unsigned long))
#define SHARED_BITMAP_NWORDS		(SHARED_BITMAP_NBITS / SHARED_BITMAP_BITS_PER_WORD)

static unsigned long shared_region_bitmap[SHARED_BITMAP_NWORDS];

static inline bool shared_bitmap_test(unsigned long bit)
{
	return (shared_region_bitmap[bit / SHARED_BITMAP_BITS_PER_WORD] >>
		(bit % SHARED_BITMAP_BITS_PER_WORD)) & 1UL;
}

static inline void shared_bitmap_set(unsigned long bit)
{
	shared_region_bitmap[bit / SHARED_BITMAP_BITS_PER_WORD] |=
		1UL << (bit % SHARED_BITMAP_BITS_PER_WORD);
}

/*
 * Mark every 2 MiB chunk that intersects [addr, addr+size).  Called
 * from the tail of alloc_shared() and track_shared_region() so the
 * bitmap stays in sync with shared_regions[].  size==0 is a no-op
 * (matches the "empty region overlaps nothing" semantics callers rely
 * on).  An out-of-span registration BUG()s loudly: the linear-scan
 * predecessor would have caught such a region, so silently dropping it
 * here would flip the safety invariant from "over-reject" to
 * "under-reject" -- the exact failure mode this whole guard exists to
 * prevent.
 */
static void shared_bitmap_mark(unsigned long addr, unsigned long size)
{
	unsigned long end, first, last, bit;

	if (size == 0)
		return;

	if (addr >= SHARED_BITMAP_VA_SPAN ||
	    size > SHARED_BITMAP_VA_SPAN - addr) {
		outputerr("shared_bitmap_mark: region 0x%lx+0x%lx outside "
			  "1<<%lu user VA span; widen SHARED_BITMAP_VA_LOG2\n",
			  addr, size, SHARED_BITMAP_VA_LOG2);
		BUG("shared region outside bitmap span");
	}

	end = addr + size - 1;
	first = addr >> SHARED_BITMAP_GRANULARITY_LOG2;
	last = end >> SHARED_BITMAP_GRANULARITY_LOG2;

	for (bit = first; bit <= last; bit++)
		shared_bitmap_set(bit);
}

/*
 * Handle a registration that arrived once shared_regions[] is full.
 *
 * The previous "warn once, then silently drop the region" policy turned
 * an over-budget host into the exact failure mode this whole tracker
 * exists to prevent: range_overlaps_shared() can no longer guard an
 * untracked writable MAP_SHARED region from a fuzzed
 * munmap/mremap/madvise/mprotect, so the next call that picks an
 * unlucky address scribbles trinity's own shared state and the
 * resulting crash looks like a kernel bug.  Silent under-protection of
 * a writable shared mapping is never preferable to a loud abort.
 *
 * New policy, per call:
 *
 *   - Always emit a LOUD outputerr() naming the caller PC (resolved via
 *     pc_to_string, same idiom as log_mprotect_failure()), the offending
 *     region, and the tail occupancy.  Per-call (not cap-once): the
 *     cap-once predecessor hid how badly the cap was over budget, which
 *     is the one piece of data needed to size a real fix.
 *
 *   - Under ASAN (the developer / debug build), BUG() immediately --
 *     overflow is a tree-state bug and we want a stack trace, not a
 *     production-shaped degradation.
 *
 *   - In release, register the region in the bounded overflow tail so
 *     the bitmap stays correct (shared_bitmap_mark already covers the
 *     range) and range_in_tracked_shared() can still match precisely.
 *     Bump shm->stats.shared_region_overflow so the over-budget state
 *     is visible in the periodic stats dump.
 *
 *   - If the overflow tail itself fills, BUG() in both debug and
 *     release.  Two layers of bounded storage is enough; a third would
 *     just be a slower path to the same silent-under-protection bug.
 */
static void register_shared_overflow(const char *who, unsigned long addr,
				     unsigned long size, void *caller)
{
	char pcbuf[128];

	outputerr("shared_regions: %s overflow: region 0x%lx+0x%lx from %s; "
		  "MAX_SHARED_ALLOCS=%d exhausted, overflow tail at %u/%d -- "
		  "raise the cap or move shared_regions[] to dynamic resize\n",
		  who, addr, size,
		  pc_to_string(caller, pcbuf, sizeof(pcbuf)),
		  MAX_SHARED_ALLOCS,
		  nr_shared_regions_overflow, SHARED_REGIONS_OVERFLOW_TAIL);

#ifdef __SANITIZE_ADDRESS__
	BUG("shared_regions[] overflow (debug build)");
#else
	if (nr_shared_regions_overflow >= SHARED_REGIONS_OVERFLOW_TAIL) {
		outputerr("shared_regions: overflow tail also exhausted "
			  "(%d slots); refusing to leave region 0x%lx+0x%lx "
			  "untracked\n",
			  SHARED_REGIONS_OVERFLOW_TAIL, addr, size);
		BUG("shared_regions overflow tail exhausted");
	}

	shared_regions_overflow[nr_shared_regions_overflow].addr = addr;
	shared_regions_overflow[nr_shared_regions_overflow].size = size;
	shared_bitmap_mark(addr, size);
	nr_shared_regions_overflow++;

	if (shm != NULL)
		__atomic_add_fetch(&shm->stats.shared_region_overflow, 1,
				   __ATOMIC_RELAXED);
#endif
}

void * alloc_shared(size_t size)
{
	void *ret;

	ret = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, -1, 0);
	if (ret == MAP_FAILED) {
		outputerr("mmap %zu failure\n", size);
		exit(EXIT_FAILURE);
	}
	/* poison with independently-random bytes to expose uninitialized reads. */
	{
		unsigned char *p = ret;
		size_t i;

		for (i = 0; i + sizeof(unsigned int) <= size; i += sizeof(unsigned int)) {
			unsigned int r = rand32();
			memcpy(p + i, &r, sizeof(r));
		}
		for (; i < size; i++)
			p[i] = (unsigned char)rand();
	}

	if (nr_shared_regions < MAX_SHARED_ALLOCS) {
		shared_regions[nr_shared_regions].addr = (unsigned long) ret;
		shared_regions[nr_shared_regions].size = size;
		shared_bitmap_mark((unsigned long) ret, size);
		nr_shared_regions++;
	} else {
		register_shared_overflow("alloc_shared", (unsigned long) ret,
					 size, __builtin_return_address(0));
	}

	return ret;
}

/*
 * Add an externally-mmap'd region to the shared_regions tracker so the
 * range_overlaps_shared() guards in the mm-syscall sanitisers refuse
 * fuzzed munmap/mremap/madvise/mprotect calls that target it.  Used by
 * code that mmaps via something other than alloc_shared() and still
 * needs the region protected from the fuzzer -- e.g., the per-child
 * kcov ring buffer mapped from /sys/kernel/debug/kcov.
 */
void track_shared_region(unsigned long addr, unsigned long size)
{
	if (nr_shared_regions < MAX_SHARED_ALLOCS) {
		shared_regions[nr_shared_regions].addr = addr;
		shared_regions[nr_shared_regions].size = size;
		shared_bitmap_mark(addr, size);
		nr_shared_regions++;
	} else {
		register_shared_overflow("track_shared_region", addr, size,
					 __builtin_return_address(0));
	}
}

bool shared_size_mul(size_t a, size_t b, size_t *out)
{
	return !__builtin_mul_overflow(a, b, out);
}

/*
 * Size-bucketed freelist for shared heap recycling.
 *
 * Eight fixed-size buckets cover the common allocation sizes.  A freed slot
 * whose aligned size falls within a bucket is pushed onto that bucket's
 * lock-free stack; the next alloc of the same size pops it instead of
 * burning new bump space.  Allocations larger than 1024 bytes bypass the
 * freelist and use the bump allocator directly (documented below).
 *
 * The freelist link lives in the slot's own first sizeof(uintptr_t) bytes.
 * This is safe because the slot is not live when the link is written: the
 * caller has just handed it back to us, and we zero the rest of the slot
 * before writing the link so that a use-after-free still surfaces as zero-
 * byte reads rather than as a stale link pointer.
 *
 * CAS ordering: RELAXED is sufficient for the same reason as the bump
 * cursor — the caller publishes the resulting object via add_object()'s
 * RELEASE store, which is the actual synchronisation point for consumers.
 *
 * ABA safety via tagged pointer.  A naive lock-free stack with a single
 * pointer head is vulnerable to the classic ABA race: a popper reads
 * old_head=X and next=*X, but before its CAS another thread pops X, pops
 * X.next, and then pushes X back.  The CAS still sees head==X and succeeds,
 * but it installs the stale "next" value, leaving head pointing at a slot
 * that has already been handed back to a caller.  Two callers then think
 * they own the same slot; the resulting double-use corrupts whichever
 * obj struct was layered over the slot and faults later in unrelated
 * code paths far from the buggy free.
 *
 * The mitigation is a 16-bit version counter packed into the high bits of
 * the head word.  Each push and pop increments the version; the CAS
 * compares the full 64-bit (version, ptr) tuple.  The A→B→A sequence above
 * now leaves the head as (X, ver+2) rather than (X, ver), so the racer's
 * CAS fails on the version mismatch and it retries with a fresh load.
 *
 * The packing exploits the canonical-form invariant of x86_64 user-space
 * virtual addresses: only bits 0-47 are significant, and bit 47 is 0 for
 * any user-space pointer (kernel pointers have bit 47 == 1 and are
 * sign-extended into the upper 16 bits).  We therefore stash the version
 * counter in bits 48-63, recover the pointer with a 48-bit mask, and need
 * no sign extension on read.  The slot's stored "next" link is just the
 * raw pointer (no version bits) — the version lives only in the head.
 *
 * The 16-bit version is finite: a perfectly-timed sequence of exactly
 * 65536 push/pop pairs in the gap between a victim's load and CAS would
 * wrap the version back to its original value and re-expose the race.
 * For a process-bounded fuzzer with sub-microsecond critical sections
 * this is astronomically improbable; if it ever proves observable the
 * head can be widened to a 128-bit (ptr, version) tuple and switched to a
 * cmpxchg16b-based DWCAS without any caller change.
 */

/*
 * The packed (ptr, version) freelist head assumes the top 16 bits of every
 * freelist pointer are zero — i.e. a 48-bit canonical userspace VA range,
 * which is the x86-64 default and is not guaranteed on arm64 (52-bit
 * possible), s390x, riscv, or x86-64 with 5-level paging enabled.  Reject
 * the build explicitly so a future port hits the wall here instead of
 * shipping a subtly-broken allocator.  Removing this guard requires either
 * a DWCAS-based 128-bit head where available or a (struct ptr, generation)
 * variant guarded by a small lock — see the comment block above the head
 * declaration.
 */
#if !defined(__x86_64__)
#error "shm freelist (ptr, version) packing assumes 48-bit userspace VA — port requires DWCAS or struct+lock variant"
#endif

#define FREELIST_PTR_MASK	((uint64_t)((1ULL << 48) - 1))
#define FREELIST_VER_SHIFT	48

static const size_t bucket_sizes[NUM_SHM_FREELIST_BUCKETS] = {
	8, 16, 32, 64, 128, 256, 512, 1024
};

/*
 * Return the index of the smallest bucket that fits an allocation of
 * already-pointer-aligned size, or -1 if size exceeds all buckets.
 */
static int freelist_bucket(size_t aligned_size)
{
	unsigned int i;

	for (i = 0; i < NUM_SHM_FREELIST_BUCKETS; i++) {
		if (aligned_size <= bucket_sizes[i])
			return (int)i;
	}
	return -1;
}

/*
 * Pop a slot from the freelist bucket whose head lives at *head.
 * Returns NULL if the freelist is empty; otherwise returns a fully-zeroed
 * slot of slot_size bytes.  ABA-safe via the version tag in the high
 * bits of the head — see the block comment above.
 */
static void *freelist_pop(uint64_t *head, size_t slot_size)
{
	uint64_t old_tagged, new_tagged;
	uintptr_t ptr, next;
	uint16_t new_ver;

	old_tagged = __atomic_load_n(head, __ATOMIC_RELAXED);
	do {
		ptr = (uintptr_t)(old_tagged & FREELIST_PTR_MASK);
		if (ptr == 0)
			return NULL;
		/* The slot's first word holds the next pointer, with no
		 * version bits — versions live only in the head. */
		next = *(uintptr_t *)ptr;
		new_ver = (uint16_t)(old_tagged >> FREELIST_VER_SHIFT) + 1;
		new_tagged = ((uint64_t)next & FREELIST_PTR_MASK) |
			     ((uint64_t)new_ver << FREELIST_VER_SHIFT);
	} while (!__atomic_compare_exchange_n(head, &old_tagged, new_tagged,
					      false,
					      __ATOMIC_RELAXED,
					      __ATOMIC_RELAXED));

	memset((void *)ptr, 0, slot_size);
	return (void *)ptr;
}

/*
 * Push a slot onto the freelist bucket whose head lives at *head.
 * The entire slot (slot_size bytes) is zeroed first so that a use-after-
 * free reads as zero rather than stale data; then the freelist link is
 * written into the slot's first word before the CAS.  The version tag in
 * the head is incremented on every successful CAS to keep poppers safe
 * from ABA — see the block comment above.
 */
static void freelist_push(uint64_t *head, void *p, size_t slot_size)
{
	uint64_t old_tagged, new_tagged;
	uint16_t new_ver;

	memset(p, 0, slot_size);
	old_tagged = __atomic_load_n(head, __ATOMIC_RELAXED);
	do {
		/* Store only the pointer half of the previous head into our
		 * slot — the version stays in the head word. */
		*(uintptr_t *)p = (uintptr_t)(old_tagged & FREELIST_PTR_MASK);
		new_ver = (uint16_t)(old_tagged >> FREELIST_VER_SHIFT) + 1;
		new_tagged = ((uint64_t)(uintptr_t)p & FREELIST_PTR_MASK) |
			     ((uint64_t)new_ver << FREELIST_VER_SHIFT);
	} while (!__atomic_compare_exchange_n(head, &old_tagged, new_tagged,
					      false,
					      __ATOMIC_RELAXED,
					      __ATOMIC_RELAXED));
}

/*
 * Shared string heap — backing store for string-shaped fields
 * (filenames, label strings, fixed-size attr buffers) hung off objs
 * that live in the shared obj heap.
 *
 * Same MAP_SHARED-before-fork argument as the obj heap: any obj
 * struct that is reachable from shm->global_objects[] must point only
 * at memory that other processes can also reach, and the only way to
 * satisfy that for allocations made after fork (the regen path) is to
 * carve out of a region that was already mapped before any child
 * forked.
 *
 * Why a sibling slab instead of reusing the obj heap:
 *
 *   The obj heap is sized for ~28k struct objects at ~150 B each; if
 *   strings shared the cursor, a regen-heavy provider could starve
 *   future obj allocations and vice versa, with no way for an
 *   exhaustion message to distinguish "out of obj slots" from "out of
 *   string slots".  Splitting the cursor (and the backing region)
 *   keeps each pool's failure mode independent and self-describing.
 *   The sizing tradeoff is also different: obj structs are uniform,
 *   strings are variable-length and dominated by short labels, so the
 *   string pool can be much smaller.
 *
 * Capacity (64 KiB):
 *
 *   The string-bearing OBJ_GLOBAL providers (file/testfile, perf,
 *   memfd) hold short payloads — file paths typically under ~100 B,
 *   memfd labels under ~32 B, perf_event_attr buffers ~120 B (kernel
 *   caps the attr at PAGE_SIZE but trinity only memcpy's a struct's
 *   worth back into the obj for replay/dump).  At ~64 B average that
 *   is ~1k entries; at ~120 B per perf entry it is ~545.  Both
 *   comfortably exceed GLOBAL_OBJ_MAX_CAPACITY (1024) for the labels
 *   case and cover hundreds of regens for the perf case.  If long
 *   fuzz runs show "alloc_shared_str: heap exhausted" the cap can be
 *   raised — bump-and-leak makes growth the only reasonable answer.
 *
 * Why two entry points (alloc_shared_str + alloc_shared_strdup):
 *
 *   The eventual callers split cleanly into two shapes:
 *
 *     - strdup-style:  init_*_fds() and the .open regen hooks have
 *       a NUL-terminated source string (filename, label) and want a
 *       pointer to a stable shm copy of it.  alloc_shared_strdup()
 *       collapses the strlen+alloc+strcpy sequence at the call site.
 *
 *     - empty-buffer:  perf's open_perf_fd() has a fixed-size attr
 *       struct and just wants raw zeroed bytes to memcpy into.
 *       alloc_shared_str(sizeof(struct perf_event_attr)) hands back
 *       exactly that, with no NUL-termination contract.
 *
 *   Both share one heap and one free; the strdup variant is a thin
 *   wrapper around the primitive, not a separate allocator.
 *
 * Free strategy:
 *
 *   Mirror of free_shared_obj — poison the slot to zeros so a
 *   use-after-free surfaces as a "" / NUL-byte read rather than a
 *   live-looking string, then recycle via the size-bucketed freelist
 *   (see freelist_push/pop above).  Callers pass the original
 *   allocation size; for strdup-style strings that is strlen(p)+1 at
 *   free time, which is correct for a still-NUL-terminated string and
 *   harmless overshoot if it isn't (the buffer was zero-initialised).
 *   Slots too large for any freelist bucket are poisoned and leaked.
 */
/*
 * 1 MiB.  Originally sized at 64 KiB for the simple-init case (memfd
 * + perf eventattr + a few testfiles), but bump-and-leak loses one
 * slot per regen and try_regenerate_fd fires often enough during
 * sustained fuzz runs (testfiles refresh, perf eventattr churn) that
 * 64 KiB exhausts within a few hours and crashes the parent.  The
 * freelist recycler now returns slots to the pool, so long-run
 * exhaustion is no longer expected; the 1 MiB ceiling remains as
 * headroom for above-bucket allocations that still bump-and-leak.
 */
#define SHARED_STR_HEAP_SIZE (1U * 1024U * 1024U)

static char *shared_str_heap;
static size_t shared_str_heap_capacity;

static void shared_str_heap_init(void)
{
	/* Same pre-fork-mapping requirement as the obj heap: the first
	 * caller must run in the parent before any child forks, which
	 * holds for all current callers (init_*_fds via open_fds()
	 * before fork_children()). */
	shared_str_heap_capacity = SHARED_STR_HEAP_SIZE;
	shared_str_heap = alloc_shared(shared_str_heap_capacity);
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
	 * primitive is generic — strings don't need it, but the empty-
	 * buffer callers (perf_event_attr) do, and one rule keeps the
	 * accounting simple. */
	size = (size + sizeof(void *) - 1) & ~(sizeof(void *) - 1);

	/* Try the freelist before touching the bump cursor. */
	bucket = freelist_bucket(size);
	if (bucket >= 0) {
		p = freelist_pop(&shm->shared_str_freelist[bucket],
				 bucket_sizes[bucket]);
		if (p != NULL)
			return p;
		/* Round bump to bucket size so the first free of a bump
		 * slot doesn't overrun the next slot via freelist_push's
		 * bucket-size memset.  See the matching comment in
		 * alloc_shared_obj for the full bug-class explanation. */
		size = bucket_sizes[bucket];
	}

	/* Lock-free bump via CAS on the shm-resident cursor.  RELAXED
	 * is sufficient for the same reason as alloc_shared_obj: the
	 * caller publishes the obj (and therefore the string pointer)
	 * to consumers via add_object()'s RELEASE store on
	 * num_entries. */
	old_used = __atomic_load_n(&shm->shared_str_heap_used,
				   __ATOMIC_RELAXED);
	do {
		new_used = old_used + size;
		if (new_used > shared_str_heap_capacity) {
			outputerr("alloc_shared_str: heap exhausted "
				  "(cap %zu, used %zu, req %zu)\n",
				  shared_str_heap_capacity, old_used,
				  size);
			return NULL;
		}
	} while (!__atomic_compare_exchange_n(&shm->shared_str_heap_used,
					      &old_used, new_used,
					      false,
					      __ATOMIC_RELAXED,
					      __ATOMIC_RELAXED));

	p = shared_str_heap + old_used;
	memset(p, 0, size);
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
	int bucket;

	if (p == NULL || size == 0)
		return;

	size = (size + sizeof(void *) - 1) & ~(sizeof(void *) - 1);

	bucket = freelist_bucket(size);
	if (bucket >= 0) {
		freelist_push(&shm->shared_str_freelist[bucket], p,
			      bucket_sizes[bucket]);
		return;
	}

	/* Size above all buckets — poison and leak (bump-and-leak fallback). */
	memset(p, 0, size);
}

/*
 * Render a PROT_* mask as "READ|WRITE|EXEC" into the caller-provided
 * buffer.  Empties to "NONE" for prot==PROT_NONE so the diagnostic line
 * is never silently truncated to nothing between the brackets.  Unknown
 * upper bits (PROT_GROWSDOWN, pkey bits, ...) are left to the raw
 * 0x%x rendering at the call site.
 */
static void prot_to_string(int prot, char *buf, size_t buflen)
{
	int n = 0;
	int written;

	if (buf == NULL || buflen == 0)
		return;

	buf[0] = '\0';

	/* snprintf returns the would-have-written length even when truncated.
	 * Naive `n += snprintf(buf+n, buflen-n, ...)` advances n past buflen
	 * once the buffer fills, so the next call writes outside buf.  Currently
	 * safe at buflen=32 with the three short strings but identical cliff
	 * to the stats.c stack-depth histogram cumulator.  Bound n each step. */
	if ((prot & PROT_READ) && (size_t)n < buflen) {
		written = snprintf(buf + n, buflen - (size_t)n, "READ");
		if (written > 0)
			n += written;
	}
	if ((prot & PROT_WRITE) && (size_t)n < buflen) {
		written = snprintf(buf + n, buflen - (size_t)n,
				   "%sWRITE", n ? "|" : "");
		if (written > 0)
			n += written;
	}
	if ((prot & PROT_EXEC) && (size_t)n < buflen) {
		written = snprintf(buf + n, buflen - (size_t)n,
				   "%sEXEC", n ? "|" : "");
		if (written > 0)
			n += written;
	}

	if (n == 0)
		snprintf(buf, buflen, "NONE");
}

static const char *mprotect_errstr(int err)
{
	switch (err) {
	case ENOMEM:	return "ENOMEM";
	case EACCES:	return "EACCES";
	case EINVAL:	return "EINVAL";
	case EAGAIN:	return "EAGAIN";
	case EFAULT:	return "EFAULT";
	default:	return "unknown error";
	}
}

void log_mprotect_failure(void *addr, size_t len, int prot,
			  void *caller, int err)
{
	char protbuf[32];
	char pcbuf[128];

	prot_to_string(prot, protbuf, sizeof(protbuf));
	outputerr("mprotect(addr=%p, len=%zu, prot=0x%x [%s]) failed at %s: %s\n",
		  addr, len, prot, protbuf,
		  pc_to_string(caller, pcbuf, sizeof(pcbuf)),
		  mprotect_errstr(err));
}

/*
 * Self-check: confirm range_overlaps_shared()'s bitmap accelerator
 * actually rejects the first registered region.  Catches construction
 * regressions (a future refactor that forgets to call
 * shared_bitmap_mark() at registration would otherwise fail open and
 * silently let the fuzzer clobber trinity's own shared state).  Runs
 * once -- the bitmap only grows with new registrations, so a single
 * positive assert is sufficient to prove the wiring works. */
void shared_bitmap_self_check(void)
{
	static bool checked;
	unsigned long base, bit;

	if (checked || nr_shared_regions == 0)
		return;
	checked = true;

	base = shared_regions[0].addr;
	bit = base >> SHARED_BITMAP_GRANULARITY_LOG2;
	if (!shared_bitmap_test(bit)) {
		outputerr("range_overlaps_shared bitmap missing first region "
			  "@ 0x%lx (bit %lu)\n", base, bit);
		BUG("shared region bitmap inconsistent");
	}
}

/* Tunable: how often range_overlaps_shared() emits a -v summary line.
 * Lower = noisier, higher = blunter. */
#define RANGE_OVERLAPS_SHARED_REJECT_REPORT_INTERVAL 10000

/* Last syscall to trip a range_overlaps_shared() reject.  Last-write-wins;
 * a coarse hint for which sanitiser is doing the most work, not a precise
 * audit trail.  Process-local statics: each child has its own copy, the
 * writer and the reader (the periodic -v summary below) live in the same
 * single-threaded child, so plain accesses suffice.  Torn reads are
 * acceptable for a diagnostic anyway. */
static unsigned int last_reject_syscall_nr;
static unsigned char last_reject_do32bit;
static unsigned char last_reject_have_syscall;

bool range_overlaps_shared(unsigned long addr, unsigned long len)
{
	unsigned long end, check_end, first, last, bit;
	bool overlap = false;
	unsigned long n;
	struct childdata *child;

	/* Treat wrapped ranges as overlapping so callers reject them. */
	if (len != 0 && addr > ULONG_MAX - len)
		return true;

	end = addr + len;

	/* Bitmap accelerator: O(ceil(len/2MB)+1) bit reads instead of an
	 * O(N) walk over shared_regions[].  A range entirely above the
	 * bitmap span has no tracked overlap -- shared_bitmap_mark()
	 * BUG()s on out-of-span registrations, so a miss here cannot hide
	 * a real region.  A zero-length probe collapses to a single bit
	 * read on the chunk containing addr; this is over-rejection
	 * relative to the original byte-precise test (which only matched
	 * an empty range strictly inside a region) but lands on the
	 * SAFETY side that callers depend on. */
	if (addr < SHARED_BITMAP_VA_SPAN) {
		check_end = end;
		if (check_end > SHARED_BITMAP_VA_SPAN)
			check_end = SHARED_BITMAP_VA_SPAN;

		first = addr >> SHARED_BITMAP_GRANULARITY_LOG2;
		if (check_end > addr)
			last = (check_end - 1) >> SHARED_BITMAP_GRANULARITY_LOG2;
		else
			last = first;

		for (bit = first; bit <= last; bit++) {
			if (shared_bitmap_test(bit)) {
				overlap = true;
				break;
			}
		}
	}

	if (!overlap)
		return false;

	child = this_child();
	if (child != NULL && child->stats_ring != NULL) {
		unsigned int nr = child->syscall.nr;
		bool do32 = child->syscall.do32bit;

		stats_ring_enqueue(child->stats_ring,
				   STATS_FIELD_RANGE_OVERLAPS_SHARED_REJECTS,
				   0, 1);
		if (nr < MAX_NR_SYSCALL) {
			enum stats_field f = do32
				? STATS_FIELD_RANGE_REJECTS_PER_SYSCALL_32
				: STATS_FIELD_RANGE_REJECTS_PER_SYSCALL_64;
			stats_ring_enqueue(child->stats_ring, f,
					   (uint16_t)nr, 1);
		}

		last_reject_syscall_nr = nr;
		last_reject_do32bit = do32 ? 1 : 0;
		last_reject_have_syscall = 1;
	} else {
		/* Parent / pre-fork context: bump the aggregate directly. */
		parent_stats.range_overlaps_shared_rejects++;
	}

	/* Per-process monotonic counter feeding the verbose rate-limited
	 * log below.  The canonical aggregate now lives in parent-private
	 * memory and is not directly visible from child context, so the
	 * "fleet-wide every Nth reject" cadence the original counter
	 * provided cannot be recovered cheaply.  Each child rate-limits
	 * its own log lines independently; the parent does the same.
	 * Verbosity-gated, informational only. */
	{
		static unsigned long local_n;

		n = ++local_n;
	}

	if (verbosity > 1 &&
	    (n % RANGE_OVERLAPS_SHARED_REJECT_REPORT_INTERVAL) == 0) {
		const char *sname = "?";
		unsigned int snr;
		unsigned char s32;

		if (last_reject_have_syscall) {
			snr = last_reject_syscall_nr;
			s32 = last_reject_do32bit;
			sname = print_syscall_name(snr, s32 != 0);
		}

		output(1, "range_overlaps_shared: %lu cumulative rejects "
			"(latest syscall=%s addr=0x%lx len=%lu)\n",
			n, sname, addr, len);
	}
	return true;
}

/*
 * Precise containment check: is [addr, addr+len) fully inside at least
 * one entry of shared_regions[]?  Used by get_writable_address() to
 * confirm a freshly-picked pool address still resolves to a tracked
 * mapping before handing it back to a sanitiser.
 *
 * Distinct from range_overlaps_shared() in three ways the caller
 * relies on:
 *   1. Polarity is "fully inside", not "overlaps".  A scribbled slot
 *      can hold a value that happens to abut a tracked region without
 *      being inside it; over-acceptance there would defeat the guard.
 *   2. Walks shared_regions[] linearly.  The bitmap accelerator that
 *      backs range_overlaps_shared() rounds to 2 MiB chunks, which is
 *      the SAFETY direction for a reject-shaped sanitiser but the
 *      WRONG direction here -- a 2 MiB chunk that contains some
 *      tracked region would falsely accept addresses elsewhere in the
 *      same chunk.
 *   3. Does not bump range_overlaps_shared_rejects.  This is a
 *      validation lookup, not a sanitiser reject; folding it into the
 *      reject counter would lie to the operator about how often the
 *      mm-syscall guards are firing.
 *
 * Empty ranges (len == 0) match if @addr lies strictly inside any
 * region; the caller controls len so this is the consistent shape.
 * Wrapped ranges return false (no real allocation can wrap user VA).
 */
bool range_in_tracked_shared(unsigned long addr, unsigned long len)
{
	unsigned long end;
	unsigned int i;

	if (len != 0 && addr > ULONG_MAX - len)
		return false;

	end = addr + len;

	for (i = 0; i < nr_shared_regions; i++) {
		unsigned long rstart = shared_regions[i].addr;
		unsigned long rend = rstart + shared_regions[i].size;

		if (addr >= rstart && end <= rend)
			return true;
	}
	/* Same byte-precise walk over the overflow tail: a region parked
	 * there is no less tracked from the caller's perspective, and a
	 * false negative would let get_writable_address() hand back a
	 * pool slot that no longer resolves to a tracked mapping. */
	for (i = 0; i < nr_shared_regions_overflow; i++) {
		unsigned long rstart = shared_regions_overflow[i].addr;
		unsigned long rend = rstart + shared_regions_overflow[i].size;

		if (addr >= rstart && end <= rend)
			return true;
	}
	return false;
}

void * __zmalloc(size_t size, const char *func)
{
	void *p;

	p = malloc(size);
	if (p == NULL) {
		/* Maybe we mlockall'd everything. Try and undo that, and retry. */
		munlockall();
		p = malloc(size);
		if (p != NULL)
			goto done;

		outputerr("%s: malloc(%zu) failure.\n", func, size);
		exit(EXIT_FAILURE);
	}

done:
	memset(p, 0, size);
	deferred_alloc_track(p);
	return p;
}

/*
 * Ownership table for syscall handlers that snapshot state into a
 * zmalloc'd struct hung off rec->post_state.  Currently only execve /
 * execveat use it, but the API is shape-agnostic so any post handler
 * that needs the same guarantee can call in.
 *
 * Background: rec->post_state is private to the post handler in the
 * syscall ABI sense, but the whole syscallrecord is reachable from
 * sibling fuzz writes -- a value-result write that lands on the
 * post_state slot can redirect it to a different, smaller heap
 * allocation that another syscall's own post_state owns.  The
 * post handler then copies sizeof(struct ...) bytes out of the foreign
 * chunk and trips an OOB read.
 *
 * The original guard against this was malloc_usable_size(snap) <
 * sizeof(*snap), which reads glibc's chunk-header allocation size.
 * That works under glibc but is undefined behaviour on a
 * non-malloc-owned pointer; libsanitizer treats it as a runtime error
 * and aborts the child with a SIGABRT cascade -- the guard meant to
 * catch sibling-stomp redirection becomes the new crash site under
 * ASAN.
 *
 * Replace the chunk-header probe with an explicit ownership table:
 * each handler registers its post_state pointer at allocation time and
 * unregisters before the deferred_freeptr() that releases it.  A snap
 * value that doesn't appear in the table cannot be a chunk we
 * produced, so the post handler bails without dereferencing.  The
 * lookup is pure pointer comparison -- well-defined under both glibc
 * and ASAN.
 *
 * Storage layout: 64-slot fixed pointer table in BSS, COW-shared at
 * fork, written single-threaded by the owning child.  No locking
 * needed.  Each child has at most one in-flight execve post_state at a
 * time (syscalls execute sequentially within a child), so the typical
 * working set is 0-1 entries; 64 slots leaves ample headroom for
 * collision tolerance and silent-drop on the rare table-full case.
 *
 * Hash: top bits of the pointer above glibc's 16-byte chunk
 * alignment.  Open addressing with linear probing for insert.  Lookup
 * and delete scan the table (bounded by POST_STATE_TABLE_SIZE) instead
 * of stopping at the first NULL slot, so a delete-induced gap can't
 * truncate a collision chain and leave a registered pointer
 * unreachable.  The scan cost is a couple of cache lines on the hot
 * path (per-syscall post handler) -- the typical hit lands at the
 * hash slot on the first probe.
 *
 * Scope: this is for the post_state ownership question specifically,
 * not a general validator for every __zmalloc() return.  Wrap the
 * allocation site at each interested caller rather than hooking
 * __zmalloc itself -- the vast majority of zmalloc callers don't need
 * this and the indirection cost would be wasted.
 */
#define POST_STATE_TABLE_SIZE	64
#define POST_STATE_TABLE_MASK	(POST_STATE_TABLE_SIZE - 1)

static void *post_state_table[POST_STATE_TABLE_SIZE];

static unsigned int post_state_hash(const void *p)
{
	return (unsigned int) (((uintptr_t) p >> 4) & POST_STATE_TABLE_MASK);
}

void post_state_register(void *p)
{
	unsigned int idx;
	unsigned int i;

	if (p == NULL)
		return;

	idx = post_state_hash(p);
	for (i = 0; i < POST_STATE_TABLE_SIZE; i++) {
		if (post_state_table[idx] == NULL) {
			post_state_table[idx] = p;
			return;
		}
		if (post_state_table[idx] == p)
			return;
		idx = (idx + 1) & POST_STATE_TABLE_MASK;
	}
	/*
	 * Table full: silently drop the registration.  Lookup will miss,
	 * the post handler will bail without dereferencing (leaks the
	 * chunk), and the child turns over fast enough that the leak is
	 * benign.  Failing safe beats failing hard here.
	 */
}

void post_state_unregister(void *p)
{
	unsigned int idx;
	unsigned int i;

	if (p == NULL)
		return;

	idx = post_state_hash(p);
	for (i = 0; i < POST_STATE_TABLE_SIZE; i++) {
		if (post_state_table[idx] == p) {
			post_state_table[idx] = NULL;
			return;
		}
		idx = (idx + 1) & POST_STATE_TABLE_MASK;
	}
}

bool post_state_is_owned(const void *p)
{
	unsigned int idx;
	unsigned int i;

	if (p == NULL)
		return false;

	idx = post_state_hash(p);
	for (i = 0; i < POST_STATE_TABLE_SIZE; i++) {
		if (post_state_table[idx] == p)
			return true;
		idx = (idx + 1) & POST_STATE_TABLE_MASK;
	}
	return false;
}

void sizeunit(unsigned long size, char *buf, size_t buflen)
{
	/* non kilobyte aligned size? */
	if (size < 1024) {
		snprintf(buf, buflen, "%lu bytes", size);
		return;
	}

	/* < 1MB ? */
	if (size < (1024 * 1024)) {
		snprintf(buf, buflen, "%luKB", size / 1024);
		return;
	}

	/* < 1GB ? */
	if (size < (1024 * 1024 * 1024)) {
		snprintf(buf, buflen, "%luMB", (size / 1024) / 1024);
		return;
	}

	snprintf(buf, buflen, "%luGB", ((size / 1024) / 1024) / 1024);
}

void kill_pid(pid_t pid)
{
	int ret;
	int childno;

	if (pid == -1) {
		show_backtrace();
		syslogf("kill_pid tried to kill -1!\n");
		return;
	}
	if (pid == 0) {
		show_backtrace();
		syslogf("tried to kill_pid 0!\n");
		return;
	}

	childno = find_childno(pid);
	if (childno != CHILD_NOT_FOUND) {
		if (children[childno]->dontkillme == true)
			return;
	}

	ret = kill(pid, SIGKILL);
	if (ret != 0)
		debugf("couldn't kill pid %d [%s]\n", pid, strerror(errno));
}

void freeptr(unsigned long *p)
{
	void *ptr = (void *) *p;

	if (ptr != NULL)
		free(ptr);
	*p = 0L;
}

/*
 * looks_like_corrupted_ptr - heuristic test for "this slot used to hold
 * a pointer we malloc'd, but somebody scribbled a non-pointer over it".
 *
 * Cluster-1 / cluster-2 / cluster-3 crash signature (residual-cores
 * triage 2026-05-02): si_addr in the killing siginfo equals si_pid (e.g.
 * si_addr=0x378a02 against pid 0x378a02).  The shape comes from a fuzzed
 * value-result syscall in some sibling child landing in trinity-internal
 * memory -- rec->aN, a struct field reachable from rec->aN, or a slot in
 * the deferred-free ring -- and overwriting a pointer that a post handler
 * was about to deref or pass to free(), with the kernel-issued tid/pid
 * value.  The deferred-free ring already mprotects between ticks so a
 * scribble there now SIGSEGVs in copy_from_user, but the rec-> path is
 * unprotected by construction (the kernel must be able to write into
 * rec->aN -- that's the whole point).
 *
 * Three rejection bands, all heuristic:
 *
 *   - v < 0x10000:  cannot be a real heap pointer.  PIDs (pid_max is
 *     typically 4 million on Linux) and small ints land here.  This is
 *     the same gate deferred_free_tick() uses as a belt-and-braces
 *     check at free time; we want to reject earlier so the ring slot
 *     never holds a bogus value at all.
 *
 *   - v >= (1UL << 47):  above the x86_64 user canonical limit.  glibc
 *     malloc / mmap / brk hand out addresses well below this; a value
 *     here is either a kernel pointer leaked back (bug regardless of
 *     post-handler state) or a tornadic write of a high-bit pattern.
 *
 *   - v & 0x7:  misaligned for an 8-byte pointer.  Every trinity heap
 *     allocator (zmalloc, alloc_iovec, get_writable_*, alloc_object)
 *     hands back >= 8-byte aligned memory.  A misaligned value in a
 *     slot we expect to free is almost certainly a partial overwrite.
 *
 * False positive cost: a legitimate-but-weird pointer would be dropped
 * (memory leak), not freed.  A leak in a post handler is benign --
 * children turn over fast and the heap evaporates at exit.  The
 * alternative (false negative) is the cluster-1/2/3 SIGSEGV class we
 * are trying to kill, so we err strict.  Audited against current post
 * handlers (deferred_freeptr, deferred_free_enqueue callers, direct
 * free() on rec->aN): every pointer those receive is heap-allocated
 * via 8-byte aligned routines, so the misalign band is safe at all
 * present call sites.  If a future caller is shown to legitimately
 * pass an unaligned value, drop the alignment check rather than
 * dropping the others.
 *
 * Returns true if the pointer looks scribbled and the caller should
 * drop it instead of dereferencing or freeing.
 */
/*
 * Update this child's per-handler attribution shard for a
 * post_handler_corrupt_ptr rejection.  Linear scan of the 32-entry shard:
 * if @nr is already present we bump its count; otherwise the lowest-count
 * slot is evicted in favour of the new key.  Eviction stays child-local,
 * so global LRU ordering across the fleet is lost on the long tail; the
 * parent merges every child's shard at dump time and the hot handlers
 * still surface in the top rows because they land in every shard.
 *
 * Each child is the sole writer of its own shard, so no lock is needed.
 * The parent is the sole reader and only at periodic-dump time -- torn
 * reads on the dump side may shave a count by one off a single shard
 * slot, which is in the noise once 32 shards are merged.
 *
 * this_child()==NULL callers (parent post-mortem paths, deferred-free
 * tick on the main process) have no shard to bump and drop the record.
 */
static void corrupt_ptr_attr_record(unsigned int nr, bool do32bit)
{
	struct childdata *child = this_child();
	struct corrupt_ptr_attr_entry *ring;
	unsigned int i, victim;
	unsigned long victim_count;

	if (child == NULL)
		return;

	ring = child->local_corrupt_ptr_attr;

	for (i = 0; i < CORRUPT_PTR_ATTR_SLOTS; i++) {
		if (ring[i].count != 0 &&
		    ring[i].nr == nr && ring[i].do32bit == do32bit) {
			ring[i].count++;
			return;
		}
	}

	victim = 0;
	victim_count = ring[0].count;
	for (i = 1; i < CORRUPT_PTR_ATTR_SLOTS; i++) {
		if (ring[i].count < victim_count) {
			victim = i;
			victim_count = ring[i].count;
		}
		if (victim_count == 0)
			break;
	}

	ring[victim].nr = nr;
	ring[victim].do32bit = do32bit;
	ring[victim].count = victim_count + 1;
}

/*
 * Record a (nr, do32bit, pc) triple into this child's per-callsite
 * sub-attribution shard.  Same eviction policy as corrupt_ptr_attr_record:
 * bump the matching slot if present, otherwise displace the lowest-count
 * slot.  No lock for the same reason -- the owning child is the sole
 * writer.  Skipped when pc==NULL (defensive -- a caller without a usable
 * return address has no useful PC to record) or when this_child() returns
 * NULL (no shard to bump).
 */
static void corrupt_ptr_pc_record(unsigned int nr, bool do32bit, void *pc,
				  const char *site)
{
	struct childdata *child = this_child();
	struct corrupt_ptr_pc_entry *ring;
	unsigned int i, victim;
	unsigned long victim_count;

	if (pc == NULL || child == NULL)
		return;

	ring = child->local_corrupt_ptr_pc;

	for (i = 0; i < CORRUPT_PTR_PC_SLOTS; i++) {
		if (ring[i].count != 0 &&
		    ring[i].nr == nr && ring[i].do32bit == do32bit &&
		    ring[i].pc == pc) {
			ring[i].count++;
			/* Late-arriving site tag for an existing entry — fill
			 * it in so the dump can disambiguate even when the
			 * first bump for this PC came through a tagless caller
			 * (e.g. the legacy macro wrapper with site=NULL). */
			if (ring[i].site == NULL && site != NULL)
				ring[i].site = site;
			return;
		}
	}

	victim = 0;
	victim_count = ring[0].count;
	for (i = 1; i < CORRUPT_PTR_PC_SLOTS; i++) {
		if (ring[i].count < victim_count) {
			victim = i;
			victim_count = ring[i].count;
		}
		if (victim_count == 0)
			break;
	}

	ring[victim].nr = nr;
	ring[victim].do32bit = do32bit;
	ring[victim].pc = pc;
	ring[victim].site = site;
	ring[victim].count = victim_count + 1;
}

void post_handler_corrupt_ptr_bump_site(struct syscallrecord *rec,
					void *caller_pc, const char *site)
{
	struct childdata *child;
	unsigned int nr;
	bool do32bit;

	/* Headline aggregate routes through the per-child stats_ring on
	 * the child path (parent drain accumulates into parent_stats).
	 * Parent-context callers (post-mortem paths, deferred-free tick
	 * on the main process) bump parent_stats directly since the
	 * parent is the sole writer in that case. */
	child = this_child();
	if (child != NULL && child->stats_ring != NULL)
		stats_ring_enqueue(child->stats_ring,
				   STATS_FIELD_POST_HANDLER_CORRUPT_PTR, 0, 1);
	else
		parent_stats.post_handler_corrupt_ptr++;

	/* Per-child shadow of the same event, scored by the storm-rate
	 * check in child_process.  Stays per-child (not in shm) -- the
	 * storm check reads it directly off childdata. */
	if (child != NULL)
		child->local_post_handler_corrupt_ptr++;

	if (rec != NULL) {
		nr = rec->nr;
		do32bit = rec->do32bit;
	} else {
		nr = CORRUPT_PTR_ATTR_NR_NONE;
		do32bit = false;
	}
	corrupt_ptr_pc_record(nr, do32bit, caller_pc, site);
	corrupt_ptr_attr_record(nr, do32bit);
}

/*
 * Record a caller PC into this child's deferred_free_reject sub-attribution
 * shard.  Same eviction policy and ownership model as corrupt_ptr_pc_record
 * -- the owning child is the sole writer of its own shard, so no lock is
 * needed; the parent merges every child's shard at dump time.  Skipped when
 * pc==NULL (defensive -- a caller without a usable return address has no
 * useful PC to record) or when this_child() returns NULL (parent post-mortem
 * path, deferred-free tick on the main process -- no shard to bump).
 * Slimmer key than corrupt_ptr_pc_record because every bump originates from
 * rec==NULL deferred_free_enqueue calls so (nr, do32bit) carry no
 * information.
 */
static void deferred_free_reject_pc_record(void *pc)
{
	struct childdata *child = this_child();
	struct deferred_free_reject_pc_entry *ring;
	unsigned int i, victim;
	unsigned long victim_count;

	if (pc == NULL || child == NULL)
		return;

	ring = child->local_deferred_free_reject_pc;

	for (i = 0; i < CORRUPT_PTR_PC_SLOTS; i++) {
		if (ring[i].count != 0 && ring[i].pc == pc) {
			ring[i].count++;
			return;
		}
	}

	victim = 0;
	victim_count = ring[0].count;
	for (i = 1; i < CORRUPT_PTR_PC_SLOTS; i++) {
		if (ring[i].count < victim_count) {
			victim = i;
			victim_count = ring[i].count;
		}
		if (victim_count == 0)
			break;
	}

	ring[victim].pc = pc;
	ring[victim].count = victim_count + 1;
}

void deferred_free_reject_bump(void *caller_pc)
{
	struct childdata *child = this_child();

	if (child != NULL && child->stats_ring != NULL)
		stats_ring_enqueue(child->stats_ring,
				   STATS_FIELD_DEFERRED_FREE_REJECT, 0, 1);
	else
		parent_stats.deferred_free_reject++;
	deferred_free_reject_pc_record(caller_pc);
}

__attribute__((noinline))
void post_handler_corrupt_ptr_bump_rzs(struct syscallrecord *rec)
{
	post_handler_corrupt_ptr_bump_site(rec, __builtin_return_address(0),
					   "handle_syscall_ret:rzs_blanket");
}

__attribute__((noinline))
void post_handler_corrupt_ptr_bump_retfd(struct syscallrecord *rec)
{
	post_handler_corrupt_ptr_bump_site(rec, __builtin_return_address(0),
					   "handle_syscall_ret:retfd_invalid");
}

/*
 * Categorise a rejected pointer value into one of four heuristic bands
 * so the sample log line tells us at a glance whether the rejection is
 * obvious noise (NULL-ish, pid-shaped, kernel-VA leak) or whether the
 * value sits in the heap-shape range and the shape heuristic itself is
 * the false positive.  The pid_max ceiling of 4194304 (the kernel
 * default for 64-bit boots) is used for the pid-shaped band so a stray
 * tid lands here even though it would also satisfy v >= 0x10000.
 */
static const char *corrupt_ptr_label(unsigned long v)
{
	if (v < 0x10000)
		return "NULL-ish";
	if (v < 4194304)
		return "pid-shaped";
	if (v >= 0x800000000000UL)
		return "kernel-VA";
	return "heap-shaped";
}

/*
 * Sample-rate for the per-rejection log line.  At the observed sustained
 * rate of ~900 rejections/min a 1-in-100 sample emits roughly nine lines
 * per minute -- enough to characterise the value distribution without
 * flooding the log faster than the operator can read it.
 */
#define CORRUPT_PTR_SAMPLE_INTERVAL	100

bool looks_like_corrupted_ptr_pc(struct syscallrecord *rec, const void *p,
				 void *caller_pc)
{
	unsigned long v = (unsigned long) p;
	unsigned long n;

	if (!is_corrupt_ptr_shape(p))
		return false;

	post_handler_corrupt_ptr_bump(rec, caller_pc);

	/*
	 * Sample every CORRUPT_PTR_SAMPLE_INTERVALth rejection.  Counter
	 * is shm-resident so the sample cadence is fleet-global rather than
	 * per-child -- a host with 32 children would otherwise emit 32x the
	 * sample volume.  RELAXED ordering: the sample is opportunistic;
	 * losing one to a torn read between siblings does not matter.
	 */
	n = __atomic_add_fetch(&shm->stats.corrupt_ptr_sample_seq, 1,
			       __ATOMIC_RELAXED);
	if ((n % CORRUPT_PTR_SAMPLE_INTERVAL) == 1) {
		const char *name;
		char pcbuf[128];

		if (rec != NULL)
			name = print_syscall_name(rec->nr, rec->do32bit);
		else
			name = "<deferred-free>";

		output(0, "corrupt-ptr reject sample: syscall=%s value=0x%lx "
			  "label=%s caller=%s\n",
			  name, v, corrupt_ptr_label(v),
			  pc_to_string(__builtin_return_address(0),
				       pcbuf, sizeof(pcbuf)));
	}
	return true;
}

bool inner_ptr_ok_to_free(struct syscallrecord *rec, const void *p,
			  const char *site)
{
	unsigned long v = (unsigned long) p;

	if (p == NULL)
		return false;

	if (!looks_like_corrupted_ptr(rec, p))
		return true;

	/*
	 * Heap-shaped but misaligned -- the exact band that bypasses the
	 * outer-ptr alignment guard (because the outer ptr passes) but
	 * trips libasan's PoisonShadow CHECK once the inner field reaches
	 * free().  Surface it explicitly so log scanners can correlate the
	 * interception with the asan_poisoning.cpp:37 crash signature; the
	 * per-handler attribution ring already names the syscall via rec.
	 */
	if (v >= 0x10000 && (v & 0x7) != 0)
		outputerr("%s: rejected misaligned heap-shaped inner ptr=0x%lx "
			  "(libasan PoisonShadow trigger; scribbled?)\n",
			  site, v);
	return false;
}

/*
 * Cached extent of the brk()-managed glibc arena, captured once at
 * init time from /proc/self/maps.  COW-shared into every forked
 * child, so a single pre-fork parse seeds the whole fleet.  heap_start
 * is stable for the lifetime of the process (the brk base doesn't
 * move), but heap_end is only a snapshot -- a child that extends brk
 * post-fork (millions of iterations of getline in /proc parsers,
 * libasan shadow growth, heavy zmalloc traffic) sails past it, so
 * consumers also consult sbrk(0) for the current break.  Zero start
 * means we never found a [heap] line; in that case is_in_glibc_heap()
 * falls back to "always true" so we don't reject legitimate frees on
 * platforms or builds where glibc has chosen an mmap-only allocation
 * strategy and the brk arena is empty.
 */
static unsigned long heap_start;
static unsigned long heap_end;

/*
 * Cached extents of non-brk allocator arenas, captured alongside the
 * [heap] line at heap_bounds_init() time.  glibc's mmap'd arenas, the
 * sanitiser-runtime allocator reservations (libasan primary/secondary
 * at 0x511000000000+, the shadow region, ...), scudo / jemalloc /
 * tcmalloc -- every well-behaved allocator labels its anonymous
 * mappings via prctl(PR_SET_VMA_ANON_NAME), which shows up in
 * /proc/self/maps as "[anon:NAME]" after the inode column.  Trinity
 * itself does not label any of its scratch mappings, so an
 * "[anon:*]" tag in the pre-fork snapshot identifies a region whose
 * contents must not be overwritten by a fuzzed kernel-write
 * argument (the alternative is a write into glibc / libasan chunk
 * metadata, surfacing later as an arena-corruption abort or an
 * ASAN bad-free).
 *
 * 16 entries comfortably covers the regions seen on a libasan-built
 * trinity under glibc 2.39 (one [heap], two glibc mmap arenas, four
 * libasan shadow / allocator regions); an overflow logs once and
 * leaves the trailing regions unprotected -- the wrong direction for
 * safety, so the cap exists to be hit and bumped if a future libsan
 * layout adds more regions.
 */
#define MAX_EXTRA_HEAP_REGIONS	16
static struct {
	unsigned long start;
	unsigned long end;
} extra_heap_regions[MAX_EXTRA_HEAP_REGIONS];
static unsigned int nr_extra_heap_regions;

/*
 * Parse a /proc/self/maps line just enough to extract the
 * [start, end), the perms field, and the trailing path/label.  Returns
 * true on success.  The label pointer (which may be NULL or point at
 * the empty string) is written into *label_out; it points into @line,
 * which the caller owns.
 *
 * A line looks like:
 *   55a1b3c00000-55a1b3c21000 rw-p 00000000 00:00 0   [heap]
 *   7f2c1b400000-7f2c1b421000 rw-p 00000000 00:00 0   [anon:libc_malloc]
 *   55a1b3a00000-55a1b3a21000 rw-p 00000000 00:00 0
 * i.e. start-end perms offset major:minor inode optional-label.
 */
static bool parse_maps_line(char *line, unsigned long *start_out,
			    unsigned long *end_out, char perms_out[5],
			    const char **label_out)
{
	unsigned long start, end;
	char perms[8];
	int label_off = -1;
	const char *label;
	char *nl;

	nl = strchr(line, '\n');
	if (nl != NULL)
		*nl = '\0';

	if (sscanf(line, "%lx-%lx %7s %*x %*x:%*x %*u %n",
		   &start, &end, perms, &label_off) < 3)
		return false;
	if (end <= start)
		return false;

	if (label_off < 0 || (size_t) label_off > strlen(line))
		label = "";
	else
		label = line + label_off;

	*start_out = start;
	*end_out = end;
	memcpy(perms_out, perms, 4);
	perms_out[4] = '\0';
	*label_out = label;
	return true;
}

/*
 * Parse /proc/self/maps once and stash the brk arena plus every
 * labeled non-brk allocator region.  Must be called before fork; the
 * results are read by every child via the inherited COW BSS.
 *
 * If the [heap] line is missing (rare: glibc tuned to
 * MALLOC_MMAP_THRESHOLD_=0 or the binary somehow hasn't grown brk
 * yet), heap_start stays 0 and is_in_glibc_heap() falls back to
 * "always true" -- we'd rather permit a marginal free than reject
 * every malloc result on a misconfigured host.
 */
void heap_bounds_init(void)
{
	FILE *f;
	char line[512];

	f = fopen("/proc/self/maps", "r");
	if (f == NULL) {
		outputerr("heap_bounds_init: open /proc/self/maps failed: %s\n",
			  strerror(errno));
		return;
	}

	while (fgets(line, sizeof(line), f) != NULL) {
		unsigned long start, end;
		char perms[5];
		const char *label;

		if (!parse_maps_line(line, &start, &end, perms, &label))
			continue;

		/*
		 * Only writable private mappings can hold allocator
		 * metadata that the kernel scribbling would corrupt.
		 * Read-only and shared mappings either can't be written
		 * by the kernel (r-- / r-x) or are trinity-controlled
		 * (MAP_SHARED via alloc_shared / track_shared_region,
		 * handled separately by range_overlaps_shared()).
		 */
		if (perms[1] != 'w' || perms[3] != 'p')
			continue;

		if (strncmp(label, "[heap]", 6) == 0 &&
		    (label[6] == '\0' || label[6] == ' ')) {
			heap_start = start;
			heap_end = end;
			continue;
		}

		/*
		 * "[anon:NAME]" labels come from
		 * prctl(PR_SET_VMA_ANON_NAME) -- glibc malloc tags its
		 * mmap'd arenas, libasan tags its primary / secondary
		 * allocator and shadow reservations, similarly for
		 * scudo / jemalloc / tcmalloc.  Trinity never labels
		 * its own anonymous mappings, so any "[anon:*]" line
		 * in the snapshot belongs to a non-trinity allocator.
		 * Trinity's BSS, stack, vdso, vvar, file-backed
		 * mappings and unlabeled scratch regions are filtered
		 * out by the perms / label tests above.
		 */
		if (strncmp(label, "[anon:", 6) != 0)
			continue;

		if (nr_extra_heap_regions >= MAX_EXTRA_HEAP_REGIONS) {
			static bool warned;

			if (!warned) {
				warned = true;
				outputerr("heap_bounds_init: "
					"MAX_EXTRA_HEAP_REGIONS (%d) reached "
					"-- '%s' and any subsequent allocator "
					"regions are unprotected; raise the "
					"cap\n",
					MAX_EXTRA_HEAP_REGIONS, label);
			}
			continue;
		}

		extra_heap_regions[nr_extra_heap_regions].start = start;
		extra_heap_regions[nr_extra_heap_regions].end = end;
		nr_extra_heap_regions++;
	}

	fclose(f);
}

/*
 * Bounds check: is @p inside the cached glibc brk arena?  Two
 * compares, branch-predictable, no syscalls.  Returns true if the
 * heap extent is unknown (init never found a [heap] line) so the
 * caller treats the validator as permissive in that case.
 *
 * Backstop for the bad-free class where a sibling stomp scribbles a
 * snapshot/arg slot with a value that defeats both the pointer-shape
 * heuristic (looks_like_corrupted_ptr) and -- in the worst case --
 * coincidentally matches a tracked malloc result still resident in
 * the alloc-track ring.  An attacker-controlled or wildly-stomped
 * value that lands outside the brk arena entirely (stack, shared
 * region, mmap'd library, executable mapping) is rejected here even
 * if the upstream guards let it through.
 */
bool is_in_glibc_heap(const void *p)
{
	unsigned long v = (unsigned long) p;
	unsigned long end, cur;

	if (heap_start == 0)
		return true;

	/*
	 * heap_end is a pre-fork snapshot.  A long-running child can
	 * extend brk past it, so consult sbrk(0) for the live break;
	 * brk only grows in the steady state, so the larger of the two
	 * is the live upper bound.  Guard against sbrk failure -- the
	 * (void *)-1 sentinel cast to unsigned long would over-include
	 * every address.
	 */
	end = heap_end;
	cur = (unsigned long) sbrk(0);
	if (cur != (unsigned long) -1 && cur > end)
		end = cur;

	return v >= heap_start && v < end;
}

/*
 * Range-overlap variant of is_in_glibc_heap() with the opposite
 * unknown-bounds polarity: returns true when [addr, addr+len)
 * intersects the cached brk arena or any captured non-brk allocator
 * region (glibc mmap arenas, libasan primary / secondary / shadow,
 * scudo / jemalloc / tcmalloc tagged regions -- see
 * extra_heap_regions[] above).  Used by avoid_shared_buffer() to
 * redirect output-buffer syscall args away from any allocator-managed
 * memory: a fuzzed pointer pointing there lets the kernel scribble
 * chunk metadata, and the next malloc anywhere in trinity finds the
 * corruption and aborts (the cluster from the overnight asan-self-
 * kill triage).  Mirrors range_overlaps_shared() semantics: a single
 * byte of overlap is enough to redirect, and a fully unknown layout
 * (no [heap] line and no captured allocator regions) is treated as
 * no-overlap so we don't redirect every legitimate write.
 */
bool range_overlaps_libc_heap(unsigned long addr, unsigned long len)
{
	unsigned long end, hend, cur;
	unsigned int i;

	/* Treat wrapped ranges as overlapping so callers reject them. */
	if (len != 0 && addr > ULONG_MAX - len)
		return true;

	end = addr + len;
	if (end == addr)
		end = addr + 1;

	if (heap_start != 0) {
		/*
		 * Same brk-grew-past-snapshot story as
		 * is_in_glibc_heap().  Missing the redirect here is
		 * the safety-critical failure mode: a fuzzed pointer
		 * landing in the brk extension above the cached
		 * heap_end gets through avoid_shared_buffer(), the
		 * kernel scribbles glibc chunk metadata in the
		 * extension, and the next malloc in the child aborts.
		 */
		hend = heap_end;
		cur = (unsigned long) sbrk(0);
		if (cur != (unsigned long) -1 && cur > hend)
			hend = cur;

		if (addr < hend && end > heap_start)
			return true;
	}

	/*
	 * Walk the captured non-brk allocator regions.  Each entry is
	 * a fixed [start, end) snapshot from heap_bounds_init() -- the
	 * underlying VMAs are large pre-reservations (libasan's primary
	 * allocator at 0x511000000000+ is one ~16 TiB reservation, glibc
	 * mmap arenas are a few MiB each) whose bounds don't move at
	 * runtime, so a one-shot snapshot is sufficient.  Post-fork
	 * secondary mmaps (large mallocs that bypass the primary
	 * allocator into one-VMA-per-alloc) can land outside the
	 * snapshot, but the dominant failure mode this guards against
	 * is sibling stomp on a co-located primary-allocator chunk that
	 * holds inner pointers (the recvmmsg msg_control bad-free), and
	 * that lives in the captured primary-allocator VMA.
	 */
	for (i = 0; i < nr_extra_heap_regions; i++) {
		if (addr < extra_heap_regions[i].end &&
		    end > extra_heap_regions[i].start)
			return true;
	}

	return false;
}

void sanitize_inherited_fds(void)
{
	DIR *dir;
	struct dirent *de;
	int dir_fd;

	dir = opendir("/proc/self/fd");
	if (dir == NULL) {
		outputerr("sanitize_inherited_fds: opendir(/proc/self/fd) failed: %s\n",
			  strerror(errno));
		return;
	}
	dir_fd = dirfd(dir);

	while ((de = readdir(dir)) != NULL) {
		char linkpath[64];
		char target[PATH_MAX];
		char *endp;
		ssize_t n;
		long fdl;
		int fd;

		if (de->d_name[0] == '.')
			continue;

		errno = 0;
		fdl = strtol(de->d_name, &endp, 10);
		if (errno != 0 || *endp != '\0' || fdl < 0 || fdl > INT_MAX)
			continue;
		fd = (int) fdl;

		/* Always keep stdin/stdout/stderr. */
		if (fd <= 2)
			continue;

		/* Skip the readdir() handle itself; closedir() will release
		 * it once the walk completes. */
		if (fd == dir_fd)
			continue;

		n = -1;
		if ((size_t) snprintf(linkpath, sizeof(linkpath),
				      "/proc/self/fd/%d", fd) < sizeof(linkpath))
			n = readlink(linkpath, target, sizeof(target) - 1);
		if (n < 0)
			n = 0;
		target[n] = '\0';

		outputerr("sanitize_inherited_fds: closing unexpected inherited fd %d (%s)\n",
			  fd, n > 0 ? target : "?");

		close(fd);
		if (shm != NULL)
			__atomic_add_fetch(&shm->stats.parent_inherited_fds_closed,
					   1, __ATOMIC_RELAXED);
	}
	closedir(dir);
}

int get_num_fds(void)
{
	struct linux_dirent64 {
		uint64_t       d_ino;
		int64_t        d_off;
		unsigned short d_reclen;
		unsigned char  d_type;
		char           d_name[];
	};
	char path[64];
	char buf[4096];
	int fd, fd_count = 0;
	long nread, pos;

	snprintf(path, sizeof(path), "/proc/%i/fd", mainpid);

	fd = open(path, O_RDONLY | O_DIRECTORY);
	if (fd == -1)
		return 0;

	while ((nread = syscall(SYS_getdents64, fd, buf, sizeof(buf))) > 0) {
		for (pos = 0; pos < nread; ) {
			struct linux_dirent64 *de = (struct linux_dirent64 *)(buf + pos);
			const char *name = de->d_name;

			/* Skip "." and ".." */
			if (!(name[0] == '.' &&
			      (name[1] == '\0' ||
			       (name[1] == '.' && name[2] == '\0'))))
				fd_count++;

			pos += de->d_reclen;
		}
	}

	close(fd);
	return fd_count;
}
