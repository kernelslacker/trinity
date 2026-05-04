#include <stdbool.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
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
	bool is_global_obj;
} shared_regions[MAX_SHARED_ALLOCS];
unsigned int nr_shared_regions;

/*
 * Fire once when shared_regions[] first runs out of slots.  Per-call
 * outputerr() would spam stderr from inside init_shm()'s for_each_child
 * loop on a host whose max_children pushes the table past capacity --
 * one warning is enough to flag the overflow class and tell the operator
 * to either raise MAX_SHARED_ALLOCS or move the table to dynamic resize.
 */
static void note_shared_overflow(const char *who, const void *addr)
{
	static bool warned;

	if (warned)
		return;
	warned = true;
	outputerr("%s: MAX_SHARED_ALLOCS (%d) reached at region %p; "
		"this and later regions are untracked -- raise "
		"MAX_SHARED_ALLOCS or move shared_regions[] to dynamic "
		"resize\n",
		who, MAX_SHARED_ALLOCS, addr);
}

static void * __alloc_shared(unsigned int size, bool is_global_obj)
{
	void *ret;

	ret = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, -1, 0);
	if (ret == MAP_FAILED) {
		outputerr("mmap %u failure\n", size);
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
		shared_regions[nr_shared_regions].is_global_obj = is_global_obj;
		nr_shared_regions++;
	} else {
		note_shared_overflow("alloc_shared", ret);
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
		shared_regions[nr_shared_regions].is_global_obj = false;
		nr_shared_regions++;
	} else {
		note_shared_overflow("track_shared_region", (const void *)addr);
	}
}

void * alloc_shared(unsigned int size)
{
	return __alloc_shared(size, false);
}

/*
 * Allocate shared memory for global object data (parallel arrays, obj
 * structs themselves, etc.).  Tagged so freeze_global_objects() can
 * mprotect just these regions PROT_READ once init is done — children
 * that stray-write into the global object pool then SIGSEGV at the
 * source instead of silently corrupting parent state.
 */
void * alloc_shared_global(unsigned int size)
{
	return __alloc_shared(size, true);
}

/*
 * Shared obj heap — backing store for individual obj structs that need
 * to be readable from any process.
 *
 * Why a pre-allocated pool instead of one mmap per object?  An
 * mmap(MAP_SHARED|MAP_ANON) issued post-fork by the parent creates a
 * fresh tmpfs-backed mapping that already-forked children have no
 * page-table entry for; following the pointer SIGSEGVs in the child.
 * The only way a single allocator can serve both pre-fork init AND
 * post-fork regen with cross-process visibility is to map the backing
 * region once before any child forks, then carve allocations out of
 * that region.  Children inherit the mapping at fork time and see
 * subsequent parent writes via ordinary shared-memory semantics.
 *
 * The backing region is tagged is_global_obj=true so
 * freeze_global_objects() mprotects it PROT_READ once init is done.
 * Children that wild-write through a stray syscall buffer pointer
 * targeting an obj slot then EFAULT inside the kernel rather than
 * silently corrupting parent state.  Parent-side mutations
 * (alloc_shared_obj, free_shared_obj, add_object's array publish,
 * __destroy_object's swap-with-last, plus the regen path's field
 * writes) all happen under the existing thaw/refreeze brackets in
 * fd_event_drain_all, add_object, remove_object_by_fd, and
 * destroy_global_objects.  Pre-freeze init runs unprotected, which
 * is when init_*_fds populates the heap.
 *
 * The chain corpus was the one child-side writer; commit f43e89c779f1
 * inlined its slots into chain_corpus_shm so the obj heap is now
 * exclusively a parent write target.
 *
 * Size: 4 MiB at ~150 B per struct object gives ~28k slots — far
 * larger than GLOBAL_OBJ_MAX_CAPACITY (1024) per type even if every
 * type were converted, with ample headroom for the freelist recycler
 * below.  Allocations too large for any freelist bucket still bump-and-
 * leak, but those are rare (obj structs are well under 1024 bytes).
 */
#define SHARED_OBJ_HEAP_SIZE (4U * 1024U * 1024U)

static char *shared_obj_heap;
static size_t shared_obj_heap_capacity;

static void shared_obj_heap_init(void)
{
	/*
	 * First call must come from the parent before any child forks,
	 * otherwise the mapping won't be in the child's address space.
	 * In practice the first caller is an init_*_fds() function
	 * driven by open_fds(), which runs before fork_children().
	 * We keep the lazy-init form (instead of an explicit hook in
	 * init_shm) because it keeps the contract local to this file.
	 */
	shared_obj_heap_capacity = SHARED_OBJ_HEAP_SIZE;
	shared_obj_heap = alloc_shared_global(shared_obj_heap_capacity);
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
static void *freelist_pop(_Atomic uint64_t *head, size_t slot_size)
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
static void freelist_push(_Atomic uint64_t *head, void *p, size_t slot_size)
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

void * alloc_shared_obj(size_t size)
{
	size_t old_used, new_used;
	void *p;
	int bucket;
	void *caller = __builtin_return_address(0);
	char pcbuf[128];

	if (size == 0)
		return NULL;

	if (shared_obj_heap == NULL)
		shared_obj_heap_init();

	/* Round up so each allocation starts pointer-aligned. */
	size = (size + sizeof(void *) - 1) & ~(sizeof(void *) - 1);

	/* Try the freelist before touching the bump cursor. */
	bucket = freelist_bucket(size);
	if (bucket >= 0) {
		p = freelist_pop(&shm->shared_obj_freelist[bucket],
				 bucket_sizes[bucket]);
		if (p != NULL) {
			__atomic_add_fetch(&shm->stats.obj_heap_allocs, 1,
					   __ATOMIC_RELAXED);
			output(2, "[shm-alloc] alloc obj p=%p sz=%zu caller=%s\n",
				p, size,
				pc_to_string(caller, pcbuf, sizeof(pcbuf)));
			return p;
		}
		/*
		 * Round bump-allocated slots up to the bucket's size so
		 * adjacent slots in the bump region are bucket_size bytes
		 * apart.  Without this the bump cursor advances by `size`
		 * (e.g. 88 for sizeof(struct object)) but freelist_push and
		 * freelist_pop both memset the full bucket_size (128), so
		 * the first free of a bump slot wholesale-zeroes the first
		 * (bucket_size - size) bytes of the next slot — corrupting
		 * the next allocation's leading fields and surfacing as
		 * mysterious crashes on the consumer side.  Bug class was
		 * masked while the obj heap was unprotected (wild writes
		 * from child syscalls swamped the signal); became
		 * deterministic the moment fbce60744dfb mprotected the
		 * heap and removed all the other corruption sources.
		 */
		size = bucket_sizes[bucket];
	}

	/*
	 * Freelist empty or size above all buckets — fall through to bump.
	 * Lock-free bump via CAS.  shm->shared_obj_heap_used lives in
	 * the SHM region, so concurrent allocators in any process see a
	 * single source of truth.  RELAXED ordering is enough: the
	 * returned pointer's contents are published downstream by the
	 * caller's add_object() RELEASE-store on num_entries, and that
	 * is what synchronises with consumers in get_random_object().
	 */
	old_used = __atomic_load_n(&shm->shared_obj_heap_used,
				   __ATOMIC_RELAXED);
	do {
		new_used = old_used + size;
		if (new_used > shared_obj_heap_capacity) {
			outputerr("alloc_shared_obj: heap exhausted "
				  "(cap %zu, used %zu, req %zu)\n",
				  shared_obj_heap_capacity, old_used,
				  size);
			return NULL;
		}
	} while (!__atomic_compare_exchange_n(&shm->shared_obj_heap_used,
					      &old_used, new_used,
					      false,
					      __ATOMIC_RELAXED,
					      __ATOMIC_RELAXED));

	p = shared_obj_heap + old_used;
	memset(p, 0, size);
	__atomic_add_fetch(&shm->stats.obj_heap_allocs, 1, __ATOMIC_RELAXED);
	output(2, "[shm-alloc] alloc obj p=%p sz=%zu caller=%s\n",
		p, size, pc_to_string(caller, pcbuf, sizeof(pcbuf)));
	return p;
}

void free_shared_obj(void *p, size_t size)
{
	int bucket;
	void *caller = __builtin_return_address(0);
	char pcbuf[128];

	if (p == NULL || size == 0)
		return;

	__atomic_add_fetch(&shm->stats.obj_heap_frees, 1, __ATOMIC_RELAXED);
	output(2, "[shm-alloc] free obj p=%p sz=%zu caller=%s\n",
		p, size, pc_to_string(caller, pcbuf, sizeof(pcbuf)));

	size = (size + sizeof(void *) - 1) & ~(sizeof(void *) - 1);

	bucket = freelist_bucket(size);
	if (bucket >= 0) {
		freelist_push(&shm->shared_obj_freelist[bucket], p,
			      bucket_sizes[bucket]);
		return;
	}

	/* Size above all buckets — poison and leak (bump-and-leak fallback). */
	memset(p, 0, size);
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
	 * before fork_children()).
	 *
	 * Tagged is_global_obj=true so freeze_global_objects() mprotects
	 * the region PROT_READ once init is done.  Same defence as the
	 * obj heap (commit fbce60744dfb): a child syscall whose user-
	 * pointer arg aliases into a slot here would otherwise let the
	 * kernel scribble through it and silently corrupt a name string,
	 * a perf_event_attr replay buffer, or an OBJ_MMAP_ANON map name —
	 * surfacing later as a libc string-fn SEGV in the parent's dump
	 * path or as a perf_event_open EINVAL once the cached eventattr
	 * stops parsing.  The freeze closes that wild-write surface.
	 *
	 * Parent-side writers (alloc_shared_str, alloc_shared_strdup,
	 * free_shared_str, plus caller snprintf/memcpy into freshly-
	 * allocated slots) all run from the same paths the obj heap
	 * commit already covered: pre-freeze init_*_fds(), and post-
	 * freeze regen via try_regenerate_fd() inside fd_event_drain_all
	 * or remove_object_by_fd's outer thaw bracket.  No new brackets
	 * needed — every existing alloc_shared_strdup site is paired
	 * with an alloc_shared_obj() in the same function, and those
	 * sites are exactly the ones the obj heap freeze already
	 * established as safe. */
	shared_str_heap_capacity = SHARED_STR_HEAP_SIZE;
	shared_str_heap = alloc_shared_global(shared_str_heap_capacity);
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

void log_mprotect_failure(void *addr, size_t len, int prot,
			  void *caller, int err)
{
	char protbuf[32];
	char pcbuf[128];

	prot_to_string(prot, protbuf, sizeof(protbuf));
	outputerr("mprotect(addr=%p, len=%zu, prot=0x%x [%s]) failed at %s: %s\n",
		  addr, len, prot, protbuf,
		  pc_to_string(caller, pcbuf, sizeof(pcbuf)),
		  strerror(err));
}

static bool global_objects_protected;

static void mprotect_global_obj_regions(int prot)
{
	unsigned int i;

	for (i = 0; i < nr_shared_regions; i++) {
		void *addr;
		size_t len;

		if (!shared_regions[i].is_global_obj)
			continue;

		addr = (void *) shared_regions[i].addr;
		len = (size_t) shared_regions[i].size;
		if (mprotect(addr, len, prot) != 0)
			log_mprotect_failure(addr, len, prot,
					     __builtin_return_address(0),
					     errno);
	}
}

void freeze_global_objects(void)
{
	mprotect_global_obj_regions(PROT_READ);
	global_objects_protected = true;
}

void thaw_global_objects(void)
{
	mprotect_global_obj_regions(PROT_READ | PROT_WRITE);
	global_objects_protected = false;
}

bool globals_are_protected(void)
{
	return global_objects_protected;
}

/*
 * Dump current obj-heap accounting under -vv: bytes consumed by the
 * bump allocator, the bucket-size table, and the depth of each
 * freelist bucket measured by walking it.  The walk traverses one
 * pointer per slot so it is O(depth) per bucket; gated tightly
 * because deep buckets (post heavy regen churn) can be expensive.
 *
 * Helps debug "is the recycler actually recycling?" — a busy run with
 * many obj allocs but consistently empty buckets means free_shared_obj
 * is not being called for most slots; the bump cursor will then race
 * shared_obj_heap_capacity and eventually exhaust the heap.
 */
/*
 * Read-side accessor for the obj-heap capacity, which is otherwise file-
 * static.  dump_stats() reads it (alongside shm->shared_obj_heap_used and
 * the alloc/free counters) to print a one-line pressure summary under -v.
 */
size_t obj_heap_get_capacity(void)
{
	return shared_obj_heap_capacity;
}

void dump_obj_heap_stats(void)
{
	unsigned int i;
	size_t used;
	char usedbuf[32], capbuf[32];

	if (verbosity <= 2)
		return;

	used = __atomic_load_n(&shm->shared_obj_heap_used, __ATOMIC_RELAXED);
	sizeunit(used, usedbuf, sizeof(usedbuf));
	sizeunit(shared_obj_heap_capacity, capbuf, sizeof(capbuf));
	output(0, "obj heap: used=%s / cap=%s (%zu / %zu bytes)\n",
		usedbuf, capbuf, used, shared_obj_heap_capacity);

	for (i = 0; i < NUM_SHM_FREELIST_BUCKETS; i++) {
		uint64_t tagged;
		uintptr_t ptr;
		unsigned int depth = 0;

		tagged = __atomic_load_n(&shm->shared_obj_freelist[i],
					 __ATOMIC_RELAXED);
		ptr = (uintptr_t)(tagged & FREELIST_PTR_MASK);
		/* Walk the singly-linked freelist; each slot's first word
		 * holds the next pointer (no version bits — those live only
		 * in the head). */
		while (ptr != 0 && depth < 1000000) {
			depth++;
			ptr = *(uintptr_t *)ptr;
		}
		output(0, "  freelist[%zuB]: depth=%u\n",
			bucket_sizes[i], depth);
	}
}

/* Tunable: how often range_overlaps_shared() emits a -v summary line.
 * Lower = noisier, higher = blunter. */
#define RANGE_OVERLAPS_SHARED_REJECT_REPORT_INTERVAL 10000

/* Last syscall to trip a range_overlaps_shared() reject.  Last-write-wins;
 * a coarse hint for which sanitiser is doing the most work, not a precise
 * audit trail.  No lock — torn reads are acceptable for a diagnostic. */
static unsigned int last_reject_syscall_nr;
static unsigned char last_reject_do32bit;
static unsigned char last_reject_have_syscall;

bool range_overlaps_shared(unsigned long addr, unsigned long len)
{
	unsigned long end = addr + len;
	unsigned int i;

	for (i = 0; i < nr_shared_regions; i++) {
		unsigned long r_start = shared_regions[i].addr;
		unsigned long r_end = r_start + shared_regions[i].size;

		if (addr < r_end && end > r_start) {
			unsigned long n;
			struct childdata *child;

			n = __atomic_add_fetch(&shm->stats.range_overlaps_shared_rejects,
					       1, __ATOMIC_RELAXED);

			child = this_child();
			if (child != NULL) {
				unsigned int nr = child->syscall.nr;
				bool do32 = child->syscall.do32bit;

				if (nr < MAX_NR_SYSCALL) {
					unsigned long *bucket = do32 ?
						&shm->stats.range_overlaps_shared_rejects_per_syscall_32[nr] :
						&shm->stats.range_overlaps_shared_rejects_per_syscall_64[nr];
					__atomic_add_fetch(bucket, 1, __ATOMIC_RELAXED);
				}

				__atomic_store_n(&last_reject_syscall_nr,
						 nr, __ATOMIC_RELAXED);
				__atomic_store_n(&last_reject_do32bit,
						 do32 ? 1 : 0,
						 __ATOMIC_RELAXED);
				__atomic_store_n(&last_reject_have_syscall, 1,
						 __ATOMIC_RELAXED);
			}

			if (verbosity > 1 &&
			    (n % RANGE_OVERLAPS_SHARED_REJECT_REPORT_INTERVAL) == 0) {
				const char *sname = "?";
				unsigned int snr;
				unsigned char s32;

				if (__atomic_load_n(&last_reject_have_syscall,
						    __ATOMIC_RELAXED)) {
					snr = __atomic_load_n(&last_reject_syscall_nr,
							      __ATOMIC_RELAXED);
					s32 = __atomic_load_n(&last_reject_do32bit,
							      __ATOMIC_RELAXED);
					sname = print_syscall_name(snr, s32 != 0);
				}

				output(1, "range_overlaps_shared: %lu cumulative rejects "
					"(latest syscall=%s addr=0x%lx len=%lu)\n",
					n, sname, addr, len);
			}
			return true;
		}
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
 * Update the per-handler attribution ring for a post_handler_corrupt_ptr
 * rejection.  Linear scan of the 32-entry ring: if @nr is already present
 * we bump its count; otherwise the lowest-count slot is evicted in favour
 * of the new key.  Eviction churn at steady state is bounded -- once the
 * ring is full of the genuinely-hot handlers, a new low-rate offender
 * displaces another low-rate offender and the high-rate slots stay put.
 *
 * Single coarse lock around the whole update: contention is limited to
 * actual rejection events, which by construction are rare relative to
 * the per-syscall hot path; the cost of a spin here is dwarfed by the
 * per-rejection outputerr() the caller is about to emit.  The lock is
 * also taken on the bump-existing path so a concurrent eviction cannot
 * race with the increment and lose the bump.
 */
static void corrupt_ptr_attr_record(unsigned int nr, bool do32bit)
{
	struct corrupt_ptr_attr_entry *ring = shm->stats.corrupt_ptr_attr;
	unsigned int i, victim;
	unsigned long victim_count;

	lock(&shm->stats.corrupt_ptr_attr_lock);

	for (i = 0; i < CORRUPT_PTR_ATTR_SLOTS; i++) {
		if (ring[i].count != 0 &&
		    ring[i].nr == nr && ring[i].do32bit == do32bit) {
			ring[i].count++;
			unlock(&shm->stats.corrupt_ptr_attr_lock);
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

	unlock(&shm->stats.corrupt_ptr_attr_lock);
}

void post_handler_corrupt_ptr_bump(struct syscallrecord *rec)
{
	unsigned int nr;
	bool do32bit;

	__atomic_add_fetch(&shm->stats.post_handler_corrupt_ptr, 1, __ATOMIC_RELAXED);

	if (rec != NULL) {
		nr = rec->nr;
		do32bit = rec->do32bit;
	} else {
		nr = CORRUPT_PTR_ATTR_NR_NONE;
		do32bit = false;
	}
	corrupt_ptr_attr_record(nr, do32bit);
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

bool looks_like_corrupted_ptr(struct syscallrecord *rec, const void *p)
{
	unsigned long v = (unsigned long) p;
	unsigned long n;

	if (v >= 0x10000 && v < (1UL << 47) && (v & 0x7) == 0)
		return false;

	post_handler_corrupt_ptr_bump(rec);

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

/*
 * Cached extent of the brk()-managed glibc arena, captured once at
 * init time from /proc/self/maps.  COW-shared into every forked child
 * (the heap address range stays stable across fork -- the kernel just
 * marks the pages CoW), so a single pre-fork parse covers the whole
 * fleet.  Zero start means we never found a [heap] line; in that case
 * is_in_glibc_heap() falls back to "always true" so we don't reject
 * legitimate frees on platforms or builds where glibc has chosen an
 * mmap-only allocation strategy and the brk arena is empty.
 */
static unsigned long heap_start;
static unsigned long heap_end;

/*
 * Parse /proc/self/maps once and stash the [heap] extent.  Must be
 * called before fork; the result is read by every child via the
 * inherited COW BSS.  The [heap] line in /proc/self/maps looks like:
 *   55a1b3c00000-55a1b3c21000 rw-p 00000000 00:00 0   [heap]
 * Two hex addresses separated by '-', followed by perms and the
 * trailing path component being the literal string "[heap]".
 *
 * If the line is missing (rare: glibc tuned to MALLOC_MMAP_THRESHOLD_=0
 * or the binary somehow hasn't grown brk yet), heap_start stays 0 and
 * the validator becomes a no-op -- we'd rather permit a marginal free
 * than reject every malloc result on a misconfigured host.
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

		if (strstr(line, "[heap]") == NULL)
			continue;
		if (sscanf(line, "%lx-%lx", &start, &end) != 2)
			continue;
		if (end <= start)
			continue;

		heap_start = start;
		heap_end = end;
		break;
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

	if (heap_start == 0)
		return true;
	return v >= heap_start && v < heap_end;
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
