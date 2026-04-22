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
#include "debug.h"
#include "pids.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/*
 * Use this allocator if you have an object a child writes to that you want
 * all other processes to see.
 *
 * Every allocation is tracked so that VM syscalls (munmap, madvise, mremap,
 * mprotect) can avoid clobbering trinity's own shared state.
 */

#define MAX_SHARED_ALLOCS 512

static struct {
	unsigned long addr;
	unsigned long size;
	bool is_global_obj;
} shared_regions[MAX_SHARED_ALLOCS];
static unsigned int nr_shared_regions;

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
		outputerr("alloc_shared: MAX_SHARED_ALLOCS (%d) reached, "
			"region %p won't be tracked by range_overlaps_shared()\n",
			MAX_SHARED_ALLOCS, ret);
	}

	return ret;
}

void * alloc_shared(unsigned int size)
{
	return __alloc_shared(size, false);
}

/*
 * Allocate shared memory for global object data (list heads, parallel
 * arrays, etc.).  Tagged so freeze_global_objects() can mprotect just
 * these regions PROT_READ once init is done — children that stray-write
 * into the global object pool then SIGSEGV at the source instead of
 * silently corrupting list pointers.
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
 * silently corrupting struct object list_heads — which is the bug
 * class that previously surfaced as parent crashes inside list_del
 * traversals.  Parent-side mutations (alloc_shared_obj, free_shared_obj,
 * list_add via add_object, list_del via __destroy_object, plus the
 * regen path's field writes) all happen under the existing
 * thaw/refreeze brackets in fd_event_drain_all, add_object,
 * remove_object_by_fd, and destroy_global_objects.  Pre-freeze init
 * runs unprotected, which is when init_*_fds populates the heap.
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
 * they own the same slot; both fill it with list_head links, and at exit
 * the iteration walks a corrupted chain and faults inside __destroy_object
 * (list_del with NULL prev/next from a slot that the other owner has since
 * zeroed via free_shared_obj's poison-on-free).
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
		if (p != NULL)
			return p;
		/*
		 * Round bump-allocated slots up to the bucket's size so
		 * adjacent slots in the bump region are bucket_size bytes
		 * apart.  Without this the bump cursor advances by `size`
		 * (e.g. 88 for sizeof(struct object)) but freelist_push and
		 * freelist_pop both memset the full bucket_size (128), so
		 * the first free of a bump slot wholesale-zeroes the first
		 * (bucket_size - size) bytes of the next slot — corrupting
		 * its list_head and surfacing as a "back-link broken"
		 * crash deep inside list_del or list_add later.  Bug class
		 * was masked while the obj heap was unprotected (wild
		 * writes from child syscalls swamped the signal); became
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
	return p;
}

void free_shared_obj(void *p, size_t size)
{
	int bucket;

	if (p == NULL || size == 0)
		return;

	/*
	 * Catch the most common allocator-side misuse: free-while-still-on-a-
	 * list.  The next list_del that walks past the freed slot will see
	 * a fully-zeroed neighbor (freelist_push memsets the slot) and trip
	 * the debug-list back-link check — but that diagnostic fires at the
	 * *unlucky* call site, not the buggy one.  This check fires here, at
	 * the bad free, with the offending caller still on the backtrace.
	 *
	 * We don't know the slot's struct shape from p alone, so heuristically
	 * treat it as a leading struct list_head and only abort when both
	 * fields look like real heap pointers (the unambiguous signature of
	 * a live linked entry).  Small ints (e.g. struct chain_entry's `len`
	 * + step nr at offsets 0/8), NULLs, self-references, and POISON
	 * values all skip past safely.
	 */
	if (size >= sizeof(struct list_head)) {
		struct list_head *fake = p;
		struct list_head *next = fake->next;
		struct list_head *prev = fake->prev;

		if ((uintptr_t)next > 0x100000000UL &&
		    (uintptr_t)prev > 0x100000000UL &&
		    next != LIST_POISON1 && prev != LIST_POISON2 &&
		    next != fake && prev != fake) {
			outputerr("free_shared_obj: slot %p (size=%zu) appears "
				"to be currently linked: list.next=%p list.prev=%p "
				"— caller forgot to list_del before free\n",
				p, size, next, prev);
			__BUG("free_shared_obj: slot is list-linked",
				__FILE__, __func__, __LINE__);
		}
	}

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

static bool global_objects_protected;

static void mprotect_global_obj_regions(int prot)
{
	unsigned int i;

	for (i = 0; i < nr_shared_regions; i++) {
		if (!shared_regions[i].is_global_obj)
			continue;
		if (mprotect((void *) shared_regions[i].addr,
			     shared_regions[i].size, prot) != 0) {
			outputerr("mprotect_global_obj_regions: failed for %p (%lu bytes, prot=%d): %s\n",
				  (void *) shared_regions[i].addr,
				  shared_regions[i].size, prot,
				  strerror(errno));
		}
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

bool range_overlaps_shared(unsigned long addr, unsigned long len)
{
	unsigned long end = addr + len;
	unsigned int i;

	for (i = 0; i < nr_shared_regions; i++) {
		unsigned long r_start = shared_regions[i].addr;
		unsigned long r_end = r_start + shared_regions[i].size;

		if (addr < r_end && end > r_start)
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
