#pragma once

#include <sys/types.h>
#include <sys/mman.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define MB(_x) ((_x) * 1024UL * 1024UL)
#define GB(_x) ((_x) * 1024UL * MB(1))

#define MAX_SHARED_ALLOCS 4096

/*
 * Reserve slots in shared_regions[] that are not consumed by per-child
 * growth (struct shm_s, syscalltable copy, kcov rings, image segments,
 * shared obj/str heaps, deferred-free, pids/children index pages, etc.).
 * Anything left after this reserve is the budget for per-child allocs.
 */
#define SHARED_REGIONS_GLOBAL_RESERVE 256

/*
 * Per-child shared allocations: childdata + fd_event_ring (see init_shm).
 * The cap formula in derive_max_children_cap() divides the remaining
 * shared_regions[] budget by this number.
 */
#define SHARED_REGIONS_PER_CHILD 2

extern unsigned int nr_shared_regions;

void * alloc_shared(size_t size);
void * alloc_shared_global(size_t size);

/*
 * Checked size = a * b for shared-allocation call sites with a variable
 * count multiplier (max_children, files_in_index, syscall table size).
 * Returns true and writes the product when it fits in size_t; returns
 * false on overflow without touching *out.  Callers are expected to
 * outputerr() and bail on a false return -- truncated size would let
 * a downstream alloc succeed with a buffer too small for the indexing
 * the caller is about to do.
 */
bool shared_size_mul(size_t a, size_t b, size_t *out);
void * alloc_shared_obj(size_t size);
void free_shared_obj(void *p, size_t size);
void * alloc_shared_str(size_t size);
char * alloc_shared_strdup(const char *src);
void free_shared_str(void *p, size_t size);
void freeze_global_objects(void);
void thaw_global_objects(void);
bool globals_are_protected(void);
bool range_overlaps_shared(unsigned long addr, unsigned long len);
void track_shared_region(unsigned long addr, unsigned long size);
void register_loaded_image_segments(void);
void dump_obj_heap_stats(void);
size_t obj_heap_get_capacity(void);

/*
 * Log an mprotect() failure as:
 *   mprotect(addr=%p, len=%zu, prot=0x%x [READ|WRITE|EXEC]) failed at
 *   <binary>+0xOFFSET: <strerror>
 *
 * `caller` should be __builtin_return_address(0) from the call site so
 * the resolved PC points back through the wrapper to the strategy that
 * triggered the mprotect.  `err` is the captured errno value.
 */
void log_mprotect_failure(void *addr, size_t len, int prot,
			  void *caller, int err);

void * __zmalloc(size_t size, const char *func);
#define zmalloc(size)	__zmalloc(size, __func__)

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define min(x, y) ({				\
	typeof(x) _min1 = (x);			\
	typeof(y) _min2 = (y);			\
	(void) (&_min1 == &_min2);		\
	_min1 < _min2 ? _min1 : _min2; })

#define max(x, y) ({				\
	typeof(x) _max1 = (x);			\
	typeof(y) _max2 = (y);			\
	(void) (&_max1 == &_max2);		\
	_max1 > _max2 ? _max1 : _max2; })

#ifndef offsetof
# define offsetof(type, member)	((size_t) &((type *) 0)->member)
#endif

#define container_of(ptr, type, member) ({                      \
	const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
	(type *)( (char *)__mptr - offsetof(type,member) );})

/*
 * swap - swap value of @a and @b
 */
#define swap(a, b) \
	do { typeof(a) __tmp = (a); (a) = (b); (b) = __tmp; } while (0)

#define MAX_ERRNO 4095
#define IS_ERR_VALUE(x) ((x) >= (unsigned long)-MAX_ERRNO)
static inline long IS_ERR(unsigned long x)
{
	return IS_ERR_VALUE(x);
}

void sizeunit(unsigned long size, char *buf, size_t buflen);

void kill_pid(pid_t pid);

void freeptr(unsigned long *p);

/*
 * Heuristic: does `p` look like a fuzzed value-result syscall scribbled
 * a non-pointer (typically a pid/tid or a small int) into a slot trinity
 * was about to deref or free?  Returns true if the value cannot plausibly
 * be a heap pointer we handed out.  See utils.c for the rationale and
 * the cluster-1/2/3 crash signature this guards against.
 *
 * @rec is the syscallrecord context the call originates from, used for
 * per-handler attribution of the global post_handler_corrupt_ptr counter.
 * Pass NULL when called outside a syscall post-handler (e.g. from inside
 * deferred_free_enqueue) -- those rejections fold into a single
 * pseudo-handler bucket in the attribution ring.  The caller is expected
 * to log its own descriptive outputerr() line; this function only handles
 * the heuristic decision and the bookkeeping that follows it.
 */
struct syscallrecord;
bool looks_like_corrupted_ptr(struct syscallrecord *rec, const void *p);

/*
 * Variant that additionally records @caller_pc into the deferred-free
 * sub-attribution ring on a positive (rec==NULL) result.  Use this from
 * the rec==NULL site inside deferred_free_enqueue so the dump can break
 * the deferred-free pseudo-handler row down by call site; pass
 * __builtin_return_address(0) so the recorded PC identifies the caller
 * of deferred_free_enqueue rather than deferred_free_enqueue itself.
 * The plain looks_like_corrupted_ptr() above is a thin wrapper that
 * calls this with caller_pc=NULL -- syscall post-handler callers do
 * not need PC attribution, the (nr, do32bit) row already names them.
 */
bool looks_like_corrupted_ptr_pc(struct syscallrecord *rec, const void *p,
				 void *caller_pc);

/*
 * Bump the post_handler_corrupt_ptr counter and record per-handler
 * attribution.  Use directly only at sites that detect corruption via a
 * mechanism other than looks_like_corrupted_ptr (e.g. the alloc-track
 * ring miss inside deferred_free_enqueue) -- shape-heuristic callers
 * should go through looks_like_corrupted_ptr() above, which calls this
 * internally on a positive result.  rec==NULL for non-syscall callers.
 *
 * @caller_pc, when non-NULL on the rec==NULL path, additionally feeds a
 * caller-PC sub-attribution ring so the deferred-free pseudo-handler
 * row of the per-handler dump can be broken down by call site.  Pass
 * NULL when caller-site attribution is irrelevant (rec!=NULL paths
 * already get per-syscall attribution) or unavailable.
 */
void post_handler_corrupt_ptr_bump(struct syscallrecord *rec, void *caller_pc);

/*
 * Inner-pointer-field free guard for post handlers that walk a
 * snapshotted struct (msghdr / mmsghdr / etc.) and free its inner
 * pointer fields.  The OUTER snapshot pointer is alignment-checked at
 * handler entry, but the inner pointer fields live in the snapshotted
 * struct's heap bytes and can be partially overwritten by a sibling
 * syscall that scribbles bytes into that allocation.  A scribble that
 * preserves the high bits (still heap-shaped) but clobbers the low byte
 * leaves a misaligned heap-shaped value, which then trips libasan's
 * PoisonShadow alignment CHECK at asan_poisoning.cpp:37 once it reaches
 * free().
 *
 * Returns true if @p is safe to hand to free().  NULL is treated as a
 * legitimate "field not populated" value (e.g. msg_name when no
 * sockaddr was generated, msg_control when sanitise_*msg chose not to
 * populate it) and does not count as a rejection.  When the rejected
 * value matches the libasan-CHECK trigger band -- heap-shaped
 * (>= 0x10000) but misaligned ((v & 0x7) != 0) -- emit an outputerr()
 * line tagged with @site so the interception is visible in logs and
 * the per-PC attribution ring (post_handler_corrupt_ptr) names the
 * offending field.
 */
bool inner_ptr_ok_to_free(struct syscallrecord *rec, const void *p,
			  const char *site);

/*
 * Cache the [heap] extent from /proc/self/maps.  Call once before
 * fork; every child inherits the cached bounds via COW BSS.
 */
void heap_bounds_init(void);

/*
 * Bounds check: is @p inside the cached glibc brk arena?  Returns
 * true if the heap extent is unknown (validator is permissive in
 * that case so a misconfigured init can't reject every legitimate
 * free).  Cheap: two compares, no syscalls.
 */
bool is_in_glibc_heap(const void *p);

/*
 * Range-overlap variant for the avoid_shared_buffer() redirect path.
 * Returns true only when [addr, addr+len) intersects the cached brk
 * arena AND the bounds were captured (unknown arena -> false, so we
 * never redirect every write on a misconfigured init).
 */
bool range_overlaps_libc_heap(unsigned long addr, unsigned long len);

int get_num_fds(void);

/*
 * Walk /proc/self/fd at parent startup and close any fd that wasn't
 * deliberately opened by trinity.  Run once, before trinity opens any
 * of its own fds — at that point the keep set is exactly {0, 1, 2}
 * and everything else came in from the launcher (or its parent).
 *
 * Defense in depth against the wedge class where an inherited fd for
 * a stuck filesystem (FUSE, NFS, etc.) ends up adopted into one of
 * trinity's per-child watch sets and a routine syscall on it blocks
 * for the lifetime of the run — stalling the parent's reap path and
 * letting zombie children pile up indefinitely.
 *
 * Bumps shm->stats.parent_inherited_fds_closed for each fd closed,
 * and logs the fd number plus its readlink target so the operator
 * can see what the launcher left behind.
 */
void sanitize_inherited_fds(void);

#define __stringify_1(x...)     #x
#define __stringify(x...)       __stringify_1(x)

#define unreachable() __builtin_unreachable()

#define likely(x)	__builtin_expect(!!(x), 1)
#define unlikely(x)	__builtin_expect(!!(x), 0)

#define RAND_ELEMENT(_array, _element) \
	_array[rand() % ARRAY_SIZE(_array)]._element

#define RAND_ARRAY(_array) _array[rand() % ARRAY_SIZE(_array)]

#define IS_ALIGNED(x, a)	(((x) & ((typeof(x))(a) - 1)) == 0)
