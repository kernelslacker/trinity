#pragma once

#include <stdbool.h>

#include "compiler.h"
#include "syscall.h"

/*
 * Deferred-free queue for syscall argument allocations.
 *
 * Instead of freeing sanitise-allocated memory immediately in post
 * callbacks, we queue it for delayed release after a random number of
 * additional syscalls (5-50).  This creates temporal overlap between
 * allocations, increasing the chance of finding UAF / stale-reference /
 * double-free bugs in the kernel.
 *
 * The queue is process-local — each forked child has its own copy.
 * No locking required.
 */

void deferred_free_init(void);

/*
 * Record a heap pointer that will later be passed back through
 * deferred_free_enqueue() / deferred_freeptr().  Opt-in: called
 * from zmalloc_tracked() (and any other allocation site that intends
 * deferred-free ownership), NOT unconditionally from __zmalloc().
 * Pointers are kept in a small per-process ring (LRU eviction);
 * deferred_free_enqueue() consumes the matching entry to confirm the
 * pointer is a real malloc result before queuing it for free().
 *
 * Process-local — must be called after fork inherits the COW heap.
 * NULL is silently ignored.
 */
void deferred_alloc_track(void *ptr);

/*
 * Non-consuming probe: returns true if @ptr was registered via
 * deferred_alloc_track() (typically via zmalloc_tracked) and still
 * sits in the alloc-track ring.  Lets readers that hold a stored
 * pointer (e.g. an object-pool slot) validate it against the live
 * tracked-allocation set BEFORE the first deref, without perturbing
 * the consume-on-free invariant deferred_free_enqueue relies on.
 * Returns false if the pointer was never tracked, was already
 * consumed, or was evicted by ring rollover.
 */
bool alloc_track_lookup(void *ptr) __must_check;

/*
 * Refresh an existing tracked allocation's LRU position.  Use this
 * when an already-tracked pointer is re-referenced (mm/maps.c dedup-skip,
 * objects.c add_object OBJ_LOCAL pool touch) and you want it
 * to survive subsequent LRU rotation.  Safe if @ptr was already
 * rotated out (acts as a fresh insert).  See alloc_track_refresh()
 * in deferred-free.c for the design rationale.
 */
void alloc_track_refresh(void *ptr);

/*
 * tracked_free_now() removes ptr from alloc_track[] LRU and
 * alloc_track_hash[], then calls free().  Use this when a caller
 * wants to synchronously dispose of a zmalloc_tracked() allocation
 * instead of routing it through the deferred ring.  Direct free() on
 * a tracked pointer leaves a stale entry behind that subsequent
 * alloc_track_lookup() callers (OBJ_LOCAL validation, deferred-free
 * gating) will falsely accept; this helper keeps the side-set in
 * lock-step with the heap.
 *
 * Safe to call with NULL.
 */
void tracked_free_now(void *ptr);

/*
 * Enqueue a pointer for deferred freeing.  Always released with free()
 * when the entry's TTL expires; the function-pointer parameter was
 * removed to eliminate the ROP/JOP surface a corrupted ring entry's
 * free_func slot would otherwise hand an attacker.
 *
 * Under VMA / ENOMEM / ring-full pressure the queue cannot admit the
 * pointer; this variant falls back to a SYNCHRONOUS free() in that
 * case so the caller's "no longer your problem" contract holds.  Use
 * this from .post handlers and other post-dispatch sites where the
 * kernel has already consumed the buffer — the sync free is safe
 * because nothing is about to read the memory.  For pre-dispatch
 * callers (sanitise sites that enqueue a buffer the kernel/post
 * handler still needs to deref), use deferred_free_enqueue_or_leak
 * instead.
 */
void deferred_free_enqueue(void *ptr);

/*
 * Pre-dispatch variant of deferred_free_enqueue.  Same NULL / shape /
 * heap-bounds / shared-region / alloc-track gates and same ring-admit
 * path on the success case; ONLY the under-pressure fallback paths
 * differ.  Where deferred_free_enqueue() falls back to a synchronous
 * free() under VMA / ENOMEM / ring-full pressure, this variant
 * INTENTIONALLY LEAKS — does nothing, returns — and lets the child's
 * eventual exit reclaim the buffer.
 *
 * Use this when the caller does NOT yet own the buffer's lifecycle:
 *
 *   - sanitise enqueues a buffer that the kernel is about to read or
 *     write during the syscall (io_uring_params, openat2 how,
 *     perf_event_attr, sched_attr, mount_attr, file_attr,
 *     xattr_args, ns_id_req, mnt_id_req, landlock_ruleset_attr, ...);
 *
 *   - sanitise enqueues a post_state snap that the .post handler
 *     still needs to deref after the syscall returns (mq_open snap).
 *
 * The plain deferred_free_enqueue() is correct for post-dispatch
 * sites where the buffer has already been consumed (.post handlers,
 * teardown helpers); the synchronous-free fallback is safe there
 * because no one is about to read the memory.  At a pre-dispatch
 * site, that same sync free becomes a use-after-free: the syscall
 * sanitiser returned "queued for later" but the buffer was actually
 * freed before the kernel got to read it.
 *
 * The leak is bounded by the child's per-process rlimits and
 * max_map_count; trinity child lifetimes are short, so a buffer
 * leaked on the pressure path is reclaimed by the kernel when the
 * child exits.  A bounded leak is a strictly better failure mode
 * than a kernel-side UAF on the input buffer.
 */
void deferred_free_enqueue_or_leak(void *ptr);

/*
 * Save the pointer value, zero the source field, and enqueue the
 * saved value for deferred free().
 */
void deferred_freeptr(unsigned long *p);

/*
 * Tick the queue — called once per syscall iteration.  Decrements TTLs
 * and frees any entries that have expired.
 */
void deferred_free_tick(void);

/*
 * Flush the entire queue — free everything immediately.
 * Called on child exit.
 */
void deferred_free_flush(void);

/*
 * Tag the argtype currently being processed by the generic_free_arg
 * cleanup loop, so deferred_free_reject_bump can attribute rejects to
 * the cleanup hook that drove them.  Set to the argtype just before
 * ops->cleanup() is called and reset to ARG_UNDEFINED immediately
 * after.  Direct (non-cleanup-loop) callers leave the tag at
 * ARG_UNDEFINED so their rejects fall into the OTHER shard.
 */
void deferred_free_set_cleanup_argtype(enum argtype t);
enum argtype deferred_free_get_cleanup_argtype(void);
