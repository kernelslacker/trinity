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
 * Enqueue a pointer for deferred freeing.  Always released with free()
 * when the entry's TTL expires; the function-pointer parameter was
 * removed to eliminate the ROP/JOP surface a corrupted ring entry's
 * free_func slot would otherwise hand an attacker.
 */
void deferred_free_enqueue(void *ptr);

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
