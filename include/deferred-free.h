#pragma once

#include <stdbool.h>

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
 * Record a heap pointer that may later be passed back through
 * deferred_free_enqueue().  Called from __zmalloc() so every malloc
 * result trinity ever produces is registered without needing per-site
 * opt-in.  Pointers are kept in a small per-process ring (LRU eviction);
 * deferred_free_enqueue() consumes the matching entry to confirm the
 * pointer is a real malloc result before queuing it for free().
 *
 * Process-local — must be called after fork inherits the COW heap.
 * NULL is silently ignored.
 */
void deferred_alloc_track(void *ptr);

/*
 * Non-consuming probe: returns true if @ptr was returned by a recent
 * __zmalloc() and still sits in the alloc-track ring.  Lets readers
 * that hold a stored pointer (e.g. an object-pool slot) validate it
 * against the live malloc-result set BEFORE the first deref, without
 * perturbing the consume-on-free invariant deferred_free_enqueue
 * relies on.  Returns false if the pointer was never tracked, was
 * already consumed, or was evicted by ring rollover.
 */
bool alloc_track_lookup(void *ptr);

/*
 * Enqueue a pointer for deferred freeing.  free_func is called when
 * the entry's TTL expires; pass NULL to use free().
 */
void deferred_free_enqueue(void *ptr, void (*free_func)(void *));

/*
 * Drop-in replacement for freeptr(): saves the pointer value, zeros
 * the source field, and enqueues for deferred free(). */
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
