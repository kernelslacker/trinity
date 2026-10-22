#pragma once

/*
 * Sizing constants of the deferred-free queue (persist/deferred-free.c),
 * shared with tests/deferred_free_test.c so its arithmetic follows the
 * production values.  Not part of the public API in deferred-free.h.
 */

#define DEFERRED_RING_SIZE	64

/*
 * Decrement-and-free runs 1-in-N ticks (N power-of-two -> bitmask);
 * the other N-1 bail before the mprotect bracket.  Effective TTL is
 * thus ~N x the 5-50 nominal (80-800 syscalls) -- intentional
 * headroom for UAF overlap.
 */
#define DEFERRED_TICK_BATCH	16

/* 4096 slots.  Long-lived MMAP_ANON pool entries must stay tracked
 * until their child cycle completes, or get_map_handle's
 * alloc_track_lookup gate false-rejects legitimate slots and burns
 * retry budget.  4096 holds those pool entries plus recent
 * zmalloc_tracked churn without rotating live entries out from under
 * the lookup. */
#define ALLOC_TRACK_SIZE	4096
