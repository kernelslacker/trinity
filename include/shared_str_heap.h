#pragma once

#include <stddef.h>

/*
 * Shared-string heap allocator.
 *
 * A size-classed slab carved out of MAP_SHARED memory so that string
 * payloads reachable from parent-published objects survive fork().  See
 * the block comment at the top of utils/shared_str_heap.c for the full
 * lifecycle and rationale; this header exposes only the caller surface.
 *
 * alloc_shared_str / alloc_shared_strdup / free_shared_str live in
 * include/utils-mem.h next to the sibling shared-region allocator; the
 * declarations below are the internals a self-test or in-tree consumer
 * needs to reach.
 */

/*
 * Reset the allocator to its pre-init state.  Intended for the unit
 * test binary, which drives the allocator across many alloc/free
 * cycles without any of the surrounding trinity lifecycle -- the heap
 * (and its metadata table) get freshly re-mmap'd on the next
 * allocation.  A no-op if the heap was never initialised.
 *
 * MUST NOT be called from production trinity: the bump cursor,
 * freelist heads, and per-slot bucket record all live in MAP_SHARED
 * memory that children have inherited pointers into; blowing them
 * away mid-run would dangle every live shared-string pointer in the
 * fleet.  The test binary is the only caller because it is a
 * single-process harness with no forks.
 */
void shared_str_heap_reset_for_test(void);
