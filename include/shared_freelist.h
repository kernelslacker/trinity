#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Fixed-size, ABA-safe, lock-free freelist over a caller-owned linear
 * heap.  See utils/shared_freelist.c for the head-word packing and the
 * invariant the primitives maintain.
 *
 * heap_base + heap_capacity describe the caller's slab; a token read
 * from any shared word — the head or a slot's link — is validated
 * against those bounds before ANY dereference.  A stomped head or link
 * (the shared heap is fuzzer-writable in the trinity threat model) is
 * dropped safely: pop returns NULL, push refuses to link a pointer
 * that isn't inside the slab.
 */

extern const size_t shared_freelist_bucket_sizes[8];

/*
 * Return the index of the smallest bucket that fits an allocation of
 * already-pointer-aligned size, or -1 if size exceeds all buckets.
 */
int shared_freelist_bucket(size_t aligned_size);

/*
 * Pop a zeroed slot of slot_size bytes from the bucket whose head lives
 * at *head; return NULL on empty-list or on any bounds-check failure.
 */
void *shared_freelist_pop(uint64_t *head, char *heap_base,
			  size_t heap_capacity, size_t slot_size);

/*
 * Push slot p (slot_size bytes, must be inside [heap_base,
 * heap_base + heap_capacity - slot_size]) onto the bucket whose head
 * lives at *head.  A p outside those bounds is refused (the slot is
 * leaked rather than linked as a wild token).
 */
void shared_freelist_push(uint64_t *head, void *p, char *heap_base,
			  size_t heap_capacity, size_t slot_size);
