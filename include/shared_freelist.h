#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Fixed-size, ABA-safe, lock-free freelist over a caller-owned linear
 * heap.  See utils/shared_freelist.c for the head-word packing and the
 * invariant the primitives maintain.
 *
 * The primitives operate against three caller-owned regions that share
 * the same lifecycle:
 *
 *   heap_base + heap_capacity: the slab that stores the slots
 *       themselves.  MAP_SHARED and fuzzer-writable in trinity's
 *       threat model.
 *
 *   head: a single 64-bit head-word per bucket.  Also MAP_SHARED and
 *       fuzzer-writable; every token read from it is validated before
 *       any deref.
 *
 *   state: a per-slot state byte array indexed by (offset /
 *       SHARED_FREELIST_SLOT_STRIDE).  The array MUST live in memory
 *       the fuzzer cannot reach -- it is the authority the primitives
 *       consult to prove a token names a live, non-interior, same-
 *       bucket slot.  A stomped token that survives the head/link
 *       bounds check still fails the state CAS and drops the slot on
 *       the floor rather than aliasing a live slot, a cross-bucket
 *       slot, or an aligned interior address.
 */

/*
 * Slot-start stride.  All bucket sizes and all bump offsets are
 * multiples of this stride, so a token whose (offset % stride) != 0 is
 * a forgery aimed at an aligned interior address and is rejected up
 * front by both push and pop.
 */
#define SHARED_FREELIST_SLOT_STRIDE	8U

/*
 * Number of size-classed buckets.  The state encoding below reserves
 * two ranges of NUM_BUCKETS bytes each in the low 5 bits of a uint8_t;
 * a future refactor past 120 buckets would collide LIVE with FREE.
 */
#define SHARED_FREELIST_NUM_BUCKETS	8

/*
 * Per-slot state encoding (uint8_t per SHARED_FREELIST_SLOT_STRIDE
 * heap bytes):
 *
 *   0                                              -- UNCARVED / interior
 *   1 .. SHARED_FREELIST_NUM_BUCKETS               -- FREE(bucket_idx = value - 1)
 *   1 + N .. 2 * SHARED_FREELIST_NUM_BUCKETS       -- LIVE(bucket_idx = value - 1 - N)
 *
 * The four provenance failures the caller cares about all collapse to
 * "state CAS from FREE(bucket_idx) -> LIVE(bucket_idx) fails" on pop
 * (or the LIVE->FREE mirror on push):
 *
 *   - link-to-live:      state is LIVE(anything), not FREE
 *   - cross-bucket:      state is FREE(other_bucket), not FREE(bucket_idx)
 *   - interior-offset:   state is 0 (only slot-start offsets ever get
 *                        a non-zero record), or the offset is not a
 *                        multiple of SHARED_FREELIST_SLOT_STRIDE (also
 *                        rejected explicitly by the primitives)
 *   - double-free:       first push transitioned LIVE->FREE, so the
 *                        second push's CAS from LIVE finds FREE
 *
 * A failing state CAS is fail-safe: the slot is leaked and the slab
 * memory is NOT touched.  Overlapping allocations and truncated free
 * chains both require *linking* the same address into more than one
 * chain, so refusing the link is sufficient.
 */
#define SHARED_FREELIST_STATE_FREE(bucket_idx)	\
	((uint8_t)((bucket_idx) + 1U))
#define SHARED_FREELIST_STATE_LIVE(bucket_idx)	\
	((uint8_t)((bucket_idx) + 1U + SHARED_FREELIST_NUM_BUCKETS))

extern const size_t shared_freelist_bucket_sizes[SHARED_FREELIST_NUM_BUCKETS];

/*
 * Return the index of the smallest bucket that fits an allocation of
 * already-pointer-aligned size, or -1 if size exceeds all buckets.
 */
int shared_freelist_bucket(size_t aligned_size);

/*
 * Pop a zeroed slot of slot_size bytes from the bucket whose head lives
 * at *head; return NULL on empty-list, on any bounds-check failure, or
 * if the popped token fails the FREE(bucket_idx) -> LIVE(bucket_idx)
 * state transition (a forged token that survives bounds).  On success
 * the primitive has installed LIVE(bucket_idx) at
 * state[(returned_offset) / SHARED_FREELIST_SLOT_STRIDE].
 */
void *shared_freelist_pop(uint64_t *head, uint8_t *state,
			  unsigned int bucket_idx,
			  char *heap_base, size_t heap_capacity,
			  size_t slot_size);

/*
 * Push slot p (slot_size bytes, must be inside [heap_base,
 * heap_base + heap_capacity - slot_size], and offset must be a
 * multiple of SHARED_FREELIST_SLOT_STRIDE) onto the bucket whose head
 * lives at *head.  A p outside those bounds, or one whose state is
 * not LIVE(bucket_idx), is refused (the slot is leaked rather than
 * linked -- a forged free of a live/wrong-bucket/interior slot would
 * otherwise overlap allocations or truncate the free chain).
 */
void shared_freelist_push(uint64_t *head, uint8_t *state,
			  unsigned int bucket_idx,
			  void *p, char *heap_base,
			  size_t heap_capacity, size_t slot_size);
