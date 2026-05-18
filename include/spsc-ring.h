#pragma once

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Generic single-producer single-consumer ring primitive.
 *
 * Several rings in this tree (fd-event, stats-ring, healer-ring,
 * edgepair-ring) had grown copies of the same shape: per-child producer,
 * parent drain, fixed-size payload slots, lock-free head/tail/overflow
 * accounting with acquire/release ordering, drop-on-full overflow policy.
 * Each reimplemented the head/tail dance and bounds masking from scratch
 * around a payload-specific apply path.  This primitive carries that
 * dance once.
 *
 * Contract
 * --------
 *   - Exactly one producer writes head (and overflow); exactly one
 *     consumer writes tail.  Both ends operate without locking.
 *   - The consumer publishes tail with release ordering; the producer
 *     pairs an acquire load to observe drained slots before reusing them.
 *     The producer publishes head with release ordering; the consumer
 *     pairs an acquire load to observe a fully-written slot before
 *     reading it.  Overflow is RELAXED -- it is a stat counter, not
 *     part of the data-visibility handshake.
 *   - Slot count must be a power of two.  Caller owns the payload
 *     storage; the primitive only manages the head/tail/overflow header.
 *   - Overflow policy: on a full enqueue the payload is dropped and the
 *     overflow counter is bumped (RELAXED).  The consumer harvests the
 *     accumulated count atomically on drain and surfaces it as it sees
 *     fit (per-ring or per-aggregate counter).
 *   - Payload validation is the caller's responsibility -- the apply
 *     callback receives raw payload bytes and must bounds-check any
 *     value it uses as an enum tag or array index.  A scribbled slot
 *     can carry any byte pattern; the fd-event drain validation model
 *     (validate-before-act) is the right reference.
 *
 * Embedding
 * ---------
 *   Embed struct spsc_ring as the first member of the typed ring and
 *   place the slot array after it:
 *
 *       struct my_ring {
 *           struct spsc_ring base;
 *           struct my_slot   slots[MY_RING_SIZE];
 *       };
 *
 *   The header keeps the producer fields (head, overflow) and the
 *   consumer field (tail) on separate cache lines.
 */

struct spsc_ring {
	/* Producer writes head + overflow. */
	uint32_t head;
	uint32_t overflow;

	/* Padding to put producer and consumer fields on separate cache lines. */
	char __pad[56];

	/* Consumer writes tail. */
	uint32_t tail;
};

typedef void (*spsc_apply_fn)(const void *slot, void *ctx);

void spsc_ring_init(struct spsc_ring *r);

/*
 * Enqueue from producer context.  Copies slot_size bytes from payload
 * into slots[head] and publishes the slot with a release-store of head.
 * Returns false on full ring; overflow bumped.  nslots must be a power
 * of two.
 */
bool spsc_ring_try_enqueue(struct spsc_ring *r,
			   void *slots, uint32_t nslots, size_t slot_size,
			   const void *payload);

/*
 * Drain all pending slots from consumer context.  For each slot:
 *   apply(slot_ptr, ctx)
 *
 * is called with a pointer into the producer's storage.  The apply
 * callback is responsible for validating the slot before using any
 * enum tag or array index it carries.
 *
 * The accumulated overflow counter is exchanged to zero atomically
 * and returned via *overflow_out (NULL is permitted -- the count is
 * still reset).  Returns the number of slots processed.
 */
uint32_t spsc_ring_drain(struct spsc_ring *r,
			 const void *slots, uint32_t nslots, size_t slot_size,
			 spsc_apply_fn apply, void *ctx,
			 uint32_t *overflow_out);
