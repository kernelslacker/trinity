/*
 * Generic single-producer single-consumer ring primitive.
 *
 * Carries the head/tail/overflow accounting that several payload-specific
 * rings in this tree (fd-event, stats-ring, healer-ring, edgepair-ring)
 * had been reimplementing in lock-step copies.  See include/spsc-ring.h
 * for the contract.
 */

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "spsc-ring.h"

void spsc_ring_init(struct spsc_ring *r)
{
	memset(r, 0, sizeof(*r));
	__atomic_store_n(&r->head, 0, __ATOMIC_RELAXED);
	__atomic_store_n(&r->tail, 0, __ATOMIC_RELAXED);
	__atomic_store_n(&r->overflow, 0, __ATOMIC_RELAXED);
}

bool spsc_ring_try_enqueue(struct spsc_ring *r,
			   void *slots, uint32_t nslots, size_t slot_size,
			   const void *payload)
{
	uint32_t head, tail, next;
	uint32_t mask = nslots - 1;
	unsigned char *base = slots;

	if (r == NULL || slots == NULL)
		return false;

	head = __atomic_load_n(&r->head, __ATOMIC_RELAXED);
	head &= mask;
	/* Acquire pairs with consumer's release-store of tail so we observe
	 * the slot as free before reusing it. */
	tail = __atomic_load_n(&r->tail, __ATOMIC_ACQUIRE);
	tail &= mask;

	next = (head + 1) & mask;
	if (next == tail) {
		__atomic_fetch_add(&r->overflow, 1, __ATOMIC_RELAXED);
		return false;
	}

	memcpy(base + (size_t)head * slot_size, payload, slot_size);

	/* Release so the slot bytes are visible to the consumer before head
	 * advances past them. */
	__atomic_store_n(&r->head, next, __ATOMIC_RELEASE);
	return true;
}

uint32_t spsc_ring_drain(struct spsc_ring *r,
			 const void *slots, uint32_t nslots, size_t slot_size,
			 spsc_apply_fn apply, void *ctx,
			 uint32_t *overflow_out)
{
	uint32_t head, tail, overflow;
	uint32_t mask = nslots - 1;
	uint32_t processed = 0;
	const unsigned char *base = slots;

	if (r == NULL || slots == NULL || apply == NULL) {
		if (overflow_out != NULL)
			*overflow_out = 0;
		return 0;
	}

	/* Common case is zero; peek with a relaxed load to avoid a locked
	 * RMW that would dirty the cacheline shared with the producer. */
	overflow = __atomic_load_n(&r->overflow, __ATOMIC_RELAXED);
	if (overflow != 0)
		overflow = __atomic_exchange_n(&r->overflow, 0,
					       __ATOMIC_RELAXED);
	if (overflow_out != NULL)
		*overflow_out = overflow;

	tail = __atomic_load_n(&r->tail, __ATOMIC_RELAXED);
	tail &= mask;
	/* Acquire pairs with producer's release-store of head so the slot
	 * bytes are observably written before we read them. */
	head = __atomic_load_n(&r->head, __ATOMIC_ACQUIRE);
	head &= mask;

	while (tail != head) {
		apply(base + (size_t)tail * slot_size, ctx);
		tail = (tail + 1) & mask;
		processed++;
	}

	/* Release so the producer sees the updated tail (and the slots are
	 * observably free) before reusing them. */
	__atomic_store_n(&r->tail, tail, __ATOMIC_RELEASE);
	return processed;
}

void spsc_ring_overwrite_enqueue(struct spsc_ring *r,
				 void *slots, uint32_t nslots, size_t slot_size,
				 const void *payload)
{
	uint32_t head;
	uint32_t mask = nslots - 1;
	unsigned char *base = slots;

	if (r == NULL || slots == NULL)
		return;

	/* Single-producer relaxed load: only this producer writes head. */
	head = __atomic_load_n(&r->head, __ATOMIC_RELAXED);
	memcpy(base + (size_t)(head & mask) * slot_size, payload, slot_size);

	/* Release so the slot bytes are visible to a snapshot reader before
	 * head advances past them.  Keep head monotonic (unmasked) so the
	 * reader can distinguish "empty" from "wrapped once" and walk back
	 * min(head, nslots) slots. */
	__atomic_store_n(&r->head, head + 1, __ATOMIC_RELEASE);
}
