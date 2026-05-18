/*
 * Per-child edgepair observation ring buffer + parent-side canonical
 * aggregate + child-RO mirror page.
 *
 * Children produce edgepair observation events ((prev_nr, curr_nr,
 * new_edges)) into their own ring (write-only-by-owner); the parent
 * drains every ring once per main_loop iteration and applies the
 * events to a parent-private struct edgepair_aggregate that lives in
 * MAP_PRIVATE memory invisible to the kernel.  The kernel can no
 * longer scribble the (prev, curr) hash table or the top-level
 * counters via a wild syscall arg pointer because the authoritative
 * copy is not at any kernel-visible address.
 *
 * One mirror page (edgepair_published) is republished from the
 * canonical at every drain so the child-side cold-pair check
 * (edgepair_is_cold) can read weights without a ring round-trip.
 *
 * Single-writer apply collapses the CAS machinery the in-shm path
 * needed: find_or_insert becomes a plain hash probe + store, no
 * atomics, no packed-CAS layout pin.  edgepair_record's atomic_fetch_
 * add on total_pair_calls becomes a ring side-effect (parent counts
 * on drain).
 */

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "child.h"
#include "edgepair.h"
#include "edgepair_ring.h"
#include "pids.h"
#include "shm.h"
#include "spsc-ring.h"
#include "trinity.h"
#include "utils.h"

struct edgepair_aggregate parent_edgepair;
struct edgepair_published *edgepair_published;

/* Same hash as edgepair.c's pair_hash -- duplicated rather than hoisted
 * into a shared header to keep the dark-launch commit self-contained.
 * The in-shm copy remains authoritative until the in-shm path is gone. */
static unsigned int aggregate_pair_hash(unsigned int prev, unsigned int curr)
{
	unsigned int h = prev * 31 + curr;

	h ^= h >> 16;
	h *= 0x45d9f3b;
	h ^= h >> 16;
	return h & EDGEPAIR_TABLE_MASK;
}

void edgepair_ring_init(struct edgepair_ring *ring)
{
	memset(ring->slots, 0, sizeof(ring->slots));
	spsc_ring_init(&ring->base);
}

/*
 * Per-child edgepair reset contract.  Called from clean_childdata()
 * when a child slot is reused so a fresh occupant starts with an empty
 * observation ring rather than inheriting the prior occupant's
 * head/tail/overflow cursors.  Without this the new child's first
 * enqueue lands at an arbitrary offset (the prior occupant's head) and
 * the parent's drain reads stale (or wrapped-around) slots from before
 * clean_childdata ran, attributing the prior occupant's (prev, curr)
 * pairs to the new child.
 *
 * Note: last_syscall_nr (the per-call predecessor read by
 * edgepair_is_cold) is also per-child edgepair state and is reset to
 * EDGEPAIR_NO_PREV earlier in clean_childdata; this helper owns the
 * ring side of the contract.
 */
void edgepair_child_reset(struct childdata *child)
{
	if (child == NULL)
		return;

	if (child->edgepair_ring != NULL)
		edgepair_ring_init(child->edgepair_ring);
}

bool edgepair_ring_enqueue(struct edgepair_ring *ring,
			   unsigned int prev_nr, unsigned int curr_nr,
			   bool new_edges)
{
	struct edgepair_event_slot slot = {
		.prev_nr = (uint16_t)prev_nr,
		.curr_nr = (uint16_t)curr_nr,
		.new_edges = new_edges ? 1 : 0,
	};

	if (ring == NULL)
		return false;

	return spsc_ring_try_enqueue(&ring->base, ring->slots,
				     EDGEPAIR_RING_SIZE, sizeof(ring->slots[0]),
				     &slot);
}

/*
 * Find or insert a pair in the canonical table.  Single-writer parent
 * context: no CAS, no probe-claim race -- a plain linear probe for the
 * matching slot or the first empty one.  Returns NULL when the probe
 * window overflows; caller bumps pairs_dropped on a NULL return.
 */
static struct edgepair_entry *aggregate_find_or_insert(unsigned int prev_nr,
						       unsigned int curr_nr)
{
	unsigned int idx = aggregate_pair_hash(prev_nr, curr_nr);
	unsigned int probe;

	for (probe = 0; probe < EDGEPAIR_MAX_PROBE; probe++) {
		struct edgepair_entry *e = &parent_edgepair.table[idx];

		if (e->prev_nr == EDGEPAIR_EMPTY) {
			e->prev_nr = prev_nr;
			e->curr_nr = curr_nr;
			parent_edgepair.pairs_tracked++;
			return e;
		}
		if (e->prev_nr == prev_nr && e->curr_nr == curr_nr)
			return e;

		idx = (idx + 1) & EDGEPAIR_TABLE_MASK;
	}

	return NULL;
}

/*
 * Apply one ring slot to the canonical aggregate.  Mirrors the in-shm
 * edgepair_record discipline -- bump total_pair_calls, find or claim
 * the slot, bump total_count, conditionally bump new_edge_count and
 * stamp last_new_at -- minus the atomic_fetch_add / CAS machinery the
 * multi-writer path needed.
 */
static void apply_slot(const void *p, void *ctx __unused__)
{
	const struct edgepair_event_slot *s = p;
	struct edgepair_entry *e;
	unsigned long call_nr;

	if (s->prev_nr >= MAX_NR_SYSCALL || s->curr_nr >= MAX_NR_SYSCALL)
		return;

	call_nr = parent_edgepair.total_pair_calls++;

	e = aggregate_find_or_insert(s->prev_nr, s->curr_nr);
	if (e == NULL) {
		parent_edgepair.pairs_dropped++;
		return;
	}

	e->total_count++;

	if (s->new_edges) {
		e->new_edge_count++;
		e->last_new_at = call_nr;
	}
}

unsigned int edgepair_ring_drain(struct edgepair_ring *ring)
{
	uint32_t overflow = 0;
	uint32_t processed;

	if (ring == NULL)
		return 0;

	processed = spsc_ring_drain(&ring->base, ring->slots,
				    EDGEPAIR_RING_SIZE, sizeof(ring->slots[0]),
				    apply_slot, NULL, &overflow);
	parent_edgepair.ring_overflow_total += overflow;
	return processed;
}

/*
 * Republish the canonical table into the mirror page.  Full publish
 * per drain: 1.5 MiB memcpy (24 B/slot * 65536 slots + header word) at
 * ms cadence is ~1.5 GB/s memory bandwidth in the worst case, well
 * under one core's memory budget on a DDR4/DDR5 box.  No dirty-row
 * tracking -- the apply path doesn't naturally produce per-row dirty
 * signal without extra accounting, and the simpler publish keeps the
 * critical section short.
 *
 * Trims total_count out of the mirror (parent-only consumer) and the
 * CAS-key union (parent doesn't need atomic claim).  Carries
 * total_pair_calls in the header so edgepair_is_cold has its "now"
 * anchor for the staleness comparison.
 */
static void edgepair_publish_locked(void)
{
	unsigned int i;

	if (edgepair_published == NULL)
		return;

	edgepair_published->total_pair_calls = parent_edgepair.total_pair_calls;

	for (i = 0; i < EDGEPAIR_TABLE_SIZE; i++) {
		struct edgepair_published_slot *ps = &edgepair_published->slots[i];
		const struct edgepair_entry *e = &parent_edgepair.table[i];

		ps->prev_nr = e->prev_nr;
		ps->curr_nr = e->curr_nr;
		ps->new_edge_count = e->new_edge_count;
		ps->last_new_at = e->last_new_at;
	}

	/* Mirror-integrity sample.  After the publish completes the
	 * mirror's first slot and total_pair_calls header should match
	 * the canonical's; the only thing that could write to the mirror
	 * between publishes is a wild kernel store, and the PROT_READ
	 * mprotect should SEGV that in the offending child instead.  A
	 * non-zero published_corrupt counter implies either a hole in
	 * the freeze/thaw bracket or a wild store that somehow bypassed
	 * the read-only mapping -- log + count, same shape as Stage 1's
	 * shm_published_corrupt mirror integrity check. */
	if (edgepair_published->total_pair_calls !=
	    parent_edgepair.total_pair_calls)
		parent_edgepair.published_corrupt++;
	if (edgepair_published->slots[0].prev_nr !=
	    parent_edgepair.table[0].prev_nr)
		parent_edgepair.published_corrupt++;
}

void edgepair_ring_drain_all(void)
{
	unsigned int i;

	if (children == NULL)
		return;

	for_each_child(i) {
		struct childdata *child;
		struct edgepair_ring *ring;

		child = __atomic_load_n(&children[i], __ATOMIC_ACQUIRE);
		if (child == NULL)
			continue;

		ring = __atomic_load_n(&child->edgepair_ring, __ATOMIC_ACQUIRE);
		if (ring == NULL)
			continue;

		(void) edgepair_ring_drain(ring);
	}

	edgepair_publish_locked();
}

void edgepair_published_init(void)
{
	unsigned int i;

	/* Initialise the parent-private canonical alongside the mirror.
	 * Both need the EDGEPAIR_EMPTY sentinel in their prev_nr / curr_nr
	 * fields so the hash probe terminates the chain at the first miss
	 * instead of walking 32 slots of zeroed (prev=0, curr=0) entries
	 * that would alias to syscall 0.  parent_edgepair lives in .bss
	 * and is zero by default; the mirror is fresh from alloc_shared()
	 * and also zero. */
	for (i = 0; i < EDGEPAIR_TABLE_SIZE; i++) {
		parent_edgepair.table[i].prev_nr = EDGEPAIR_EMPTY;
		parent_edgepair.table[i].curr_nr = EDGEPAIR_EMPTY;
	}

	edgepair_published = alloc_shared(sizeof(struct edgepair_published));
	memset(edgepair_published, 0, sizeof(struct edgepair_published));

	for (i = 0; i < EDGEPAIR_TABLE_SIZE; i++) {
		edgepair_published->slots[i].prev_nr = EDGEPAIR_EMPTY;
		edgepair_published->slots[i].curr_nr = EDGEPAIR_EMPTY;
	}
}
