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

#include <errno.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "arch.h"		/* page_size */
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

/*
 * Dirty-slot tracking for the published-mirror republish path.
 *
 * apply_slot() is the SOLE writer to parent_edgepair.table; on every
 * successful find_or_insert it does one test-and-set against the
 * bitmap and, on the 0 -> 1 transition, appends the slot index to the
 * queue.  edgepair_publish_locked() then walks the queue and copies
 * just those slots into the mirror, replacing the unconditional 6 MiB
 * memcpy with ~24 B per actually-touched slot.
 *
 * Parent-private, single-writer (parent drain context only). No
 * atomics, same discipline as the rest of struct edgepair_aggregate.
 *
 * The bitmap covers EDGEPAIR_TABLE_SIZE bits (32 KiB) so a slot can be
 * test-and-set in a single masked load + store with no probe.  The
 * queue is the actual work list; bitmap exists only to debounce
 * repeated test-and-sets for the same hot pair within one publish
 * window.  Bitmap and queue MUST stay in sync: a queue push happens
 * iff the test-and-set transitioned 0 -> 1.
 *
 * On queue overflow (more than EDGEPAIR_DIRTY_QUEUE_SIZE unique slots
 * touched between publishes) we flip need_full_publish and let the
 * remaining applies in the window stop enqueueing -- the next publish
 * does a full walk and resets the state, which is cheaper than
 * tracking a queue spillover separately.  Same fallback handles the
 * first-ever publish so the mirror is populated even if no apply has
 * fired yet (need_full_publish is true at startup and re-asserted by
 * edgepair_published_init).
 */
#define EDGEPAIR_DIRTY_BITMAP_WORDS	(EDGEPAIR_TABLE_SIZE / 64)
#define EDGEPAIR_DIRTY_QUEUE_SIZE	4096

static uint64_t edgepair_dirty_bitmap[EDGEPAIR_DIRTY_BITMAP_WORDS];
static uint32_t edgepair_dirty_queue[EDGEPAIR_DIRTY_QUEUE_SIZE];
static unsigned int edgepair_dirty_queue_head;
static bool edgepair_need_full_publish = true;

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
	unsigned int idx;
	uint64_t *word;
	uint64_t mask;

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

	/* Mark the slot dirty for the next publish.  Test-and-set
	 * debounces repeated apply for the same hot pair; queue push
	 * happens iff the bit transitioned 0 -> 1.  On queue overflow
	 * flip need_full_publish -- the bitmap can keep being set
	 * (cheap) but we stop pushing to the queue, and the next
	 * publish does a full walk + state reset. */
	idx = (unsigned int)(e - parent_edgepair.table);
	word = &edgepair_dirty_bitmap[idx >> 6];
	mask = (uint64_t)1 << (idx & 63);
	if (!(*word & mask)) {
		*word |= mask;
		if (edgepair_dirty_queue_head < EDGEPAIR_DIRTY_QUEUE_SIZE)
			edgepair_dirty_queue[edgepair_dirty_queue_head++] = idx;
		else
			edgepair_need_full_publish = true;
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
 * Republish the canonical table into the mirror page.  Dirty-slot
 * publish: apply_slot() is the sole writer to parent_edgepair.table
 * and marks each touched slot in a parent-private dirty bitmap +
 * queue (see the declarations above this function); this function
 * walks the queue and copies only those slots (~24 B per dirty index)
 * instead of the unconditional 6 MiB memcpy the prior version did.
 *
 * Background: a full walk had ~100% of edgepair_ring_drain_all's CPU
 * sitting on a single load instruction at 76% DRAM stall once the
 * 8 MiB canonical table and the 6 MiB mirror outgrew L3 under fuzz
 * pressure.  Every published-row that didn't actually change still
 * cost a cache-line read + write, and the working set evicted itself
 * between drains.  In a healthy run the per-drain dirty count is much
 * smaller than EDGEPAIR_TABLE_SIZE, so the memcpy collapses to
 * dirty_count * 24 B and the DRAM stall vanishes.
 *
 * Fallback to the full walk on:
 *   - First publish (need_full_publish set at startup and re-asserted
 *     by edgepair_published_init), so the mirror is populated even if
 *     no apply has fired yet.
 *   - Dirty-queue overflow within a publish window (more than
 *     EDGEPAIR_DIRTY_QUEUE_SIZE unique slots touched between
 *     publishes).  Republishing everything is cheaper than tracking
 *     the spillover and the next publish resets the state cleanly.
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

	if (edgepair_need_full_publish) {
		for (i = 0; i < EDGEPAIR_TABLE_SIZE; i++) {
			struct edgepair_published_slot *ps = &edgepair_published->slots[i];
			const struct edgepair_entry *e = &parent_edgepair.table[i];

			ps->prev_nr = e->prev_nr;
			ps->curr_nr = e->curr_nr;
			ps->new_edge_count = e->new_edge_count;
			ps->last_new_at = e->last_new_at;
		}
		edgepair_need_full_publish = false;
	} else {
		for (i = 0; i < edgepair_dirty_queue_head; i++) {
			unsigned int idx = edgepair_dirty_queue[i];
			struct edgepair_published_slot *ps = &edgepair_published->slots[idx];
			const struct edgepair_entry *e = &parent_edgepair.table[idx];

			ps->prev_nr = e->prev_nr;
			ps->curr_nr = e->curr_nr;
			ps->new_edge_count = e->new_edge_count;
			ps->last_new_at = e->last_new_at;
		}
	}

	memset(edgepair_dirty_bitmap, 0, sizeof(edgepair_dirty_bitmap));
	edgepair_dirty_queue_head = 0;

	/* Release-store the header AFTER all slot stores complete so a
	 * child reading total_pair_calls with __ATOMIC_ACQUIRE in
	 * edgepair_is_cold() is guaranteed to see the matching
	 * last_new_at update too.  Without this ordering, a child could
	 * observe the new total alongside an old last_new_at for a pair
	 * that just produced a new edge, making (total - last)
	 * artificially large and tripping the cold predicate against a
	 * pair that just got productive.  On x86-64 this lowers to a
	 * plain MOV -- stores already have release semantics; the
	 * atomic only constrains the compiler. */
	__atomic_store_n(&edgepair_published->total_pair_calls,
			 parent_edgepair.total_pair_calls,
			 __ATOMIC_RELEASE);

	/* Mirror-integrity sample.  After the publish completes the
	 * mirror's first slot and total_pair_calls header should match
	 * the canonical's; the only thing that could write to the mirror
	 * between publishes is a wild kernel store, and the PROT_READ
	 * mprotect should SEGV that in the offending child instead.  A
	 * non-zero published_corrupt counter implies either a hole in
	 * the freeze/thaw bracket or a wild store that somehow bypassed
	 * the read-only mapping -- log + count, same shape as Stage 1's
	 * shm_published_corrupt mirror integrity check.
	 *
	 * Slot 0 may not be in this round's dirty set; the sample still
	 * works because between publishes the mirror's slot 0 is only
	 * written by this function, and a previously-published slot 0
	 * either matches the canonical (clean) or was scribbled by a
	 * wild store (caught). */
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

	/* Re-assert the first-publish fallback so the next
	 * edgepair_publish_locked() does a full walk -- if init runs
	 * after any apply has already fired (e.g. a re-init path) the
	 * bitmap / queue would only describe slots touched since that
	 * apply, missing the EDGEPAIR_EMPTY sentinel reset above. */
	memset(edgepair_dirty_bitmap, 0, sizeof(edgepair_dirty_bitmap));
	edgepair_dirty_queue_head = 0;
	edgepair_need_full_publish = true;
}

/*
 * Per-child mprotect freeze of the edgepair mirror page.  The mirror
 * is intended parent-write / child-read (edgepair_is_cold reads
 * total_pair_calls + the matching slot's new_edge_count / last_new_at
 * off this page on the syscall-selection biasing path; the parent's
 * drain in edgepair_publish_locked() is the sole writer).  The
 * mirror-integrity sample at the bottom of that function documents
 * the PROT_READ contract -- "the only thing that could write to the
 * mirror between publishes is a wild kernel store, and the PROT_READ
 * mprotect should SEGV that in the offending child instead" -- but
 * the matching mprotect() call was missing, leaving the contract as
 * comment only.
 *
 * Called from the per-child post-fork init hook so the freeze applies
 * in child address space.  mprotect is per-process, so the parent's
 * mapping stays PROT_READ|PROT_WRITE and the drain's publish keeps
 * writing through; only children see the read-only view.
 *
 * Best-effort on failure: log via the canonical helper and continue.
 * mprotect can ENOMEM if the kernel runs out of VMA slots splitting
 * the mapping that backs the mirror (same failure mode as the
 * freeze_sibling_childdata sweep) and turning a transient kernel
 * limit into a fleet-wide crash would be worse than leaving the
 * mirror RW for the lifetime of the affected child.
 */
void edgepair_published_freeze(void)
{
	size_t bytes;

	if (edgepair_published == NULL)
		return;

	bytes = sizeof(struct edgepair_published);
	bytes = (bytes + page_size - 1) & PAGE_MASK;
	if (mprotect(edgepair_published, bytes, PROT_READ) != 0)
		log_mprotect_failure(edgepair_published, bytes, PROT_READ,
				     __builtin_return_address(0), errno);
}
