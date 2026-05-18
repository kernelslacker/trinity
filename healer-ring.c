/*
 * Per-child HEALER observation ring buffer + parent-side canonical
 * aggregate + child-RO mirror pages.
 *
 * Children produce HEALER observation events (TRIPLE: (pred_a, pred_b,
 * succ); PAIR: (pred, succ)) into their own ring (write-only-by-owner);
 * the parent drains every ring once per main_loop iteration and applies
 * the events to a parent-private struct healer_aggregate that lives in
 * MAP_PRIVATE memory invisible to the kernel.  The kernel can no longer
 * scribble either table via a wild syscall arg pointer because the
 * authoritative copy is not at any kernel-visible address.
 *
 * Two mirror pages (healer_relations_published, healer_pair_published)
 * are republished from the canonical at every drain so the child-side
 * picker (set_syscall_nr_healer) can read weights without a ring round-
 * trip.  Dirty-row tracking keeps the publish cost at ~KiB/drain steady
 * state instead of the worst-case 5 MiB memcpy a naive full-table
 * publish would cost.
 *
 * Single-writer apply collapses the CAS machinery the in-shm path
 * needed: triple-table promoted-entry insertion is a straight scan +
 * eviction by lowest-weight, no per-slot CAS loop, no restart_budget.
 * Pair-table bumps are plain stores with saturation clamp.  Decay
 * becomes a straight walk on its trigger; no CAS election.
 */

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "child.h"
#include "edgepair.h"		/* EDGEPAIR_NO_PREV */
#include "healer.h"
#include "healer_ring.h"
#include "pids.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

struct healer_aggregate parent_healer;
struct healer_relation *healer_relations_published;
unsigned int (*healer_pair_published)[MAX_NR_SYSCALL];

/* Mirror healer.c's per-cell saturation cap and decay cadences.  Kept
 * as local statics so this file is self-contained for the dark-launch
 * commit; once the in-shm tables are gone they remain the only
 * definitions in the tree. */
#define HEALER_PAIR_MAX_WEIGHT		(1U << 24)
#define HEALER_DECAY_OBSERVATIONS	5000UL
#define HEALER_DECAY_INTERVAL_SEC	1800UL

/* FNV-1a parameters and packed-key helpers mirror healer.c.  Duplicated
 * rather than hoisted into a shared header to keep the file count down
 * and the dark-launch commit self-contained; the in-shm copies remain
 * authoritative until C3 deletes them. */
#define FNV1A_OFFSET_BASIS 0x811c9dc5U
#define FNV1A_PRIME        0x01000193U

static unsigned int aggregate_predset_hash(unsigned int pred_a,
					   unsigned int pred_b)
{
	uint32_t h = FNV1A_OFFSET_BASIS;
	unsigned char buf[sizeof(unsigned int) * 2];
	size_t i;

	memcpy(buf, &pred_a, sizeof(pred_a));
	memcpy(buf + sizeof(pred_a), &pred_b, sizeof(pred_b));

	for (i = 0; i < sizeof(buf); i++) {
		h ^= buf[i];
		h *= FNV1A_PRIME;
	}

	if (h == 0)
		h = 1;
	return h;
}

static uint64_t aggregate_pack_key(unsigned int pred_a, unsigned int pred_b,
				   unsigned int predset_hash)
{
	struct {
		uint16_t pa;
		uint16_t pb;
		uint32_t h;
	} tmp = { (uint16_t)pred_a, (uint16_t)pred_b, predset_hash };
	uint64_t packed;

	memcpy(&packed, &tmp, sizeof(packed));
	return packed;
}

static uint64_t aggregate_pack_promoted(unsigned int nr, unsigned int weight)
{
	struct {
		unsigned int n;
		unsigned int w;
	} tmp = { nr, weight };
	uint64_t packed;

	memcpy(&packed, &tmp, sizeof(packed));
	return packed;
}

static void aggregate_unpack_promoted(uint64_t entry, unsigned int *nr,
				      unsigned int *weight)
{
	struct {
		unsigned int n;
		unsigned int w;
	} tmp;

	memcpy(&tmp, &entry, sizeof(tmp));
	*nr = tmp.n;
	*weight = tmp.w;
}

void healer_ring_init(struct healer_ring *ring)
{
	memset(ring, 0, sizeof(*ring));
	__atomic_store_n(&ring->head, 0, __ATOMIC_RELAXED);
	__atomic_store_n(&ring->tail, 0, __ATOMIC_RELAXED);
	__atomic_store_n(&ring->overflow, 0, __ATOMIC_RELAXED);
}

/*
 * Per-child HEALER reset contract.  Called from clean_childdata() when
 * a child slot is reused so a fresh occupant starts with an empty seq
 * buffer and an empty observation ring rather than inheriting the
 * predecessor's (pred_a, pred_b) window and any pending unfdrained
 * slots.  Without this:
 *   - healer_seq[] / healer_seq_count carry forward from the prior
 *     occupant, so the first observer-hook fire under the new child
 *     attributes its succ to predecessors that ran in a different
 *     process under different fds and a different rng stream;
 *   - the per-child healer_ring inherits the prior occupant's head/tail
 *     cursor, so the first enqueue lands at an arbitrary offset and the
 *     parent's drain reads stale (or wrapped-around) slots.
 * EDGEPAIR_NO_PREV is the documented "no usable predecessor" sentinel:
 * the observer-hook already filters seq slots carrying it (see
 * healer_observe_relation in healer.c), so stamping it on reset keeps
 * any path that reads healer_seq[] before healer_seq_count gates from
 * seeing stale syscall numbers.
 */
void healer_child_reset(struct childdata *child)
{
	if (child == NULL)
		return;

	child->healer_seq[0] = EDGEPAIR_NO_PREV;
	child->healer_seq[1] = EDGEPAIR_NO_PREV;
	child->healer_seq_count = 0;

	if (child->healer_ring != NULL)
		healer_ring_init(child->healer_ring);
}

static bool healer_ring_enqueue_slot(struct healer_ring *ring,
				     const struct healer_event_slot *slot)
{
	uint32_t head, tail, next;

	if (ring == NULL)
		return false;

	head = __atomic_load_n(&ring->head, __ATOMIC_RELAXED);
	head &= (HEALER_RING_SIZE - 1);
	tail = __atomic_load_n(&ring->tail, __ATOMIC_ACQUIRE);
	tail &= (HEALER_RING_SIZE - 1);

	next = (head + 1) & (HEALER_RING_SIZE - 1);
	if (next == tail) {
		__atomic_fetch_add(&ring->overflow, 1,
					  __ATOMIC_RELAXED);
		return false;
	}

	ring->slots[head] = *slot;

	__atomic_store_n(&ring->head, next, __ATOMIC_RELEASE);
	return true;
}

bool healer_ring_enqueue_triple(struct healer_ring *ring,
				unsigned int pred_a, unsigned int pred_b,
				unsigned int succ)
{
	struct healer_event_slot slot = {
		.kind = HEALER_EVT_TRIPLE,
		.pred_a = (uint16_t)pred_a,
		.pred_b = (uint16_t)pred_b,
		.succ = (uint16_t)succ,
	};

	return healer_ring_enqueue_slot(ring, &slot);
}

bool healer_ring_enqueue_pair(struct healer_ring *ring,
			      unsigned int pred, unsigned int succ)
{
	struct healer_event_slot slot = {
		.kind = HEALER_EVT_PAIR,
		.pred_a = 0,
		.pred_b = (uint16_t)pred,
		.succ = (uint16_t)succ,
	};

	return healer_ring_enqueue_slot(ring, &slot);
}

/*
 * Apply a TRIPLE event to the canonical relation table.  Single-writer
 * parent context: no CAS, no restart loop, no defensive retry budget.
 * Bumps pred_appearance for both predecessors (skipping the second on
 * a self-paired predset so the same syscall doesn't get double-counted),
 * walks the open-addressed probe chain looking for the matching predset
 * or an empty slot, then bumps / claims / evicts inside the slot.
 *
 * Mirrors the apply discipline of the in-shm path (healer.c
 * healer_observe_relation + healer_slot_record) but collapsed to
 * straight-line code -- the lockless retry machinery only existed
 * because multiple observers wrote concurrently.
 */
static void apply_triple(unsigned int pred_a, unsigned int pred_b,
			 unsigned int succ)
{
	unsigned int predset_hash;
	unsigned int slot_idx;
	unsigned int probe;
	uint64_t target_key;
	struct healer_relation *table = parent_healer.relations;
	struct healer_relation *slot = NULL;
	unsigned int i;
	unsigned int victim_idx = 0;
	unsigned int victim_weight = 0;
	bool victim_found = false;
	bool evicted = false;

	/* The child-side enqueue already sorted (pred_a, pred_b) and
	 * filtered EDGEPAIR_NO_PREV before placing the event in the ring,
	 * but a scribbled ring slot can carry any 16-bit value -- bound-
	 * check before indexing. */
	if (pred_a >= MAX_NR_SYSCALL || pred_b >= MAX_NR_SYSCALL ||
	    succ >= MAX_NR_SYSCALL)
		return;

	parent_healer.pred_appearance[pred_a]++;
	if (pred_b != pred_a)
		parent_healer.pred_appearance[pred_b]++;

	predset_hash = aggregate_predset_hash(pred_a, pred_b);
	slot_idx = predset_hash & (HEALER_RELATION_SLOTS - 1);
	target_key = aggregate_pack_key(pred_a, pred_b, predset_hash);

	for (probe = 0; probe < HEALER_PROBE_LIMIT; probe++) {
		unsigned int idx = (slot_idx + probe) & (HEALER_RELATION_SLOTS - 1);

		slot = &table[idx];
		if (slot->key == 0) {
			slot->key = target_key;
			parent_healer.relations_dirty[idx] = 1;
			break;
		}
		if (slot->key == target_key) {
			parent_healer.relations_dirty[idx] = 1;
			break;
		}
	}

	if (probe == HEALER_PROBE_LIMIT) {
		parent_healer.table_full++;
		parent_healer.relations_observed++;
		return;
	}

	/* Phase 1: look for existing (predset, succ) entry, bump it. */
	for (i = 0; i < HEALER_PROMOTED_PER_SLOT; i++) {
		unsigned int weight, nr;

		aggregate_unpack_promoted(slot->promoted[i].entry, &nr, &weight);
		if (weight != 0 && nr == succ) {
			slot->promoted[i].weight++;
			goto out;
		}
	}

	/* Phase 2: claim an empty entry. */
	for (i = 0; i < HEALER_PROMOTED_PER_SLOT; i++) {
		if (slot->promoted[i].entry == 0) {
			slot->promoted[i].entry =
				aggregate_pack_promoted(succ, 1);
			goto out;
		}
	}

	/* Phase 3: evict lowest-weight entry.  Inherit victim weight + 1
	 * so a freshly displaced predset isn't instantly re-evicted on
	 * its next observation -- mirrors the in-shm eviction policy. */
	for (i = 0; i < HEALER_PROMOTED_PER_SLOT; i++) {
		unsigned int weight, nr;

		aggregate_unpack_promoted(slot->promoted[i].entry, &nr, &weight);
		if (!victim_found || weight < victim_weight) {
			victim_idx = i;
			victim_weight = weight;
			victim_found = true;
		}
	}
	slot->promoted[victim_idx].entry =
		aggregate_pack_promoted(succ, victim_weight + 1);
	evicted = true;

out:
	parent_healer.relations_observed++;
	if (evicted)
		parent_healer.evictions++;
}

/*
 * Apply a PAIR event to the canonical pair table.  Single-writer
 * parent context: plain increment with saturation clamp at
 * HEALER_PAIR_MAX_WEIGHT, mirrors the in-shm path's CAS loop without
 * the loop.
 */
static void apply_pair(unsigned int pred, unsigned int succ)
{
	unsigned int *cell;

	if (pred >= MAX_NR_SYSCALL || succ >= MAX_NR_SYSCALL)
		return;

	cell = &parent_healer.pair_table[pred][succ];
	if (*cell < HEALER_PAIR_MAX_WEIGHT) {
		(*cell)++;
		parent_healer.pair_dirty[pred] = 1;
	}
}

static void apply_slot(const struct healer_event_slot *s)
{
	switch (s->kind) {
	case HEALER_EVT_TRIPLE:
		apply_triple(s->pred_a, s->pred_b, s->succ);
		break;
	case HEALER_EVT_PAIR:
		apply_pair(s->pred_b, s->succ);
		break;
	default:
		/* Out-of-range kind: silent drop.  A scribbled slot can
		 * carry any value; the surrounding ring overflow counter
		 * already conveys "we lost samples". */
		break;
	}
}

unsigned int healer_ring_drain(struct healer_ring *ring)
{
	uint32_t head, tail, overflow;
	unsigned int processed = 0;

	if (ring == NULL)
		return 0;

	overflow = __atomic_load_n(&ring->overflow, __ATOMIC_RELAXED);
	if (overflow != 0)
		overflow = __atomic_exchange_n(&ring->overflow, 0,
						    __ATOMIC_RELAXED);
	if (overflow > 0)
		parent_healer.ring_overflow_total += overflow;

	tail = __atomic_load_n(&ring->tail, __ATOMIC_RELAXED);
	tail &= (HEALER_RING_SIZE - 1);
	head = __atomic_load_n(&ring->head, __ATOMIC_ACQUIRE);
	head &= (HEALER_RING_SIZE - 1);

	while (tail != head) {
		apply_slot(&ring->slots[tail]);
		tail = (tail + 1) & (HEALER_RING_SIZE - 1);
		processed++;
	}

	__atomic_store_n(&ring->tail, tail, __ATOMIC_RELEASE);
	return processed;
}

/*
 * Decay one (pred -> succ) row of the pair table in place.  Halves
 * every cell above the floor and reports whether anything changed so
 * the caller can flip the row's dirty bit for the next publish.
 *
 * The uniform-decay policy is deliberate for this commit: every
 * non-floor cell halves, regardless of how it got there (static seed
 * vs accumulated dynamic evidence).  A future change to separate the
 * static-prior contribution from dynamic-evidence accumulation will
 * add a gate here (e.g. "skip cells whose dynamic-evidence component
 * is below their seed weight") -- the per-cell branch is the single
 * decision point, so that follow-up is a one-line addition rather
 * than a restructure.
 */
static bool healer_decay_pair_row(unsigned int pred)
{
	bool row_modified = false;
	unsigned int succ;

	for (succ = 0; succ < MAX_NR_SYSCALL; succ++) {
		unsigned int w = parent_healer.pair_table[pred][succ];

		if (w <= 1)
			continue;

		parent_healer.pair_table[pred][succ] = w / 2;
		row_modified = true;
	}
	return row_modified;
}

/*
 * Parent-side decay walk.  Same trigger pair as the in-shm path
 * (observation count + wall-clock) but evaluated against parent-
 * private counters during drain.  No CAS election (single writer).
 * Marks the entire relation table dirty on a real decay so the next
 * publish propagates the halved weights.  Same trigger fires the
 * pair-table decay so both tables age in lockstep -- without that,
 * long-running fuzzes (or runs warm-started from a saturated
 * snapshot) leave the pair table holding stale weights that no live
 * observation ever displaces, since apply_pair only saturates
 * upward.  decay_epoch advances by one on every fire and is the
 * reference clock for the per-slot prune logic the next commit
 * builds on top.
 */
static void healer_apply_maybe_decay(void)
{
	unsigned long obs_now = parent_healer.relations_observed;
	unsigned long old_obs = parent_healer.obs_at_last_decay;
	unsigned long now_sec = (unsigned long)time(NULL);
	unsigned long old_time = parent_healer.time_at_last_decay;
	bool obs_trigger, time_trigger;
	unsigned int i, j;
	bool any_dirty = false;

	obs_trigger = (obs_now >= old_obs + HEALER_DECAY_OBSERVATIONS);
	time_trigger = (now_sec >= old_time + HEALER_DECAY_INTERVAL_SEC);

	if (!obs_trigger && !time_trigger)
		return;

	parent_healer.obs_at_last_decay = obs_now;
	parent_healer.time_at_last_decay = now_sec;

	for (i = 0; i < HEALER_RELATION_SLOTS; i++) {
		struct healer_relation *slot = &parent_healer.relations[i];

		if (slot->key == 0)
			continue;

		for (j = 0; j < HEALER_PROMOTED_PER_SLOT; j++) {
			unsigned int weight, nr, halved;

			aggregate_unpack_promoted(slot->promoted[j].entry,
						  &nr, &weight);
			if (weight <= 1)
				continue;

			halved = weight / 2;
			if (halved < 1)
				halved = 1;
			slot->promoted[j].weight = halved;
			any_dirty = true;
		}
		if (any_dirty)
			parent_healer.relations_dirty[i] = 1;
	}

	for (i = 0; i < MAX_NR_SYSCALL; i++) {
		if (healer_decay_pair_row(i))
			parent_healer.pair_dirty[i] = 1;
	}

	parent_healer.decay_epoch++;
	parent_healer.weight_decays_run++;
}

/*
 * Publish dirty rows of both tables to the mirror pages.  Caller must
 * have already thawed the global-obj freeze.  Walks the dirty bitmaps
 * once, clears each set bit as the row is copied.  Steady-state cost
 * is dominated by the bitmap scan; the actual memcpy is small.
 */
static void healer_publish_locked(void)
{
	unsigned int i;

	if (healer_relations_published != NULL) {
		for (i = 0; i < HEALER_RELATION_SLOTS; i++) {
			if (!parent_healer.relations_dirty[i])
				continue;
			healer_relations_published[i] =
				parent_healer.relations[i];
			parent_healer.relations_dirty[i] = 0;
		}
	}

	if (healer_pair_published != NULL) {
		for (i = 0; i < MAX_NR_SYSCALL; i++) {
			if (!parent_healer.pair_dirty[i])
				continue;
			memcpy(healer_pair_published[i],
			       parent_healer.pair_table[i],
			       sizeof(parent_healer.pair_table[i]));
			parent_healer.pair_dirty[i] = 0;
		}
	}

	/* Mirror-integrity sample.  After the publish completes the
	 * mirror's first relation slot and pair-table cell should match
	 * the canonical's; the only thing that could write to the mirror
	 * between publishes is a wild kernel store, and the PROT_READ
	 * mprotect should SEGV that in the offending child instead.  A
	 * non-zero published_corrupt counter implies either a hole in
	 * the freeze/thaw bracket or a wild store that somehow bypassed
	 * the read-only mapping -- log + count, same shape as Stage 1's
	 * shm_published_corrupt mirror integrity check. */
	if (healer_relations_published != NULL &&
	    healer_relations_published[0].key !=
		parent_healer.relations[0].key)
		parent_healer.published_corrupt++;
	if (healer_pair_published != NULL &&
	    healer_pair_published[0][0] != parent_healer.pair_table[0][0])
		parent_healer.published_corrupt++;
}

void healer_ring_drain_all(void)
{
	unsigned int i;

	if (children == NULL)
		return;

	for_each_child(i) {
		struct childdata *child;
		struct healer_ring *ring;

		child = __atomic_load_n(&children[i], __ATOMIC_ACQUIRE);
		if (child == NULL)
			continue;

		ring = __atomic_load_n(&child->healer_ring, __ATOMIC_ACQUIRE);
		if (ring == NULL)
			continue;

		(void) healer_ring_drain(ring);
	}

	healer_apply_maybe_decay();
	healer_publish_locked();
	/* Snapshot trigger evaluated against parent-private counters and
	 * fired from drain context (single writer); save-file is a normal
	 * sequential call from here, no CAS election needed. */
	healer_maybe_snapshot();
}

void healer_published_init(void)
{
	healer_relations_published = alloc_shared(
		sizeof(struct healer_relation) * HEALER_RELATION_SLOTS);
	memset(healer_relations_published, 0,
	       sizeof(struct healer_relation) * HEALER_RELATION_SLOTS);

	healer_pair_published = alloc_shared(
		sizeof(unsigned int) * MAX_NR_SYSCALL * MAX_NR_SYSCALL);
	memset(healer_pair_published, 0,
	       sizeof(unsigned int) * MAX_NR_SYSCALL * MAX_NR_SYSCALL);
}

void healer_aggregate_pair_set(unsigned int pred, unsigned int succ,
			       unsigned int weight)
{
	if (pred >= MAX_NR_SYSCALL || succ >= MAX_NR_SYSCALL)
		return;

	/* Idempotent CAS-from-zero: a previous loader call (or the in-shm
	 * seed installer, while both coexist during the staged migration)
	 * already populated this cell -- skip silently rather than
	 * overwriting an authoritative existing value. */
	if (parent_healer.pair_table[pred][succ] != 0)
		return;

	parent_healer.pair_table[pred][succ] = weight;
	parent_healer.pair_dirty[pred] = 1;
	parent_healer.pair_seeded++;
}
