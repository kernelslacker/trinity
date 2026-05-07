/*
 * HEALER syscall-relation observer (Phase A: instrumentation only).
 *
 * Records (predset -> nr) edges discovered when a new kcov PC edge fires
 * after a syscall sequence whose two-syscall predecessor window has been
 * captured in the per-child sequence buffer.  Phase A populates the
 * relation table only -- the syscall picker does not consult it, no
 * STRATEGY_HEALER bandit arm exists yet, and there is no CLI flag.  The
 * goal is to gather enough operator-visible data over a review window
 * to validate that the relations the observer learns look plausible
 * before authorising the picker work in Phase B.
 *
 * See include/healer.h for the data structure and per-field comments,
 * and ~/gdrive/Obsidian/projects/trinity/trinity-todo.md (Multi-Strategy
 * Rotation Phase 2 -> HEALER section) for the broader two-phase design.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "child.h"
#include "edgepair.h"		/* EDGEPAIR_NO_PREV */
#include "healer.h"
#include "shm.h"
#include "stats.h"
#include "tables.h"		/* print_syscall_name */
#include "trinity.h"

/*
 * Number of (predset, promoted_nr) tuples surfaced by the periodic
 * dump.  Kept small enough that the per-tick output stays readable
 * even at saturated load -- the underlying table can hold up to
 * HEALER_RELATION_SLOTS * HEALER_PROMOTED_PER_SLOT (= 128K) entries
 * if it ever fills, far more than an operator could scan inline.
 */
#define HEALER_DUMP_TOP_N 10

/*
 * FNV-1a parameters from the canonical 32-bit FNV definition.  Used
 * over the byte representation of the sorted (pred_a, pred_b) tuple
 * to derive the initial slot index.  Cheap enough on the (rare)
 * observer-hook path that adding a stronger hash is not worth the
 * dependency cost.
 */
#define FNV1A_OFFSET_BASIS 0x811c9dc5U
#define FNV1A_PRIME        0x01000193U

static unsigned int healer_predset_hash(unsigned int pred_a, unsigned int pred_b)
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

	/* predset_hash == 0 is the empty-slot sentinel; the (vanishingly
	 * rare) FNV-1a output of 0 collapses onto 1 so a real predset
	 * never collides with the empty marker. */
	if (h == 0)
		h = 1;
	return h;
}

void healer_seq_push(struct childdata *child, unsigned int nr)
{
	if (child == NULL)
		return;

	child->healer_seq[0] = child->healer_seq[1];
	child->healer_seq[1] = nr;
	if (child->healer_seq_count < 2)
		child->healer_seq_count++;
}

/*
 * Bump the (predset, current_nr) tuple in `slot`, evicting the lowest-
 * weight existing promoted entry when the slot is full.  Returns true
 * if an eviction took place, so the caller can bump the eviction
 * counter without re-scanning the array.  The caller holds
 * shm->healer_relations_lock across the whole insertion sequence so a
 * concurrent observer cannot lose a bump or evict our just-inserted
 * entry.
 */
static bool healer_slot_record(struct healer_relation *slot,
			       unsigned int current_nr)
{
	unsigned int i, victim;
	unsigned int victim_weight;

	for (i = 0; i < slot->promoted_count; i++) {
		if (slot->promoted[i].nr == current_nr) {
			slot->promoted[i].weight++;
			return false;
		}
	}

	if (slot->promoted_count < HEALER_PROMOTED_PER_SLOT) {
		slot->promoted[slot->promoted_count].nr = current_nr;
		slot->promoted[slot->promoted_count].weight = 1;
		slot->promoted_count++;
		return false;
	}

	/* Slot is full -- displace the lowest-weight entry.  Mirrors
	 * corrupt_ptr_attr_record's eviction policy: the new entry inherits
	 * victim_weight + 1 so a freshly displaced predset is not instantly
	 * re-evicted on its next observation. */
	victim = 0;
	victim_weight = slot->promoted[0].weight;
	for (i = 1; i < HEALER_PROMOTED_PER_SLOT; i++) {
		if (slot->promoted[i].weight < victim_weight) {
			victim = i;
			victim_weight = slot->promoted[i].weight;
		}
		if (victim_weight == 0)
			break;
	}
	slot->promoted[victim].nr = current_nr;
	slot->promoted[victim].weight = victim_weight + 1;
	return true;
}

void healer_observe_relation(struct childdata *child, unsigned int current_nr)
{
	unsigned int pred_a, pred_b;
	unsigned int predset_hash;
	unsigned int slot_idx;
	unsigned int probe;
	struct healer_relation *table;
	bool evicted = false;

	if (child == NULL)
		return;

	/* Need both predecessor slots populated.  The first two syscalls of
	 * a child's life have nothing to point at; skipping them costs us
	 * at most a handful of observations per child lifetime. */
	if (child->healer_seq_count < 2)
		return;

	pred_a = child->healer_seq[0];
	pred_b = child->healer_seq[1];

	/* An EDGEPAIR_NO_PREV sentinel can ride into the buffer if the
	 * child resets its sequence (e.g. between op-types); treat that as
	 * "no usable predset" and skip rather than learning a relation
	 * anchored on a sentinel value. */
	if (pred_a == EDGEPAIR_NO_PREV || pred_b == EDGEPAIR_NO_PREV)
		return;

	if (pred_a > pred_b) {
		unsigned int tmp = pred_a;
		pred_a = pred_b;
		pred_b = tmp;
	}

	predset_hash = healer_predset_hash(pred_a, pred_b);
	slot_idx = predset_hash & (HEALER_RELATION_SLOTS - 1);
	table = shm->healer_relations;

	lock(&shm->healer_relations_lock);

	for (probe = 0; probe < HEALER_PROBE_LIMIT; probe++) {
		struct healer_relation *slot;
		unsigned int idx;

		idx = (slot_idx + probe) & (HEALER_RELATION_SLOTS - 1);
		slot = &table[idx];

		if (slot->predset_hash == 0) {
			slot->predset_hash = predset_hash;
			slot->pred_a = pred_a;
			slot->pred_b = pred_b;
			slot->promoted[0].nr = current_nr;
			slot->promoted[0].weight = 1;
			slot->promoted_count = 1;
			break;
		}

		if (slot->predset_hash == predset_hash &&
		    slot->pred_a == pred_a &&
		    slot->pred_b == pred_b) {
			evicted = healer_slot_record(slot, current_nr);
			break;
		}
	}

	if (probe == HEALER_PROBE_LIMIT) {
		/* Ran off the end of the probe window without finding
		 * either the matching predset or an empty slot.  Drop the
		 * observation and surface the table-full event so the
		 * operator can spot a saturated table in the periodic dump. */
		shm->stats.healer_table_full++;
	}

	shm->stats.healer_relations_observed++;
	if (evicted)
		shm->stats.healer_evictions++;

	unlock(&shm->healer_relations_lock);
}

/*
 * Snapshot tuple emitted to the dump's top-N selector.  Each promoted
 * entry yields one of these; predset_hash is omitted because the
 * (pred_a, pred_b) pair is already self-identifying for the dump's
 * grouping needs.
 */
struct healer_dump_entry {
	unsigned int pred_a;
	unsigned int pred_b;
	unsigned int promoted_nr;
	unsigned int weight;
};

static int healer_dump_entry_cmp(const void *a, const void *b)
{
	const struct healer_dump_entry *ea = a;
	const struct healer_dump_entry *eb = b;

	if (ea->weight > eb->weight)
		return -1;
	if (ea->weight < eb->weight)
		return 1;
	return 0;
}

void healer_table_dump(void)
{
	struct healer_dump_entry top[HEALER_DUMP_TOP_N];
	unsigned int top_count = 0;
	unsigned int occupied = 0;
	unsigned long total_promoted = 0;
	unsigned int i, j;
	unsigned long observed, table_full, evictions;

	lock(&shm->healer_relations_lock);

	for (i = 0; i < HEALER_RELATION_SLOTS; i++) {
		const struct healer_relation *slot = &shm->healer_relations[i];

		if (slot->predset_hash == 0)
			continue;
		occupied++;
		total_promoted += slot->promoted_count;

		for (j = 0; j < slot->promoted_count; j++) {
			unsigned int weight = slot->promoted[j].weight;
			unsigned int min_idx = 0;
			unsigned int k;

			if (top_count < HEALER_DUMP_TOP_N) {
				top[top_count].pred_a = slot->pred_a;
				top[top_count].pred_b = slot->pred_b;
				top[top_count].promoted_nr =
					slot->promoted[j].nr;
				top[top_count].weight = weight;
				top_count++;
				continue;
			}

			for (k = 1; k < HEALER_DUMP_TOP_N; k++) {
				if (top[k].weight < top[min_idx].weight)
					min_idx = k;
			}
			if (weight > top[min_idx].weight) {
				top[min_idx].pred_a = slot->pred_a;
				top[min_idx].pred_b = slot->pred_b;
				top[min_idx].promoted_nr =
					slot->promoted[j].nr;
				top[min_idx].weight = weight;
			}
		}
	}

	/* Refresh the lazily-maintained occupancy counter while we still
	 * hold the lock so the value the dump prints matches what we just
	 * scanned. */
	shm->stats.healer_unique_predsets = occupied;

	observed = shm->stats.healer_relations_observed;
	table_full = shm->stats.healer_table_full;
	evictions = shm->stats.healer_evictions;

	unlock(&shm->healer_relations_lock);

	if (occupied == 0 && observed == 0)
		return;

	stats_log_write("HEALER relation table: %u/%u slots filled, %lu total promoted entries, %lu probe-limit hits, %lu evictions, %lu observations\n",
			occupied, HEALER_RELATION_SLOTS, total_promoted,
			table_full, evictions, observed);

	if (top_count == 0)
		return;

	qsort(top, top_count, sizeof(top[0]), healer_dump_entry_cmp);

	stats_log_write("HEALER top %u relations by weight:\n", top_count);
	for (i = 0; i < top_count; i++) {
		stats_log_write("  {%s, %s} -> %s weight=%u\n",
				print_syscall_name(top[i].pred_a, false),
				print_syscall_name(top[i].pred_b, false),
				print_syscall_name(top[i].promoted_nr, false),
				top[i].weight);
	}
}
