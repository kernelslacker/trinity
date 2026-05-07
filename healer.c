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

/*
 * Layout-pinning asserts so the (pred_a, pred_b, predset_hash) tuple
 * accessed via the .key uint64_t union member matches what the
 * struct-member view writes, and likewise for (nr, weight) inside
 * struct healer_promoted.  A future struct reorder that breaks the
 * packing fails to compile rather than silently desynchronising the
 * lockless CAS payload from the field view.  Mirrors the static
 * asserts edgepair.c uses to pin its own packed-key claim path.
 */
_Static_assert(offsetof(struct healer_relation, pred_a) == 0,
	       "pred_a must be at offset 0 for packed CAS");
_Static_assert(offsetof(struct healer_relation, pred_b) == 2,
	       "pred_b must be at offset 2 for packed CAS");
_Static_assert(offsetof(struct healer_relation, predset_hash) == 4,
	       "predset_hash must be at offset 4 for packed CAS");
_Static_assert(sizeof(uint16_t) == 2,
	       "uint16_t must be 2 bytes for packed CAS");
_Static_assert(sizeof(uint32_t) == 4,
	       "uint32_t must be 4 bytes for packed CAS");

_Static_assert(offsetof(struct healer_promoted, nr) == 0,
	       "nr must be at offset 0 for packed CAS");
_Static_assert(offsetof(struct healer_promoted, weight) == 4,
	       "weight must be at offset 4 for packed CAS");
_Static_assert(sizeof(unsigned int) == 4,
	       "unsigned int must be 4 bytes for packed CAS");

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
 * Pack (pred_a, pred_b, predset_hash) into a uint64_t matching the
 * union layout in struct healer_relation.  Goes through a typed
 * temporary + memcpy so the access stays inside the well-defined
 * union view that strict aliasing permits, the same trick edgepair.c
 * uses for its packed (prev_nr, curr_nr) key.
 */
static uint64_t healer_pack_key(unsigned int pred_a, unsigned int pred_b,
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

/*
 * Unpack pred_a / pred_b out of a previously-loaded slot key.  The
 * dump path uses this so it can pull the full identifier triple from
 * the single ACQUIRE-load of slot->key, rather than re-reading the
 * struct fields and exposing itself to a non-atomic tear against a
 * concurrent CAS-claim.
 */
static void healer_unpack_key(uint64_t key, unsigned int *pred_a,
			      unsigned int *pred_b)
{
	struct {
		uint16_t pa;
		uint16_t pb;
		uint32_t h;
	} tmp;

	memcpy(&tmp, &key, sizeof(tmp));
	*pred_a = tmp.pa;
	*pred_b = tmp.pb;
}

/*
 * Pack (nr, weight) into the uint64_t entry view of struct
 * healer_promoted.  weight == 0 marks an empty entry; a real entry
 * always carries weight >= 1, so the packed value is non-zero
 * whenever the slot is populated.
 */
static uint64_t healer_pack_promoted(unsigned int nr, unsigned int weight)
{
	struct {
		unsigned int n;
		unsigned int w;
	} tmp = { nr, weight };
	uint64_t packed;

	memcpy(&packed, &tmp, sizeof(packed));
	return packed;
}

static void healer_unpack_promoted(uint64_t entry, unsigned int *nr,
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

/*
 * Bump the (predset, current_nr) tuple in `slot`, evicting the lowest-
 * weight existing promoted entry when the slot is full.  Returns true
 * if an eviction took place, so the caller can bump the eviction
 * counter without re-scanning the array.  Lockless: each promoted
 * entry is mutated via a 64-bit CAS on the (nr, weight) packed view,
 * weight == 0 is the empty-entry sentinel, and CAS failure restarts
 * the scan so we re-pick up any state another observer just published
 * (a concurrent insert of the same nr collapses onto the bump path
 * on the next pass; a concurrent eviction reopens an empty entry that
 * the next pass tries to claim before scanning for a new victim).
 */
static bool healer_slot_record(struct healer_relation *slot,
			       unsigned int current_nr)
{
	unsigned int i;
	unsigned int victim_idx = 0;
	unsigned int victim_weight = 0;
	uint64_t victim_packed = 0;
	bool victim_found;
	uint64_t expected, target;
	int restart_budget = HEALER_PROMOTED_PER_SLOT * 2;

restart:
	if (--restart_budget < 0) {
		/* Defensive bound on the lockless retry loop -- under
		 * pathological CAS contention we'd rather drop one
		 * observation than spin forever.  In practice the
		 * observer-hook fire rate keeps per-slot contention
		 * vanishingly small; this exists for the worst-case
		 * tail and never trips in steady state. */
		return false;
	}

	/* Phase 1: scan for an existing (predset, current_nr) entry and
	 * bump its weight.  Atomic load gives us a coherent snapshot of
	 * the (nr, weight) pair; weight == 0 means the entry is empty
	 * (and not in flight, since claim/evict CASes publish weight >=
	 * 1 atomically). */
	for (i = 0; i < HEALER_PROMOTED_PER_SLOT; i++) {
		uint64_t entry;
		unsigned int weight, nr;

		entry = __atomic_load_n(&slot->promoted[i].entry,
					__ATOMIC_RELAXED);
		healer_unpack_promoted(entry, &nr, &weight);

		if (weight != 0 && nr == current_nr) {
			__atomic_fetch_add(&slot->promoted[i].weight,
					   1, __ATOMIC_RELAXED);
			return false;
		}
	}

	/* Phase 2: try to claim an empty entry for current_nr.  CAS the
	 * packed (nr, weight) field from the all-zero empty marker to
	 * (current_nr, 1); a competing observer that wins the CAS for
	 * some nr' instead leaves us to restart, so we either land on
	 * the existing-match path (if nr' == current_nr) or claim a
	 * different empty entry on the next pass. */
	for (i = 0; i < HEALER_PROMOTED_PER_SLOT; i++) {
		uint64_t loaded;

		loaded = __atomic_load_n(&slot->promoted[i].entry,
					 __ATOMIC_RELAXED);
		if (loaded != 0)
			continue;

		expected = 0;
		target = healer_pack_promoted(current_nr, 1);

		if (__atomic_compare_exchange_n(&slot->promoted[i].entry,
						&expected, target, false,
						__ATOMIC_RELEASE,
						__ATOMIC_RELAXED))
			return false;

		/* CAS lost: another observer just published into this
		 * entry.  Restart from Phase 1 in case they published
		 * our nr (in which case we want the bump path). */
		goto restart;
	}

	/* Phase 3: slot is full -- displace the lowest-weight entry.
	 * Mirrors the original eviction policy: the new entry inherits
	 * victim_weight + 1 so a freshly displaced predset is not
	 * instantly re-evicted on its next observation.  CAS the
	 * victim's exact prior packed value so a concurrent bump or
	 * eviction is detected and triggers a re-scan. */
	victim_found = false;
	for (i = 0; i < HEALER_PROMOTED_PER_SLOT; i++) {
		uint64_t entry;
		unsigned int weight, nr;

		entry = __atomic_load_n(&slot->promoted[i].entry,
					__ATOMIC_RELAXED);
		healer_unpack_promoted(entry, &nr, &weight);

		/* Re-check for a concurrent insert of current_nr before
		 * we evict -- another observer might have published our
		 * nr while we were scanning Phases 1-2. */
		if (weight != 0 && nr == current_nr) {
			__atomic_fetch_add(&slot->promoted[i].weight,
					   1, __ATOMIC_RELAXED);
			return false;
		}

		/* A concurrent eviction may have just opened a fresh
		 * empty entry; restart so we can try the cheaper Phase 2
		 * claim path before resorting to another eviction. */
		if (weight == 0)
			goto restart;

		if (!victim_found || weight < victim_weight) {
			victim_idx = i;
			victim_weight = weight;
			victim_packed = entry;
			victim_found = true;
		}
	}

	expected = victim_packed;
	target = healer_pack_promoted(current_nr, victim_weight + 1);

	if (__atomic_compare_exchange_n(&slot->promoted[victim_idx].entry,
					&expected, target, false,
					__ATOMIC_RELEASE,
					__ATOMIC_RELAXED))
		return true;

	/* Victim was bumped or evicted out from under us -- restart. */
	goto restart;
}

void healer_observe_relation(struct childdata *child, unsigned int current_nr)
{
	unsigned int pred_a, pred_b;
	unsigned int predset_hash;
	unsigned int slot_idx;
	unsigned int probe;
	struct healer_relation *table;
	uint64_t target_key;
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
	target_key = healer_pack_key(pred_a, pred_b, predset_hash);

	for (probe = 0; probe < HEALER_PROBE_LIMIT; probe++) {
		struct healer_relation *slot;
		unsigned int idx;
		uint64_t slot_key;

		idx = (slot_idx + probe) & (HEALER_RELATION_SLOTS - 1);
		slot = &table[idx];
		slot_key = __atomic_load_n(&slot->key, __ATOMIC_ACQUIRE);

		if (slot_key == 0) {
			uint64_t expected = 0;

			if (__atomic_compare_exchange_n(
					&slot->key, &expected, target_key,
					false, __ATOMIC_RELEASE,
					__ATOMIC_RELAXED)) {
				/* Slot is now ours.  Fall through to
				 * healer_slot_record so the first promoted
				 * entry goes in via the same CAS-claim
				 * machinery any concurrent observer also
				 * uses -- a second observer that ACQUIREs
				 * slot->key right after our publish and
				 * races into promoted[0] is handled
				 * uniformly without needing a special
				 * "winner stores promoted[0] directly"
				 * path that would race against them. */
				evicted = healer_slot_record(slot, current_nr);
				break;
			}

			/* CAS lost: another observer claimed this slot.
			 * `expected` now holds the winning key -- if it
			 * matches our predset, fall through to the match
			 * path so we still bump (predset, current_nr). */
			slot_key = expected;
			if (slot_key != target_key)
				continue;
		}

		if (slot_key == target_key) {
			evicted = healer_slot_record(slot, current_nr);
			break;
		}
	}

	if (probe == HEALER_PROBE_LIMIT) {
		/* Ran off the end of the probe window without finding
		 * either the matching predset or an empty slot.  Drop the
		 * observation and surface the table-full event so the
		 * operator can spot a saturated table in the periodic dump. */
		__atomic_fetch_add(&shm->stats.healer_table_full, 1,
				   __ATOMIC_RELAXED);
	}

	__atomic_fetch_add(&shm->stats.healer_relations_observed, 1,
			   __ATOMIC_RELAXED);
	if (evicted)
		__atomic_fetch_add(&shm->stats.healer_evictions, 1,
				   __ATOMIC_RELAXED);
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

	/* Lockless sweep: each slot is read via a single ACQUIRE-load of
	 * slot->key so the (pred_a, pred_b, predset_hash) tuple is a
	 * coherent snapshot against the writer's RELEASE-CAS, and each
	 * promoted entry is read via a single atomic load of the packed
	 * (nr, weight) field for the same reason.  The cross-slot
	 * snapshot is best-effort -- entries may appear or advance
	 * during the scan -- which matches the dump's "approximate
	 * top-10 right now" intent and is the same tolerance
	 * cmp_hints' lockless reader documents. */
	for (i = 0; i < HEALER_RELATION_SLOTS; i++) {
		const struct healer_relation *slot = &shm->healer_relations[i];
		uint64_t slot_key;
		unsigned int slot_pred_a, slot_pred_b;
		unsigned int slot_promoted = 0;

		slot_key = __atomic_load_n(&slot->key, __ATOMIC_ACQUIRE);
		if (slot_key == 0)
			continue;

		healer_unpack_key(slot_key, &slot_pred_a, &slot_pred_b);

		for (j = 0; j < HEALER_PROMOTED_PER_SLOT; j++) {
			uint64_t entry;
			unsigned int weight, nr;
			unsigned int min_idx = 0;
			unsigned int k;

			entry = __atomic_load_n(&slot->promoted[j].entry,
						__ATOMIC_RELAXED);
			healer_unpack_promoted(entry, &nr, &weight);

			if (weight == 0)
				continue;

			slot_promoted++;

			if (top_count < HEALER_DUMP_TOP_N) {
				top[top_count].pred_a = slot_pred_a;
				top[top_count].pred_b = slot_pred_b;
				top[top_count].promoted_nr = nr;
				top[top_count].weight = weight;
				top_count++;
				continue;
			}

			for (k = 1; k < HEALER_DUMP_TOP_N; k++) {
				if (top[k].weight < top[min_idx].weight)
					min_idx = k;
			}
			if (weight > top[min_idx].weight) {
				top[min_idx].pred_a = slot_pred_a;
				top[min_idx].pred_b = slot_pred_b;
				top[min_idx].promoted_nr = nr;
				top[min_idx].weight = weight;
			}
		}

		if (slot_promoted > 0) {
			occupied++;
			total_promoted += slot_promoted;
		}
	}

	/* Refresh the lazily-maintained occupancy counter so the dump
	 * we are about to emit reflects the slot scan we just did.  The
	 * hot observer-hook path stays free of an extra counter store. */
	__atomic_store_n(&shm->stats.healer_unique_predsets, occupied,
			 __ATOMIC_RELAXED);

	observed = __atomic_load_n(&shm->stats.healer_relations_observed,
				   __ATOMIC_RELAXED);
	table_full = __atomic_load_n(&shm->stats.healer_table_full,
				     __ATOMIC_RELAXED);
	evictions = __atomic_load_n(&shm->stats.healer_evictions,
				    __ATOMIC_RELAXED);

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
