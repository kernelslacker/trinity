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
 *
 * --- Lineage note ---
 *
 * The name HEALER comes from the SOSP'21 paper "HEALER: Relation
 * Learning Guided Kernel Fuzzing" (Sun et al.), which seeds an
 * influence relation matrix R[a][b] from MoonShine-style static
 * field analysis of kernel handlers and refines it dynamically via
 * observed coverage gain.  This implementation is HEALER-INSPIRED
 * rather than a faithful port; meaningful divergences worth noting
 * for anyone reading the literature alongside the code:
 *
 *   - The original HEALER stores PAIRS (a -> b) in a 2D matrix.
 *     This implementation tracks TRIPLES ((pred_a, pred_b) -> succ)
 *     in a sparse hash table.  The pair table introduced by the
 *     static-seed work is parallel storage, not the primary unit.
 *
 *   - The original HEALER's static prior comes from MoonShine's
 *     read/write field analysis on kernel sources.  Trinity has no
 *     such analyser; the static seed here is a coarser approximation
 *     derived from trinity's own ARG_FD_* / ret_objtype metadata
 *     (producer syscall A's return type matches a typed-arg slot of
 *     consumer B).  Probably ~80% of MoonShine's signal at zero
 *     analysis cost.
 *
 *   - The original HEALER's R is consumed by upstream fuzzing's program
 *     generator to bias A->B sequence picks.  The trinity picker
 *     does NOT yet consult this table -- the bandit/explorer
 *     strategies pick syscalls from coverage feedback alone.
 *     "Phase B" above is where this is supposed to change.
 *
 *   - TF-IDF normalisation, per-predecessor frequency tracking,
 *     decay walks, the corrupt-entry filter, and the low-confidence
 *     and minimum-raw qualification floors are all trinity-specific
 *     additions that don't appear in the original paper.
 *
 * In practice the module is closer to a "syscall relation observer
 * + dump" than to HEALER's program generator.  Name retained because
 * the intellectual lineage is real and the literature reference is
 * useful for new contributors.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include "arch.h"		/* biarch */
#include "child.h"
#include "edgepair.h"		/* EDGEPAIR_NO_PREV */
#include "healer.h"
#include "params.h"		/* do_32_arch, do_64_arch */
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
 * Low-confidence floor for top-N qualification.  Entries whose
 * predecessor pair has a zero appearance counter on at least one side
 * lack this-run evidence and are dropped before the normalised score
 * is even computed -- a complementary mechanism to the
 * HEALER_NORM_PREDFREQ_BIAS pseudo-count that dampens the score for
 * entries that survive the filter (predfreq >= 1 on both sides) and
 * for the pair-side dump path which has no equivalent filter at all.
 * Two real shapes hit this filter:
 *   - warm-started entries inherited from a prior run, whose pair
 *     hasn't yet been observed in the new run (both counters still 0);
 *   - predecessor-skipped leftovers, where one side of the pair is a
 *     syscall the observer-hook gate now refuses to feed into
 *     healer_seq (e.g. a syscall returning ENOSYS on this kernel),
 *     so its appearance counter stays 0 forever and the entry
 *     persists in the table until decay+eviction reclaims it.
 * Filter at top-N qualification only; the observation, save/load and
 * decay paths keep handling these entries normally.
 */
#define HEALER_DUMP_MIN_PRED_APPEARANCES 1

/*
 * Minimum raw-observation floor for top-N qualification.  A promoted
 * entry's weight is the raw count of times that (predset -> successor)
 * triple has been observed; entries with raw=1 are single-shot events
 * and carry no statistical signal yet.  Without this floor the TF-IDF
 * normalisation in healer_normalised_score_milli amplifies a single
 * observation into a high norm score whenever either predecessor's
 * appearance count is small (the isqrt(a*b+1) denominator is tiny when
 * one side is in the low single digits), so raw=1 noise was repeatedly
 * elevating itself into the dump's top-10 alongside genuinely repeated
 * patterns.  Filter at top-N qualification only; observation, save/load
 * and decay all keep handling these entries normally so they remain
 * available to graduate into the ranking once they accumulate evidence.
 */
#define HEALER_DUMP_MIN_RAW 3

/*
 * Initial weight installed by the static-seed loader for each producer/
 * consumer pair derived from the existing ret_objtype / argtype metadata
 * the syscall table already carries.  Held at the same value as
 * HEALER_DUMP_MIN_RAW so seeded pairs clear the top-N qualification
 * floor immediately, but a real triple with raw>=4 still beats them
 * once observations actually accumulate.  Bootstraps the picker's pair
 * prior on cold runs without dominating the ranking long-term.
 */
#define HEALER_STATIC_SEED_WEIGHT 3

/*
 * Additive bias applied to each predecessor-appearance count before the
 * normalisation denominator is computed.  Acts as a Bayesian-style
 * pseudo-count: a predecessor that has not yet been observed in the
 * current run is treated as if it had been observed this many times,
 * so the denominator never collapses to its minimum value (isqrt(0+1)
 * == isqrt(1) == 1) and seeded entries with predfreq == 0 stop scoring
 * at raw_weight * 1000 -- which on the pair-side dump made every static
 * seed install render as norm == raw and crowd dynamically observed
 * entries (whose denominator was already > 1) out of the top-N entirely.
 *
 * Sized at 5 because the dynamic-pair entries that demonstrably carry
 * signal (the post-load observer-bumped pairs that actually fired in
 * the run) hit predfreq counts in the low single digits within the
 * first dump tick, and crossing K is what lets a real entry rise above
 * the seed-baseline.  Lower K leaves seeds visible in the ranking;
 * higher K over-suppresses early-run dynamic signal before the
 * counters have had time to accumulate.
 */
#define HEALER_NORM_PREDFREQ_BIAS 5

/*
 * Display-time pollution filter: minimum total HEALER observation
 * count before the dump suppresses static-seeded entries whose
 * participating syscalls have never been attempted by any child this
 * run.  Below this threshold the dump trusts the seed-derived
 * ranking, since "never attempted" early in a run just means "the
 * random scheduler hasn't picked it yet".  Above it, attempted == 0
 * means the kernel is rejecting the syscall (ENOSYS, missing CONFIG,
 * sandboxed) and the seed's pair will never produce real signal -- so
 * surfacing it in the top-N is pure UX noise (e.g. {*, landlock_*}
 * lines on a no-LANDLOCK kernel that pollute the seed-only section
 * for the entire run).  Replaces the failed startup ENOSYS-probe
 * approach (commits 9ec0ac291dd2 / 3f61a24beebd, both reverted for
 * hangs and fragility) with a no-startup-cost dump-path filter.
 *
 * Sized at 1000 because by the time HEALER has logged that many
 * observations the random scheduler has had ample opportunity to dial
 * any genuinely-supported syscall at least once; an entry still at
 * attempted == 0 at that point is overwhelmingly likely to be one the
 * kernel will keep rejecting.
 */
#define HEALER_POLLUTION_FILTER_THRESHOLD 1000UL

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

static void healer_maybe_decay(void);

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

	/* Pair-table observer: credit the (immediate-predecessor -> current_nr)
	 * relationship.  The immediate predecessor is healer_seq[1], which is
	 * still in pred_b at this point (the pred_a/pred_b swap below normalises
	 * for the triple-table key but discards the temporal ordering we need
	 * here).  Without this call the pair table never accumulates weight
	 * beyond the static seed and is indistinguishable from the producer/
	 * consumer prior. */
	healer_pair_observe(pred_b, current_nr);

	if (pred_a > pred_b) {
		unsigned int tmp = pred_a;
		pred_a = pred_b;
		pred_b = tmp;
	}

	/*
	 * Bump the per-syscall predecessor-appearance counter that feeds the
	 * TF-IDF-style normalisation on the dump path.  Done before the
	 * lookup so a probe-limit miss still increments the denominator --
	 * the syscall *did* appear as a predecessor in an observation, even
	 * if no slot was available to credit the pair.  Skip the second
	 * bump when pred_a == pred_b so a self-paired predset (same syscall
	 * fired twice in a row) doesn't get double-counted against itself.
	 */
	if (pred_a < MAX_NR_SYSCALL)
		__atomic_add_fetch(&shm->stats.healer_pred_appearance[pred_a],
				   1, __ATOMIC_RELAXED);
	if (pred_b != pred_a && pred_b < MAX_NR_SYSCALL)
		__atomic_add_fetch(&shm->stats.healer_pred_appearance[pred_b],
				   1, __ATOMIC_RELAXED);

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

	/* Periodic weight-decay: every HEALER_DECAY_OBSERVATIONS one
	 * CAS-elected observer halves all entry weights (floor 1) so the
	 * relation table converges on persistently-correlated tuples
	 * rather than accumulating weight=1 co-occurrence noise that
	 * eviction alone only sheds at slot saturation.  Cheap fast path
	 * when the gap isn't reached. */
	healer_maybe_decay();
}

/*
 * Periodic weight-decay trigger.
 *
 * Without decay, every (predset, nr) tuple ever observed accumulates
 * weight monotonically until the slot saturates and the lowest-weight
 * entry gets evicted -- which means a single one-time co-occurrence
 * (weight=1) sits in the table forever as long as the slot has room,
 * dragging the top-N dump toward syscall-frequency noise rather than
 * causal correlation.  Periodic halving lets the table converge on
 * persistently-correlated tuples: anything getting bumped at least
 * every other window holds its rank, while a one-shot weight=1 entry
 * stays at the noise floor and gets displaced when a real follow-up
 * needs the slot.
 *
 * 5000 observations: tighter than the snapshot cadence (50000) on
 * purpose -- fleet data shows the observation rate collapses an order
 * of magnitude (~30/sec early-run -> ~0.5/sec post-saturation) once
 * KCOV coverage flattens, so a 50K threshold meant decay never fired
 * during the saturated steady state where it's most needed (top-N
 * dominated by frozen historical bursts that don't reflect current
 * causation).  5K fires several times during the hot phase too, but
 * the decay walk is a single relaxed-atomic sweep so the cost is
 * negligible vs the snapshot cadence on which the operator's only
 * visible artifact (the dump line) rides.  Decoupled from the
 * snapshot interval since the two don't need to share a value.
 */
#define HEALER_DECAY_OBSERVATIONS	5000UL

/*
 * Wall-clock secondary trigger for the decay walk.  The observation-based
 * trigger above only fires when new edges are being discovered, but on a
 * long-running fuzz the KCOV edge set saturates and the observation rate
 * collapses to ~0 -- which leaves the table frozen with whatever
 * historical weights it had at saturation, defeating the purpose of
 * decay (the top-N becomes a snapshot of the early-run discovery burst
 * rather than what's productive right now).  600s is comfortably longer
 * than a hot-phase observation window (decay fires several times during
 * the burst via the observation trigger, well before 10 minutes elapses)
 * but short enough that a saturated steady-state table doesn't sit
 * unaged for hours.  Hardcoded -- no operator knob, no expectation that
 * fleet boxes will need to retune this.
 */
#define HEALER_DECAY_INTERVAL_SEC	600UL

/*
 * Single-runner election + decay walk.  Mirrors healer_maybe_snapshot's
 * window-CAS pattern so concurrent observers don't all walk the table
 * at the same boundary; the decay walk itself is best-effort relaxed
 * stores against the live table -- a concurrent observer's
 * fetch-add-1 on an entry the decay walk just halved loses at most one
 * weight bump, which the next observation re-credits.  Intentionally
 * cheaper than the snapshot path: no staging buffer, no fsync, no
 * rename -- just one pass over HEALER_RELATION_SLOTS * HEALER_PROMOTED_PER_SLOT
 * entries (= 128K relaxed atomic ops worst case, well under a millisecond).
 */
static void healer_maybe_decay(void)
{
	unsigned long obs_now, old;
	unsigned long now_sec, old_time, new_obs;
	unsigned int i, j;
	bool obs_trigger, time_trigger;

	if (shm == NULL)
		return;

	obs_now = __atomic_load_n(&shm->stats.healer_relations_observed,
				  __ATOMIC_RELAXED);
	old = __atomic_load_n(&shm->stats.healer_obs_at_last_decay,
			      __ATOMIC_RELAXED);
	old_time = __atomic_load_n(&shm->stats.healer_time_at_last_decay,
				   __ATOMIC_RELAXED);
	now_sec = (unsigned long)time(NULL);

	obs_trigger = (obs_now >= old + HEALER_DECAY_OBSERVATIONS);
	time_trigger = (now_sec >= old_time + HEALER_DECAY_INTERVAL_SEC);

	if (!obs_trigger && !time_trigger)
		return;

	/* Window-CAS election on healer_obs_at_last_decay: whichever observer
	 * wins owns this decay boundary; losers see the advanced high-water-
	 * mark on their next call and early-return.  RELAXED is enough -- the
	 * walk's atomic stores carry their own ordering against concurrent
	 * observer bumps, and the counter is just gating who runs, not what
	 * they observe.
	 *
	 * When only the time trigger fires, obs_now may equal `old` (no new
	 * observations since the last decay), and a CAS of (old -> old) would
	 * succeed for every concurrent observer rather than electing one.
	 * Force the new value to be strictly greater in that case so the CAS
	 * is a real change and contested calls actually serialise.  The +1
	 * skew on the next observation-trigger boundary is irrelevant against
	 * the 5000-observation window. */
	new_obs = (obs_now > old) ? obs_now : old + 1;
	if (!__atomic_compare_exchange_n(&shm->stats.healer_obs_at_last_decay,
					 &old, new_obs,
					 false,
					 __ATOMIC_RELAXED, __ATOMIC_RELAXED))
		return;

	/* Won the election -- advance the time baseline so the next time-
	 * trigger window starts cleanly regardless of which trigger fired
	 * this time.  No CAS needed: the obs-field election above already
	 * guarantees we're the sole writer for this decay boundary. */
	__atomic_store_n(&shm->stats.healer_time_at_last_decay, now_sec,
			 __ATOMIC_RELAXED);

	/* Walk the table once, halving every populated entry's weight with
	 * a floor of 1.  Floor 1 (rather than evicting weight=0 entries) is
	 * deliberate: a borderline-real relation that hasn't yet accumulated
	 * a second bump still gets one more decay window to prove itself
	 * before the slot's eviction policy gets a crack at it.  Race window
	 * with concurrent observers is fine: a fetch_add on an entry we
	 * halved races, but the worst case is one lost bump per racing
	 * observer per decay -- vanishing against the per-window observation
	 * count. */
	for (i = 0; i < HEALER_RELATION_SLOTS; i++) {
		struct healer_relation *slot = &shm->healer_relations[i];
		uint64_t slot_key;

		slot_key = __atomic_load_n(&slot->key, __ATOMIC_ACQUIRE);
		if (slot_key == 0)
			continue;

		for (j = 0; j < HEALER_PROMOTED_PER_SLOT; j++) {
			uint64_t entry;
			unsigned int weight, nr, halved;

			entry = __atomic_load_n(&slot->promoted[j].entry,
						__ATOMIC_RELAXED);
			healer_unpack_promoted(entry, &nr, &weight);

			if (weight <= 1)
				continue;

			halved = weight / 2;
			if (halved < 1)
				halved = 1;
			__atomic_store_n(&slot->promoted[j].weight, halved,
					 __ATOMIC_RELAXED);
		}
	}

	__atomic_fetch_add(&shm->stats.healer_weight_decays_run, 1,
			   __ATOMIC_RELAXED);
}

/*
 * Snapshot tuple emitted to the dump's top-N selector.  Each promoted
 * entry yields one of these; predset_hash is omitted because the
 * (pred_a, pred_b) pair is already self-identifying for the dump's
 * grouping needs.  pred_a_freq / pred_b_freq are the per-predecessor
 * appearance counters captured at scan time, kept on the entry so the
 * sort-by-normalised-score and the per-line display both work from the
 * same snapshot value (re-reading the live counter for the display
 * after sorting on a stale read would risk emitting a normalised score
 * that doesn't match the freq numbers shown next to it).
 *
 * Pair-table entries reuse this struct so the same sort and top-N
 * selection ranks triples and pairs head-to-head by normalised score.
 * For a pair entry (is_pair == true): pred_b carries the producer
 * syscall, promoted_nr carries the consumer, pred_b_freq carries the
 * producer's appearance count, and pred_a / pred_a_freq are unused
 * (the rendered line shows `*` in the slot a triple would put pred_a).
 */
struct healer_dump_entry {
	unsigned int pred_a;
	unsigned int pred_b;
	unsigned int promoted_nr;
	unsigned int weight;
	unsigned long pred_a_freq;
	unsigned long pred_b_freq;
	unsigned long norm_score_milli;
	bool is_pair;
};

/*
 * Integer square root via Newton's method, used by the dump-path
 * normalisation.  Trinity has no isqrt helper of its own and pulling in
 * libm just for sqrt() on a once-per-dump-tick path is overkill; this
 * converges in a handful of iterations for the input range we care
 * about (per-syscall appearance products fit comfortably in 64 bits
 * across any realistic fuzz duration).
 */
static unsigned long healer_isqrt(unsigned long n)
{
	unsigned long x, y;

	if (n < 2)
		return n;
	x = n;
	y = (x + 1) / 2;
	while (y < x) {
		x = y;
		y = (x + n / x) / 2;
	}
	return x;
}

/*
 * TF-IDF-style normalisation for the relation-table dump.  Returns a
 * fixed-point score scaled by 1000 so the dump path can sort and emit
 * two-decimal precision without dragging floating point onto the hot
 * stats output.
 *
 * Formula:
 *   a     = pred_a_freq + HEALER_NORM_PREDFREQ_BIAS
 *   b     = pred_b_freq + HEALER_NORM_PREDFREQ_BIAS
 *   norm  = (raw_weight * 1000) / isqrt(a * b + 1)
 *
 * Rationale (chose sqrt-dampening over log2 or one-sided / max):
 *   - sqrt has the right monotonic shape: a predecessor that appears 100x
 *     gets penalised ~10x, one that appears 10000x gets penalised ~100x.
 *     The penalty grows with frequency but not as steeply as plain
 *     division by frequency, so a pair with one slightly-frequent and
 *     one rare predecessor still scores meaningfully higher than a pair
 *     of two frequent ones.
 *   - HEALER_NORM_PREDFREQ_BIAS shifts each predfreq by a constant
 *     pseudo-count before the multiply-and-sqrt, so a not-yet-observed
 *     predecessor (predfreq == 0) no longer collapses the denominator
 *     to isqrt(0*0 + 1) == 1.  Without that bias, every entry whose
 *     pair was static-seeded but not yet dynamically observed scored
 *     at raw_weight * 1000 -- the entire top-N degenerated into the
 *     seed floor and dynamically observed entries with real signal
 *     (denominator > 1) were buried below them.
 *   - The "+1" inside the isqrt is now redundant for divide-by-zero
 *     protection (the K-bias guarantees a*b >= K*K > 0), but is kept
 *     so the formula's textual shape stays comparable to the prior
 *     baseline and the post-isqrt `denom == 0` guard below remains a
 *     trivial cheap check.
 *   - Cheaper to compute than a portable integer log2 (no special-case
 *     handling for small values, no __builtin_clzl shape-fixup) and
 *     less aggressive than `weight / max(a, b)` which would over-penalise
 *     a pair where both predecessors are productive.
 *
 * Raw weight is preserved on the per-entry display so the operator can
 * still see the underlying signal alongside the normalised ranking.
 */
static unsigned long healer_normalised_score_milli(unsigned long raw_weight,
						   unsigned long pred_a_freq,
						   unsigned long pred_b_freq)
{
	unsigned long a = pred_a_freq + HEALER_NORM_PREDFREQ_BIAS;
	unsigned long b = pred_b_freq + HEALER_NORM_PREDFREQ_BIAS;
	unsigned long product = a * b + 1;
	unsigned long denom = healer_isqrt(product);

	if (denom == 0)
		denom = 1;
	return (raw_weight * 1000UL) / denom;
}

static int healer_dump_entry_cmp(const void *a, const void *b)
{
	const struct healer_dump_entry *ea = a;
	const struct healer_dump_entry *eb = b;

	if (ea->norm_score_milli > eb->norm_score_milli)
		return -1;
	if (ea->norm_score_milli < eb->norm_score_milli)
		return 1;
	return 0;
}

/*
 * Bounded-size top-N insertion shared by the triple and pair
 * collection loops.  Holds the top HEALER_DUMP_TOP_N entries in
 * unsorted form: fills until full, then evicts the slot with the
 * smallest norm_score_milli when a higher-scoring candidate arrives.
 * Hoisted out of the dump body so the same heap-replacement logic
 * does not have to be repeated for the dynamic and seed-only pools
 * the caller now keeps separate.
 */
static void healer_top_n_insert(struct healer_dump_entry *top,
				unsigned int *top_count,
				const struct healer_dump_entry *cand)
{
	unsigned int min_idx = 0;
	unsigned int k;

	if (*top_count < HEALER_DUMP_TOP_N) {
		top[*top_count] = *cand;
		(*top_count)++;
		return;
	}

	for (k = 1; k < HEALER_DUMP_TOP_N; k++) {
		if (top[k].norm_score_milli < top[min_idx].norm_score_milli)
			min_idx = k;
	}
	if (cand->norm_score_milli > top[min_idx].norm_score_milli)
		top[min_idx] = *cand;
}

/*
 * Emit one ranked section of the top-N dump.  Caller passes a header
 * format string with a single %u for the count plus the already-sorted
 * top[] slice; this just walks the slice and prints each entry in the
 * same shape healer_table_dump used to print a single combined block.
 * Pair entries render with `*` in the slot a triple would put pred_a so
 * the operator can tell at a glance which lines come from the
 * producer/consumer prior vs the runtime-observed triple table.
 */
static void healer_dump_emit_top(const char *header_fmt,
				 const struct healer_dump_entry *top,
				 unsigned int count)
{
	unsigned int i;

	stats_log_write(header_fmt, count);
	for (i = 0; i < count; i++) {
		if (top[i].is_pair) {
			stats_log_write("  {*, %s} -> %s norm=%lu.%03lu (raw=%u, predfreq=%lu)\n",
					print_syscall_name(top[i].pred_b, false),
					print_syscall_name(top[i].promoted_nr, false),
					top[i].norm_score_milli / 1000,
					top[i].norm_score_milli % 1000,
					top[i].weight,
					top[i].pred_b_freq);
			continue;
		}
		stats_log_write("  {%s, %s} -> %s norm=%lu.%03lu (raw=%u, predfreq a=%lu b=%lu)\n",
				print_syscall_name(top[i].pred_a, false),
				print_syscall_name(top[i].pred_b, false),
				print_syscall_name(top[i].promoted_nr, false),
				top[i].norm_score_milli / 1000,
				top[i].norm_score_milli % 1000,
				top[i].weight,
				top[i].pred_a_freq,
				top[i].pred_b_freq);
	}
}

/*
 * Per-syscall aggregate used by the predecessor-frequency leader
 * display: appearance counter snapshot + sum of weights where this
 * syscall is the *successor* of some pair.  The latter lets the
 * operator distinguish a pure noise rider (high appearance, zero
 * successor weight -- e.g. getppid on the live runs) from a syscall
 * that's frequent as a predecessor and also genuinely productive
 * (high appearance, also non-trivial successor weight).
 */
struct healer_pred_leader {
	unsigned int nr;
	unsigned long appearances;
	unsigned long succ_weight;
};

static int healer_pred_leader_cmp(const void *a, const void *b)
{
	const struct healer_pred_leader *la = a;
	const struct healer_pred_leader *lb = b;

	if (la->appearances > lb->appearances)
		return -1;
	if (la->appearances < lb->appearances)
		return 1;
	return 0;
}

#define HEALER_PRED_LEADERS_TOP_N 5

/*
 * True if the syscall's per-entry attempted counter is still zero --
 * i.e. no child has ever called this syscall this run.  Backs the
 * dump-path pollution filter (HEALER_POLLUTION_FILTER_THRESHOLD).
 *
 * NULL or out-of-range entries are treated as unattempted: a slot
 * the build's syscall table does not even carry cannot meaningfully
 * have been attempted, and the surrounding filter still requires the
 * total observation threshold before acting on the result, so a
 * mis-seeded out-of-range nr cannot suppress anything until the run
 * is well past warmup.  do32 is left at false to match the call shape
 * print_syscall_name uses everywhere else in the dump path -- HEALER
 * does not separately track 32-bit dispatches.
 */
static bool healer_syscall_unattempted(unsigned int nr)
{
	const struct syscallentry *entry;

	if (nr >= MAX_NR_SYSCALL)
		return true;
	entry = get_syscall_entry(nr, false);
	if (entry == NULL)
		return true;
	return entry->attempted == 0;
}

void healer_table_dump(void)
{
	/*
	 * Two parallel top-N pools so the dump can show high-confidence
	 * (any predfreq>0, dynamically observed at least once) and seed-
	 * only (predfreq==0, purely static-seeded) entries in separate
	 * ranked sections.  Without the split, the K=5 denominator bias
	 * leaves un-confirmed seeds at norm=1.500 and they crowd out any
	 * dynamically observed entry whose normalised score has been
	 * dampened by the actual pred-appearance counts -- the seed pool
	 * dominates the combined ranking until dynamic entries accumulate
	 * enough observations to overtake them, which is the opposite of
	 * what the dump should be highlighting.
	 */
	struct healer_dump_entry top_dyn[HEALER_DUMP_TOP_N];
	struct healer_dump_entry top_seed[HEALER_DUMP_TOP_N];
	unsigned int top_dyn_count = 0;
	unsigned int top_seed_count = 0;
	unsigned int occupied = 0;
	unsigned long total_promoted = 0;
	unsigned long total_weight = 0;
	unsigned long weight_gt_1 = 0;
	unsigned long weight_gt_5 = 0;
	unsigned long weight_gt_10 = 0;
	unsigned long mean_milli = 0;
	/*
	 * Counts relation-table slots whose unpacked (pred_a, pred_b) tuple
	 * or whose inner promoted entry's nr is >= MAX_NR_SYSCALL — i.e. not
	 * a real syscall number.  Real syscall nrs top out around 471 today;
	 * any larger value in a slot is the signature of a stray scribble
	 * landing on healer_relations[] in shm (same broad corruption class
	 * being chased separately for rec->retval).  Skip these from both
	 * the gt counts and the top-N display so they don't poison the
	 * normalised ranking — a corrupt entry has appearance counters of
	 * zero and would otherwise sort to the top via the divide-by-tiny-
	 * denominator code path.  The count itself is surfaced on the dump
	 * line so the operator can see corruption is actually there.
	 */
	unsigned long corrupt_in_table = 0;
	/*
	 * Counts entries skipped from top-N qualification because their
	 * predecessor pair has at least one appearance counter still at
	 * zero — see HEALER_DUMP_MIN_PRED_APPEARANCES for why.  Surfaced
	 * on the dump line so the operator can tell when the filter is
	 * actively suppressing entries (e.g. shortly after a warm-start)
	 * vs when the table is genuinely all this-run-observed.  Counted
	 * once per promoted entry, not per slot, so the number lines up
	 * with how many would otherwise have been candidates.
	 */
	unsigned long low_confidence_skipped = 0;
	/*
	 * Counts entries skipped from top-N qualification because their raw
	 * observation count is below HEALER_DUMP_MIN_RAW — single-shot triples
	 * that the TF-IDF amplification path would otherwise float to the top.
	 * Kept separate from low_confidence_skipped because the two filters
	 * answer different questions (predecessor evidence vs triple-level
	 * evidence) and an operator wants to see them independently.
	 */
	unsigned long low_raw_skipped = 0;
	/*
	 * Counts entries skipped from top-N qualification because both
	 * participating syscalls have entry->attempted == 0 and HEALER's
	 * total observation count is past HEALER_POLLUTION_FILTER_THRESHOLD
	 * — i.e. seed-only pollution from syscalls the running kernel
	 * keeps rejecting (ENOSYS, missing CONFIG, sandboxed).  Surfaced
	 * on its own dump line so the operator can see the filter doing
	 * useful work (or, if the count is implausibly large, notice the
	 * threshold is mistuned for the current workload).
	 */
	unsigned long pollution_filtered = 0;
	/*
	 * Per-dump tally of the static-seed pair table: total nonzero
	 * cells and the subset of those whose weight has reached >=2 (i.e.
	 * either a seed that has been confirmed by at least one dynamic
	 * observation, or a runtime-only pair that has been observed at
	 * least twice).  Walked here so the second figure tracks "how many
	 * pairs have evidence on top of the prior" without standing up a
	 * separate dump pass.
	 */
	unsigned long pair_populated = 0;
	unsigned long pair_weighted = 0;
	unsigned int i, j;
	unsigned long observed, table_full, evictions, decays_run;
	/*
	 * Per-syscall successor-weight accumulator built up during the
	 * relation sweep below: succ_weight[nr] += promoted entry's weight
	 * whenever that entry's promoted_nr == nr.  Used downstream by the
	 * predecessor-frequency leader display to annotate each leader with
	 * how productive it has been *as a successor* (vs how often it
	 * landed in a predecessor slot).  Kept as a heap allocation rather
	 * than a stack array so a future MAX_NR_SYSCALL bump doesn't blow
	 * the dump-path stack frame.
	 */
	unsigned long *succ_weight;

	succ_weight = calloc(MAX_NR_SYSCALL, sizeof(*succ_weight));
	if (succ_weight == NULL)
		return;

	/* Drive a time-triggered decay from the dump path.  Decay is
	 * primarily called from healer_observe_relation on every observation,
	 * but observations dry up once KCOV coverage saturates -- with no
	 * observation-side caller, the wall-clock secondary trigger inside
	 * healer_maybe_decay would never get a chance to fire.  The dump runs
	 * on a fixed cadence regardless of observation activity, so calling
	 * maybe_decay here gives the time trigger a guaranteed evaluation
	 * point.  CAS election inside maybe_decay makes it safe to be called
	 * concurrently with the observation-path callers. */
	healer_maybe_decay();

	/* Snapshot the total observation count once up-front so the
	 * pollution filter inside the scan loops compares every
	 * candidate against the same threshold value -- re-reading the
	 * live counter per candidate would let the threshold trip
	 * mid-scan and produce an inconsistent dump where a few early
	 * entries survived the filter and later identical entries did
	 * not.  Reused for the summary line below in place of a second
	 * load; the older code read it again there only because nothing
	 * upstream had needed it yet. */
	observed = __atomic_load_n(&shm->stats.healer_relations_observed,
				   __ATOMIC_RELAXED);

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
		unsigned long pred_a_freq, pred_b_freq;

		slot_key = __atomic_load_n(&slot->key, __ATOMIC_ACQUIRE);
		if (slot_key == 0)
			continue;

		healer_unpack_key(slot_key, &slot_pred_a, &slot_pred_b);

		/* Slot-level corruption check: pred_a / pred_b stamped with a
		 * non-syscall value mean a stray write hit this slot's key.
		 * Skip the entire slot — all its promoted entries inherit the
		 * bad predecessor pair and have nothing to contribute to the
		 * dump.  Count once per corrupt slot, not per promoted entry. */
		if (slot_pred_a >= MAX_NR_SYSCALL ||
		    slot_pred_b >= MAX_NR_SYSCALL) {
			corrupt_in_table++;
			continue;
		}

		/* Hoist the per-syscall appearance reads out of the per-promoted
		 * inner loop -- they are slot-constant (every promoted entry in
		 * the slot shares the same predecessor pair) and the dump path
		 * shouldn't pay HEALER_PROMOTED_PER_SLOT extra atomic loads per
		 * slot for a value it could read once. */
		pred_a_freq = __atomic_load_n(
			&shm->stats.healer_pred_appearance[slot_pred_a],
			__ATOMIC_RELAXED);
		pred_b_freq = __atomic_load_n(
			&shm->stats.healer_pred_appearance[slot_pred_b],
			__ATOMIC_RELAXED);

		for (j = 0; j < HEALER_PROMOTED_PER_SLOT; j++) {
			uint64_t entry;
			unsigned int weight, nr;
			unsigned long norm_score;
			struct healer_dump_entry cand;

			entry = __atomic_load_n(&slot->promoted[j].entry,
						__ATOMIC_RELAXED);
			healer_unpack_promoted(entry, &nr, &weight);

			if (weight == 0)
				continue;

			/* Per-entry corruption check: stray scribble may have
			 * left pred_a/pred_b intact but trashed the promoted
			 * entry's nr.  Skip from gt counts + top-N — a corrupt
			 * weight=1 entry would otherwise inflate the noise
			 * floor and chase the normalised ranking. */
			if (nr >= MAX_NR_SYSCALL) {
				corrupt_in_table++;
				continue;
			}

			slot_promoted++;
			total_weight += weight;
			if (weight > 1)
				weight_gt_1++;
			if (weight > 5)
				weight_gt_5++;
			if (weight > 10)
				weight_gt_10++;

			/* Successor-weight accumulator: a syscall's "productive
			 * as successor" score is the sum of weights of every
			 * promoted entry whose nr is this syscall, regardless
			 * of which predset led there. */
			if (nr < MAX_NR_SYSCALL)
				succ_weight[nr] += weight;

			norm_score = healer_normalised_score_milli(weight,
								   pred_a_freq,
								   pred_b_freq);

			/*
			 * Low-confidence floor: drop entries from top-N
			 * qualification when at least one predecessor has no
			 * this-run appearance signal.  Both warm-start
			 * zombies (both counters at zero) and predecessor-
			 * skipped leftovers (one counter pinned at zero)
			 * land here.  HEALER_NORM_PREDFREQ_BIAS already
			 * keeps the denominator off its minimum value, but
			 * this filter additionally insists on at least some
			 * this-run evidence before an entry can rank --
			 * "denominator no longer pathological" is not the
			 * same standard as "this entry was actually
			 * observed in the current run".  Per-promoted
			 * accounting matches the corruption skip a few
			 * lines up so the surfaced counts are comparable.
			 */
			if (pred_a_freq < HEALER_DUMP_MIN_PRED_APPEARANCES ||
			    pred_b_freq < HEALER_DUMP_MIN_PRED_APPEARANCES) {
				low_confidence_skipped++;
				continue;
			}

			/*
			 * Raw-observation floor: a single sighting carries no
			 * statistical weight on its own and would otherwise be
			 * lifted into the top-N by the TF-IDF denominator when
			 * either predecessor's appearance count is small.  Same
			 * top-N-only treatment as the low-confidence filter
			 * above, counted per promoted entry for parity.
			 */
			if (weight < HEALER_DUMP_MIN_RAW) {
				low_raw_skipped++;
				continue;
			}

			/*
			 * Pollution filter: once HEALER has accumulated enough
			 * total observations, drop entries whose predecessor
			 * pair references syscalls no child has ever attempted
			 * (ENOSYS / missing CONFIG / sandboxed).  These persist
			 * indefinitely as static-seed installs the kernel will
			 * never let HEALER confirm dynamically -- e.g. the
			 * landlock_create_ruleset pollution Dave saw in the
			 * seed-only section on a no-LANDLOCK kernel.  Top-N
			 * qualification only; the slot itself stays put for
			 * load/save and weight-decay handling.
			 */
			if (observed >= HEALER_POLLUTION_FILTER_THRESHOLD &&
			    healer_syscall_unattempted(slot_pred_a) &&
			    healer_syscall_unattempted(slot_pred_b)) {
				pollution_filtered++;
				continue;
			}

			cand.pred_a = slot_pred_a;
			cand.pred_b = slot_pred_b;
			cand.promoted_nr = nr;
			cand.weight = weight;
			cand.pred_a_freq = pred_a_freq;
			cand.pred_b_freq = pred_b_freq;
			cand.norm_score_milli = norm_score;
			cand.is_pair = false;

			/*
			 * Triples reach here only after both predfreqs have
			 * cleared HEALER_DUMP_MIN_PRED_APPEARANCES, so they
			 * always satisfy the dynamic-section criterion (>=1
			 * predecessor observed this run).  The seed-only pool
			 * remains reachable in principle if that minimum is
			 * ever lowered to 0, which is why the route is written
			 * as the same pred_a||pred_b>0 test the spec defines
			 * rather than an unconditional dynamic-pool insert.
			 */
			if (pred_a_freq > 0 || pred_b_freq > 0)
				healer_top_n_insert(top_dyn, &top_dyn_count,
						    &cand);
			else
				healer_top_n_insert(top_seed, &top_seed_count,
						    &cand);
		}

		if (slot_promoted > 0) {
			occupied++;
			total_promoted += slot_promoted;
		}
	}

	/*
	 * Pair-table sweep.  Walks the producer/consumer pair matrix that
	 * the static-seed loader (and, once the observer-bump path lands,
	 * dynamic observations) populates and merges its entries into the
	 * same top[] candidate list as triples.  Pair entries are scored
	 * with a single-predecessor adaptation of the triple normalisation
	 * (raw * 1000 / isqrt(producer_appearances + 1)) and ranked
	 * head-to-head against triples by norm_score_milli, so the operator
	 * sees the strongest pair priors interleaved with the strongest
	 * runtime-observed triples instead of dropped onto a separate
	 * second dump.
	 *
	 * The pair table is a dense [MAX_NR_SYSCALL][MAX_NR_SYSCALL] matrix
	 * (a few hundred K cells, mostly zero on a fresh run), so the bulk
	 * walk happens once per dump tick and is cheap enough not to need
	 * any sparser indexing.  HEALER_DUMP_MIN_RAW gates pair entries the
	 * same way it gates triples: with HEALER_STATIC_SEED_WEIGHT == 3 ==
	 * HEALER_DUMP_MIN_RAW the floor lets every fresh seed install
	 * qualify on its first dump while still dropping a raw=1 or raw=2
	 * dynamic-only pair (which the same statistical-noise argument that
	 * motivates the triple-side floor applies to verbatim).  Skips are
	 * tallied into the existing low_raw_skipped counter so the
	 * "low-raw skipped: N" line covers both the triple and pair sides.
	 */
	for (i = 0; i < MAX_NR_SYSCALL; i++) {
		unsigned long producer_freq = __atomic_load_n(
			&shm->stats.healer_pred_appearance[i],
			__ATOMIC_RELAXED);

		for (j = 0; j < MAX_NR_SYSCALL; j++) {
			unsigned int weight;
			unsigned long denom, norm_score;
			struct healer_dump_entry cand;

			weight = healer_pair_get(i, j);
			if (weight == 0)
				continue;

			pair_populated++;
			if (weight >= 2)
				pair_weighted++;

			if (weight < HEALER_DUMP_MIN_RAW) {
				low_raw_skipped++;
				continue;
			}

			/*
			 * Pollution filter, pair-side: same shape as the
			 * triple-side check above, applied to the producer
			 * (i) / consumer (j) syscall pair the dump renders as
			 * `{*, producer} -> consumer`.  This is the section
			 * the original landlock_create_ruleset pollution
			 * showed up in -- pair seeds for syscalls the kernel
			 * keeps rejecting accumulate at the top of the
			 * seed-only ranking with predfreq=0 forever.
			 */
			if (observed >= HEALER_POLLUTION_FILTER_THRESHOLD &&
			    healer_syscall_unattempted(i) &&
			    healer_syscall_unattempted(j)) {
				pollution_filtered++;
				continue;
			}

			/*
			 * Single-predecessor TF-IDF analog: the triple form
			 * dampens by isqrt((a+K)*(b+K) + 1) over both
			 * predecessor antecedents; a pair has only one
			 * antecedent (the producer), so the denominator
			 * collapses to isqrt(producer_freq + K + 1).  Reuses
			 * healer_isqrt() rather than repeating the Newton
			 * iteration.  HEALER_NORM_PREDFREQ_BIAS is the same
			 * pseudo-count shift the triple-side formula uses,
			 * applied here for the same reason: without it,
			 * every static-seeded pair whose producer had not
			 * yet been observed (producer_freq == 0) collapsed
			 * the denominator to isqrt(1) == 1 and rendered as
			 * norm == raw * 1000, dominating the top-N over any
			 * dynamically observed pair whose producer had a
			 * non-zero appearance count.  The trailing "+1" is
			 * redundant for divide-by-zero with the bias in
			 * place but is retained so the formula reads as a
			 * direct K-shift of the prior baseline.
			 */
			denom = healer_isqrt(producer_freq +
					     HEALER_NORM_PREDFREQ_BIAS + 1);
			if (denom == 0)
				denom = 1;
			norm_score = (weight * 1000UL) / denom;

			cand.pred_a = 0;
			cand.pred_b = i;
			cand.promoted_nr = j;
			cand.weight = weight;
			cand.pred_a_freq = 0;
			cand.pred_b_freq = producer_freq;
			cand.norm_score_milli = norm_score;
			cand.is_pair = true;

			/*
			 * Pair entries split on producer_freq: a producer that
			 * has been observed at least once this run lifts the
			 * pair into the dynamic pool, otherwise it is a pure
			 * static-seed prior and lands in the seed-only pool.
			 * This is the case the split exists for -- without it,
			 * un-confirmed seeds at norm=raw*1000/isqrt(K+1)
			 * dominate any dynamic pair whose denominator has been
			 * dampened by an actual producer appearance count.
			 */
			if (producer_freq > 0)
				healer_top_n_insert(top_dyn, &top_dyn_count,
						    &cand);
			else
				healer_top_n_insert(top_seed, &top_seed_count,
						    &cand);
		}
	}

	/* Refresh the lazily-maintained occupancy counter so the dump
	 * we are about to emit reflects the slot scan we just did.  The
	 * hot observer-hook path stays free of an extra counter store. */
	__atomic_store_n(&shm->stats.healer_unique_predsets, occupied,
			 __ATOMIC_RELAXED);

	table_full = __atomic_load_n(&shm->stats.healer_table_full,
				     __ATOMIC_RELAXED);
	evictions = __atomic_load_n(&shm->stats.healer_evictions,
				    __ATOMIC_RELAXED);
	decays_run = __atomic_load_n(&shm->stats.healer_weight_decays_run,
				     __ATOMIC_RELAXED);

	if (occupied == 0 && observed == 0 && pair_populated == 0) {
		free(succ_weight);
		return;
	}

	stats_log_write("HEALER relation table: %u/%u slots filled, %lu total promoted entries, %lu probe-limit hits, %lu evictions, %lu observations\n",
			occupied, HEALER_RELATION_SLOTS, total_promoted,
			table_full, evictions, observed);

	/* Per-mille mean (sum * 1000 / count) keeps two decimals without
	 * dragging in floating point on the dump path; matches the
	 * scaled-integer trick the defense-counter rate dump uses for its
	 * per-second formatting. */
	if (total_promoted > 0)
		mean_milli = (total_weight * 1000UL) / total_promoted;
	stats_log_write("  weight distribution: gt1=%lu, gt5=%lu, gt10=%lu  (mean=%lu.%03lu, decays=%lu)\n",
			weight_gt_1, weight_gt_5, weight_gt_10,
			mean_milli / 1000, mean_milli % 1000, decays_run);

	if (corrupt_in_table != 0)
		stats_log_write("  corrupt entries skipped: %lu (slot-key or promoted-nr >= MAX_NR_SYSCALL)\n",
				corrupt_in_table);

	if (low_confidence_skipped != 0)
		stats_log_write("  low-confidence skipped: %lu (min predfreq < %u)\n",
				low_confidence_skipped,
				HEALER_DUMP_MIN_PRED_APPEARANCES);

	if (low_raw_skipped != 0)
		stats_log_write("  low-raw skipped: %lu (raw < %u)\n",
				low_raw_skipped,
				HEALER_DUMP_MIN_RAW);

	if (pollution_filtered != 0)
		stats_log_write("HEALER pollution-filtered: %lu seed pairs hidden (predfreq=0, attempted=0)\n",
				pollution_filtered);

	if (top_dyn_count == 0 && top_seed_count == 0) {
		free(succ_weight);
		return;
	}

	/*
	 * Two independently-ranked sections.  Title still says "by
	 * normalised weight" so the operator immediately notices the
	 * ranking is the dampened score (the raw weight is emitted
	 * alongside, and the predfreq numbers make the per-line scaling
	 * auditable on the spot).  The seed-only section is suppressed
	 * when empty (and likewise for the dynamic section) so a fresh
	 * run with nothing in either pool does not print empty headers.
	 */
	if (top_dyn_count > 0) {
		qsort(top_dyn, top_dyn_count, sizeof(top_dyn[0]),
		      healer_dump_entry_cmp);
		healer_dump_emit_top(
			"HEALER top %u dynamically-observed relations by normalised weight:\n",
			top_dyn, top_dyn_count);
	}

	if (top_seed_count > 0) {
		qsort(top_seed, top_seed_count, sizeof(top_seed[0]),
		      healer_dump_entry_cmp);
		healer_dump_emit_top(
			"HEALER top %u seed-only relations (predfreq=0, awaiting dynamic confirmation):\n",
			top_seed, top_seed_count);
	}

	/*
	 * Pair-table summary line: total cells holding any weight, plus
	 * the subset whose weight has reached >=2.  The first figure
	 * reflects the static-seed install size; the second tracks how
	 * many pairs have evidence beyond the bare prior, so an operator
	 * can tell whether dynamic observation is accumulating on top of
	 * the seed (rising weighted_count) or whether the table is still
	 * the loader's first install (weighted_count near zero).
	 */
	stats_log_write("HEALER pair table: %lu/%lu populated, %lu with weight>=2\n",
			pair_populated,
			(unsigned long)MAX_NR_SYSCALL * MAX_NR_SYSCALL,
			pair_weighted);

	/*
	 * Predecessor-frequency leader display.  Surfaces the top-N
	 * syscalls by appearance counter alongside the sum of weights they
	 * have produced *as a successor* of any pair, so the operator can
	 * tell at a glance which leaders are pure noise riders (high
	 * appearance, zero or near-zero successor weight) vs which are
	 * genuinely productive in both roles.  The first kind is what the
	 * dump's normalised ranking is dampening; the second kind is fine
	 * to leave at full credit and the operator can confirm that here.
	 */
	{
		struct healer_pred_leader leaders[HEALER_PRED_LEADERS_TOP_N];
		unsigned int leader_count = 0;
		unsigned int n;

		for (n = 0; n < MAX_NR_SYSCALL; n++) {
			unsigned long appearances;
			unsigned int min_idx = 0;
			unsigned int k;

			appearances = __atomic_load_n(
				&shm->stats.healer_pred_appearance[n],
				__ATOMIC_RELAXED);
			if (appearances == 0)
				continue;

			if (leader_count < HEALER_PRED_LEADERS_TOP_N) {
				leaders[leader_count].nr = n;
				leaders[leader_count].appearances = appearances;
				leaders[leader_count].succ_weight = succ_weight[n];
				leader_count++;
				continue;
			}

			for (k = 1; k < HEALER_PRED_LEADERS_TOP_N; k++) {
				if (leaders[k].appearances < leaders[min_idx].appearances)
					min_idx = k;
			}
			if (appearances > leaders[min_idx].appearances) {
				leaders[min_idx].nr = n;
				leaders[min_idx].appearances = appearances;
				leaders[min_idx].succ_weight = succ_weight[n];
			}
		}

		if (leader_count > 0) {
			qsort(leaders, leader_count, sizeof(leaders[0]),
			      healer_pred_leader_cmp);
			stats_log_write("HEALER predecessor-frequency leaders:\n");
			for (n = 0; n < leader_count; n++) {
				stats_log_write("  %s: appearances=%lu (succ_weight=%lu)\n",
						print_syscall_name(leaders[n].nr, false),
						leaders[n].appearances,
						leaders[n].succ_weight);
			}
		}
	}

	free(succ_weight);
}

/*
 * Cross-run persistence.
 *
 * The relation table lives in shm and dies with the trinity process; every
 * restart is otherwise a cold start.  Phase B's syscall picker needs the
 * table to settle (24-48h of observations) before the bandit arm has any
 * usable signal, but trinity's children OOM/crash long before that on
 * realistic fleet hosts -- so without persistence the table never reaches
 * the maturity threshold and Phase B stays gated indefinitely.
 *
 * The save/load wire-format and election machinery here mirror the same
 * pattern minicorpus.c and effector-map.c established for their own per-
 * run-vs-cross-run state: an XDG_CACHE_HOME / mkdir-p / atomic-rename-via-
 * tmp-file save path, a header carrying magic + version + dimensions +
 * kernel-utsname + payload CRC32, and a CAS-elected snapshot trigger so
 * concurrent fuzz children don't race into the save.  See effector-map.c
 * for the mirrored header-shape rationale; the duplication is deliberate
 * (a future divergence in any one persistence file's format shouldn't
 * ripple into the others).
 *
 * File layout (little-endian, packed as written):
 *
 *   offset  size   field
 *   ------  ----   ----------------------------------------------------
 *        0     4   magic = 0x48524C54 ('H','R','L','T' -- HEALER
 *                          Relation-table) sniff anchor.
 *        4     4   version = HEALER_FILE_VERSION (currently 1).
 *        8     4   relation_slots = HEALER_RELATION_SLOTS at write time.
 *                          A loader compiled with a different value
 *                          refuses the file (the on-disk layout is
 *                          dimensioned by it).
 *       12     4   promoted_per_slot = HEALER_PROMOTED_PER_SLOT at write
 *                          time.  Same dimension-mismatch reject.
 *       16     4   max_nr_syscall = MAX_NR_SYSCALL at write time.  Reject
 *                          on mismatch -- the (pred_a, pred_b, nr) fields
 *                          are uint16_t and a build with different syscall
 *                          numbering would silently misinterpret entries.
 *       20     4   payload_crc32 over the relation payload that follows
 *                          (header-internal fields are not covered; the
 *                          dimension/magic/version checks catch tampered
 *                          headers earlier and cheaper).
 *       24     8   observations = shm->stats.healer_relations_observed at
 *                          write time.  Restored on load so the snapshot
 *                          gating threshold is anchored to the cumulative
 *                          observation count rather than the post-load
 *                          delta.
 *       32    65   kernel_release = utsname.release captured at write
 *                          time, NUL-terminated, fixed-width.  Loader
 *                          compares strncmp(); a mismatch logs and
 *                          cold-starts (the relation table is meaningful
 *                          only against the kernel it was learned on,
 *                          since syscall numbering and per-syscall edge
 *                          fingerprints can shift between kernels).
 *       97    65   kernel_version = utsname.version captured at write
 *                          time, NUL-terminated, fixed-width.  Stored
 *                          for forensic value (strings(1) on a stale
 *                          snapshot can still identify the exact build
 *                          it came from) but NOT compared on load: the
 *                          build timestamp changes on every kernel
 *                          rebuild, and the relation table is indexed
 *                          by syscall number -- which is stable across
 *                          rebuilds of the same source -- so .release
 *                          alone is the right warm-start gate.
 *      162     6   pad to round struct healer_file_header to 8 bytes.
 *
 *      168 onwards  payload = HEALER_RELATION_SLOTS * sizeof(struct
 *                  healer_relation) bytes of relation table, laid out
 *                  in C row-major order matching the in-memory
 *                  shm->healer_relations[] indexing.  No per-slot
 *                  framing; reads/writes are bulk into the in-shm
 *                  array.  payload_crc32 is computed over exactly
 *                  these bytes.
 *
 * Atomicity: save writes to "<path>.tmp.<pid>", fsyncs, then renames into
 * place; the per-pid suffix stops two concurrent --healer-snapshot saves
 * (e.g. snapshot-trigger fire racing with the atexit save) from
 * interleaving writes.  Snapshot-window concurrent observers are handled
 * by copying the live shm payload into a heap buffer before the CRC is
 * computed, so the on-disk CRC and the on-disk payload describe
 * byte-identical bytes -- without that staging, observer hooks CASing
 * into the relation table during the ~1.13MB write would leave the CRC
 * describing the table at T1 and the payload at T2, and the loader's
 * CRC check would reject the snapshot.  The loader's CRC still catches
 * the (much rarer) bytes-written-mid-rename failure mode on top.
 */

#define HEALER_FILE_MAGIC		0x48524C54U	/* "HRLT" */
#define HEALER_FILE_VERSION		1U
#define HEALER_UTSNAME_LEN		65	/* matches Linux __NEW_UTS_LEN+1 */

/*
 * Periodic snapshot trigger.  Every HEALER_SNAPSHOT_OBSERVATIONS the
 * fleet-wide observation counter advances past, one CAS-elected child
 * runs the save while everyone else early-returns; the next window opens
 * once the next slice has accumulated.  50000 was picked to amortise the
 * ~1.13MB write across roughly a minute of steady-state fuzzing on a
 * typical fleet host -- frequent enough that an OOM-mid-run only loses
 * the last cadence window of observations, infrequent enough that the
 * write-back pressure stays in the noise.
 */
#define HEALER_SNAPSHOT_OBSERVATIONS	50000UL

/* Header layout is naturally packed under the LP64 ABIs trinity targets:
 * 6 uint32_t fields, a uint64_t, then two fixed-width char arrays plus
 * a 6-byte tail pad summing to 168 bytes with no compiler-inserted
 * padding.  No __attribute__((packed)) needed -- and adding one would
 * trip -Wpacked. */
struct healer_file_header {
	uint32_t magic;
	uint32_t version;
	uint32_t relation_slots;
	uint32_t promoted_per_slot;
	uint32_t max_nr_syscall;
	uint32_t payload_crc32;
	uint64_t observations;
	char kernel_release[HEALER_UTSNAME_LEN];
	char kernel_version[HEALER_UTSNAME_LEN];
	uint8_t pad[6];
};

#define HEALER_PAYLOAD_BYTES \
	((size_t)HEALER_RELATION_SLOTS * sizeof(struct healer_relation))

/* Plain CRC32 (IEEE 802.3 polynomial, reflected).  Same algorithm the
 * minicorpus and effector-map persistence files use; kept local rather
 * than refactored into a shared helper so a future divergence in any
 * one file's format doesn't ripple over here. */
static uint32_t healer_crc32(const void *buf, size_t len)
{
	static uint32_t table[256];
	static bool table_built;
	const uint8_t *p = buf;
	uint32_t crc = 0xffffffffU;
	size_t i;

	if (!table_built) {
		uint32_t c;
		unsigned int n, k;

		for (n = 0; n < 256; n++) {
			c = n;
			for (k = 0; k < 8; k++)
				c = (c & 1) ? (0xedb88320U ^ (c >> 1)) : (c >> 1);
			table[n] = c;
		}
		table_built = true;
	}

	for (i = 0; i < len; i++)
		crc = table[(crc ^ p[i]) & 0xff] ^ (crc >> 8);

	return crc ^ 0xffffffffU;
}

static ssize_t healer_write_all(int fd, const void *buf, size_t len)
{
	const uint8_t *p = buf;
	size_t left = len;

	while (left > 0) {
		ssize_t n = write(fd, p, left);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			return -1;
		p += n;
		left -= n;
	}
	return (ssize_t)len;
}

static ssize_t healer_read_all(int fd, void *buf, size_t len)
{
	uint8_t *p = buf;
	size_t left = len;

	while (left > 0) {
		ssize_t n = read(fd, p, left);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			break;
		p += n;
		left -= n;
	}
	return (ssize_t)(len - left);
}

/*
 * Scrub a heap snapshot of the relation table (HEALER_PAYLOAD_BYTES of
 * back-to-back struct healer_relation slots) of any per-slot or per-entry
 * scribbles where pred_a / pred_b / promoted_nr was stamped with a
 * non-syscall value by a stray write hitting the live table in shm.
 * Mirrors the slot-level + per-entry bound checks the dump path uses to
 * skip corrupt slots: if pred_a or pred_b is >= MAX_NR_SYSCALL the whole
 * slot is unrecoverable (every promoted entry inherits the bad pair) and
 * gets memset to zero -- key == 0 is the empty-slot sentinel and
 * weight == 0 the empty-entry one, so a zeroed slot loads back as
 * cleanly empty.  Otherwise each promoted entry is checked individually
 * and only entries with nr >= MAX_NR_SYSCALL get zeroed, preserving the
 * slot's legitimate promoted entries.  Returns the count of slots and
 * per-entry zeroings performed.
 *
 * Used by both healer_save_file() (so the on-disk file is an idealised
 * clean view and the loader sees no corruption to begin with) and
 * healer_load_file() (defence-in-depth: an old file written before the
 * save-side scrub, or a tail-probability bit-flip in a hex value that
 * still satisfies the on-disk CRC, still gets cleaned before the memcpy
 * into shm).  Operates ONLY on the heap buffer it is handed; the live
 * shm->healer_relations[] is never touched here -- decay and eviction
 * age corrupt slots out in the normal way.
 */
static unsigned int healer_scrub_snapshot(void *snapshot)
{
	struct healer_relation *snap_slots = snapshot;
	unsigned int scrubbed = 0;
	unsigned int i, j;

	for (i = 0; i < HEALER_RELATION_SLOTS; i++) {
		struct healer_relation *slot = &snap_slots[i];
		unsigned int slot_pred_a, slot_pred_b;

		if (slot->key == 0)
			continue;

		healer_unpack_key(slot->key, &slot_pred_a, &slot_pred_b);

		if (slot_pred_a >= MAX_NR_SYSCALL ||
		    slot_pred_b >= MAX_NR_SYSCALL) {
			memset(slot, 0, sizeof(*slot));
			scrubbed++;
			continue;
		}

		for (j = 0; j < HEALER_PROMOTED_PER_SLOT; j++) {
			unsigned int nr, weight;

			healer_unpack_promoted(slot->promoted[j].entry,
					       &nr, &weight);
			if (weight == 0)
				continue;
			if (nr >= MAX_NR_SYSCALL) {
				slot->promoted[j].entry = 0;
				scrubbed++;
			}
		}
	}

	return scrubbed;
}

bool healer_save_file(const char *path)
{
	struct healer_file_header hdr;
	struct utsname u;
	char tmppath[PATH_MAX];
	void *snapshot;
	unsigned int scrubbed;
	int fd;
	int ret;

	if (path == NULL || shm == NULL)
		return false;

	if (uname(&u) != 0)
		return false;

	/* Stage the payload through a heap buffer so healer_crc32() and
	 * healer_write_all() see byte-identical bytes.  Observer hooks CAS
	 * into shm->healer_relations continuously during the ~1.13MB write;
	 * computing the CRC straight from shm and then writing straight
	 * from shm again would describe T1 in the on-disk CRC and T2 in the
	 * on-disk payload, which the loader's CRC check would then reject.
	 * Mirror the load path's staging discipline. */
	snapshot = malloc(HEALER_PAYLOAD_BYTES);
	if (snapshot == NULL)
		return false;
	memcpy(snapshot, shm->healer_relations, HEALER_PAYLOAD_BYTES);

	/* Sanitise the heap snapshot before computing the CRC and writing
	 * it out, so corrupt-slot scribbles in the live table don't get
	 * persisted to disk and reloaded back into shm on warm-start,
	 * carrying garbage across runs.  See healer_scrub_snapshot() for
	 * the slot-level + per-entry rules.  The on-disk file becomes an
	 * idealised clean view; the live shm->healer_relations[] is
	 * untouched -- decay and eviction handle it in the normal way. */
	scrubbed = healer_scrub_snapshot(snapshot);

	memset(&hdr, 0, sizeof(hdr));
	hdr.magic = HEALER_FILE_MAGIC;
	hdr.version = HEALER_FILE_VERSION;
	hdr.relation_slots = HEALER_RELATION_SLOTS;
	hdr.promoted_per_slot = HEALER_PROMOTED_PER_SLOT;
	hdr.max_nr_syscall = MAX_NR_SYSCALL;
	hdr.payload_crc32 = healer_crc32(snapshot, HEALER_PAYLOAD_BYTES);
	hdr.observations = __atomic_load_n(&shm->stats.healer_relations_observed,
					   __ATOMIC_RELAXED);
	strncpy(hdr.kernel_release, u.release, sizeof(hdr.kernel_release) - 1);
	hdr.kernel_release[sizeof(hdr.kernel_release) - 1] = '\0';
	strncpy(hdr.kernel_version, u.version, sizeof(hdr.kernel_version) - 1);
	hdr.kernel_version[sizeof(hdr.kernel_version) - 1] = '\0';

	ret = snprintf(tmppath, sizeof(tmppath), "%s.tmp.%d",
			path, (int)getpid());
	if (ret < 0 || (size_t)ret >= sizeof(tmppath)) {
		free(snapshot);
		return false;
	}

	fd = open(tmppath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		free(snapshot);
		return false;
	}

	if (healer_write_all(fd, &hdr, sizeof(hdr)) < 0)
		goto fail;
	if (healer_write_all(fd, snapshot, HEALER_PAYLOAD_BYTES) < 0)
		goto fail;

	if (fsync(fd) != 0)
		goto fail;
	if (close(fd) != 0) {
		(void)unlink(tmppath);
		free(snapshot);
		return false;
	}

	if (rename(tmppath, path) != 0) {
		(void)unlink(tmppath);
		free(snapshot);
		return false;
	}
	free(snapshot);
	if (scrubbed != 0)
		output(0, "healer_save_file: scrubbed %u corrupt slots/entries from snapshot\n",
		       scrubbed);
	return true;

fail:
	(void)close(fd);
	(void)unlink(tmppath);
	free(snapshot);
	return false;
}

bool healer_load_file(const char *path)
{
	struct healer_file_header hdr;
	struct utsname u;
	void *tmpbuf;
	uint32_t want_crc;
	unsigned int scrubbed = 0;
	int fd;
	bool ok = false;

	if (path == NULL || shm == NULL)
		return false;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return false;

	if (healer_read_all(fd, &hdr, sizeof(hdr)) != (ssize_t)sizeof(hdr))
		goto out_close;

	if (hdr.magic != HEALER_FILE_MAGIC ||
	    hdr.version != HEALER_FILE_VERSION ||
	    hdr.relation_slots != HEALER_RELATION_SLOTS ||
	    hdr.promoted_per_slot != HEALER_PROMOTED_PER_SLOT ||
	    hdr.max_nr_syscall != MAX_NR_SYSCALL)
		goto out_close;

	if (uname(&u) != 0)
		goto out_close;

	hdr.kernel_release[sizeof(hdr.kernel_release) - 1] = '\0';
	hdr.kernel_version[sizeof(hdr.kernel_version) - 1] = '\0';
	/* Cold-start path: gate warm-start on utsname.release only.  The
	 * relation table is indexed by syscall number, and syscall numbers
	 * are stable across kernel rebuilds of the same source tree, so a
	 * fresh build with an unchanged release should reuse the cache.
	 * utsname.version (the build timestamp) was previously also gated
	 * on, but that was over-strict: it threw away the entire warm-start
	 * cache after every kernel rebuild for no functional reason.  The
	 * relations might be slightly stale at the margins if the kernel's
	 * CFG shifted under recompile, but they're not wrong -- at worst
	 * a few pairs point at slightly less-productive paths.  A release
	 * mismatch, by contrast, can shift syscall numbers outright, so
	 * that one still cold-starts. */
	if (strncmp(hdr.kernel_release, u.release,
			sizeof(hdr.kernel_release)) != 0) {
		outputerr("healer: skipping warm-start of %s -- file built against release %s, running release %s\n",
			  path, hdr.kernel_release, u.release);
		goto out_close;
	}

	/* Stage the payload into a heap buffer first so a partial read or
	 * CRC failure leaves shm->healer_relations untouched (a torn load
	 * straight into shm would poison every child's view of the table). */
	tmpbuf = malloc(HEALER_PAYLOAD_BYTES);
	if (tmpbuf == NULL)
		goto out_close;

	if (healer_read_all(fd, tmpbuf, HEALER_PAYLOAD_BYTES)
			!= (ssize_t)HEALER_PAYLOAD_BYTES)
		goto out_free;

	want_crc = healer_crc32(tmpbuf, HEALER_PAYLOAD_BYTES);
	if (want_crc != hdr.payload_crc32)
		goto out_free;

	/* Defence-in-depth: even after CRC has confirmed bit-for-bit fidelity
	 * with what was written, the file itself may carry corrupt slots --
	 * an old snapshot saved before the save-side scrub commit, or a
	 * tail-probability bit-flip in a hex value that still satisfies CRC.
	 * Run the same sanitiser the save side runs so the bytes we're about
	 * to memcpy into shm match the slot-level + per-entry invariants the
	 * dump path enforces.  The scrub touches tmpbuf only; shm still gets
	 * the cleaned bytes via the existing memcpy below. */
	scrubbed = healer_scrub_snapshot(tmpbuf);

	memcpy(shm->healer_relations, tmpbuf, HEALER_PAYLOAD_BYTES);
	__atomic_store_n(&shm->stats.healer_relations_observed,
			 hdr.observations, __ATOMIC_RELAXED);
	__atomic_store_n(&shm->stats.healer_obs_at_last_snapshot,
			 hdr.observations, __ATOMIC_RELAXED);
	ok = true;
	if (scrubbed != 0)
		output(0, "healer_load_file: scrubbed %u corrupt slots/entries from loaded snapshot\n",
		       scrubbed);

out_free:
	free(tmpbuf);
out_close:
	(void)close(fd);
	return ok;
}

/*
 * Build a default per-arch healer relation-table path under
 * $XDG_CACHE_HOME/trinity/healer/ (or $HOME/.cache/...).  Parallel to
 * minicorpus_default_path's corpus/ and effector_map_default_path's
 * effector/ directories; kept separate so the three artifacts can be
 * removed or copied independently.  Creates the parent directory tree
 * on demand.
 */
const char *healer_default_path(void)
{
	static char pathbuf[PATH_MAX];
	const char *xdg = getenv("XDG_CACHE_HOME");
	const char *home = getenv("HOME");
	char dir[PATH_MAX];
	const char *arch;
	struct utsname u;
	char *r;
	int ret;

#if defined(__x86_64__)
	arch = "x86_64";
#elif defined(__i386__)
	arch = "i386";
#elif defined(__aarch64__)
	arch = "aarch64";
#elif defined(__arm__)
	arch = "arm";
#elif defined(__powerpc64__)
	arch = "ppc64";
#elif defined(__powerpc__)
	arch = "ppc";
#elif defined(__s390x__)
	arch = "s390x";
#elif defined(__mips__)
	arch = "mips";
#elif defined(__sparc__)
	arch = "sparc";
#elif defined(__riscv) || defined(__riscv__)
	arch = "riscv64";
#else
	arch = "unknown";
#endif

	if (uname(&u) != 0)
		return NULL;
	for (r = u.release; *r; r++) {
		if (*r == '/')
			*r = '_';
	}

	if (xdg && xdg[0] == '/')
		ret = snprintf(dir, sizeof(dir), "%s/trinity/healer", xdg);
	else if (home && home[0] == '/')
		ret = snprintf(dir, sizeof(dir),
			"%s/.cache/trinity/healer", home);
	else
		return NULL;
	if (ret < 0 || (size_t)ret >= sizeof(dir))
		return NULL;

	{
		char *p;

		for (p = dir + 1; *p; p++) {
			if (*p == '/') {
				*p = '\0';
				if (mkdir(dir, 0755) != 0 && errno != EEXIST) {
					*p = '/';
					return NULL;
				}
				*p = '/';
			}
		}
		if (mkdir(dir, 0755) != 0 && errno != EEXIST)
			return NULL;
	}

	ret = snprintf(pathbuf, sizeof(pathbuf), "%s/%s-%s",
			dir, arch, u.release);
	if (ret < 0 || (size_t)ret >= sizeof(pathbuf))
		return NULL;
	return pathbuf;
}

/*
 * Periodic snapshot trigger.
 *
 * Mirror of minicorpus_maybe_snapshot(): the save path is set in the
 * parent before fork via healer_enable_snapshots() and inherited COW by
 * every child.  All children call healer_maybe_snapshot() from the
 * observer-hook fire path; the function early-returns cheaply unless the
 * fleet-wide observation counter has advanced HEALER_SNAPSHOT_OBSERVATIONS
 * past the last snapshot's high-water-mark.
 *
 * The election is two-step:
 *
 *   1. CAS shm->stats.healer_obs_at_last_snapshot forward to obs_now.
 *      Whichever caller wins this CAS owns the WINDOW boundary -- the
 *      losers see the new high-water-mark on their next call and
 *      early-return.  This step is unchanged.
 *
 *   2. CAS shm->stats.healer_save_in_progress 0 -> 1.  The window-CAS
 *      alone is not enough to keep healer_save_file() singleton: the
 *      save takes wall-clock time (snapshot the relation table, write to
 *      .tmp.<pid>, fsync, rename) and during that window non-saving
 *      children continue to bump healer_relations_observed.  On a hot
 *      fleet the counter can pile up by another full WINDOW before the
 *      first saver returns; the next caller's window-CAS would then
 *      also succeed and a second healer_save_file() would race the
 *      first on the rename(.tmp.<pid>, healer_snapshot_path) step --
 *      last rename wins, so the on-disk file ends up being whichever
 *      saver finishes second, not necessarily the one with the more
 *      recent observations.  The in-progress CAS closes that hole: if
 *      it loses, a previous saver is still mid-write, so we bump
 *      shm->stats.healer_snapshot_overruns and return without rolling
 *      back the window-CAS (that boundary belongs to the in-flight
 *      saver -- the next post-completion call sees the advanced
 *      high-water-mark and waits another full WINDOW).
 *
 * Folding the two CAS attempts together would be wrong: the window-CAS
 * advances the high-water-mark unconditionally so the next snapshot
 * opportunity opens after exactly one more WINDOW; if that single CAS
 * also gated the in-progress check, an overrun-skip would silently
 * advance the high-water-mark without a save running, delaying the
 * next save attempt by a second WINDOW.  Keep them separate.
 */
static char healer_snapshot_path[PATH_MAX];
static bool healer_snapshot_enabled;

void healer_enable_snapshots(const char *path)
{
	size_t len;

	if (path == NULL)
		return;
	len = strlen(path);
	if (len == 0 || len >= sizeof(healer_snapshot_path))
		return;
	memcpy(healer_snapshot_path, path, len + 1);
	healer_snapshot_enabled = true;
}

void healer_maybe_snapshot(void)
{
	unsigned long obs_now, old, expect;

	if (!healer_snapshot_enabled || shm == NULL)
		return;

	obs_now = __atomic_load_n(&shm->stats.healer_relations_observed,
				  __ATOMIC_RELAXED);
	old = __atomic_load_n(&shm->stats.healer_obs_at_last_snapshot,
			      __ATOMIC_RELAXED);

	if (obs_now < old + HEALER_SNAPSHOT_OBSERVATIONS)
		return;

	/* Race for the window slot.  Whoever wins this CAS owns the
	 * WINDOW boundary; the others see the new high-water-mark on
	 * their next call and early-return.  RELAXED ordering is enough
	 * -- the save itself reads the relation table via the same
	 * atomic-load discipline the dump path uses, and the counter is
	 * just gating who runs, not what they observe. */
	if (!__atomic_compare_exchange_n(&shm->stats.healer_obs_at_last_snapshot,
					 &old, obs_now,
					 false,
					 __ATOMIC_RELAXED, __ATOMIC_RELAXED))
		return;

	/* Race for the active-saver slot.  A previous WINDOW's saver may
	 * still be mid-healer_save_file() (slow disk, hot fleet); if so,
	 * bail before starting a second concurrent save into the same
	 * path -- two savers would race on the final rename and the
	 * on-disk file would end up being whichever finished second.
	 * The window-CAS above is left advanced; that boundary belongs
	 * to the in-flight saver. */
	expect = 0;
	if (!__atomic_compare_exchange_n(&shm->stats.healer_save_in_progress,
					 &expect, 1UL,
					 false,
					 __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
		__atomic_fetch_add(&shm->stats.healer_snapshot_overruns, 1,
				   __ATOMIC_RELAXED);
		return;
	}

	healer_save_file(healer_snapshot_path);

	__atomic_store_n(&shm->stats.healer_save_in_progress, 0,
			 __ATOMIC_RELAXED);
}

/*
 * --- Pair-relation table (single-predecessor companion) ---
 *
 * Parallel storage to the (predset -> nr) triple table above, indexed
 * (pred -> succ) instead of ((pred_a, pred_b) -> succ).  Coarser-
 * grained than triples but cheap to seed from a static prior derived
 * from existing ARG_FD_* / ret_objtype metadata, which the upcoming
 * follow-up commits will plumb in.  Nothing in this file or anywhere
 * else calls the APIs below yet -- this commit only stages the
 * storage and the three accessors so the seed-loader and observer-
 * merge work has a stable destination to build against.
 *
 * Sizing: MAX_NR_SYSCALL * MAX_NR_SYSCALL * 4 bytes.  Lives in
 * process-private BSS rather than shm because the dominant access
 * pattern is one bulk parent-side seed write before fork followed by
 * read-mostly child-side lookups; the per-child divergence on later
 * observation bumps is acceptable in exchange for not growing the
 * shm budget the much larger triple table already carries.
 */
static unsigned int healer_pair_table[MAX_NR_SYSCALL][MAX_NR_SYSCALL];

void healer_pair_seed(unsigned int pred, unsigned int succ, unsigned int weight)
{
	unsigned int expected = 0;

	if (pred >= MAX_NR_SYSCALL || succ >= MAX_NR_SYSCALL)
		return;

	/* Don't overwrite a cell that already carries a weight -- a
	 * previous seed call (or, once the observer-bump merge lands,
	 * an in-flight observation) for this (pred, succ) pair is more
	 * authoritative than this caller, and the seed loader is
	 * expected to be idempotent.  CAS failure is a silent no-op so
	 * the loader can re-run without double-counting. */
	if (__atomic_compare_exchange_n(&healer_pair_table[pred][succ],
					&expected, weight, false,
					__ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
		if (shm != NULL)
			__atomic_fetch_add(&shm->stats.healer_pair_seeded, 1,
					   __ATOMIC_RELAXED);
	}
}

void healer_pair_observe(unsigned int pred, unsigned int succ)
{
	if (pred >= MAX_NR_SYSCALL || succ >= MAX_NR_SYSCALL)
		return;

	__atomic_fetch_add(&healer_pair_table[pred][succ], 1, __ATOMIC_RELAXED);
}

unsigned int healer_pair_get(unsigned int pred, unsigned int succ)
{
	if (pred >= MAX_NR_SYSCALL || succ >= MAX_NR_SYSCALL)
		return 0;

	return __atomic_load_n(&healer_pair_table[pred][succ], __ATOMIC_RELAXED);
}

/*
 * --- Producer/consumer classifier (static-seed prior) ---
 *
 * Bootstraps the (pred -> succ) pair table above from the metadata
 * already carried by every syscallentry: ret_objtype tags the kind of
 * fd a syscall produces, and the per-arg argtype[] slots tag the kind
 * of fd a syscall consumes.  A producer A and a consumer B form a
 * candidate pair when A's ret_objtype matches one of B's typed-fd
 * argtype slots; the seed loader (separate follow-up commit) will
 * iterate the same shape and call healer_pair_seed() per match.  This
 * commit lands the helpers and a count-only entry point so the
 * classifier can be sanity-checked in isolation before the loader
 * starts mutating the pair table.
 */

/*
 * Map a typed-fd argtype to the matching object-type kind.  Returns
 * OBJ_NONE for the untyped ARG_FD slot (the kernel doesn't tell us
 * what kind of fd is expected) and for every non-fd argtype.
 *
 * Mirrors the per-argtype mapping at childops/fd-stress.c:107-119 by
 * shape rather than by include: the fd-stress copy is wired into the
 * typed-fd-pair sampler and is tightly coupled to that subsystem's
 * out-pointer signature, so a HEALER-local stand-alone helper avoids
 * dragging in childops/ headers (which pull child-side runtime state
 * the parent-side classifier has no business touching).
 */
static enum objecttype healer_argtype_to_objtype(enum argtype t)
{
	switch (t) {
	case ARG_FD_BPF_BTF:	return OBJ_FD_BPF_BTF;
	case ARG_FD_BPF_LINK:	return OBJ_FD_BPF_LINK;
	case ARG_FD_BPF_MAP:	return OBJ_FD_BPF_MAP;
	case ARG_FD_BPF_PROG:	return OBJ_FD_BPF_PROG;
	case ARG_FD_EPOLL:	return OBJ_FD_EPOLL;
	case ARG_FD_EVENTFD:	return OBJ_FD_EVENTFD;
	case ARG_FD_FANOTIFY:	return OBJ_FD_FANOTIFY;
	case ARG_FD_FS_CTX:	return OBJ_FD_FS_CTX;
	case ARG_FD_INOTIFY:	return OBJ_FD_INOTIFY;
	case ARG_FD_IO_URING:	return OBJ_FD_IO_URING;
	case ARG_FD_LANDLOCK:	return OBJ_FD_LANDLOCK;
	case ARG_FD_MEMFD:	return OBJ_FD_MEMFD;
	case ARG_FD_MOUNT:	return OBJ_FD_MOUNT;
	case ARG_FD_MQ:		return OBJ_FD_MQ;
	case ARG_FD_PERF:	return OBJ_FD_PERF;
	case ARG_FD_PIDFD:	return OBJ_FD_PIDFD;
	case ARG_FD_PIPE:	return OBJ_FD_PIPE;
	case ARG_FD_SIGNALFD:	return OBJ_FD_SIGNALFD;
	case ARG_FD_SOCKET:	return OBJ_FD_SOCKET;
	case ARG_FD_TIMERFD:	return OBJ_FD_TIMERFD;
	default:		return OBJ_NONE;
	}
}

/*
 * True when `entry` accepts an fd of `kind` in any of its argument
 * slots.  OBJ_NONE never matches -- the untyped ARG_FD slot also maps
 * to OBJ_NONE, so collapsing both to "no signal" keeps the classifier
 * from manufacturing a pair out of two unrelated unknowns.
 */
static bool healer_consumes_objtype(const struct syscallentry *entry,
				    enum objecttype kind)
{
	unsigned int i;

	if (kind == OBJ_NONE)
		return false;

	for (i = 0; i < entry->num_args && i < 6; i++) {
		if (healer_argtype_to_objtype(entry->argtype[i]) == kind)
			return true;
	}
	return false;
}

/*
 * The kind of fd `entry` produces, or OBJ_NONE if none.  Today this
 * is a one-line accessor over ret_objtype, but it exists as its own
 * function so a future producer that returns multiple kinds (e.g.
 * pidfd_open, which emits both an OBJ_FD_PIDFD and an OBJ_FD slot
 * to the parent's tracking pool) can be promoted to an iterator
 * without touching every caller.
 */
static enum objecttype healer_produces_objtype(const struct syscallentry *entry)
{
	return entry->ret_objtype;
}

/*
 * Per-table classifier helper.  Counts seed-eligible (producer,
 * consumer) pairs within a single syscall table -- the biarch caller
 * invokes this once per arch and sums the results, the uniarch caller
 * invokes it once on the only table.  Self-pairs (a == b) are counted:
 * a producer that also consumes its own kind is a real shape (dup,
 * dup2, dup3 -- consume an fd, produce an fd) and the pair table
 * indexes (pred == succ) cells just like any other.
 */
static unsigned int healer_count_pc_pairs_in_table(const struct syscalltable *tbl,
						   unsigned int n)
{
	unsigned int a, b, count = 0;

	if (tbl == NULL)
		return 0;

	for (a = 0; a < n; a++) {
		const struct syscallentry *entry_a = tbl[a].entry;
		enum objecttype kind;

		if (entry_a == NULL)
			continue;

		kind = healer_produces_objtype(entry_a);
		if (kind == OBJ_NONE)
			continue;

		for (b = 0; b < n; b++) {
			const struct syscallentry *entry_b = tbl[b].entry;

			if (entry_b == NULL)
				continue;

			if (healer_consumes_objtype(entry_b, kind))
				count++;
		}
	}
	return count;
}

/*
 * Classifier dry-run: count seed-eligible (producer, consumer) pairs
 * across the active syscall table(s) without writing to the pair
 * table.  Lets the seed loader (a follow-up commit) be split in two:
 * this commit's count proves the classifier picks up the metadata
 * edges we expect on the current arch, and the loader commit re-walks
 * the same shape but emits healer_pair_seed() per match instead of
 * just incrementing a counter.
 *
 * Biarch builds keep separate 32-bit and 64-bit syscall tables (the
 * uniarch `syscalls` global is left NULL on those builds), so the
 * walk has to fan out across both -- mirroring the biarch branch
 * stats.c's json_emit_syscalls_array uses for the same reason.  The
 * pair table itself is biarch-flat (indexed by raw syscall number),
 * so summing across both arches matches the seed loader's eventual
 * write pattern.
 */
unsigned int healer_count_pc_pairs(void)
{
	unsigned int count = 0;

	if (biarch == true) {
		/* Only walk a table if its arch is active; -a64 / -a32 / uniarch all naturally avoid the pair_R cross-arch number collision. */
		if (do_64_arch == true)
			count += healer_count_pc_pairs_in_table(syscalls_64bit,
								max_nr_64bit_syscalls);
		if (do_32_arch == true)
			count += healer_count_pc_pairs_in_table(syscalls_32bit,
								max_nr_32bit_syscalls);
	} else {
		count += healer_count_pc_pairs_in_table(syscalls,
							max_nr_syscalls);
	}
	return count;
}

/*
 * Per-table static-seed installer.  Walks one syscall table and calls
 * healer_pair_seed(HEALER_STATIC_SEED_WEIGHT) for every (producer A,
 * consumer B) match where A's ret_objtype is consumed by one of B's
 * argtype slots.  Mirrors healer_count_pc_pairs_in_table by shape so
 * the "what gets seeded" inventory matches the dry-run counter exactly,
 * with two differences: the per-match action is a write rather than a
 * counter increment, and self-pairs (a == b) are skipped.  A self-pair
 * captures the dup/dup2/dup3 shape (consume an fd of kind K, produce an
 * fd of kind K), which is a duplicate-class shape rather than a
 * productive state-transition prior, so seeding (a -> a) would inject
 * a synthetic edge with no underlying semantics.
 */
static void healer_load_pc_pairs_in_table(const struct syscalltable *tbl,
					  unsigned int n)
{
	unsigned int a, b;

	if (tbl == NULL)
		return;

	for (a = 0; a < n; a++) {
		const struct syscallentry *entry_a = tbl[a].entry;
		enum objecttype kind;

		if (entry_a == NULL)
			continue;

		kind = healer_produces_objtype(entry_a);
		if (kind == OBJ_NONE)
			continue;

		for (b = 0; b < n; b++) {
			const struct syscallentry *entry_b = tbl[b].entry;

			if (entry_b == NULL)
				continue;
			if (a == b)
				continue;
			if (healer_consumes_objtype(entry_b, kind))
				healer_pair_seed(entry_a->number,
						 entry_b->number,
						 HEALER_STATIC_SEED_WEIGHT);
		}
	}
}

/*
 * Static-seed loader entry point.  Walks the active syscall table(s)
 * at startup and pre-populates the pair-relation table with
 * HEALER_STATIC_SEED_WEIGHT for every (producer, consumer) edge
 * implied by the metadata already attached to each syscallentry.  Run
 * pre-fork so children inherit the populated table by COW; the pair
 * table is process-private BSS and is not persisted across runs, so
 * this loader is the only path that pre-populates it.
 *
 * Idempotent: healer_pair_seed CAS-installs from 0, so cells already
 * carrying a weight (either from a previous loader call within this
 * process, or, once the observer-bump merge lands in a follow-up
 * commit, from an in-flight observation) silently no-op.  This
 * matters on biarch builds where the 32-bit and 64-bit tables can
 * map the same raw syscall number to different syscalls; the second
 * walk's CAS just fails on any cell the first walk already filled,
 * and the cell keeps the first walk's weight.
 *
 * Returns the number of fresh CAS-successful seed installs over the
 * course of this call, measured as the delta on
 * shm->stats.healer_pair_seeded across the load.  Cells already
 * populated when the loader runs are silently skipped and do not
 * contribute to the return value.  On a cold-start run with an empty
 * pair table the return value matches one side of the (producer-
 * consumer-edges-on-this-arch) inventory healer_count_pc_pairs()
 * reports, modulo the self-pair skip.
 *
 * Logs the install count through stats_log_write so the seeding event
 * is captured in the per-run stats.log alongside the periodic dumps;
 * this is the only fleet-visible signal that the static-seed path
 * actually fired on a given startup.
 */
unsigned int healer_load_static_seed(void)
{
	unsigned long before, after;
	unsigned int installed;

	before = (shm != NULL) ?
		__atomic_load_n(&shm->stats.healer_pair_seeded, __ATOMIC_RELAXED) : 0;

	if (biarch == true) {
		/* Only walk a table if its arch is active; -a64 / -a32 / uniarch all naturally avoid the pair_R cross-arch number collision. */
		if (do_64_arch == true)
			healer_load_pc_pairs_in_table(syscalls_64bit,
						      max_nr_64bit_syscalls);
		if (do_32_arch == true)
			healer_load_pc_pairs_in_table(syscalls_32bit,
						      max_nr_32bit_syscalls);
	} else {
		healer_load_pc_pairs_in_table(syscalls, max_nr_syscalls);
	}

	after = (shm != NULL) ?
		__atomic_load_n(&shm->stats.healer_pair_seeded, __ATOMIC_RELAXED) : 0;
	installed = (unsigned int)(after - before);

	stats_log_write("HEALER static seed: %u producer/consumer pairs installed\n",
			installed);
	return installed;
}
