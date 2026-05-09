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
 * Low-confidence floor for top-N qualification.  Entries whose
 * predecessor pair has a zero appearance counter on at least one side
 * lack this-run evidence and would otherwise be amplified by the
 * tiny-denominator code path inside healer_normalised_score_milli
 * (isqrt(a*b + 1) collapses to 1 when either factor is zero, so any
 * weight=1 entry would jump to score=1000).  Two real shapes hit this:
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
 */
struct healer_dump_entry {
	unsigned int pred_a;
	unsigned int pred_b;
	unsigned int promoted_nr;
	unsigned int weight;
	unsigned long pred_a_freq;
	unsigned long pred_b_freq;
	unsigned long norm_score_milli;
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
 * Formula:  norm = (raw_weight * 1000) / isqrt(pred_a_freq * pred_b_freq + 1)
 *
 * Rationale (chose sqrt-dampening over log2 or one-sided / max):
 *   - sqrt has the right monotonic shape: a predecessor that appears 100x
 *     gets penalised ~10x, one that appears 10000x gets penalised ~100x.
 *     The penalty grows with frequency but not as steeply as plain
 *     division by frequency, so a pair with one slightly-frequent and
 *     one rare predecessor still scores meaningfully higher than a pair
 *     of two frequent ones.
 *   - The "+1" guarantees the denominator is at least 1 even when both
 *     appearance counters are still zero (e.g. a freshly warm-started
 *     entry whose pair hasn't been re-observed yet).  Without it a
 *     warm-start entry with zero freq would divide-by-zero; with it,
 *     the entry simply scores at raw_weight * 1000 until the counters
 *     accumulate.
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
	unsigned long product = pred_a_freq * pred_b_freq + 1;
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

void healer_table_dump(void)
{
	struct healer_dump_entry top[HEALER_DUMP_TOP_N];
	unsigned int top_count = 0;
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
			unsigned int min_idx = 0;
			unsigned int k;
			unsigned long norm_score;

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
			 * land here, and both would otherwise dominate the
			 * dump via the isqrt(0+1)=1 amplification branch.
			 * Per-promoted accounting matches the corruption
			 * skip a few lines up so the surfaced counts are
			 * comparable.
			 */
			if (pred_a_freq < HEALER_DUMP_MIN_PRED_APPEARANCES ||
			    pred_b_freq < HEALER_DUMP_MIN_PRED_APPEARANCES) {
				low_confidence_skipped++;
				continue;
			}

			if (top_count < HEALER_DUMP_TOP_N) {
				top[top_count].pred_a = slot_pred_a;
				top[top_count].pred_b = slot_pred_b;
				top[top_count].promoted_nr = nr;
				top[top_count].weight = weight;
				top[top_count].pred_a_freq = pred_a_freq;
				top[top_count].pred_b_freq = pred_b_freq;
				top[top_count].norm_score_milli = norm_score;
				top_count++;
				continue;
			}

			for (k = 1; k < HEALER_DUMP_TOP_N; k++) {
				if (top[k].norm_score_milli < top[min_idx].norm_score_milli)
					min_idx = k;
			}
			if (norm_score > top[min_idx].norm_score_milli) {
				top[min_idx].pred_a = slot_pred_a;
				top[min_idx].pred_b = slot_pred_b;
				top[min_idx].promoted_nr = nr;
				top[min_idx].weight = weight;
				top[min_idx].pred_a_freq = pred_a_freq;
				top[min_idx].pred_b_freq = pred_b_freq;
				top[min_idx].norm_score_milli = norm_score;
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
	decays_run = __atomic_load_n(&shm->stats.healer_weight_decays_run,
				     __ATOMIC_RELAXED);

	if (occupied == 0 && observed == 0) {
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

	if (top_count == 0) {
		free(succ_weight);
		return;
	}

	qsort(top, top_count, sizeof(top[0]), healer_dump_entry_cmp);

	/* Title flips from "by weight" to "by normalised weight" so the
	 * operator immediately notices the ranking has changed -- the raw
	 * weight is still emitted alongside, and the predfreq numbers make
	 * the per-line scaling auditable on the spot. */
	stats_log_write("HEALER top %u relations by normalised weight:\n",
			top_count);
	for (i = 0; i < top_count; i++) {
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
 *       97    65   kernel_version = utsname.version, same reject
 *                          semantics; .release alone is too coarse to
 *                          identify one specific compiled kernel image.
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
	if (strncmp(hdr.kernel_release, u.release,
			sizeof(hdr.kernel_release)) != 0 ||
	    strncmp(hdr.kernel_version, u.version,
			sizeof(hdr.kernel_version)) != 0) {
		/* Cold-start path: the file is structurally valid but was
		 * written against a different compiled kernel image, so its
		 * (pred_a, pred_b, nr) entries reference syscall and edge IDs
		 * that may have shifted under us.  Surface this so the
		 * operator can see why the warm-start was skipped without
		 * having to compare uname output by hand. */
		outputerr("healer: skipping warm-start of %s -- file built against %s, running %s\n",
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
