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
 *   - Beta-Binomial smoothed score normalisation, per-predecessor
 *     frequency tracking, decay walks, the corrupt-entry filter, and
 *     the low-confidence and minimum-raw qualification floors are all
 *     trinity-specific additions that don't appear in the original
 *     paper.
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
#include "exit.h"		/* EXIT_NO_SYSCALLS_ENABLED */
#include "healer.h"
#include "healer_ring.h"
#include "kcov.h"		/* kcov_get_kernel_fp */
#include "locks.h"
#include "params.h"		/* do_32_arch, do_64_arch */
#include "pids.h"		/* getpid wrapper */
#include "random.h"		/* ONE_IN */
#include "shm.h"
#include "stats.h"
#include "syscall.h"		/* set_syscall_nr_random, EXPENSIVE */
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
 * HEALER_NORM_ALPHA / HEALER_NORM_BETA Bayesian shrinkage that dampens
 * the score for entries that survive the filter (predfreq >= 1 on both
 * sides) and for the pair-side dump path which has no equivalent
 * filter at all.
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
 * and carry no statistical signal yet.  Without this floor the
 * normalisation in healer_normalised_score_milli amplifies a small
 * observation count into a misleadingly high norm score whenever the
 * combined predecessor frequency is also small -- the noise pairs that
 * dominated the top-10 before the bias bumps were precisely small-raw
 * entries riding a small denominator.  Filter at top-N qualification
 * only; observation, save/load and decay all keep handling these
 * entries normally so they remain available to graduate into the
 * ranking once they accumulate evidence.
 */
#define HEALER_DUMP_MIN_RAW 20

/*
 * Initial weight installed by the static-seed loader for each producer/
 * consumer pair derived from the existing ret_objtype / argtype metadata
 * the syscall table already carries.  Bootstraps the picker's pair
 * prior on cold runs; the seed value is now stored separately from
 * runtime dynamic_hits in each pair cell (see struct healer_pair_cell)
 * so the dump can route seed-only pairs to their own pool and the
 * eligibility gate can require real dynamic evidence regardless of
 * how many cells the seed installer populated.  3 is small enough that
 * a handful of dynamic observations easily overtake it in the picker
 * weight (static_prior + dynamic_hits) and the seed contribution
 * becomes negligible in the long run.
 */
#define HEALER_STATIC_SEED_WEIGHT 3

/*
 * Bayesian smoothing constants applied to the relation-table dump's
 * normalised score.  The displayed score is
 *
 *   norm = (raw + ALPHA) / (predfreq + ALPHA + BETA)
 *
 * which is the posterior mean of a Beta-Binomial model over the
 * "observed | predecessor appeared" rate, with a Beta(ALPHA, BETA)
 * prior centred at ALPHA/(ALPHA+BETA) ~= 0.2.  The shrinkage suppresses
 * spurious co-occurrence pairs whose raw and predfreq are both small
 * (where the unsmoothed raw/predfreq metric inflated noise into the
 * top-N) without distorting high-N entries: at predfreq in the
 * hundreds the +ALPHA / +BETA terms are dwarfed by the live counts and
 * the score tracks the raw ratio closely.  Replaces the prior
 * isqrt-dampened TF-IDF formulation, whose square-root denominator
 * compressed the large-N range too aggressively while still rewarding
 * single-digit-predfreq pairs at the noise floor.
 *
 * ALPHA == 5 matches the pseudo-count the prior PREDFREQ_BIAS used to
 * keep the denominator off its minimum value, calibrated to the
 * dynamic-pair entries that demonstrably carry signal in the first
 * dump tick.  BETA == 20 matches HEALER_DUMP_MIN_RAW: a fresh entry at
 * the qualification floor with no predecessor history scores at most
 * raw/(raw + BETA) == 0.5, capping the prior's influence on barely-
 * qualified entries while letting genuinely repeated triples climb.
 */
#define HEALER_NORM_ALPHA 5
#define HEALER_NORM_BETA  20

/*
 * Empirical-Bayes pseudocount bonus added to HEALER_NORM_ALPHA when
 * (pred_a, pred_b, succ) all share the same syscallentry .group
 * (and the group is not GROUP_NONE).  Same-family syscall triples
 * are more likely to share kernel state and thus more likely to have
 * a real causal coupling; a thin-evidence intra-family triple deserves
 * a head-start over an equally-thin cross-family triple.  The bonus
 * is dwarfed by raw counts in the hundreds, so high-N entries
 * (intra-family or not) are unaffected -- the prior fades out
 * automatically once raw evidence accumulates.
 */
#define HEALER_FAMILY_BONUS 5

/*
 * Coverage-weighted promotion floor.  HEALER's normalised score is
 * multiplied by a productivity ratio derived from the existing edgepair
 * table (new_edges / total for the immediate-predecessor -> successor
 * pair, smoothed with the same Beta(ALPHA, BETA) shape as the score
 * itself).  The multiplier is held in milli-fixed-point and bottoms out
 * at this floor so triples whose last-step pair has shown zero coverage
 * productivity still rank -- they keep the floor's contribution while
 * fully-productive triples climb to floor + 1000.  At the default of 250
 * a zero-productivity triple scores ~0.2x base and a maximally
 * productive triple scores 1.0x base, i.e. a 5x relative spread.
 * Lowering the floor makes the coverage signal more dominant; raising
 * it makes it more advisory.  Expect retuning after the top-N rerank
 * settles.
 */
#define HEALER_COVERAGE_FLOOR_MILLI 250

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
 * Layout-pinning asserts: the (pred_a, pred_b, predset_hash) tuple is
 * accessed both as struct fields and as a 64-bit .key union member by
 * the on-disk file format and the apply/dump paths.  Likewise (nr,
 * weight) inside struct healer_promoted.  A struct reorder that broke
 * the packing would fail to compile rather than silently producing
 * unreadable healer snapshot files.
 */
_Static_assert(offsetof(struct healer_relation, pred_a) == 0,
	       "pred_a must be at offset 0 for packed key view");
_Static_assert(offsetof(struct healer_relation, pred_b) == 2,
	       "pred_b must be at offset 2 for packed key view");
_Static_assert(offsetof(struct healer_relation, predset_hash) == 4,
	       "predset_hash must be at offset 4 for packed key view");
_Static_assert(sizeof(uint16_t) == 2, "uint16_t must be 2 bytes");
_Static_assert(sizeof(uint32_t) == 4, "uint32_t must be 4 bytes");
_Static_assert(offsetof(struct healer_promoted, nr) == 0,
	       "nr must be at offset 0 for packed promoted view");
_Static_assert(offsetof(struct healer_promoted, weight) == 4,
	       "weight must be at offset 4 for packed promoted view");
_Static_assert(sizeof(unsigned int) == 4, "unsigned int must be 4 bytes");

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

void healer_observe(struct childdata *child, unsigned int current_nr,
		    unsigned int flags, unsigned int edge_delta,
		    unsigned int result_class)
{
	unsigned int pred_prev, pred_last;

	if (child == NULL || child->healer_ring == NULL)
		return;

	/* Read predecessors in their original chronological order.  The
	 * triple-table apply sorts before hashing so (A, B) and (B, A)
	 * collapse into the same slot; the pair-table apply uses the
	 * immediate predecessor directly.  Storing them unsorted on the
	 * wire preserves ordering for downstream consumers that want it. */
	pred_prev = (child->healer_seq_count >= 2) ? child->healer_seq[0]
						   : EDGEPAIR_NO_PREV;
	pred_last = (child->healer_seq_count >= 1) ? child->healer_seq[1]
						   : EDGEPAIR_NO_PREV;

	/* No usable immediate predecessor -- nothing to learn.  Covers
	 * the very first syscall of a child's life and any window where
	 * the seq buffer was just reset (clean_childdata stamps both
	 * slots with EDGEPAIR_NO_PREV).  Triple-table updates additionally
	 * need pred_prev != EDGEPAIR_NO_PREV; the apply path handles that
	 * gating per-update so the pair half still runs when only the
	 * immediate predecessor is valid. */
	if (pred_last == EDGEPAIR_NO_PREV)
		return;

	/* Enqueue one unified observation slot for the parent's drain to
	 * apply.  Drives BOTH the pair-table bump (pred_last -> current_nr)
	 * AND the triple-table bump (sort(pred_prev, pred_last) -> current_nr)
	 * atomically from one slot, eliminating the partial-observation-loss
	 * window where one of the two enqueues could succeed while the
	 * other dropped.  See apply_observation() in healer-ring.c.
	 *
	 * Drop on ring overflow: parent_healer.ring_overflow_total
	 * already conveys "we lost samples".  In the cold-start regime
	 * (~30 observations/sec) the ring drains every main_loop tick well
	 * before it can fill; in the post-saturation steady state the
	 * observation rate collapses to ~0.5/sec so the ring is essentially
	 * always empty. */
	(void)healer_ring_enqueue_observation(child->healer_ring,
					      pred_prev, pred_last, current_nr,
					      flags, edge_delta, result_class);
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
 * Bayesian-smoothed normalisation for the relation-table dump.  Returns
 * a fixed-point score scaled by 1000 so the dump path can sort and emit
 * three-decimal precision without dragging floating point onto the hot
 * stats output.
 *
 * Formula:
 *   combined_freq = isqrt(pred_a_freq * pred_b_freq)
 *   alpha         = ALPHA + (same_family ? FAMILY_BONUS : 0)
 *   norm          = (raw_weight + alpha) * 1000
 *                 / (combined_freq + alpha + BETA)
 *
 * The two predecessor appearance counts are folded into a single
 * combined frequency via geometric mean, matching the prior formula's
 * intent that a triple with one rare predecessor still scores
 * meaningfully higher than one with two frequent predecessors.  The
 * Beta(ALPHA, BETA) pseudo-counts then shrink the resulting ratio
 * toward the prior mean, so a small-raw / small-predfreq pair no
 * longer races to the top of the ranking on a tiny denominator.  At
 * combined_freq in the hundreds the +ALPHA / +BETA terms are dominated
 * by the live counts and the score tracks the raw ratio closely, so
 * genuinely high-signal entries are not perturbed.
 *
 * The same_family flag inflates the alpha pseudocount by
 * HEALER_FAMILY_BONUS for intra-family triples (all three syscalls
 * sharing the same syscallentry .group, e.g. GROUP_NET / GROUP_VFS).
 * Same-family triples are a priori more likely to share kernel state
 * and thus more likely to express a real causal coupling, so the
 * empirical-Bayes prior gives them a head-start when raw evidence is
 * thin.  The bonus is automatically washed out once raw evidence
 * accumulates -- alpha terms in the single digits do not perturb a
 * triple with raw counts in the hundreds.
 *
 * Raw weight is preserved on the per-entry display so the operator can
 * still see the underlying signal alongside the normalised ranking.
 */
static bool healer_same_family(unsigned int pred_a_nr,
			       unsigned int pred_b_nr,
			       unsigned int succ_nr)
{
	struct syscallentry *a, *b, *s;

	if (syscalls == NULL)
		return false;
	if (pred_a_nr >= max_nr_syscalls ||
	    pred_b_nr >= max_nr_syscalls ||
	    succ_nr   >= max_nr_syscalls)
		return false;

	a = syscalls[pred_a_nr].entry;
	b = syscalls[pred_b_nr].entry;
	s = syscalls[succ_nr].entry;

	if (a == NULL || b == NULL || s == NULL)
		return false;
	if (a->group == GROUP_NONE)
		return false;
	return (a->group == b->group) && (b->group == s->group);
}

/*
 * Coverage-productivity multiplier derived from the existing edgepair
 * table.  HEALER triples are sorted by predset before they reach the
 * dump path (pred_a <= pred_b), so we no longer know which of the two
 * predecessors was the immediate predecessor at observation time.
 * Probe both orderings via edgepair_get_stats() and pick the more
 * productive ratio -- both are valid candidates for the last-step pair,
 * and the optimistic pick keeps a triple from being penalised by a
 * coincidentally-quiet alternative ordering.  The ratio reuses the
 * scoring side's HEALER_NORM_ALPHA / HEALER_NORM_BETA so the operator
 * only learns one Bayesian shape; the result is in milli-fixed-point
 * and clamped at HEALER_COVERAGE_FLOOR_MILLI.  Returns a multiplier in
 * the range [floor, floor + 1000] which the caller normalises against
 * (floor + 1000) to recover a 0.x..1.0 scaling factor.
 */
static unsigned long healer_coverage_multiplier_milli(unsigned int pred_a,
						      unsigned int pred_b,
						      unsigned int succ)
{
	struct edgepair_stats sa = edgepair_get_stats(pred_a, succ);
	struct edgepair_stats sb = edgepair_get_stats(pred_b, succ);
	unsigned long ra, rb, ratio;

	ra = ((sa.new_edges + HEALER_NORM_ALPHA) * 1000UL) /
	     (sa.total + HEALER_NORM_ALPHA + HEALER_NORM_BETA);
	rb = ((sb.new_edges + HEALER_NORM_ALPHA) * 1000UL) /
	     (sb.total + HEALER_NORM_ALPHA + HEALER_NORM_BETA);

	ratio = (ra > rb) ? ra : rb;
	return HEALER_COVERAGE_FLOOR_MILLI + ratio;
}

static unsigned long healer_normalised_score_milli(unsigned long raw_weight,
						   unsigned long pred_a_freq,
						   unsigned long pred_b_freq,
						   bool same_family,
						   unsigned int pred_a,
						   unsigned int pred_b,
						   unsigned int succ)
{
	unsigned long combined_freq = healer_isqrt(pred_a_freq * pred_b_freq);
	unsigned long alpha = HEALER_NORM_ALPHA;
	unsigned long denom, base, mult;

	if (same_family)
		alpha += HEALER_FAMILY_BONUS;

	denom = combined_freq + alpha + HEALER_NORM_BETA;
	base = ((raw_weight + alpha) * 1000UL) / denom;

	mult = healer_coverage_multiplier_milli(pred_a, pred_b, succ);
	return (base * mult) / (HEALER_COVERAGE_FLOOR_MILLI + 1000UL);
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
 * True if the syscall's per-entry successes counter is still zero --
 * i.e. either no child has ever called this syscall this run, OR every
 * call has failed (typical for syscalls the running kernel does not
 * support: landlock_* on a no-LANDLOCK kernel, etc.).  Backs the
 * dump-path pollution filter (HEALER_POLLUTION_FILTER_THRESHOLD).
 *
 * The earlier check on entry->attempted only caught the never-picked
 * case and missed unsupported-syscall noise: landlock_create_ruleset
 * gets picked normally on a no-LANDLOCK kernel, returns ENOSYS, bumps
 * attempted but not successes, and slipped past the filter despite
 * being exactly the noise the filter exists to suppress.  Using
 * successes covers both shapes -- attempted == 0 implies successes ==
 * 0 -- and the outer HEALER_POLLUTION_FILTER_THRESHOLD already gates
 * on the run being mature enough that "no successes yet" means
 * "structurally won't succeed" rather than "warmup".
 *
 * NULL or out-of-range entries are treated as unproductive: a slot
 * the build's syscall table does not even carry cannot meaningfully
 * succeed, and the surrounding filter still requires the total
 * observation threshold before acting on the result.  do32 is left at
 * false to match the call shape print_syscall_name uses everywhere
 * else in the dump path -- HEALER does not separately track 32-bit
 * dispatches.
 */
static bool healer_syscall_unattempted(unsigned int nr)
{
	const struct syscallentry *entry;

	if (nr >= MAX_NR_SYSCALL)
		return true;
	entry = get_syscall_entry(nr, false);
	if (entry == NULL)
		return true;
	return entry->successes == 0;
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
	 * that the smoothed normalisation could still float to the top of
	 * the prior-dominated regime where ALPHA outweighs raw_weight.  Kept
	 * separate from low_confidence_skipped because the two filters
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
	 * Per-dump tally of the pair table: total nonzero cells and the
	 * subset with any dynamic_hits.  Walked here so the second figure
	 * tracks "how many pairs the runtime observer has actually
	 * touched" cleanly, separate from the static-seed install
	 * footprint that populates pair_populated independently.
	 */
	unsigned long pair_populated = 0;
	unsigned long pair_weighted = 0;
	/*
	 * Pressure-tracking stats surfaced on the dump so an operator can
	 * see whether decay + slot pruning are actually reclaiming
	 * capacity.  active_predsets shadows `occupied` for the pressure
	 * line's self-contained shape; prunable_predsets counts slots
	 * whose every populated promoted entry has decayed to the floor
	 * (the prune walk in healer-ring.c needs one more aged-out epoch
	 * before evicting these); pair_rows_with_dynamic_mass counts pair-
	 * table rows where at least one cell has dynamic_hits > 0 (i.e.
	 * the runtime observer has touched it, separately from any
	 * static prior installed by the seed loader).  All three are
	 * recomputed from the canonical at every dump so the values track
	 * the live table rather than a stale snapshot taken at the last
	 * decay run.
	 */
	unsigned long active_predsets = 0;
	unsigned long prunable_predsets = 0;
	unsigned long pair_rows_with_dynamic_mass = 0;
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

	/* Decay runs from the parent's healer_ring_drain_all() now -- the
	 * drain fires once per main_loop iteration regardless of observer
	 * activity, so the wall-clock secondary trigger inside
	 * healer_apply_maybe_decay() always gets evaluated.  The dump no
	 * longer needs to chase the trigger from this side. */

	/* Snapshot the total observation count once up-front so the
	 * pollution filter inside the scan loops compares every
	 * candidate against the same threshold value -- re-reading the
	 * live counter per candidate would let the threshold trip
	 * mid-scan and produce an inconsistent dump where a few early
	 * entries survived the filter and later identical entries did
	 * not.  Reused for the summary line below in place of a second
	 * load; the older code read it again there only because nothing
	 * upstream had needed it yet. */
	observed = parent_healer.relations_observed;

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
		const struct healer_relation *slot = &parent_healer.relations[i];
		uint64_t slot_key;
		unsigned int slot_pred_a, slot_pred_b;
		unsigned int slot_promoted = 0;
		unsigned int slot_max_weight = 0;
		unsigned long pred_a_freq, pred_b_freq;

		/* Parent-private read: single-writer aggregate, no atomic
		 * load needed.  The slot-level / per-entry MAX_NR_SYSCALL
		 * bound checks that the in-shm path needed (to skip stray
		 * kernel scribbles) are gone -- the canonical lives in
		 * MAP_PRIVATE parent memory and the apply path itself
		 * rejects out-of-range events on enqueue. */
		slot_key = slot->key;
		if (slot_key == 0)
			continue;

		healer_unpack_key(slot_key, &slot_pred_a, &slot_pred_b);

		/* Hoist the per-syscall appearance reads out of the per-promoted
		 * inner loop -- they are slot-constant (every promoted entry in
		 * the slot shares the same predecessor pair). */
		pred_a_freq = parent_healer.pred_appearance[slot_pred_a];
		pred_b_freq = parent_healer.pred_appearance[slot_pred_b];

		for (j = 0; j < HEALER_PROMOTED_PER_SLOT; j++) {
			uint64_t entry;
			unsigned int weight, nr;
			unsigned long norm_score;
			struct healer_dump_entry cand;

			entry = slot->promoted[j].entry;
			healer_unpack_promoted(entry, &nr, &weight);

			if (weight == 0)
				continue;

			slot_promoted++;
			total_weight += weight;
			if (weight > slot_max_weight)
				slot_max_weight = weight;
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
			succ_weight[nr] += weight;

			norm_score = healer_normalised_score_milli(weight,
								   pred_a_freq,
								   pred_b_freq,
								   healer_same_family(slot_pred_a,
										      slot_pred_b,
										      nr),
								   slot_pred_a,
								   slot_pred_b,
								   nr);

			/*
			 * Low-confidence floor: drop entries from top-N
			 * qualification when at least one predecessor has no
			 * this-run appearance signal.  Both warm-start
			 * zombies (both counters at zero) and predecessor-
			 * skipped leftovers (one counter pinned at zero)
			 * land here.  The Beta(ALPHA, BETA) shrinkage in
			 * healer_normalised_score_milli already keeps the
			 * score off its raw-ratio extreme, but this filter
			 * additionally insists on at least some this-run
			 * evidence before an entry can rank -- "score
			 * no longer pathological" is not the same standard
			 * as "this entry was actually observed in the
			 * current run".  Per-promoted accounting matches the
			 * corruption skip a few lines up so the surfaced
			 * counts are comparable.
			 */
			if (pred_a_freq < HEALER_DUMP_MIN_PRED_APPEARANCES ||
			    pred_b_freq < HEALER_DUMP_MIN_PRED_APPEARANCES) {
				low_confidence_skipped++;
				continue;
			}

			/*
			 * Raw-observation floor: a single sighting carries no
			 * statistical weight on its own and would otherwise be
			 * lifted into the top-N by the smoothed score when
			 * the combined predfreq is small enough that the
			 * Beta prior dominates raw_weight.  Same top-N-only
			 * treatment as the low-confidence filter above,
			 * counted per promoted entry for parity.
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
			/* Slots whose every populated entry is at the decay
			 * floor would prune on the next sufficiently-aged
			 * decay run -- surface the count so an operator can
			 * tell at a glance how much capacity is sitting one
			 * cycle away from reclamation. */
			if (slot_max_weight <= 1)
				prunable_predsets++;
		}
	}
	active_predsets = occupied;

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
	 * any sparser indexing.  Static prior and dynamic evidence live in
	 * separate fields of each cell, so the routing test is direct:
	 * cells with any dynamic_hits go to the dynamically-confirmed
	 * pool, the rest land in the seed-only pool.  HEALER_DUMP_MIN_RAW
	 * still gates the dynamically-confirmed pool against single-shot
	 * noise (dropped entries are tallied into low_raw_skipped), but
	 * the seed-only pool ignores it -- a bare seed is itself the entry
	 * the section exists to surface.
	 */
	for (i = 0; i < MAX_NR_SYSCALL; i++) {
		unsigned long producer_freq = parent_healer.pred_appearance[i];
		bool row_dynamic_mass = false;

		for (j = 0; j < MAX_NR_SYSCALL; j++) {
			unsigned int weight, dyn_hits;
			unsigned long norm_score;
			struct healer_dump_entry cand;

			weight = healer_pair_get(i, j);
			if (weight == 0)
				continue;

			pair_populated++;
			/*
			 * Dynamic-hits is the runtime-evidence half of the
			 * cell.  Counting cells with dyn_hits > 0 (rather
			 * than `weight >= 2` against the combined value)
			 * keeps the per-dump pair_weighted statistic from
			 * conflating the seed install footprint with
			 * dynamic observation -- the old test counted bare
			 * seeds at weight == 3 as "weighted", which is the
			 * exact confusion the cell-struct split exists to
			 * remove.
			 */
			dyn_hits = healer_pair_dynamic_hits(i, j);
			if (dyn_hits > 0) {
				pair_weighted++;
				row_dynamic_mass = true;
			}

			/* Dynamic-pool floor: a single sighting carries no
			 * statistical weight even when stacked on a static
			 * prior.  Pure seeds (dyn_hits == 0) skip this floor
			 * -- they land in the seed-only pool, where the
			 * point IS to surface the static prior itself. */
			if (dyn_hits > 0 && dyn_hits < HEALER_DUMP_MIN_RAW) {
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
			 * Bayesian-smoothed single-predecessor analog of the
			 * triple-side formula: a pair has only one antecedent
			 * (the producer), so the combined predfreq collapses
			 * directly to producer_freq with no isqrt step.  Same
			 * Beta(ALPHA, BETA) pseudo-counts shrink the ratio
			 * toward the prior, so a static-seeded pair whose
			 * producer has never fired (producer_freq == 0) now
			 * scores at (raw + ALPHA) / (ALPHA + BETA) instead of
			 * raw -- noise pairs no longer crowd out dynamically-
			 * observed entries with non-zero producer counts, and
			 * the unsmoothed raw/predfreq pathology that elevated
			 * small-raw / small-predfreq cells into the top-N is
			 * directly corrected.
			 */
			norm_score = healer_normalised_score_milli(weight,
								   producer_freq,
								   producer_freq,
								   false,
								   i, i, j);

			cand.pred_a = 0;
			cand.pred_b = i;
			cand.promoted_nr = j;
			cand.weight = weight;
			cand.pred_a_freq = 0;
			cand.pred_b_freq = producer_freq;
			cand.norm_score_milli = norm_score;
			cand.is_pair = true;

			/*
			 * Pool routing is per-cell now: a cell with any
			 * dynamic_hits is dynamically-confirmed regardless of
			 * whether a static prior underlies it, and a cell with
			 * dynamic_hits == 0 is seed-only regardless of the
			 * producer's overall appearance count.  The previous
			 * proxy (producer_freq > 0) lifted seed-only cells
			 * whose producer happened to fire as part of some
			 * other (pred, succ) pair into the dynamic pool even
			 * though THIS pair had no runtime evidence.
			 */
			if (dyn_hits > 0)
				healer_top_n_insert(top_dyn, &top_dyn_count,
						    &cand);
			else
				healer_top_n_insert(top_seed, &top_seed_count,
						    &cand);
		}
		if (row_dynamic_mass)
			pair_rows_with_dynamic_mass++;
	}

	/* Parent-private aggregate reads -- no atomic load needed since
	 * the apply path is single-writer in parent context.  Occupancy
	 * is no longer surfaced through a separate stats field; the
	 * `occupied` local from the slot scan above is dumped directly. */
	table_full = parent_healer.table_full;
	evictions = parent_healer.evictions;
	decays_run = parent_healer.weight_decays_run;

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

	if (parent_healer.published_corrupt != 0)
		stats_log_write("  mirror integrity mismatches: %lu (canonical vs published page)\n",
				parent_healer.published_corrupt);

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
			"HEALER top %u seed-only relations (dynamic_hits=0, awaiting runtime confirmation):\n",
			top_seed, top_seed_count);
	}

	/*
	 * Pair-table summary line: total cells holding any weight, plus
	 * the subset with at least one dynamic_hits observation.  The
	 * first figure reflects the static-seed install size; the second
	 * is a direct count of cells the runtime observer has actually
	 * touched, so an operator can tell at a glance whether dynamic
	 * evidence is accumulating on top of the seed (rising
	 * dynamically_confirmed) or whether the table is still the
	 * loader's first install (dynamically_confirmed near zero).
	 */
	stats_log_write("HEALER pair table: %lu/%lu populated, %lu dynamically-confirmed (dynamic_hits>0)\n",
			pair_populated,
			(unsigned long)MAX_NR_SYSCALL * MAX_NR_SYSCALL,
			pair_weighted);

	/*
	 * Decay/prune pressure stats.  Together with the existing probe-
	 * limit-hits figure on the relation-table summary line, these tell
	 * an operator whether the decay + slot-prune machinery is keeping
	 * pace with the run's observation churn: a healthy fleet shows
	 * active_predsets well below HEALER_RELATION_SLOTS, a non-zero
	 * prunable_predsets value (decay is pushing entries toward the
	 * floor), and pair_rows_with_dynamic_mass climbing over the run as
	 * dynamic observations refine the static seed prior.  A run where
	 * active_predsets has saturated against HEALER_RELATION_SLOTS and
	 * probe-limit-hits is climbing past zero is the picture of a stuck
	 * table -- the prune threshold (HEALER_PRUNE_EPOCHS) likely needs
	 * lowering, or the workload is genuinely producing more distinct
	 * predsets than the table can hold and the slot count needs to
	 * grow.
	 */
	stats_log_write("HEALER pressure: %lu active predsets, %lu prunable (all entries at floor), %lu pair rows with dynamic mass (any cell dynamic_hits>0)\n",
			active_predsets, prunable_predsets,
			pair_rows_with_dynamic_mass);

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

			appearances = parent_healer.pred_appearance[n];
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
 * The relation table, pair table, decay clock and per-syscall appearance
 * counters are all parent-private state that dies with the trinity
 * process; every restart is otherwise a cold start.  Phase B's syscall
 * picker needs both tables to settle (24-48h of observations) before the
 * bandit arm has any usable signal, but trinity's children OOM/crash
 * long before that on realistic fleet hosts -- so without persistence
 * the tables never reach the maturity threshold and Phase B stays gated
 * indefinitely.
 *
 * Earlier versions of this file persisted parent_healer.relations only;
 * the pair table, pred_appearance counters and decay state were lost on
 * every restart even when the file was successfully loaded.  That gap
 * mattered increasingly as the picker grew direct dependencies on each
 * of those fields:
 *
 *   - The pair table now distinguishes the static prior installed by
 *     the seed loader from the dynamic_hits accumulated by the runtime
 *     observer (see struct healer_pair_cell in include/healer_ring.h);
 *     warm-starting only the static side throws away the runtime
 *     evidence the picker was supposed to converge on.
 *   - The eligibility gate in strategy.c reads dynamic_hits directly to
 *     decide whether the runtime observer has seen a pair, so a missing
 *     warm-start makes the picker fall back to the seed-only signal on
 *     every restart.
 *   - pred_appearance is the denominator of the low-confidence filter
 *     in the periodic dump; losing it leaves the per-run filter
 *     mis-calibrated for the first thousands of observations after
 *     restart.
 *   - decay_epoch is the prune clock anchor; losing it forces the
 *     loader to either treat every slot as freshly-stamped (which
 *     postpones legitimate eviction of stale slots) or as
 *     unconditionally ancient (which evicts every loaded relation on
 *     the first decay walk).  Persisting the epoch alongside the per-
 *     slot last-refreshed array preserves the correct age relationship.
 *
 * The save/load wire-format mirrors the cmp_hints / minicorpus / kcov-
 * bitmap pattern: XDG_CACHE_HOME / mkdir-p / atomic-rename-via-tmp-file
 * save path, fixed-size header carrying magic + version + dimensions +
 * kernel-utsname + kallsyms fingerprint + CRC32, then the payload as
 * four concatenated regions: relations[], pair_table[][],
 * pred_appearance[], relations_last_refreshed[].  CRC covers all four
 * payload regions exactly as they are written.  See cmp_hints.c for the
 * mirrored shape; the duplication is deliberate (a future divergence in
 * any one persistence file's format shouldn't ripple into the others).
 *
 * File layout (little-endian, packed as written):
 *
 *   offset  size   field
 *   ------  ----   ----------------------------------------------------
 *        0     4   magic = 0x48524C54 ('H','R','L','T' -- HEALER
 *                          Relation-table) sniff anchor.  Retained from
 *                          v1.
 *        4     4   version = HEALER_FILE_VERSION (currently 2).  A
 *                          loader compiled against a different version
 *                          refuses the file outright; the v1 -> v2
 *                          rewrite below changes the payload shape
 *                          materially.
 *        8     4   relation_slots = HEALER_RELATION_SLOTS at write time.
 *       12     4   promoted_per_slot = HEALER_PROMOTED_PER_SLOT at write
 *                          time.
 *       16     4   max_nr_syscall = MAX_NR_SYSCALL at write time.
 *       20     4   relation_size = sizeof(struct healer_relation) at
 *                          write time.  Reject on mismatch -- the
 *                          packed-key / promoted-array layout determines
 *                          how the bulk-copied payload is interpreted.
 *       24     4   pair_cell_size = sizeof(struct healer_pair_cell) at
 *                          write time.  Reject on mismatch -- a v1
 *                          loader treating cells as a single uint
 *                          would silently mis-read dynamic_hits.
 *       28     4   payload_crc32 over the concatenated payload regions
 *                          that follow (header-internal fields are not
 *                          covered; the dimension/magic/version checks
 *                          catch tampered headers earlier and cheaper).
 *       32     8   payload_bytes = expected total payload size in bytes
 *                          (sum of the four regions below).  Cross-
 *                          checked against the dimension-derived
 *                          expectation on load.
 *       40     8   observations = parent_healer.relations_observed at
 *                          write time.  Restored on load.
 *       48     8   obs_at_last_decay / time_at_last_decay /
 *       56     8     weight_decays_run / pair_seeded /
 *       64     8     table_full / evictions
 *       72     8     -- accumulated counters restored verbatim so the
 *       80     8     decay schedule and dump totals continue from
 *       88     8     where the previous run left off.
 *       96     2   decay_epoch = parent_healer.decay_epoch at write
 *                          time.  Restored on load so the relation-slot
 *                          prune clock (which reads age = decay_epoch -
 *                          relations_last_refreshed[i]) stays in lock-
 *                          step with the per-slot last_refreshed values
 *                          in payload region 4.
 *       98     6   pad6a -- align to 8.
 *      104    65   kernel_release = utsname.release captured at write
 *                          time, NUL-terminated, fixed-width.  Loader
 *                          compares strncmp(); a mismatch logs and
 *                          cold-starts (the relation/pair tables are
 *                          meaningful only against the kernel they were
 *                          learned on; release-level mismatches can
 *                          shift syscall numbers outright).
 *      169    65   kernel_version = utsname.version captured at write
 *                          time, NUL-terminated, fixed-width.  Stored
 *                          for forensic value but NOT compared on load.
 *      234    32   kallsyms_sha256 = kcov_get_kernel_fp() result at
 *                          write time.  A rebuilt kernel changes the
 *                          fingerprint and the loader cold-starts -- the
 *                          same gate the kcov bitmap and cmp-hints
 *                          files use, so a rebuilt kernel invalidates
 *                          all three in lock-step.  dynamic_hits and
 *                          relation weights both reflect per-kernel
 *                          edge behaviour, not just syscall numbering,
 *                          so a CFG-shifting rebuild can poison them
 *                          even when .release is unchanged.
 *      266     6   pad_end -- round struct healer_file_header to 8 bytes.
 *
 *      272 onwards  payload, four concatenated regions:
 *                      region 1: relations[]      HEALER_RELATION_SLOTS *
 *                                                   sizeof(struct
 *                                                   healer_relation)
 *                      region 2: pair_table[][]   MAX_NR_SYSCALL *
 *                                                   MAX_NR_SYSCALL *
 *                                                   sizeof(struct
 *                                                   healer_pair_cell)
 *                      region 3: pred_appearance  MAX_NR_SYSCALL *
 *                                                   sizeof(uint64_t)
 *                      region 4: relations_last_refreshed
 *                                                 HEALER_RELATION_SLOTS *
 *                                                   sizeof(uint16_t)
 *                  Regions are laid out in C row-major order matching
 *                  the in-memory parent_healer fields, with no per-slot
 *                  framing.  payload_crc32 covers exactly these bytes.
 *
 * Atomicity: save writes to "<path>.tmp.<pid>", fsyncs, then renames
 * into place.  Both saver and loader run from parent context (single
 * writer); the staging-buffer-against-concurrent-observers discipline
 * the in-shm path required is gone.  The loader's CRC still catches a
 * bytes-written-mid-rename failure mode.
 */

#define HEALER_FILE_MAGIC		0x48524C54U	/* "HRLT" */
#define HEALER_FILE_VERSION		2U
#define HEALER_UTSNAME_LEN		65	/* matches Linux __NEW_UTS_LEN+1 */

/*
 * Per-cell saturation cap for pair_table[][].dynamic_hits.  A single hot
 * (pred, succ) pair fired in a tight loop would otherwise drive its
 * cell's weight into the millions within seconds and dominate the dump-
 * side ranking forever; the cap lets a steady observer signal accumulate
 * well above the noise floor while still leaving room for late-arriving
 * pairs to overtake an early hotspot via decay (when decay lands).
 * Picked at 1<<24 (~16M) to comfortably outrun any realistic per-run
 * observation count for a single pair while staying far below uint32
 * saturation.  Defined here so the persistence loader can clamp a
 * corrupt on-disk dynamic_hits value against the same ceiling apply_pair
 * enforces; the same constant is also re-defined locally in healer-ring.c
 * so that file stays self-contained.
 */
#define HEALER_PAIR_MAX_WEIGHT		(1U << 24)

/*
 * Periodic snapshot trigger.  Every HEALER_SNAPSHOT_OBSERVATIONS the
 * fleet-wide observation counter advances past, the parent drain calls
 * healer_save_file().  5000 was picked against measured post-saturation
 * observation rates of ~0.7-1.5/sec: at 50000 the window stretched to
 * 9-20 hours of wall time and the typical 15min-2h fuzz run died
 * (OOM-kill, ASAN cascade, hard crash) without ever firing a single
 * snapshot, losing the entire run's HEALER table back to cold start.
 * At 5000 the window collapses to roughly 1-2 hours of post-saturation
 * runtime, and the wall-clock secondary trigger below (5min floor)
 * catches the rest -- crashes now lose at most a few minutes of
 * relations.
 */
#define HEALER_SNAPSHOT_OBSERVATIONS	5000UL

/*
 * Wall-clock secondary trigger for healer_maybe_snapshot().  The
 * observation-based trigger above only fires when relations are being
 * actively observed; on a saturated fuzz the observation rate collapses
 * (~0.7-1.5/sec) and even the reduced 5000-observation window can take
 * over an hour to cross, longer than many runs survive before being
 * killed.  300s caps the worst-case loss-on-crash at five minutes of
 * relations regardless of observation rate, while still leaving the
 * cheap obs-trigger fast path in charge during the early-run discovery
 * burst (where it fires several times within a single 5-minute window).
 * Hardcoded -- no operator knob, no expectation that fleet boxes will
 * need to retune this.
 */
#define HEALER_SNAPSHOT_INTERVAL_SEC	300UL

/* Header layout is naturally packed under the LP64 ABIs trinity targets:
 * 8 uint32_t fields, 8 uint64_t fields, a uint16_t, two 6-byte pads,
 * two 65-byte char arrays and a 32-byte fingerprint sum to 272 bytes
 * with no compiler-inserted padding.  No __attribute__((packed))
 * needed -- and adding one would trip -Wpacked. */
struct healer_file_header {
	uint32_t magic;			/*   0  4 */
	uint32_t version;		/*   4  4 */
	uint32_t relation_slots;	/*   8  4 */
	uint32_t promoted_per_slot;	/*  12  4 */
	uint32_t max_nr_syscall;	/*  16  4 */
	uint32_t relation_size;		/*  20  4 */
	uint32_t pair_cell_size;	/*  24  4 */
	uint32_t payload_crc32;		/*  28  4 */
	uint64_t payload_bytes;		/*  32  8 */
	uint64_t observations;		/*  40  8 */
	uint64_t obs_at_last_decay;	/*  48  8 */
	uint64_t time_at_last_decay;	/*  56  8 */
	uint64_t weight_decays_run;	/*  64  8 */
	uint64_t pair_seeded;		/*  72  8 */
	uint64_t table_full;		/*  80  8 */
	uint64_t evictions;		/*  88  8 */
	uint16_t decay_epoch;		/*  96  2 */
	uint8_t  pad6a[6];		/*  98  6 */
	char kernel_release[HEALER_UTSNAME_LEN];	/* 104 65 */
	char kernel_version[HEALER_UTSNAME_LEN];	/* 169 65 */
	uint8_t  kallsyms_sha256[32];	/* 234 32 */
	uint8_t  pad_end[6];		/* 266  6 */
};

#define HEALER_RELATIONS_BYTES \
	((size_t)HEALER_RELATION_SLOTS * sizeof(struct healer_relation))
#define HEALER_PAIR_TABLE_BYTES \
	((size_t)MAX_NR_SYSCALL * MAX_NR_SYSCALL * sizeof(struct healer_pair_cell))
#define HEALER_PRED_APPEARANCE_BYTES \
	((size_t)MAX_NR_SYSCALL * sizeof(uint64_t))
#define HEALER_LAST_REFRESHED_BYTES \
	((size_t)HEALER_RELATION_SLOTS * sizeof(uint16_t))
#define HEALER_PAYLOAD_BYTES \
	(HEALER_RELATIONS_BYTES + HEALER_PAIR_TABLE_BYTES + \
	 HEALER_PRED_APPEARANCE_BYTES + HEALER_LAST_REFRESHED_BYTES)

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
 * Pack the four payload regions into a single heap buffer in the order
 * the on-disk layout specifies.  Caller frees on success; returns NULL
 * on alloc failure.  Used both to write the file and to feed the CRC
 * computation -- a single contiguous buffer avoids running the CRC over
 * four separate ranges and keeps the on-disk and in-memory views byte-
 * identical.  pred_appearance is widened to uint64_t in the on-disk
 * record (parent_healer holds it as unsigned long, which is 32-bit on
 * the 32-bit arches trinity still builds for) so the file shape is
 * stable across word size.
 */
static uint8_t *healer_serialise_payload(void)
{
	uint8_t *buf;
	size_t off = 0;
	unsigned int i;
	uint64_t *appear_widened;

	buf = malloc(HEALER_PAYLOAD_BYTES);
	if (buf == NULL)
		return NULL;

	memcpy(buf + off, parent_healer.relations, HEALER_RELATIONS_BYTES);
	off += HEALER_RELATIONS_BYTES;

	memcpy(buf + off, parent_healer.pair_table, HEALER_PAIR_TABLE_BYTES);
	off += HEALER_PAIR_TABLE_BYTES;

	appear_widened = (uint64_t *)(buf + off);
	for (i = 0; i < MAX_NR_SYSCALL; i++)
		appear_widened[i] = (uint64_t)parent_healer.pred_appearance[i];
	off += HEALER_PRED_APPEARANCE_BYTES;

	memcpy(buf + off, parent_healer.relations_last_refreshed,
	       HEALER_LAST_REFRESHED_BYTES);
	off += HEALER_LAST_REFRESHED_BYTES;

	/* off == HEALER_PAYLOAD_BYTES by construction; the macro is the
	 * sum of the four region sizes appended above. */
	(void)off;
	return buf;
}

bool healer_save_file(const char *path)
{
	struct healer_file_header hdr;
	struct utsname u;
	uint8_t *payload;
	char tmppath[PATH_MAX];
	int fd;
	int ret;

	if (path == NULL)
		return false;

	if (!healer_snapshot_dirty) {
		output(0, "healer: snapshot skipped, no changes since last save\n");
		return true;
	}

	if (uname(&u) != 0)
		return false;

	memset(&hdr, 0, sizeof(hdr));
	hdr.magic = HEALER_FILE_MAGIC;
	hdr.version = HEALER_FILE_VERSION;
	hdr.relation_slots = HEALER_RELATION_SLOTS;
	hdr.promoted_per_slot = HEALER_PROMOTED_PER_SLOT;
	hdr.max_nr_syscall = MAX_NR_SYSCALL;
	hdr.relation_size = (uint32_t)sizeof(struct healer_relation);
	hdr.pair_cell_size = (uint32_t)sizeof(struct healer_pair_cell);
	hdr.payload_bytes = (uint64_t)HEALER_PAYLOAD_BYTES;
	hdr.observations = parent_healer.relations_observed;
	hdr.obs_at_last_decay = parent_healer.obs_at_last_decay;
	hdr.time_at_last_decay = parent_healer.time_at_last_decay;
	hdr.weight_decays_run = parent_healer.weight_decays_run;
	hdr.pair_seeded = parent_healer.pair_seeded;
	hdr.table_full = parent_healer.table_full;
	hdr.evictions = parent_healer.evictions;
	hdr.decay_epoch = parent_healer.decay_epoch;
	/* snprintf guarantees NUL termination at sizeof(dst)-1 without
	 * tripping -Wstringop-truncation the way the strncpy-plus-explicit-
	 * NUL idiom does once the function is large enough for GCC to
	 * partially inline it. */
	(void)snprintf(hdr.kernel_release, sizeof(hdr.kernel_release),
		       "%s", u.release);
	(void)snprintf(hdr.kernel_version, sizeof(hdr.kernel_version),
		       "%s", u.version);

	/* Fingerprint failure is non-fatal at write time: the existing
	 * loader gate still falls through to utsname.release matching, and
	 * a saved file with a zero fingerprint will simply cold-start on
	 * any reader that reaches the fingerprint check.  Logging is left
	 * to kcov_get_kernel_fp's own diagnostic. */
	(void)kcov_get_kernel_fp(hdr.kallsyms_sha256);

	payload = healer_serialise_payload();
	if (payload == NULL)
		return false;
	hdr.payload_crc32 = healer_crc32(payload, HEALER_PAYLOAD_BYTES);

	ret = snprintf(tmppath, sizeof(tmppath), "%s.tmp.%d",
			path, (int)getpid());
	if (ret < 0 || (size_t)ret >= sizeof(tmppath)) {
		free(payload);
		return false;
	}

	fd = open(tmppath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		free(payload);
		return false;
	}

	/* Neutralise any fuzzer-installed umask so the save mode is 0644. */
	if (fchmod(fd, 0644) != 0) {
		(void)close(fd);
		(void)unlink(tmppath);
		free(payload);
		return false;
	}

	if (healer_write_all(fd, &hdr, sizeof(hdr)) < 0)
		goto fail;
	if (healer_write_all(fd, payload, HEALER_PAYLOAD_BYTES) < 0)
		goto fail;

	if (fsync(fd) != 0)
		goto fail;
	if (close(fd) != 0) {
		(void)unlink(tmppath);
		free(payload);
		return false;
	}

	if (rename(tmppath, path) != 0) {
		(void)unlink(tmppath);
		free(payload);
		return false;
	}
	free(payload);
	healer_snapshot_dirty = false;
	return true;

fail:
	(void)close(fd);
	(void)unlink(tmppath);
	free(payload);
	return false;
}

/*
 * Per-slot validation for the relations region.  Returns true if the
 * slot looks intact AND occupies the position the in-memory hash/probe
 * walk would assign to its (pred_a, pred_b) key.  An empty slot (key=0)
 * is valid trivially.  Promoted entries are checked in-place by the
 * caller after this returns true; a populated slot with one invalid
 * promoted entry doesn't cause the whole slot to be rejected (the
 * promoted entry alone is cleared, matching the cmp-hints loader's
 * per-entry rejection policy).
 *
 * predset_hash is recomputed from the slot's stored (pred_a, pred_b)
 * pair and required to match the on-disk hash.  A mismatch indicates
 * either bit-rot in the file or that the FNV-1a hash constants changed
 * underneath us; either way, accepting the slot would put it on the
 * wrong probe chain and apply_triple would never find it again.
 */
static bool healer_loaded_relation_valid(const struct healer_relation *slot)
{
	unsigned int pred_a = slot->pred_a;
	unsigned int pred_b = slot->pred_b;
	uint32_t hash;

	if (slot->key == 0)
		return true;

	if (pred_a >= MAX_NR_SYSCALL || pred_b >= MAX_NR_SYSCALL)
		return false;
	if (pred_a > pred_b)
		return false;

	hash = healer_predset_hash(pred_a, pred_b);
	if (hash != slot->predset_hash)
		return false;
	/* key is a packed view of (pred_a, pred_b, predset_hash); the
	 * upper bits must agree with the recomputed hash since the lower
	 * bits already agreed (they're the same pred_a/pred_b we hashed). */
	if (slot->key != healer_pack_key(pred_a, pred_b, hash))
		return false;

	return true;
}

bool healer_load_file(const char *path)
{
	struct healer_file_header hdr;
	struct utsname u;
	uint8_t cur_fp[32];
	uint8_t *tmpbuf = NULL;
	uint32_t want_crc;
	size_t expected_payload;
	size_t off;
	ssize_t hn;
	unsigned int slots_loaded = 0;
	unsigned int slots_rejected = 0;
	unsigned int slots_duplicate = 0;
	unsigned int promoted_rejected = 0;
	unsigned int pair_cells_clamped = 0;
	unsigned int pair_rows_loaded = 0;
	bool have_fp;
	bool ok = false;
	int fd;
	unsigned int i, j;

	if (path == NULL)
		return false;

	have_fp = kcov_get_kernel_fp(cur_fp);

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		if (errno == ENOENT)
			output(0, "healer: no persisted state at %s -- cold start\n",
			       path);
		else
			output(0, "healer: open(%s) failed: %s -- cold start\n",
			       path, strerror(errno));
		return false;
	}

	hn = healer_read_all(fd, &hdr, sizeof(hdr));
	if (hn != (ssize_t)sizeof(hdr)) {
		output(0, "healer: header truncated at %s (got %zd, want %zu) -- cold start\n",
		       path, hn, sizeof(hdr));
		goto out_close;
	}

	if (hdr.magic != HEALER_FILE_MAGIC) {
		output(0, "healer: file magic 0x%08x != expected 0x%08x at %s -- cold start\n",
		       hdr.magic, HEALER_FILE_MAGIC, path);
		goto out_close;
	}
	if (hdr.version != HEALER_FILE_VERSION) {
		output(0, "healer: file version %u != expected %u at %s (format changed; previous-version files will be regenerated by the next snapshot) -- cold start\n",
		       hdr.version, HEALER_FILE_VERSION, path);
		goto out_close;
	}
	if (hdr.relation_slots != HEALER_RELATION_SLOTS) {
		output(0, "healer: relation_slots %u != expected %u at %s (file built with a different HEALER_RELATION_SLOTS) -- cold start\n",
		       hdr.relation_slots, HEALER_RELATION_SLOTS, path);
		goto out_close;
	}
	if (hdr.promoted_per_slot != HEALER_PROMOTED_PER_SLOT) {
		output(0, "healer: promoted_per_slot %u != expected %u at %s (file built with a different HEALER_PROMOTED_PER_SLOT) -- cold start\n",
		       hdr.promoted_per_slot, HEALER_PROMOTED_PER_SLOT, path);
		goto out_close;
	}
	if (hdr.max_nr_syscall != MAX_NR_SYSCALL) {
		output(0, "healer: max_nr_syscall %u != expected %u at %s (file built with a different MAX_NR_SYSCALL) -- cold start\n",
		       hdr.max_nr_syscall, MAX_NR_SYSCALL, path);
		goto out_close;
	}
	if (hdr.relation_size != (uint32_t)sizeof(struct healer_relation)) {
		output(0, "healer: relation_size %u != expected %zu at %s (struct healer_relation layout changed) -- cold start\n",
		       hdr.relation_size,
		       sizeof(struct healer_relation), path);
		goto out_close;
	}
	if (hdr.pair_cell_size != (uint32_t)sizeof(struct healer_pair_cell)) {
		output(0, "healer: pair_cell_size %u != expected %zu at %s (struct healer_pair_cell layout changed) -- cold start\n",
		       hdr.pair_cell_size,
		       sizeof(struct healer_pair_cell), path);
		goto out_close;
	}
	expected_payload = HEALER_PAYLOAD_BYTES;
	if (hdr.payload_bytes != (uint64_t)expected_payload) {
		output(0, "healer: payload_bytes %llu != expected %zu at %s -- cold start\n",
		       (unsigned long long)hdr.payload_bytes,
		       expected_payload, path);
		goto out_close;
	}

	if (uname(&u) != 0) {
		output(0, "healer: uname() failed: %s -- cold start\n",
		       strerror(errno));
		goto out_close;
	}

	hdr.kernel_release[sizeof(hdr.kernel_release) - 1] = '\0';
	hdr.kernel_version[sizeof(hdr.kernel_version) - 1] = '\0';
	if (strncmp(hdr.kernel_release, u.release,
			sizeof(hdr.kernel_release)) != 0) {
		outputerr("healer: skipping warm-start of %s -- file built against release %s, running release %s\n",
			  path, hdr.kernel_release, u.release);
		goto out_close;
	}

	if (have_fp &&
	    memcmp(hdr.kallsyms_sha256, cur_fp, sizeof(cur_fp)) != 0) {
		output(0, "healer: kernel fingerprint mismatch at %s (kallsyms content differs from when the file was written) -- cold start\n",
		       path);
		goto out_close;
	}

	/* Stage the payload into a heap buffer first so a partial read or
	 * CRC failure leaves parent_healer untouched (a torn load would
	 * poison the dump and the next publish). */
	tmpbuf = malloc(expected_payload);
	if (tmpbuf == NULL) {
		output(0, "healer: scratch alloc fail (%zu bytes) -- cold start\n",
		       expected_payload);
		goto out_close;
	}

	hn = healer_read_all(fd, tmpbuf, expected_payload);
	if (hn != (ssize_t)expected_payload) {
		output(0, "healer: payload truncated at %s (got %zd, want %zu) -- cold start\n",
		       path, hn, expected_payload);
		goto out_free;
	}

	want_crc = healer_crc32(tmpbuf, expected_payload);
	if (want_crc != hdr.payload_crc32) {
		output(0, "healer: payload CRC mismatch at %s (got 0x%08x, want 0x%08x) -- cold start\n",
		       path, want_crc, hdr.payload_crc32);
		goto out_free;
	}

	/* Past header / fingerprint / CRC gates the payload is considered
	 * authoritative against the running kernel.  Per-region apply
	 * below; per-slot bounds rejection on the relations region drops
	 * any slot whose hash/probe identity doesn't reconstruct, so a
	 * single bit-rotted slot doesn't sink the whole warm-start.  Pair
	 * cells and counters are validated by simple range clamp. */

	/* Region 1: relations[].  Validate each slot; copy good ones to
	 * parent_healer.relations.  Track keys we've seen so a duplicate
	 * key in two slots (which would put two cells on the same probe
	 * chain and confuse apply_triple's "first matching key" probe)
	 * is detected and the duplicate dropped. */
	memset(parent_healer.relations, 0, HEALER_RELATIONS_BYTES);
	off = 0;
	{
		const struct healer_relation *src =
			(const struct healer_relation *)(tmpbuf + off);
		bool key_seen_in_chain;
		unsigned int probe;
		unsigned int chain_idx;

		for (i = 0; i < HEALER_RELATION_SLOTS; i++) {
			struct healer_relation slot = src[i];

			if (slot.key == 0)
				continue;

			if (!healer_loaded_relation_valid(&slot)) {
				slots_rejected++;
				continue;
			}

			/* Duplicate detection: probe the same chain
			 * apply_triple would use; if a slot in that chain
			 * already carries this key, this is the duplicate.
			 * Document choice: reject (drop the duplicate),
			 * keeping the first occurrence in the file. */
			key_seen_in_chain = false;
			chain_idx = slot.predset_hash &
				    (HEALER_RELATION_SLOTS - 1);
			for (probe = 0; probe < HEALER_PROBE_LIMIT; probe++) {
				unsigned int idx = (chain_idx + probe) &
					(HEALER_RELATION_SLOTS - 1);
				if (parent_healer.relations[idx].key ==
				    slot.key) {
					key_seen_in_chain = true;
					break;
				}
				if (parent_healer.relations[idx].key == 0)
					break;
			}
			if (key_seen_in_chain) {
				slots_duplicate++;
				continue;
			}

			/* Per-promoted-entry range check.  An entry with
			 * weight 0 is the empty sentinel and stays.  An
			 * entry with nr >= MAX_NR_SYSCALL is bit-rot; zero
			 * the entry and count the rejection but keep the
			 * surrounding slot. */
			for (j = 0; j < HEALER_PROMOTED_PER_SLOT; j++) {
				unsigned int weight, nr;

				healer_unpack_promoted(slot.promoted[j].entry,
							  &nr, &weight);
				if (weight == 0)
					continue;
				if (nr >= MAX_NR_SYSCALL) {
					slot.promoted[j].entry = 0;
					promoted_rejected++;
				}
			}

			parent_healer.relations[i] = slot;
			parent_healer.relations_dirty[i] = 1;
			slots_loaded++;
		}
	}
	off += HEALER_RELATIONS_BYTES;

	/* Region 2: pair_table[][].  Bulk-copy then walk to clamp
	 * dynamic_hits at the saturation cap (a corrupt file with a
	 * higher value would otherwise bypass the saturation discipline
	 * apply_pair maintains).  Mark rows dirty so the first publish
	 * refreshes the mirror page. */
	memcpy(parent_healer.pair_table, tmpbuf + off, HEALER_PAIR_TABLE_BYTES);
	off += HEALER_PAIR_TABLE_BYTES;
	for (i = 0; i < MAX_NR_SYSCALL; i++) {
		bool row_populated = false;

		for (j = 0; j < MAX_NR_SYSCALL; j++) {
			struct healer_pair_cell *cell =
				&parent_healer.pair_table[i][j];

			if (cell->dynamic_hits > HEALER_PAIR_MAX_WEIGHT) {
				cell->dynamic_hits = HEALER_PAIR_MAX_WEIGHT;
				pair_cells_clamped++;
			}
			if (cell->dynamic_hits != 0 || cell->static_prior != 0)
				row_populated = true;
		}

		if (row_populated) {
			parent_healer.pair_dirty[i] = 1;
			pair_rows_loaded++;
		}
	}

	/* Region 3: pred_appearance[].  Widen from on-disk uint64_t back
	 * to in-memory unsigned long; on 64-bit hosts this is a straight
	 * copy, on 32-bit hosts the file value is saturated at ULONG_MAX
	 * (capping rather than truncating preserves the "predecessor has
	 * fired a lot" signal even on a builder whose word size is too
	 * narrow for the original count). */
	{
		const uint64_t *appear_on_disk =
			(const uint64_t *)(tmpbuf + off);

		for (i = 0; i < MAX_NR_SYSCALL; i++) {
			uint64_t v = appear_on_disk[i];

			if (v > (uint64_t)ULONG_MAX)
				v = (uint64_t)ULONG_MAX;
			parent_healer.pred_appearance[i] = (unsigned long)v;
		}
	}
	off += HEALER_PRED_APPEARANCE_BYTES;

	/* Region 4: relations_last_refreshed[].  Restored verbatim;
	 * combined with the restored decay_epoch in the header this
	 * preserves each slot's "epochs since last observation" age so
	 * the prune walk picks up where the previous run left off
	 * instead of either resetting every slot to fresh or marking
	 * every slot as ancient. */
	memcpy(parent_healer.relations_last_refreshed, tmpbuf + off,
	       HEALER_LAST_REFRESHED_BYTES);
	off += HEALER_LAST_REFRESHED_BYTES;
	(void)off;

	/* Restore the accumulated counters and decay clock.  Doing this
	 * here, after the per-region copy succeeds, keeps the warm-start
	 * either complete or skipped -- partial state is never installed.
	 * obs_at_last_snapshot is anchored at the restored observation
	 * count so the next snapshot fires after a fresh
	 * HEALER_SNAPSHOT_OBSERVATIONS delta of new evidence rather than
	 * triggering immediately on top of an empty delta. */
	parent_healer.relations_observed = hdr.observations;
	parent_healer.obs_at_last_snapshot = hdr.observations;
	parent_healer.obs_at_last_decay = hdr.obs_at_last_decay;
	parent_healer.time_at_last_decay = hdr.time_at_last_decay;
	parent_healer.weight_decays_run = hdr.weight_decays_run;
	parent_healer.pair_seeded = hdr.pair_seeded;
	parent_healer.table_full = hdr.table_full;
	parent_healer.evictions = hdr.evictions;
	parent_healer.decay_epoch = hdr.decay_epoch;

	output(0, "healer: loaded %u relations (%u rejected, %u duplicate, %u promoted entries rejected) + %u pair rows (%u cells clamped) + %lu observations + decay_epoch=%u from %s\n",
	       slots_loaded, slots_rejected, slots_duplicate,
	       promoted_rejected, pair_rows_loaded, pair_cells_clamped,
	       (unsigned long)hdr.observations,
	       (unsigned int)hdr.decay_epoch, path);

	/* Canonical now matches the on-disk image bit-for-bit -- mark
	 * clean so a load-then-immediate-exit cycle (warm-start under a
	 * Ctrl-C restart loop) skips the redundant end-of-run save.  Any
	 * subsequent mutation (load_static_seed installing fresh cells,
	 * the drain applying observations, the decay walk firing) will
	 * flip this true again. */
	healer_snapshot_dirty = false;

	ok = true;

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
 * Periodic snapshot trigger.  The save path is set in the parent at
 * startup via healer_enable_snapshots() and inherited COW by every
 * child.  healer_maybe_snapshot() runs from the parent drain
 * (healer_ring_drain_all in healer-ring.c), evaluated against
 * parent_healer's observation-count and wall-clock high-water-marks;
 * the function early-returns cheaply unless one of the two triggers
 * has fired.  The two-step CAS election the in-shm path used to
 * serialise concurrent child callers collapses to a plain comparison
 * here -- drain context is single-writer, and a sequential call to
 * healer_save_file cannot race itself.
 */
static char healer_snapshot_path[PATH_MAX];
static bool healer_snapshot_enabled;

/*
 * Dirty-bit for healer_save_file().  Set by every parent-private mutation
 * to parent_healer that lands in the persisted file (apply_triple,
 * apply_pair, the decay/prune walk, the static-seed installer); cleared
 * after a successful save and on a successful warm-start load.  When
 * clear, healer_save_file() short-circuits without touching disk -- the
 * canonical and on-disk images are bit-for-bit identical, so the rename()
 * would just narrow the window in which a concurrent reader could be
 * looking at the old file with no compensating benefit.
 *
 * Default false: a cold-start run with no save file and no static-seed
 * installs has nothing to persist; load_static_seed() runs after
 * load_file() in the parent startup path and flips this true if any new
 * cells get installed.  Parent-private (sits next to healer_snapshot_path
 * above).  Visible to healer-ring.c via the extern in include/healer_ring.h
 * so the mutating apply paths can flip it without each one needing a
 * round-trip back through a setter.
 *
 * Counter-style proxies (relations_observed, weight_decays_run, pair_seeded)
 * were considered but rejected: apply_pair mutates pair_table without
 * advancing any of those counters, so any single existing counter would
 * miss a real mutation class and any combined-counter aggregate would have
 * to be re-summed on every save call.  A plain bool is cheaper and covers
 * every mutation path uniformly.
 */
bool healer_snapshot_dirty;

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

	/* Anchor the wall-clock floor to fuzz-start so the first time-trigger
	 * fires HEALER_SNAPSHOT_INTERVAL_SEC after enable rather than
	 * immediately on the first drain against a near-empty table. */
	parent_healer.last_snapshot_time = (unsigned long)time(NULL);
}

void healer_maybe_snapshot(void)
{
	unsigned long obs_now, old, now_sec, old_time;
	bool obs_trigger, time_trigger;

	if (!healer_snapshot_enabled)
		return;

	/* Single-writer parent-context state -- the CAS election that
	 * existed to serialise concurrent child callers collapses to a
	 * plain comparison now that healer_maybe_snapshot() runs only
	 * from healer_ring_drain_all().  Same trigger pair as before
	 * (observation-count + wall-clock), same thresholds, same on-
	 * disk output: only the locking discipline changed. */
	obs_now = parent_healer.relations_observed;
	old = parent_healer.obs_at_last_snapshot;
	old_time = parent_healer.last_snapshot_time;
	now_sec = (unsigned long)time(NULL);

	obs_trigger = (obs_now >= old + HEALER_SNAPSHOT_OBSERVATIONS);
	time_trigger = (now_sec >= old_time + HEALER_SNAPSHOT_INTERVAL_SEC);

	if (!obs_trigger && !time_trigger)
		return;

	parent_healer.obs_at_last_snapshot = obs_now;
	healer_save_file(healer_snapshot_path);
	parent_healer.last_snapshot_time = now_sec;
}

/*
 * --- Pair-relation table (single-predecessor companion) ---
 *
 * Parallel storage to the (predset -> nr) triple table above, indexed
 * (pred -> succ) instead of ((pred_a, pred_b) -> succ).  Coarser-
 * grained than triples but cheap to seed from a static prior derived
 * from existing ARG_FD_* / ret_objtype metadata, which the static-seed
 * loader below plumbs in pre-fork.
 *
 * The backing store lives at shm->healer_pair_table (declared in
 * include/shm.h) so the parent's pre-fork seed AND each child's later
 * observer-side bumps land in the same fleet-wide region; see the
 * declaration's comment for the rationale on shm vs process-private
 * BSS.  Locking model matches healer_relations[]: relaxed-atomic
 * compare-exchange for the seed installer (idempotent CAS-from-zero)
 * and a relaxed-atomic load + CAS loop bounded by HEALER_PAIR_MAX_WEIGHT
 * for the observer bump.  No new lock or pattern is introduced here.
 */

void healer_pair_seed(unsigned int pred, unsigned int succ, unsigned int weight)
{
	/* Forward to the parent-private canonical setter.  The seed
	 * loader runs pre-fork in the parent and writes parent_healer
	 * directly; the first publish step inside healer_ring_drain_all()
	 * propagates the seeded weights to the mirror page that children
	 * then read from set_syscall_nr_healer.  Idempotent (skips a
	 * cell already carrying a weight). */
	healer_aggregate_pair_set(pred, succ, weight);
}

/*
 * Picker-side weight formula.  Sums the static-prior bootstrap value
 * (held in uint8_t but widened here for the add) and the runtime
 * dynamic_hits accumulator into a single picker weight.  Kept as a
 * single point-of-truth so any future tuning (weight the dynamic side
 * more, ignore the prior past some hit count, etc.) lands in one
 * place rather than scattered across the picker's distribution loop.
 */
static unsigned int healer_pair_cell_picker_weight(const struct healer_pair_cell *cell)
{
	return (unsigned int)cell->static_prior + cell->dynamic_hits;
}

unsigned int healer_pair_get(unsigned int pred, unsigned int succ)
{
	if (pred >= MAX_NR_SYSCALL || succ >= MAX_NR_SYSCALL)
		return 0;
	if (healer_pair_published == NULL)
		return 0;

	/* Mirror read.  Picker (child context) and dump (parent context)
	 * both call through here; the parent's drain refreshes dirty
	 * rows of healer_pair_published from parent_healer.pair_table on
	 * every iteration, so the worst-case staleness is one drain
	 * cadence (~ms) -- operationally indistinguishable from fresh
	 * given the second-to-hour timescale on which (pred -> succ)
	 * relations evolve. */
	return healer_pair_cell_picker_weight(&healer_pair_published[pred][succ]);
}

unsigned int healer_pair_dynamic_hits(unsigned int pred, unsigned int succ)
{
	if (pred >= MAX_NR_SYSCALL || succ >= MAX_NR_SYSCALL)
		return 0;
	if (healer_pair_published == NULL)
		return 0;

	return healer_pair_published[pred][succ].dynamic_hits;
}

/*
 * STRATEGY_HEALER readiness threshold: number of pair-table cells with
 * dynamic_hits >= HEALER_STRATEGY_PAIR_CELL_MIN_HITS required before the
 * picker has enough runtime signal to score against uniform random.
 * Picked to roughly match the inflection point at which the operator-
 * side dump starts surfacing relations whose normalised score clears
 * the noise floor.
 */
#define HEALER_STRATEGY_PAIR_CELL_THRESHOLD 1000

/*
 * Per-cell dynamic-hits floor for the readiness scan.  A single hit on
 * a pair is observation noise; demanding several confirms the runtime
 * observer has actually seen the (pred, succ) pair lead to a new edge
 * more than once before that cell contributes to the fleet-wide "we
 * have enough signal to schedule the arm" decision.  Small (3) so the
 * gate still trips early in a run -- the dump-side HEALER_DUMP_MIN_RAW
 * threshold is for displaying confident relations; this one is for
 * confirming the picker is worth waking up at all.
 *
 * Critically, this test reads dynamic_hits SPECIFICALLY rather than
 * the combined picker weight (static_prior + dynamic_hits): the
 * previous gate counted any cell with weight > 1, which a freshly-
 * seeded pair at static_prior=HEALER_STATIC_SEED_WEIGHT=3 trivially
 * cleared even though no runtime evidence existed.  That made the gate
 * trip on a cold table whose populated cells were entirely the seed
 * loader's, with no runtime confirmation that the relations actually
 * mattered for the kernel under test.
 */
#define HEALER_STRATEGY_PAIR_CELL_MIN_HITS 3

/*
 * Hard cap on cells inspected per healer_strategy_ready() call.  The
 * pair table is dense (MAX_NR_SYSCALL^2 = ~1M cells); a full scan at
 * every rotation boundary is bounded but not free, so we early-out as
 * soon as we have either crossed the threshold or scanned the whole
 * table.  The pair table is mutated lock-free; relaxed loads via
 * healer_pair_dynamic_hits() race observer bumps benignly because the
 * readiness check itself is a coarse gate, not an exact count.
 */
#define HEALER_STRATEGY_SCAN_CAP \
	((unsigned long)MAX_NR_SYSCALL * (unsigned long)MAX_NR_SYSCALL)

bool healer_strategy_ready_explicit(enum healer_readiness *out)
{
	unsigned long scanned = 0;
	unsigned long dyn_cells = 0;
	bool any_seed = false;
	unsigned int pred, succ;

	for (pred = 0; pred < MAX_NR_SYSCALL; pred++) {
		for (succ = 0; succ < MAX_NR_SYSCALL; succ++) {
			/* Mirror reads through the same view the picker
			 * sees.  Bounded staleness (~ms per drain) is
			 * acceptable for a coarse gate.  Compute both halves
			 * of the cell up front so the seed-only check can
			 * test the static-prior side directly without a
			 * second mirror lookup. */
			unsigned int dyn = healer_pair_dynamic_hits(pred, succ);
			unsigned int total = healer_pair_get(pred, succ);

			scanned++;
			if (dyn >= HEALER_STRATEGY_PAIR_CELL_MIN_HITS) {
				dyn_cells++;
				if (dyn_cells >= HEALER_STRATEGY_PAIR_CELL_THRESHOLD) {
					if (out != NULL)
						*out = HEALER_READY_DYNAMIC;
					return true;
				}
			} else if (total > 0) {
				/* Cell carries a static prior (and/or sub-floor
				 * dynamic hits) but does not contribute to the
				 * strict threshold.  Latching `any_seed` lets us
				 * return seed-only readiness even if the strict
				 * threshold is never reached. */
				any_seed = true;
			}
			if (scanned >= HEALER_STRATEGY_SCAN_CAP)
				goto done;
		}
	}
done:
	if (any_seed) {
		if (out != NULL)
			*out = HEALER_READY_SEED_ONLY;
		return true;
	}
	if (out != NULL)
		*out = HEALER_NOT_READY;
	return false;
}

bool healer_strategy_ready(void)
{
	enum healer_readiness r;

	(void)healer_strategy_ready_explicit(&r);
	return r == HEALER_READY_DYNAMIC;
}

bool healer_strategy_ready_plateau_bypass(void)
{
	enum healer_readiness r;

	(void)healer_strategy_ready_explicit(&r);
	return r != HEALER_NOT_READY;
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
 * Idempotent: healer_pair_seed forwards to healer_aggregate_pair_set
 * which skips a cell already carrying a weight.  This matters on
 * biarch builds where the 32-bit and 64-bit tables can map the same
 * raw syscall number to different syscalls; the second walk's set
 * just no-ops on any cell the first walk already filled and the cell
 * keeps the first walk's weight.
 *
 * Returns the number of fresh seed installs over the course of this
 * call, measured as the delta on parent_healer.pair_seeded across the
 * load.  Cells already populated when the loader runs are silently
 * skipped and do not contribute to the return value.  On a cold-start
 * run with an empty pair table the return value matches one side of
 * the (producer-consumer-edges-on-this-arch) inventory
 * healer_count_pc_pairs() reports, modulo the self-pair skip.
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

	before = parent_healer.pair_seeded;

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

	after = parent_healer.pair_seeded;
	installed = (unsigned int)(after - before);

	stats_log_write("HEALER static seed: %u producer/consumer pairs installed\n",
			installed);
	return installed;
}

/*
 * --- STRATEGY_HEALER picker (Phase B) ---
 *
 * Implements the SOSP'21 HEALER paper's bias-toward-known-productive-
 * relations principle on top of the Phase A observer's pair and triple
 * relation tables.  At each pick:
 *
 *   - Picks the most-recent predecessor out of the per-child sequence
 *     buffer (healer_seq[1] when both slots are populated, healer_seq[0]
 *     when only one is).
 *   - Builds a per-call weighted distribution over the active syscall
 *     table using healer_pair_published[pred][succ] for each candidate
 *     succ (reads the parent-published mirror page, not the canonical
 *     parent_healer.pair_table).  When both predecessor slots are
 *     populated, the matching triple-table slot's promoted (succ,
 *     weight) entries are summed into the same distribution so
 *     candidates that appear in both tables get extra weight without
 *     a separate normalisation step.
 *   - Picks weighted-random via a CDF walk; on a validate / EXPENSIVE
 *     dead-end the chosen index is dropped from the distribution and
 *     the pick is re-rolled until the budget is exhausted or no weight
 *     remains.
 *   - Falls back to set_syscall_nr_random() when the predecessor is
 *     missing (cold-start), is the EDGEPAIR_NO_PREV sentinel, or when
 *     the predecessor row carries no positive weight at all (the
 *     observer has not yet learned anything productive about it).
 *
 * The bandit picker decides WHEN to schedule this arm via UCB1 reward;
 * is_strategy_eligible(STRATEGY_HEALER) gates the arm out entirely
 * until the pair table has accumulated enough signal to score against
 * uniform random.  The picker itself stays zero-malloc on the hot path
 * by building the distribution into a stack array sized to the dense
 * MAX_NR_SYSCALL bound (a per-call ~4 KiB stack frame, comfortably
 * inside the syscall-pick stack budget).
 *
 * Biarch builds: defer to set_syscall_nr_random.  The pair table is a
 * single MAX_NR_SYSCALL x MAX_NR_SYSCALL matrix indexed by raw syscall
 * number, so 32-bit and 64-bit syscalls collide on the same cells when
 * their numbers happen to overlap; the picker has no clean way to
 * disentangle that without a per-arch table split, which is out of
 * scope here.  Falling back keeps the bandit's reward signal honest
 * (the arm reverts to RANDOM-equivalent behaviour) while leaving the
 * uniarch path -- where the observer's signal is unambiguous -- to
 * exercise the full HEALER algorithm.
 */
bool set_syscall_nr_healer(struct syscallrecord *rec, struct childdata *child)
{
	struct syscallentry *entry;
	unsigned int weights[MAX_NR_SYSCALL];
	unsigned long total_weight = 0;
	unsigned int nr_syscalls;
	unsigned int pred;
	unsigned int idx;
	unsigned int outer_attempts = 0;
	unsigned int syscallnr;
	int val;
	bool used_triple = false;

	if (biarch) {
		__atomic_fetch_add(&shm->stats.healer_picker_cold_start, 1UL,
				   __ATOMIC_RELAXED);
		return set_syscall_nr_random(rec, child);
	}

	if (child == NULL || child->active_syscalls == NULL ||
	    child->healer_seq_count == 0) {
		__atomic_fetch_add(&shm->stats.healer_picker_cold_start, 1UL,
				   __ATOMIC_RELAXED);
		return set_syscall_nr_random(rec, child);
	}

	pred = (child->healer_seq_count >= 2) ? child->healer_seq[1]
					      : child->healer_seq[0];
	if (pred == EDGEPAIR_NO_PREV || pred >= MAX_NR_SYSCALL) {
		__atomic_fetch_add(&shm->stats.healer_picker_cold_start, 1UL,
				   __ATOMIC_RELAXED);
		return set_syscall_nr_random(rec, child);
	}

	nr_syscalls = max_nr_syscalls;
	if (nr_syscalls > MAX_NR_SYSCALL)
		nr_syscalls = MAX_NR_SYSCALL;
	memset(weights, 0, sizeof(weights[0]) * nr_syscalls);

	/* Pair-table contribution: one dense row read.  active_syscalls[idx]
	 * encodes (syscall_nr + 1) for active entries and 0 for inactive,
	 * so an idx whose value is 0 contributes nothing to the distribution
	 * and is silently skipped. */
	for (idx = 0; idx < nr_syscalls; idx++) {
		unsigned int nr;
		unsigned int w;

		val = child->active_syscalls[idx];
		if (val == 0)
			continue;
		nr = (unsigned int)val - 1U;
		if (nr >= MAX_NR_SYSCALL)
			continue;
		w = healer_pair_get(pred, nr);
		if (w == 0)
			continue;
		weights[idx] = w;
		total_weight += w;
	}

	/* Triple-table contribution: when the child has both predecessor
	 * slots populated, sum the matching triple slot's promoted-entry
	 * weights into the per-succ distribution so candidates that appear
	 * in BOTH tables ride a higher combined weight without a separate
	 * normalisation step.  Raw sum (rather than a fixed e.g. 70/30 mix)
	 * keeps the picker zero-FP and lets the relative magnitudes of the
	 * two tables speak for themselves -- the pair table dominates by
	 * design (static seed + dense observer) and the triple table acts
	 * as a sparse boost for higher-confidence relations. */
	if (child->healer_seq_count >= 2) {
		unsigned int pa = child->healer_seq[0];
		unsigned int pb = child->healer_seq[1];

		if (pa != EDGEPAIR_NO_PREV && pb != EDGEPAIR_NO_PREV &&
		    pa < MAX_NR_SYSCALL && pb < MAX_NR_SYSCALL) {
			unsigned int predset_hash;
			unsigned int slot_idx;
			unsigned int probe;
			uint64_t target_key;

			if (pa > pb) {
				unsigned int tmp = pa;
				pa = pb;
				pb = tmp;
			}
			predset_hash = healer_predset_hash(pa, pb);
			slot_idx = predset_hash & (HEALER_RELATION_SLOTS - 1);
			target_key = healer_pack_key(pa, pb, predset_hash);

			if (healer_relations_published == NULL)
				goto skip_triple;

			for (probe = 0; probe < HEALER_PROBE_LIMIT; probe++) {
				const struct healer_relation *slot;
				unsigned int slot_idx_real;
				uint64_t slot_key;
				unsigned int j;

				slot_idx_real = (slot_idx + probe) &
						(HEALER_RELATION_SLOTS - 1);
				slot = &healer_relations_published[slot_idx_real];
				/* Read from the mirror page (PROT_READ from
				 * children).  The published view lags the
				 * canonical by at most one drain (~ms); a torn
				 * row from a publish racing this read leaves
				 * the picker with a mix of old and new weights,
				 * which is acceptable for a syscall-prior bias
				 * where relative magnitudes matter rather than
				 * exact values. */
				slot_key = slot->key;
				if (slot_key == 0)
					break;
				if (slot_key != target_key)
					continue;

				/* Slot match -- walk promoted[] and add each
				 * (nr, weight) to the matching active_syscalls
				 * index.  We linear-scan active_syscalls per
				 * promoted entry; promoted is at most 8 wide so
				 * the inner cost is bounded at 8*nr_syscalls,
				 * negligible vs. the pair-table walk above. */
				for (j = 0; j < HEALER_PROMOTED_PER_SLOT; j++) {
					uint64_t entry_packed;
					unsigned int p_nr, p_w;
					unsigned int k;

					entry_packed = slot->promoted[j].entry;
					if (entry_packed == 0)
						continue;
					healer_unpack_promoted(entry_packed,
							       &p_nr, &p_w);
					if (p_w == 0 || p_nr >= MAX_NR_SYSCALL)
						continue;
					for (k = 0; k < nr_syscalls; k++) {
						val = child->active_syscalls[k];
						if (val == 0)
							continue;
						if ((unsigned int)val - 1U == p_nr) {
							weights[k] += p_w;
							total_weight += p_w;
							used_triple = true;
							break;
						}
					}
				}
				break;
			}
skip_triple:
			;
		}
	}

	if (total_weight == 0) {
		__atomic_fetch_add(&shm->stats.healer_picker_zero_weight_fallback,
				   1UL, __ATOMIC_RELAXED);
		return set_syscall_nr_random(rec, child);
	}

retry:
	if (no_syscalls_enabled() == true) {
		output(0, "[%d] No more syscalls enabled. Exiting\n", getpid());
		__atomic_store_n(&shm->exit_reason, EXIT_NO_SYSCALLS_ENABLED,
				 __ATOMIC_RELAXED);
		return FAIL;
	}

	if (outer_attempts++ > 10000) {
		output(0, "[%d] set_syscall_nr_healer exceeded retry budget\n",
		       getpid());
		return FAIL;
	}

	if (total_weight == 0) {
		/* Every candidate retired by validate / EXPENSIVE / table-
		 * deactivation during the retry loop -- there is nothing left
		 * to weight, so collapse to the canonical fallback rather than
		 * spinning. */
		__atomic_fetch_add(&shm->stats.healer_picker_zero_weight_fallback,
				   1UL, __ATOMIC_RELAXED);
		return set_syscall_nr_random(rec, child);
	}

	{
		unsigned long roll = (unsigned long)rand() % total_weight;
		unsigned int picked = nr_syscalls;

		for (idx = 0; idx < nr_syscalls; idx++) {
			if (weights[idx] == 0)
				continue;
			if (roll < weights[idx]) {
				picked = idx;
				break;
			}
			roll -= weights[idx];
		}
		if (picked >= nr_syscalls) {
			/* Defensive: total_weight desynced from weights[].  Drop
			 * to fallback rather than dereferencing an out-of-range
			 * index. */
			__atomic_fetch_add(
				&shm->stats.healer_picker_zero_weight_fallback,
				1UL, __ATOMIC_RELAXED);
			return set_syscall_nr_random(rec, child);
		}
		idx = picked;
	}

	val = child->active_syscalls[idx];
	if (val == 0) {
		/* Race: another child deactivated this slot between distribution
		 * build and pick.  Drop and re-roll. */
		total_weight -= weights[idx];
		weights[idx] = 0;
		goto retry;
	}
	syscallnr = (unsigned int)val - 1U;

	if (validate_specific_syscall_silent(syscalls, syscallnr) == false) {
		deactivate_syscall(syscallnr, false);
		total_weight -= weights[idx];
		weights[idx] = 0;
		goto retry;
	}

	entry = get_syscall_entry(syscallnr, false);
	if (entry->flags & EXPENSIVE) {
		if (!ONE_IN(1000)) {
			/* EXPENSIVE: keep the index in the distribution -- a
			 * future re-roll might still pick it on the 1-in-1000
			 * acceptance path -- but consume a retry to avoid a
			 * tight spin on a pair-table row dominated by
			 * EXPENSIVE entries. */
			goto retry;
		}
	}

	lock(&rec->lock);
	rec->do32bit = false;
	rec->nr = syscallnr;
	unlock(&rec->lock);

	if (used_triple)
		__atomic_fetch_add(&shm->stats.healer_picker_triple_path, 1UL,
				   __ATOMIC_RELAXED);
	else
		__atomic_fetch_add(&shm->stats.healer_picker_pair_path, 1UL,
				   __ATOMIC_RELAXED);

	return true;
}
