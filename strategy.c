/*
 * Multi-strategy syscall-picker rotation: arm-selection policies.
 *
 * Phase 1 shipped a fixed round-robin between STRATEGY_HEURISTIC and
 * STRATEGY_RANDOM, with per-strategy edge attribution recorded in
 * shm->pc_edge_calls_by_strategy[].  This file adds a UCB1 bandit-arm
 * picker that consumes those same per-strategy call counts as the
 * reward signal and biases future window picks toward arms producing
 * new-edge calls the fastest, while still occasionally exploring the
 * others so a temporarily-stuck arm doesn't starve forever.  The
 * parallel pc_edge_count_by_strategy[] series (real bucket counts) is
 * surfaced in dump_strategy_stats() as a diagnostic but does not
 * currently feed the learner.
 *
 * Picker mode is selected once at parse_args() time via --strategy
 * and stashed in shm->picker_mode so every child agrees on the
 * policy.  The CAS-winning child at a rotation boundary calls
 * pick_next_strategy() and bandit_record_pull(), runs the bandit
 * math itself, and writes the outcome back to shm->current_strategy.
 *
 * UCB1 is tractable here because the arm count is tiny (2 today,
 * a handful tomorrow) and the picker only runs once per
 * STRATEGY_WINDOW (~100 sec at 10K iter/sec).  Floating-point sqrt
 * and log inside the picker are noise relative to the work done in
 * the window itself.
 */

#include <limits.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "debug.h"
#include "healer.h"		/* healer_pair_get */
#include "kcov.h"		/* KCOV_CMP_RECORDS_MAX, kcov_shm */
#include "params.h"
#include "shm.h"
#include "stats.h"		/* stats_log_write */
#include "strategy.h"
#include "syscall.h"		/* MAX_NR_SYSCALL */
#include "utils.h"

/*
 * STRATEGY_HEALER eligibility threshold: number of pair-table cells
 * with weight strictly greater than the static-seed value (i.e. cells
 * the runtime observer has actually bumped at least once, or that
 * received multiple seed-installs from overlapping classifier matches)
 * required before the picker has enough signal to score arms against
 * uniform random.  Picked to roughly match the inflection point at
 * which the operator-side dump starts surfacing relations whose
 * normalised score clears the noise floor.
 */
#define HEALER_PICKER_PAIR_CELL_THRESHOLD 1000

/*
 * Hard cap on cells inspected per is_strategy_eligible(STRATEGY_HEALER)
 * call.  The pair table is dense (MAX_NR_SYSCALL^2 = ~1M cells); a full
 * scan at every rotation boundary is bounded but not free, so we
 * early-out as soon as we have either crossed the threshold or scanned
 * enough cells to know we are not going to.  The pair table is mutated
 * lock-free; relaxed loads here race observer bumps benignly because the
 * eligibility check itself is a coarse gate, not an exact count.
 */
#define HEALER_PICKER_ELIGIBILITY_SCAN_CAP \
	((unsigned long)MAX_NR_SYSCALL * (unsigned long)MAX_NR_SYSCALL)

/* Same KCOV_CMP_CONST bit cmp_hints.c uses; from uapi/linux/kcov.h. */
#define KCOV_CMP_CONST  (1U << 0)
#define WORDS_PER_CMP   4

/*
 * Set by parse_args() before init_shm() runs, then propagated into
 * shm->picker_mode where every child reads it on the rotation path.
 * Not declared in a header — only params.c writes it and only
 * init_shm() reads it.
 */
enum picker_mode_t picker_mode_arg = PICKER_ROUND_ROBIN;

/*
 * UCB1 exploration constant.  Standard derivation gives c = sqrt(2);
 * we leave it tunable because reward magnitudes (edges-per-window)
 * are not in [0,1] and the right exploration weight depends on the
 * normalisation choice.  Rewards are normalised by the largest
 * mean-reward observed across arms (see ucb1_score), so a c near 1
 * keeps the exploration term comparable to the exploit term.
 */
#define UCB1_EXPLORATION_C 1.41421356  /* sqrt(2) */

/*
 * Translate the --strategy=NAME argument into a picker_mode_t.
 * Recognises the human-friendly aliases ("round-robin", "rr",
 * "bandit", "ucb1", "bandit-ucb1").  Returns false on unknown
 * input so the caller can emit a tidy error before exiting.
 */
bool parse_picker_mode(const char *name, enum picker_mode_t *out)
{
	if (name == NULL || out == NULL)
		return false;

	if (strcmp(name, "round-robin") == 0 ||
	    strcmp(name, "rr") == 0) {
		*out = PICKER_ROUND_ROBIN;
		return true;
	}
	if (strcmp(name, "bandit") == 0 ||
	    strcmp(name, "ucb1") == 0 ||
	    strcmp(name, "bandit-ucb1") == 0) {
		*out = PICKER_BANDIT_UCB1;
		return true;
	}
	return false;
}

const char *picker_mode_name(enum picker_mode_t mode)
{
	switch (mode) {
	case PICKER_ROUND_ROBIN:	return "round-robin";
	case PICKER_BANDIT_UCB1:	return "bandit-ucb1";
	}
	return "unknown";
}

const char *strategy_name(int arm)
{
	switch (arm) {
	case STRATEGY_HEURISTIC:		return "HEURISTIC";
	case STRATEGY_RANDOM:			return "RANDOM";
	case STRATEGY_COVERAGE_FRONTIER:	return "COVERAGE_FRONTIER";
	case STRATEGY_HEALER:			return "HEALER";
	default:				return "?";
	}
}

/*
 * STRATEGY_HEALER readiness gate.  Scans the pair-relation table for
 * cells with weight > 1 (i.e. observer-bumped or multiply-seeded; a
 * single seed install at HEALER_STATIC_SEED_WEIGHT == 3 counts because
 * the test is strict-greater-than-one) and short-circuits as soon as
 * HEALER_PICKER_PAIR_CELL_THRESHOLD have been seen.  When the kcov
 * plateau detector reports the fleet is stalled, the threshold is
 * bypassed -- a stalled bandit benefits from any signal that nudges it
 * off the current local minimum, even one whose own data is thin.
 */
static bool healer_picker_eligible(void)
{
	unsigned long scanned = 0;
	unsigned long hits = 0;
	unsigned int pred, succ;

	if (kcov_shm != NULL && kcov_shm->plateau_active)
		return true;

	for (pred = 0; pred < MAX_NR_SYSCALL; pred++) {
		for (succ = 0; succ < MAX_NR_SYSCALL; succ++) {
			/* Reads through the picker's mirror page so the
			 * eligibility scan sees the same published view
			 * the picker itself would; bounded staleness
			 * (~ms per drain) is acceptable for a coarse
			 * gating decision. */
			unsigned int w = healer_pair_get(pred, succ);

			scanned++;
			if (w > 1) {
				hits++;
				if (hits >= HEALER_PICKER_PAIR_CELL_THRESHOLD)
					return true;
			}
			if (scanned >= HEALER_PICKER_ELIGIBILITY_SCAN_CAP)
				return false;
		}
	}
	return false;
}

bool is_strategy_eligible(int arm)
{
	if (arm < 0 || arm >= NR_STRATEGIES)
		return false;

	if (arm == STRATEGY_HEALER) {
		if (no_healer)
			return false;
		return healer_picker_eligible();
	}

	return true;
}

/*
 * Record the just-finished window: bump pull count for the arm that
 * was active, add its edge yield plus the CMP-novelty term to the
 * cumulative reward, and update the diagnostic CMP-share running sum.
 * Called by the CAS-winning child during maybe_rotate_strategy(),
 * which serialises with the picker — so picker-side reads of
 * bandit_pulls[] / bandit_reward_calls[] / bandit_reward_pc_edge_count[]
 * / bandit_cmp_share_sum_x1000[] inside pick_next_strategy() are
 * covered by the strategy-switch store's release semantics on the
 * next CAS winner.
 *
 * dump_strategy_stats() is parent-side and runs outside the CAS
 * protocol, so it can race a child that is mid-update here.  To keep
 * its per-arm reads from tearing against these writes, the writes use
 * __atomic_fetch_add(..., RELAXED) and dump_strategy_stats() pairs
 * them with __atomic_load_n(..., RELAXED).  Relaxed is sufficient: the
 * dump is a diagnostic snapshot with no ordering requirement against
 * other shm fields.  The stats counter bump uses an atomic add for the
 * same reason.
 *
 * pc_edge_calls is the per-window pc_edge_calls_by_strategy delta
 * (calls with >=1 new edge).  pc_edge_count is the parallel
 * pc_edge_count_by_strategy delta (real bucket-edge bits flipped).
 * cmp_new_constants is the per-window bandit_cmp_new_constants delta.
 * The learner-facing combined reward is pc_edge_calls +
 * cmp_new_constants / CMP_BANDIT_REWARD_WEIGHT_RECIPROCAL (integer
 * division — sub-weight residues round to zero, deliberately so a
 * window with a handful of novel constants doesn't perturb the
 * headline PC signal).  The pc_edge_count delta accumulates into the
 * parallel diagnostic reward (no cmp term folded in) so the operator
 * can compare what the real-count reward would have looked like.
 */
void bandit_record_pull(int arm,
			unsigned long pc_edge_calls,
			unsigned long pc_edge_count,
			unsigned long cmp_new_constants)
{
	unsigned long cmp_term;
	unsigned long total;

	if (arm < 0 || arm >= NR_STRATEGIES)
		return;

	cmp_term = cmp_new_constants / CMP_BANDIT_REWARD_WEIGHT_RECIPROCAL;
	total = pc_edge_calls + cmp_term;

	__atomic_fetch_add(&shm->bandit_pulls[arm], 1UL, __ATOMIC_RELAXED);
	__atomic_fetch_add(&shm->bandit_reward_calls[arm], total,
			   __ATOMIC_RELAXED);
	__atomic_fetch_add(&shm->bandit_reward_pc_edge_count[arm],
			   pc_edge_count, __ATOMIC_RELAXED);

	if (cmp_term == 0)
		return;

	__atomic_fetch_add(&shm->stats.bandit_cmp_reward_added, 1UL,
			   __ATOMIC_RELAXED);

	/* Per-arm running sum of cmp_term's share of the combined reward,
	 * scaled to parts per thousand.  total is non-zero here because
	 * cmp_term > 0.  Averaged at end-of-run to surface the empirical
	 * CMP weighting per arm so the 0.25 constant can be tuned. */
	__atomic_fetch_add(&shm->bandit_cmp_share_sum_x1000[arm],
			   (cmp_term * 1000UL) / total,
			   __ATOMIC_RELAXED);
}

/*
 * Per-syscall comparison-constant novelty bloom.
 *
 * Two complementary 64-bit hashes derive ten-bit indices into a
 * 1024-bit (128-byte) bloom filter per syscall.  The multipliers are
 * splitmix64-style high-entropy odd constants; XOR-folding the upper
 * half into the index defeats the multiplier's tendency to leave low
 * bits weakly mixed when val itself has small magnitude (true for
 * many comparison constants the kernel checks against -- length
 * limits, error codes, magic numbers in the first few KiB of address
 * space).  Two hashes is the textbook efficient point for k below
 * ~3% FPR at the loads expected here (a few hundred distinct
 * constants per syscall over the K-window decay).
 */
static inline uint32_t cmp_bloom_h1(unsigned long val)
{
	uint64_t x = (uint64_t)val * 0x9e3779b97f4a7c15ULL;
	x ^= x >> 32;
	return (uint32_t)(x & 0x3FF);
}

static inline uint32_t cmp_bloom_h2(unsigned long val)
{
	uint64_t x = (uint64_t)val * 0xbf58476d1ce4e5b9ULL;
	x ^= x >> 32;
	x ^= x >> 16;
	return (uint32_t)(x & 0x3FF);
}

/*
 * Same "boring constant" filter cmp_hints.c uses (interesting_value).
 * Kept private here so the two filters can drift independently if it
 * turns out the novelty signal benefits from a different threshold
 * than the hint-substitution pool.
 */
static bool cmp_novelty_interesting(unsigned long val)
{
	if (val == 0 || val == 1)
		return false;
	if (val == (unsigned long) -1)
		return false;
	if (val < 4)
		return false;
	return true;
}

/*
 * Lazy bloom decay.  If the entry's window_tag is more than
 * CMP_NOVELTY_DECAY_WINDOWS rotations behind the current rotation
 * counter, zero the bloom and republish the tag.  CAS protects against
 * multiple children racing to clear the same entry — the loser sees
 * the new tag on the second load and skips the clear.  Children that
 * race the clear and observe a half-zeroed bloom may miss-credit a
 * constant as novel; that is benign for a noisy diagnostic counter
 * and self-correcting on the next observation.
 */
static void cmp_bloom_maybe_decay(struct cmp_novelty_entry *e,
				  uint32_t now)
{
	uint32_t tag = __atomic_load_n(&e->window_tag, __ATOMIC_RELAXED);

	if (now - tag <= CMP_NOVELTY_DECAY_WINDOWS)
		return;

	if (!__atomic_compare_exchange_n(&e->window_tag, &tag, now,
					 false,
					 __ATOMIC_RELAXED, __ATOMIC_RELAXED))
		return;

	memset((void *)e->bloom, 0, sizeof(e->bloom));
}

/*
 * Test-and-set one bloom bit.  Returns true if the bit was previously
 * clear (the constant is novel along this hash).  Bits are atomic at
 * byte granularity; the caller treats "either hash bit was clear" as
 * "constant is novel".
 */
static bool cmp_bloom_set(uint8_t *bloom, uint32_t bit)
{
	uint8_t mask = (uint8_t)(1U << (bit & 7));
	uint8_t prev = __atomic_fetch_or(&bloom[bit >> 3], mask,
					 __ATOMIC_RELAXED);

	return (prev & mask) == 0;
}

void bandit_cmp_observe(unsigned long *trace_buf, unsigned int nr,
			bool is_explorer, int strategy_at_pick)
{
	struct cmp_novelty_entry *e;
	unsigned long count, i;
	unsigned long novel = 0;
	uint32_t now;

	if (trace_buf == NULL || nr >= MAX_NR_SYSCALL)
		return;

	count = __atomic_load_n(&trace_buf[0], __ATOMIC_RELAXED);
	if (count == 0)
		return;
	if (count > KCOV_CMP_RECORDS_MAX)
		count = KCOV_CMP_RECORDS_MAX;

	e = &shm->cmp_novelty[nr];
	now = (uint32_t)__atomic_load_n(&shm->bandit_window_count,
					__ATOMIC_RELAXED);
	cmp_bloom_maybe_decay(e, now);

	for (i = 0; i < count; i++) {
		unsigned long type = trace_buf[1 + i * WORDS_PER_CMP];
		unsigned long arg1 = trace_buf[1 + i * WORDS_PER_CMP + 1];
		unsigned long arg2 = trace_buf[1 + i * WORDS_PER_CMP + 2];
		unsigned long c;
		bool novel_here;

		if (!(type & KCOV_CMP_CONST))
			continue;

		c = cmp_novelty_interesting(arg1) ? arg1 :
		    cmp_novelty_interesting(arg2) ? arg2 : 0;
		if (c == 0)
			continue;

		novel_here = cmp_bloom_set(e->bloom, cmp_bloom_h1(c));
		novel_here = cmp_bloom_set(e->bloom, cmp_bloom_h2(c)) ||
			     novel_here;
		if (novel_here)
			novel++;
	}

	if (novel == 0)
		return;

	/* Explorer-pool children run a different strategy than whatever the
	 * bandit picked for the bandit pool; crediting their CMP novelty
	 * into bandit_cmp_new_constants[] would misattribute their work and
	 * bias the bandit's reward calculation.  The bloom updates above
	 * still run so the global novelty horizon stays consistent across
	 * the fleet. */
	if (is_explorer)
		return;

	/* Attribute to the arm that PICKED the syscall, snapshotted in
	 * set_syscall_nr().  Re-reading shm->current_strategy here would
	 * misattribute any call whose syscall started under one arm and
	 * completed under another (rotation lands mid-syscall) -- frequent
	 * for long or blocking syscalls.  -1 sentinel and any other
	 * out-of-range value (e.g. a wild shm write landing on the field)
	 * skip attribution naturally via the bounds check. */
	if (strategy_at_pick < 0 || strategy_at_pick >= NR_STRATEGIES)
		return;

	__atomic_fetch_add(&shm->bandit_cmp_new_constants[strategy_at_pick],
			   novel, __ATOMIC_RELAXED);
}

/*
 * Per-syscall frontier-edge ring accessors.
 *
 * The ring is a fixed-width window of FRONTIER_DECAY_WINDOWS slots per
 * syscall; the slot currently being filled is (frontier_slot &
 * (FRONTIER_DECAY_WINDOWS - 1)).  Producers (kcov_collect on the
 * new-edge branch) atomic-add into the current slot.  The rotation hook
 * advances the slot index and zeroes the slot it just moved into, so
 * sums across the ring give the trailing K-window frontier count for
 * each syscall -- effectively a sliding window with discrete decay.
 *
 * FRONTIER_DECAY_WINDOWS is currently 8 (see strategy.h); the AND-mask
 * approach assumes it stays a power of two -- enforced by the
 * static_assert below so a future change to a non-pot value fails at
 * compile time rather than silently producing wrong slot indices.
 */
_Static_assert((FRONTIER_DECAY_WINDOWS &
		(FRONTIER_DECAY_WINDOWS - 1)) == 0,
	       "FRONTIER_DECAY_WINDOWS must be a power of two");

void frontier_record_new_edge(unsigned int nr)
{
	uint32_t slot;
	unsigned long w;
	unsigned int cached;

	if (nr >= MAX_NR_SYSCALL)
		return;

	slot = __atomic_load_n(&shm->frontier_slot, __ATOMIC_RELAXED) &
	       (FRONTIER_DECAY_WINDOWS - 1);
	__atomic_fetch_add(&shm->frontier_history[nr][slot], 1U,
			   __ATOMIC_RELAXED);
	__atomic_fetch_add(&shm->frontier_recent_count_cached[nr], 1U,
			   __ATOMIC_RELAXED);

	/* Ratchet the cached max upward if this bump pushed nr's recent
	 * count past it.  No CAS: a racing producer that also raises the
	 * max can clobber our store with its (also-correct) value, and a
	 * racing rotation will overwrite with the authoritative recompute.
	 * Both outcomes leave the cache within one window's slack. */
	w = frontier_recent_count(nr);
	if (w > UINT_MAX)
		w = UINT_MAX;
	cached = __atomic_load_n(&shm->frontier_max_weight_cached,
				 __ATOMIC_RELAXED);
	if ((unsigned int)w > cached)
		__atomic_store_n(&shm->frontier_max_weight_cached,
				 (unsigned int)w, __ATOMIC_RELAXED);
}

unsigned long frontier_recent_count(unsigned int nr)
{
	if (nr >= MAX_NR_SYSCALL)
		return 0;

	return __atomic_load_n(&shm->frontier_recent_count_cached[nr],
			       __ATOMIC_RELAXED);
}

void frontier_window_advance(void)
{
	uint32_t next;
	unsigned int nr;
	unsigned long max_weight = 0;

	/* Bump the slot index FIRST so producers racing the rotation start
	 * targeting the new slot before we clear it.  We then zero the new
	 * slot to drop the K-windows-old contents.  A producer that bumps
	 * the slot between the store and the clear loses its add (rare,
	 * benign for a noisy weight signal); a producer bumping after the
	 * clear lands on the freshly zeroed slot as intended. */
	next = __atomic_add_fetch(&shm->frontier_slot, 1U, __ATOMIC_RELAXED);
	next &= (FRONTIER_DECAY_WINDOWS - 1);

	/* Single fused pass: drop the K-windows-old slot and recompute the
	 * authoritative cached max over the just-rotated ring at the same
	 * time.  Per-syscall the work is one exchange (zero the slot, hand
	 * back its contribution), one fetch_sub (remove that contribution
	 * from the per-nr running sum), and a max compare -- two atomics
	 * total instead of one store plus an FRONTIER_DECAY_WINDOWS-deep
	 * ring walk per syscall.  Reads here are RELAXED; a producer's add
	 * that interleaves with the exchange/sub on the same nr can leave
	 * the cached running sum one bump above the live ring sum, bounded
	 * by one window and folded back in by the next rotation. */
	for (nr = 0; nr < MAX_NR_SYSCALL; nr++) {
		uint32_t old_slot;
		uint32_t old_cached;
		uint32_t new_sum;

		old_slot = __atomic_exchange_n(&shm->frontier_history[nr][next],
					       0U, __ATOMIC_RELAXED);
		old_cached = __atomic_fetch_sub(
			&shm->frontier_recent_count_cached[nr],
			old_slot, __ATOMIC_RELAXED);
		new_sum = old_cached - old_slot;
		if (new_sum > max_weight)
			max_weight = new_sum;
	}
	if (max_weight > UINT_MAX)
		max_weight = UINT_MAX;
	__atomic_store_n(&shm->frontier_max_weight_cached,
			 (unsigned int)max_weight, __ATOMIC_RELAXED);
}

/*
 * Compute the UCB1 score for one arm.  Standard formulation:
 *
 *     score_i = mean_reward_i / norm + c * sqrt(ln(N) / n_i)
 *
 * where:
 *   mean_reward_i = bandit_reward_calls[i] / bandit_pulls[i]
 *   norm          = max over arms of mean_reward_j (or 1 if all zero)
 *   N             = sum of pulls across arms (== total_pulls)
 *   n_i           = bandit_pulls[i]
 *   c             = UCB1_EXPLORATION_C
 *
 * Normalising the exploit term by the largest observed mean keeps it
 * in roughly the same range as the exploration term (~1) regardless
 * of whether per-window rewards are in the hundreds or hundreds of
 * thousands.  Without normalisation, a UCB1 picker over edges-per-
 * window degenerates into "always pick the arm with the highest
 * cumulative average" because the exploit term dwarfs sqrt(ln/n).
 *
 * The reward signal consumed here is the CALL-COUNT series
 * (bandit_reward_calls[] -- calls-with-≥1-edge plus the weighted CMP
 * novelty term).  The parallel real bucket-count series
 * (bandit_reward_pc_edge_count[]) is recorded for the operator dump
 * but does not feed the score; switching the learner to consume it
 * (or a transform of it) is a separate decision once both signals
 * have been observed against real run data.
 */
static double ucb1_score(int arm, unsigned long total_pulls,
			 double norm)
{
	unsigned long pulls = shm->bandit_pulls[arm];
	unsigned long reward = shm->bandit_reward_calls[arm];
	double exploit, explore;

	exploit = (double)reward / (double)pulls / norm;
	explore = UCB1_EXPLORATION_C *
		  sqrt(log((double)total_pulls) / (double)pulls);

	return exploit + explore;
}

/*
 * Pick the arm to run during the next window using the configured
 * arm-selection POLICY only.  Returns an index in [0, NR_STRATEGIES)
 * and writes the reason path through *reason_out.  The caller
 * (maybe_rotate_strategy via select_next_strategy) has already
 * updated bandit_pulls[]/bandit_reward_calls[] (plus the parallel
 * bandit_reward_pc_edge_count[] diagnostic series) for the
 * just-finished window unless that window was a forced intervention.
 *
 * Cold-start: any arm with zero pulls wins immediately (UCB1's
 * convention — every arm gets one pull before the score formula
 * makes sense).  Ties broken in favour of the lower index, which
 * keeps the warm-up deterministic.
 *
 * Round-robin mode bypasses the bandit entirely and just steps to
 * the next arm — same behaviour as Phase 1.
 *
 * Plateau-driven interventions used to live inside this function as
 * an early-return override; they now sit one level up in
 * select_next_strategy() so forced-intervention windows can be kept
 * out of the UCB learner's pull/reward history.  This picker is pure
 * policy — no intervention awareness.
 */
int pick_next_strategy(int prev, enum strategy_selection_reason *reason_out)
{
	enum picker_mode_t mode;
	bool eligible[NR_STRATEGIES];
	unsigned long total_pulls = 0;
	double max_mean = 0.0;
	double best_score;
	int best_arm = -1;
	int i;

	mode = __atomic_load_n(&shm->picker_mode, __ATOMIC_RELAXED);

	/* Cache per-arm eligibility once: the check can scan O(MAX_NR_SYSCALL^2)
	 * cells for STRATEGY_HEALER and we consult it twice (cold-start scan
	 * and UCB1 score loop).  Round-robin still needs the cache so it can
	 * skip past an ineligible arm without falling off NR_STRATEGIES. */
	for (i = 0; i < NR_STRATEGIES; i++)
		eligible[i] = is_strategy_eligible(i);

	if (mode == PICKER_ROUND_ROBIN) {
		int next = prev;
		*reason_out = SR_ROUND_ROBIN;
		for (i = 0; i < NR_STRATEGIES; i++) {
			next = (next + 1) % NR_STRATEGIES;
			if (eligible[next])
				return next;
		}
		/* Every arm ineligible — should not happen because at least
		 * STRATEGY_HEURISTIC and STRATEGY_RANDOM have no preconditions.
		 * Fall back to the historical Phase 1 behaviour rather than
		 * returning -1 to a caller that expects a valid index. */
		return (prev + 1) % NR_STRATEGIES;
	}

	/* Cold-start: prefer any unpulled eligible arm before scoring. */
	for (i = 0; i < NR_STRATEGIES; i++) {
		if (!eligible[i])
			continue;
		if (shm->bandit_pulls[i] == 0) {
			*reason_out = SR_COLD_START;
			return i;
		}
		total_pulls += shm->bandit_pulls[i];
	}

	/* Normalise by the largest mean-reward across eligible arms so the
	 * exploit term lives in the same numeric range as the exploration
	 * term.  Falls back to 1.0 when every arm has yielded zero edges
	 * so far (well-defined and harmless). */
	for (i = 0; i < NR_STRATEGIES; i++) {
		double mean;

		if (!eligible[i])
			continue;
		mean = (double)shm->bandit_reward_calls[i] /
		       (double)shm->bandit_pulls[i];
		if (mean > max_mean)
			max_mean = mean;
	}
	if (max_mean <= 0.0)
		max_mean = 1.0;

	best_score = -1.0;
	for (i = 0; i < NR_STRATEGIES; i++) {
		double s;

		if (!eligible[i])
			continue;
		s = ucb1_score(i, total_pulls, max_mean);
		if (best_arm < 0 || s > best_score) {
			best_score = s;
			best_arm = i;
		}
	}
	if (best_arm < 0)
		best_arm = STRATEGY_HEURISTIC;
	*reason_out = SR_NORMAL_UCB;
	return best_arm;
}

/*
 * Intervention layer above pick_next_strategy().  Today's only
 * intervention is plateau-driven: when kcov reports the fleet's
 * edge-discovery rate is stalled, force STRATEGY_RANDOM with reason
 * SR_PLATEAU_FORCE without consulting the UCB scorer, so the bandit
 * is shaken out of whatever local minimum it has settled into.  The
 * rotation site checks the stamped reason at window close and skips
 * the bandit_record_pull() call for SR_PLATEAU_FORCE windows so the
 * learner's reward history stays clean of intervention noise.
 *
 * Round-robin mode bypasses the intervention -- its own cycling
 * already includes RANDOM, and forcing it here would collapse the
 * cycle to one arm.
 *
 * Future dispatches will replace the "force STRATEGY_RANDOM" policy
 * with smarter interventions (e.g. a classifier that picks the arm
 * most likely to break the stall) inside this function; the
 * separation between intervention and learner keeps that work from
 * disturbing the UCB scoring path.
 */
int select_next_strategy(int prev,
			 enum strategy_selection_reason *reason_out)
{
	enum picker_mode_t mode;

	mode = __atomic_load_n(&shm->picker_mode, __ATOMIC_RELAXED);

	if (mode == PICKER_BANDIT_UCB1 &&
	    kcov_shm != NULL && kcov_shm->plateau_active) {
		__atomic_fetch_add(&shm->stats.plateau_forced_windows, 1UL,
				   __ATOMIC_RELAXED);
		*reason_out = SR_PLATEAU_FORCE;
		return STRATEGY_RANDOM;
	}

	return pick_next_strategy(prev, reason_out);
}

const char *strategy_selection_reason_name(enum strategy_selection_reason r)
{
	switch (r) {
	case SR_NORMAL_UCB:	return "NORMAL_UCB";
	case SR_ROUND_ROBIN:	return "ROUND_ROBIN";
	case SR_COLD_START:	return "COLD_START";
	case SR_PLATEAU_FORCE:	return "PLATEAU_FORCE";
	}
	return "?";
}

void strategy_plateau_response(void)
{
	/* Force the strategy picker to rotate on the next syscall dispatch
	 * so the intervention layer in select_next_strategy (returns
	 * STRATEGY_RANDOM with SR_PLATEAU_FORCE while plateau_active is set)
	 * takes effect within seconds rather than waiting up to
	 * STRATEGY_WINDOW (~1M ops, ~9 minutes at 2K iter/sec) for the
	 * natural rotation cadence.  Setting syscalls_at_last_switch to 0
	 * makes maybe_rotate_strategy trip on the next call from any child;
	 * the CAS guard there ensures only one child does the rotation work
	 * even though every child sees the trigger.  After this fires once,
	 * the field advances to op_count and the next forced rotation waits
	 * for the usual window — which is fine, because the intervention
	 * stays latched on plateau_active for as long as the plateau
	 * persists. */
	__atomic_store_n(&shm->syscalls_at_last_switch, 0UL, __ATOMIC_RELAXED);
	stats_log_write("PLATEAU RESPONSE: forcing STRATEGY_RANDOM until plateau clears\n");
}

/*
 * Operator-facing summary, called from dump_stats() at end of run.
 * Always shows the picker mode (cheap context); per-arm pulls and
 * mean reward are skipped for the round-robin path because Phase 1
 * already prints the per-window switch line on every rotation and
 * the totals are uninteresting under a fixed rotation.
 */
void dump_strategy_stats(void)
{
	enum picker_mode_t mode;
	unsigned long total_pulls = 0;
	unsigned long explorer_edges, bandit_edges;
	unsigned long plateau_forced;
	int i;

	mode = __atomic_load_n(&shm->picker_mode, __ATOMIC_RELAXED);

	output(0, "strategy picker: %s\n", picker_mode_name(mode));

	/* Forced-intervention cohort.  These windows ran STRATEGY_RANDOM
	 * over the picker's head because the kcov plateau detector
	 * reported the fleet was stalled; their pulls/reward are
	 * deliberately NOT folded into the per-arm bandit_pulls[] /
	 * bandit_reward_calls[] series so a forced-RANDOM intervention
	 * does not get conflated with a policy-chosen RANDOM in the
	 * learner's history. */
	plateau_forced = __atomic_load_n(&shm->stats.plateau_forced_windows,
					 __ATOMIC_RELAXED);
	if (plateau_forced > 0)
		output(0, "  plateau-forced windows: %lu (STRATEGY_RANDOM via SR_PLATEAU_FORCE, excluded from UCB learner)\n",
		       plateau_forced);

	/* Hybrid bandit/explorer split summary.  Suppressed when the run had
	 * no explorers reserved (explorer_children == 0) -- the bandit-pool
	 * counter still ran but there is nothing to compare it against.
	 *
	 * Beyond the raw per-pool edge counts, this block derives:
	 *   - per-child rate for each pool (edges / pool size), so the
	 *     larger pool isn't credited just for having more workers
	 *   - explorer share of total edges (vs fleet share)
	 *   - one-line verdict (over-performing / at parity / under-)
	 *     against the 2x-fleet-share threshold from the design doc.
	 *     Hitting >=2x sustained across multiple runs is the trigger
	 *     for considering per-child bandit (Option C). */
	if (explorer_children > 0) {
		unsigned int bandit_children;
		unsigned long total_edges;
		unsigned long per_explorer, per_bandit;
		unsigned long share_pct_x10;
		unsigned long ratio_x100;
		const char *verdict;

		explorer_edges = __atomic_load_n(
			&shm->stats.explorer_pool_edges_discovered,
			__ATOMIC_RELAXED);
		bandit_edges = __atomic_load_n(
			&shm->stats.bandit_pool_edges_discovered,
			__ATOMIC_RELAXED);
		bandit_children = max_children > explorer_children ?
			max_children - explorer_children : 0;
		total_edges = explorer_edges + bandit_edges;

		output(0, "  explorer pool: %u children, %lu edges\n",
		       explorer_children, explorer_edges);
		output(0, "  bandit pool:   %u children, %lu edges\n",
		       bandit_children, bandit_edges);

		/* Per-child rate: rounded down to nearest whole edge.  A run
		 * too short for meaningful per-child rates renders as zero
		 * and that's an informative diagnostic. */
		per_explorer = explorer_edges / explorer_children;
		per_bandit = bandit_children > 0 ?
			bandit_edges / bandit_children : 0;
		output(0, "  per-explorer-child: %lu edges, per-bandit-child: %lu edges\n",
		       per_explorer, per_bandit);

		/* Edge-share comparison and verdict.  Suppressed on a
		 * zero-edge run -- nothing meaningful to compare. */
		if (total_edges > 0 && bandit_children > 0) {
			share_pct_x10 = (explorer_edges * 1000UL) / total_edges;
			output(0, "  explorer share: %lu.%lu%% of edges (fleet share %u/%u children)\n",
			       share_pct_x10 / 10, share_pct_x10 % 10,
			       explorer_children, max_children);

			/* ratio = (explorer_edges / total_edges) /
			 *        (explorer_children / max_children)
			 * computed as a single integer division to avoid
			 * losing precision when the fleet share is tiny
			 * (e.g. --explorer-children=1 with -C16384). */
			ratio_x100 = (explorer_edges *
				      (unsigned long)max_children * 100UL) /
				     (total_edges *
				      (unsigned long)explorer_children);
			if (ratio_x100 >= 200)
				verdict = "explorer pool over-performing (>=2x fleet share -- per-child bandit trigger met)";
			else if (ratio_x100 <= 50)
				verdict = "explorer pool under-performing";
			else
				verdict = "explorer pool at parity";
			output(0, "  verdict: %s (ratio %lu.%02lux)\n",
			       verdict,
			       ratio_x100 / 100, ratio_x100 % 100);
		}
	}

	for (i = 0; i < NR_STRATEGIES; i++)
		total_pulls += __atomic_load_n(&shm->bandit_pulls[i],
					       __ATOMIC_RELAXED);

	if (total_pulls == 0)
		return;

	for (i = 0; i < NR_STRATEGIES; i++) {
		unsigned long pulls = __atomic_load_n(&shm->bandit_pulls[i],
						      __ATOMIC_RELAXED);
		unsigned long reward = __atomic_load_n(
			&shm->bandit_reward_calls[i], __ATOMIC_RELAXED);
		unsigned long reward_pc_edges = __atomic_load_n(
			&shm->bandit_reward_pc_edge_count[i], __ATOMIC_RELAXED);
		unsigned long cmp_new = __atomic_load_n(
			&shm->bandit_cmp_new_constants[i], __ATOMIC_RELAXED);
		unsigned long share_sum = __atomic_load_n(
			&shm->bandit_cmp_share_sum_x1000[i], __ATOMIC_RELAXED);
		unsigned long mean_calls_x1000 = pulls ? (reward * 1000UL / pulls) : 0;
		/* Parallel mean for the real bucket-edge series, so the operator
		 * can eyeball how the two reward shapes would score each arm.
		 * Strictly >= the call-count mean (a call that produces N edges
		 * adds N to this series but only 1 to the call-count series). */
		unsigned long mean_pc_edges_x1000 =
			pulls ? (reward_pc_edges * 1000UL / pulls) : 0;
		/* Average per-window CMP share, parts per thousand.  Divides
		 * by total pulls (not just CMP-contributing pulls) so a low
		 * value can mean either "CMP rarely fires" or "CMP fires but
		 * is small relative to PC reward" — both are interesting for
		 * tuning the 0.25 weight constant. */
		unsigned long share_avg_x1000 = pulls ? (share_sum / pulls) : 0;

		output(0, "  arm[%d]: pulls=%lu reward_calls=%lu mean_calls=%lu.%03lu/window reward_edge_count=%lu mean_edge_count=%lu.%03lu/window cmp_novel=%lu cmp_share=%lu.%lu%%\n",
		       i, pulls, reward,
		       mean_calls_x1000 / 1000UL, mean_calls_x1000 % 1000UL,
		       reward_pc_edges,
		       mean_pc_edges_x1000 / 1000UL,
		       mean_pc_edges_x1000 % 1000UL,
		       cmp_new,
		       share_avg_x1000 / 10UL, share_avg_x1000 % 10UL);
	}
}
