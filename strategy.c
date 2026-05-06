/*
 * Multi-strategy syscall-picker rotation: arm-selection policies.
 *
 * Phase 1 shipped a fixed round-robin between STRATEGY_HEURISTIC and
 * STRATEGY_RANDOM, with per-strategy edge attribution recorded in
 * shm->edges_by_strategy[].  This file adds a UCB1 bandit-arm picker
 * that consumes those same per-strategy edge counts as the reward
 * signal and biases future window picks toward arms producing edges
 * the fastest, while still occasionally exploring the others so a
 * temporarily-stuck arm doesn't starve forever.
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

#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "debug.h"
#include "kcov.h"		/* KCOV_CMP_RECORDS_MAX */
#include "params.h"
#include "shm.h"
#include "stats.h"
#include "strategy.h"
#include "syscall.h"		/* MAX_NR_SYSCALL */
#include "utils.h"

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

/*
 * Record the just-finished window: bump pull count for the arm that
 * was active, add its edge yield plus the CMP-novelty term to the
 * cumulative reward, and update the diagnostic CMP-share running sum.
 * Called by the CAS-winning child during maybe_rotate_strategy(),
 * which serialises with the picker, so plain (non-atomic) writes
 * to bandit_pulls[] / bandit_reward[] / bandit_cmp_share_sum_x1000[]
 * are safe — readers only run inside the next pick_next_strategy()
 * call on the next CAS winner, and the strategy-switch store has
 * release semantics.  The stats counter bump uses an atomic add
 * because dump_stats() is parent-side and may read concurrently.
 *
 * pc_edges is the per-window edges-by-strategy delta; cmp_new_constants
 * is the per-window bandit_cmp_new_constants delta.  Combined reward
 * is pc_edges + cmp_new_constants /
 * CMP_BANDIT_REWARD_WEIGHT_RECIPROCAL (integer division — sub-weight
 * residues round to zero, deliberately so a window with a handful
 * of novel constants doesn't perturb the headline PC signal).
 */
void bandit_record_pull(int arm, unsigned long pc_edges,
			unsigned long cmp_new_constants)
{
	unsigned long cmp_term;
	unsigned long total;

	if (arm < 0 || arm >= NR_STRATEGIES)
		return;

	cmp_term = cmp_new_constants / CMP_BANDIT_REWARD_WEIGHT_RECIPROCAL;
	total = pc_edges + cmp_term;

	shm->bandit_pulls[arm]++;
	shm->bandit_reward[arm] += total;

	if (cmp_term == 0)
		return;

	__atomic_fetch_add(&shm->stats.bandit_cmp_reward_added, 1UL,
			   __ATOMIC_RELAXED);

	/* Per-arm running sum of cmp_term's share of the combined reward,
	 * scaled to parts per thousand.  total is non-zero here because
	 * cmp_term > 0.  Averaged at end-of-run to surface the empirical
	 * CMP weighting per arm so the 0.25 constant can be tuned. */
	shm->bandit_cmp_share_sum_x1000[arm] +=
		(cmp_term * 1000UL) / total;
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
static bool cmp_bloom_set(_Atomic uint8_t *bloom, uint32_t bit)
{
	uint8_t mask = (uint8_t)(1U << (bit & 7));
	uint8_t prev = __atomic_fetch_or(&bloom[bit >> 3], mask,
					 __ATOMIC_RELAXED);

	return (prev & mask) == 0;
}

void bandit_cmp_observe(unsigned long *trace_buf, unsigned int nr,
			bool is_explorer)
{
	struct cmp_novelty_entry *e;
	unsigned long count, i;
	unsigned long novel = 0;
	uint32_t now;
	int strat;

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
	 * bandit picked for the bandit pool; crediting their CMP novelty to
	 * shm->current_strategy would misattribute their work and bias the
	 * bandit's reward calculation.  The bloom updates above still run so
	 * the global novelty horizon stays consistent across the fleet. */
	if (is_explorer)
		return;

	strat = __atomic_load_n(&shm->current_strategy, __ATOMIC_RELAXED);
	if (strat < 0 || strat >= NR_STRATEGIES)
		return;

	__atomic_fetch_add(&shm->bandit_cmp_new_constants[strat], novel,
			   __ATOMIC_RELAXED);
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

	if (nr >= MAX_NR_SYSCALL)
		return;

	slot = __atomic_load_n(&shm->frontier_slot, __ATOMIC_RELAXED) &
	       (FRONTIER_DECAY_WINDOWS - 1);
	__atomic_fetch_add(&shm->frontier_history[nr][slot], 1U,
			   __ATOMIC_RELAXED);
}

unsigned long frontier_recent_count(unsigned int nr)
{
	unsigned long sum = 0;
	unsigned int s;

	if (nr >= MAX_NR_SYSCALL)
		return 0;

	for (s = 0; s < FRONTIER_DECAY_WINDOWS; s++)
		sum += __atomic_load_n(&shm->frontier_history[nr][s],
				       __ATOMIC_RELAXED);
	return sum;
}

void frontier_window_advance(void)
{
	uint32_t next;
	unsigned int nr;

	/* Bump the slot index FIRST so producers racing the rotation start
	 * targeting the new slot before we clear it.  We then zero the new
	 * slot to drop the K-windows-old contents.  A producer that bumps
	 * the slot between the store and the clear loses its add (rare,
	 * benign for a noisy weight signal); a producer bumping after the
	 * clear lands on the freshly zeroed slot as intended. */
	next = __atomic_add_fetch(&shm->frontier_slot, 1U, __ATOMIC_RELAXED);
	next &= (FRONTIER_DECAY_WINDOWS - 1);

	for (nr = 0; nr < MAX_NR_SYSCALL; nr++)
		__atomic_store_n(&shm->frontier_history[nr][next], 0U,
				 __ATOMIC_RELAXED);
}

/*
 * Compute the UCB1 score for one arm.  Standard formulation:
 *
 *     score_i = mean_reward_i / norm + c * sqrt(ln(N) / n_i)
 *
 * where:
 *   mean_reward_i = bandit_reward[i] / bandit_pulls[i]
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
 */
static double ucb1_score(int arm, unsigned long total_pulls,
			 double norm)
{
	unsigned long pulls = shm->bandit_pulls[arm];
	unsigned long reward = shm->bandit_reward[arm];
	double exploit, explore;

	exploit = (double)reward / (double)pulls / norm;
	explore = UCB1_EXPLORATION_C *
		  sqrt(log((double)total_pulls) / (double)pulls);

	return exploit + explore;
}

/*
 * Pick the arm to run during the next window.  Returns an index in
 * [0, NR_STRATEGIES).  The caller (maybe_rotate_strategy) has already
 * updated bandit_pulls[]/bandit_reward[] for the just-finished window.
 *
 * Cold-start: any arm with zero pulls wins immediately (UCB1's
 * convention — every arm gets one pull before the score formula
 * makes sense).  Ties broken in favour of the lower index, which
 * keeps the warm-up deterministic.
 *
 * Round-robin mode bypasses the bandit entirely and just steps to
 * the next arm — same behaviour as Phase 1.
 */
int pick_next_strategy(int prev)
{
	enum picker_mode_t mode;
	unsigned long total_pulls = 0;
	double max_mean = 0.0;
	double best_score;
	int best_arm = 0;
	int i;

	mode = __atomic_load_n(&shm->picker_mode, __ATOMIC_RELAXED);

	if (mode == PICKER_ROUND_ROBIN)
		return (prev + 1) % NR_STRATEGIES;

	/* Cold-start: prefer any unpulled arm before scoring. */
	for (i = 0; i < NR_STRATEGIES; i++) {
		if (shm->bandit_pulls[i] == 0)
			return i;
		total_pulls += shm->bandit_pulls[i];
	}

	/* Normalise by the largest mean-reward across arms so the
	 * exploit term lives in the same numeric range as the
	 * exploration term.  Falls back to 1.0 when every arm has
	 * yielded zero edges so far (well-defined and harmless). */
	for (i = 0; i < NR_STRATEGIES; i++) {
		double mean = (double)shm->bandit_reward[i] /
			      (double)shm->bandit_pulls[i];
		if (mean > max_mean)
			max_mean = mean;
	}
	if (max_mean <= 0.0)
		max_mean = 1.0;

	best_score = ucb1_score(0, total_pulls, max_mean);
	best_arm = 0;
	for (i = 1; i < NR_STRATEGIES; i++) {
		double s = ucb1_score(i, total_pulls, max_mean);
		if (s > best_score) {
			best_score = s;
			best_arm = i;
		}
	}
	return best_arm;
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
	int i;

	mode = __atomic_load_n(&shm->picker_mode, __ATOMIC_RELAXED);

	output(0, "strategy picker: %s\n", picker_mode_name(mode));

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
		total_pulls += shm->bandit_pulls[i];

	if (total_pulls == 0)
		return;

	for (i = 0; i < NR_STRATEGIES; i++) {
		unsigned long pulls = shm->bandit_pulls[i];
		unsigned long reward = shm->bandit_reward[i];
		unsigned long cmp_new = __atomic_load_n(
			&shm->bandit_cmp_new_constants[i], __ATOMIC_RELAXED);
		unsigned long share_sum = shm->bandit_cmp_share_sum_x1000[i];
		unsigned long mean_x1000 = pulls ? (reward * 1000UL / pulls) : 0;
		/* Average per-window CMP share, parts per thousand.  Divides
		 * by total pulls (not just CMP-contributing pulls) so a low
		 * value can mean either "CMP rarely fires" or "CMP fires but
		 * is small relative to PC reward" — both are interesting for
		 * tuning the 0.25 weight constant. */
		unsigned long share_avg_x1000 = pulls ? (share_sum / pulls) : 0;

		output(0, "  arm[%d]: pulls=%lu reward=%lu mean=%lu.%03lu edges/window cmp_novel=%lu cmp_share=%lu.%lu%%\n",
		       i, pulls, reward,
		       mean_x1000 / 1000UL, mean_x1000 % 1000UL,
		       cmp_new,
		       share_avg_x1000 / 10UL, share_avg_x1000 % 10UL);
	}
}
