/*
 * Multi-strategy syscall-picker rotation: arm-selection policies.
 *
 * Two arm-selection policies are wired in here: a fixed round-robin
 * (the original picker) and a UCB1 bandit picker.  Both consume the
 * per-strategy edge attribution recorded in
 * shm->pc_edge_calls_by_strategy[]; the bandit treats those call
 * counts as the reward signal and biases future window picks toward
 * arms producing new-edge calls the fastest, while still occasionally
 * exploring the others so a temporarily-stuck arm doesn't starve
 * forever.  The parallel pc_edge_count_by_strategy[] series (real
 * bucket counts) is surfaced in dump_strategy_stats() as a diagnostic
 * but does not currently feed the learner.
 *
 * Picker mode is selected once at parse_args() time via --strategy
 * and stashed in shm->picker_mode so every child agrees on the
 * policy.  The CAS-winning child at a rotation boundary calls
 * pick_next_strategy() and bandit_record_pull(), runs the bandit
 * math itself, and writes the outcome back to shm->current_strategy.
 *
 * UCB1 is tractable here because the arm count is tiny (NR_STRATEGIES
 * is a handful -- four today, see enum strategy_t) and the picker only
 * runs once per STRATEGY_WINDOW (~100 sec at 10K iter/sec).
 * Floating-point sqrt and log inside the picker are noise relative to
 * the work done in the window itself.
 */

#include <limits.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "child.h"		/* struct childdata */
#include "cmp_hints.h"		/* cmp_hints_shm */
#include "debug.h"
#include "edgepair.h"		/* EDGEPAIR_NO_PREV */
#include "healer.h"		/* healer_strategy_ready */
#include "kcov.h"		/* KCOV_CMP_RECORDS_MAX, kcov_shm */
#include "params.h"
#include "shm.h"
#include "stats.h"		/* stats_log_write */
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
 * EMA discount for the recent_pulls_x1000[]/recent_reward_x1000[]
 * counters defined in shm.h.  Each non-intervention window multiplies
 * every arm's counter by gamma = 1 - alpha, then increments the
 * active arm by 1.0 / window_reward.  Alpha = 0.05 gives a half-life
 * of log(0.5)/log(0.95) ≈ 13.5 windows -- around 22 minutes of fleet
 * wall time at the ~100 sec/window cadence, comfortably inside the
 * 10-30 window design target and short enough that the picker
 * recovers within a few rotations when an arm's yield collapses.
 *
 * BANDIT_EMA_SCALE is the fixed-point divisor: counters are stored
 * as their real value times 1000 so the integer math stays exact for
 * the alpha=0.05 step.
 */
#define BANDIT_EMA_ALPHA_X1000  50UL
#define BANDIT_EMA_SCALE        1000UL

/*
 * Decay one fixed-point counter by gamma = 1 - alpha.  Operates on
 * the parts-per-thousand value: 950/1000 stays integer and the
 * multiplication can't overflow because the inputs cap at
 * ~SCALE/alpha * (typical per-window reward) = a few million for
 * recent_pulls_x1000 (≤ 20000) and on the order of 1e9 for
 * recent_reward_x1000 (bounded by the headroom of unsigned long).
 */
static inline unsigned long bandit_ema_decay(unsigned long x_x1000)
{
	return (x_x1000 * (BANDIT_EMA_SCALE - BANDIT_EMA_ALPHA_X1000)) /
	       BANDIT_EMA_SCALE;
}

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

bool is_strategy_eligible(int arm)
{
	if (arm < 0 || arm >= NR_STRATEGIES)
		return false;

	if (arm == STRATEGY_HEALER) {
		if (no_healer)
			return false;
		/* Plateau path is willing to schedule HEALER on thinner
		 * evidence than the strict gate -- a stalled bandit
		 * benefits from any signal that nudges it off the local
		 * minimum.  Calling the bypass explicitly (rather than
		 * burying the plateau check inside the predicate) keeps
		 * the two decisions -- "is the gate met" vs "may we bend
		 * the gate right now" -- separately auditable. */
		if (kcov_shm != NULL && kcov_shm->plateau_active)
			return healer_strategy_ready_plateau_bypass();
		return healer_strategy_ready();
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
void bandit_record_pull(int arm, enum strategy_selection_reason reason,
			unsigned long pc_edge_calls,
			unsigned long pc_edge_count,
			unsigned long cmp_new_constants)
{
	unsigned long cmp_term;
	unsigned long total;
	unsigned long now_window;
	int i;

	if (arm < 0 || arm >= NR_STRATEGIES)
		return;
	if (reason < 0 || reason >= NR_SELECTION_REASONS)
		return;

	cmp_term = cmp_new_constants / CMP_BANDIT_REWARD_WEIGHT_RECIPROCAL;
	total = pc_edge_calls + cmp_term;

	/* Always bucket the just-finished window by (arm, reason) before
	 * any cohort-gated learner update.  These matrices are diagnostic
	 * (the picker does not score against them) so they capture every
	 * window including SR_PLATEAU_FORCE -- intervention reward is the
	 * exact signal a future plateau-rescue classifier wants to read
	 * back, and excluding it here would silently zero the cohort the
	 * classifier is meant to study. */
	__atomic_fetch_add(&shm->bandit_pulls_by_reason[arm][reason], 1UL,
			   __ATOMIC_RELAXED);
	__atomic_fetch_add(&shm->bandit_reward_calls_by_reason[arm][reason],
			   total, __ATOMIC_RELAXED);
	__atomic_fetch_add(
		&shm->bandit_reward_pc_edge_count_by_reason[arm][reason],
		pc_edge_count, __ATOMIC_RELAXED);

	/* SR_PLATEAU_FORCE windows skip the learner-facing updates: an
	 * intervention window ran STRATEGY_RANDOM because every arm was
	 * stalled, which is structurally different from "RANDOM scored
	 * best under UCB" (the bandit had no input on the pick).  Folding
	 * the forced window into bandit_pulls[] / bandit_reward_calls[] /
	 * the recent_*_x1000 EMA contaminates the learner so the bandit
	 * can't tell policy-chosen RANDOM windows from forced RANDOM
	 * windows once the plateau clears.  The caller-side guard that
	 * used to gate this call moved in here so the by-reason bucketing
	 * above stays unconditional. */
	if (reason == SR_PLATEAU_FORCE)
		return;

	__atomic_fetch_add(&shm->bandit_pulls[arm], 1UL, __ATOMIC_RELAXED);
	__atomic_fetch_add(&shm->bandit_reward_calls[arm], total,
			   __ATOMIC_RELAXED);
	__atomic_fetch_add(&shm->bandit_reward_pc_edge_count[arm],
			   pc_edge_count, __ATOMIC_RELAXED);

	/* Discounted "recent" series update.  Decay every arm's counters
	 * by gamma = 1 - alpha first, THEN credit the active arm with one
	 * effective pull and the window's reward.  Decaying all arms (not
	 * just the pulled one) is what keeps the UCB1 explore-term
	 * denominator meaningful under discounting -- an arm that stops
	 * being picked must see its effective sample count shrink so the
	 * picker eventually re-tries it.  Single writer (CAS-serialised
	 * rotation path) so plain reads of the old values are safe;
	 * RELEASE stores back so the parent-side dump's RELAXED loads see
	 * complete values rather than torn intermediates.  This update
	 * runs alongside the lifetime fields above; ucb1_score() reads the
	 * recent series for both exploit and explore terms (D-UCB), while
	 * cold-start in pick_next_strategy() still reads lifetime
	 * bandit_pulls[] -- "never observed" rather than "not observed
	 * lately" -- and the lifetime fields also back dump_strategy_stats. */
	now_window = __atomic_load_n(&shm->bandit_window_count,
				     __ATOMIC_RELAXED);
	for (i = 0; i < NR_STRATEGIES; i++) {
		unsigned long p = shm->recent_pulls_x1000[i];
		unsigned long r = shm->recent_reward_x1000[i];

		__atomic_store_n(&shm->recent_pulls_x1000[i],
				 bandit_ema_decay(p), __ATOMIC_RELAXED);
		__atomic_store_n(&shm->recent_reward_x1000[i],
				 bandit_ema_decay(r), __ATOMIC_RELAXED);
	}
	__atomic_fetch_add(&shm->recent_pulls_x1000[arm], BANDIT_EMA_SCALE,
			   __ATOMIC_RELAXED);
	__atomic_fetch_add(&shm->recent_reward_x1000[arm],
			   total * BANDIT_EMA_SCALE, __ATOMIC_RELAXED);
	__atomic_store_n(&shm->last_selected_window[arm], now_window,
			 __ATOMIC_RELAXED);

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
		bool novel_here;

		if (!(type & KCOV_CMP_CONST))
			continue;

		/* arg1 is the compile-time constant under KCOV_CMP_CONST
		 * (clang/gcc's __sanitizer_cov_trace_const_cmpN convention);
		 * arg2 is the runtime value the kernel compared it against
		 * and would just credit the bandit for novelty in the
		 * fuzzer's own input distribution. */
		if (!cmp_novelty_interesting(arg1))
			continue;

		novel_here = cmp_bloom_set(e->bloom, cmp_bloom_h1(arg1));
		novel_here = cmp_bloom_set(e->bloom, cmp_bloom_h2(arg1)) ||
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
	uint32_t cur, next;
	unsigned int nr;
	unsigned long max_weight = 0;
	bool underflow_seen = false;

	/* Clear-then-publish, the opposite of the previous order.  The old
	 * code bumped frontier_slot first and then aged out the slot it had
	 * just published, which opened a window in which a producer could
	 * (a) add into the new slot before we cleared it, (b) have that
	 * write exchanged back to zero, and (c) issue its cached-sum
	 * increment AFTER our subtract.  In the worst case the rotator's
	 * fetch_sub ran with an old_slot value that was larger than the
	 * cached running sum -- because part of the producer's contribution
	 * was already in the slot but not yet in the cached counter -- so
	 * the subtract wrapped negative and the cached count flipped to a
	 * near-UINT32_MAX weight.  That bogus weight is consumed by
	 * random-syscall.c's frontier roulette wheel; an arm-wide blow-up
	 * either collapses the wheel onto one syscall or pushes the
	 * rejection sampler into an effectively-uniform reject loop.
	 *
	 * We now compute the next slot index without publishing it, age out
	 * the slot's contents from every per-nr running sum while no
	 * producer is targeting that slot (frontier_slot still points to
	 * the previous slot), and only then bump frontier_slot.  A producer
	 * racing the rotation keeps adding into the previous slot for a
	 * handful of instructions -- a bounded window-boundary attribution
	 * error -- instead of having its addition silently dropped or
	 * inverting the cached sum.
	 *
	 * The saturating subtract is kept as a hard guard: even with the
	 * reorder, a CAS-clamped update means a producer that races our
	 * read-modify-write on cached can't drive it negative.  Hitting the
	 * clamp bumps frontier_underflow_prevented -- the metric is
	 * expected to read zero in steady state. */
	cur = __atomic_load_n(&shm->frontier_slot, __ATOMIC_RELAXED);
	next = (cur + 1U) & (FRONTIER_DECAY_WINDOWS - 1);

	for (nr = 0; nr < MAX_NR_SYSCALL; nr++) {
		uint32_t old_slot;
		uint32_t old_cached;
		uint32_t new_sum;

		old_slot = __atomic_exchange_n(&shm->frontier_history[nr][next],
					       0U, __ATOMIC_RELAXED);

		/* CAS loop so a concurrent producer's fetch_add against the
		 * cached counter cannot be lost and cannot underflow the
		 * sum.  Producers should not be racing this nr at this
		 * point (frontier_slot still names the previous slot) but
		 * the loop costs at most a handful of retries and removes
		 * the underflow case unconditionally. */
		old_cached = __atomic_load_n(
			&shm->frontier_recent_count_cached[nr],
			__ATOMIC_RELAXED);
		for (;;) {
			if (old_cached >= old_slot)
				new_sum = old_cached - old_slot;
			else
				new_sum = 0;
			if (__atomic_compare_exchange_n(
				    &shm->frontier_recent_count_cached[nr],
				    &old_cached, new_sum, false,
				    __ATOMIC_RELAXED, __ATOMIC_RELAXED))
				break;
		}
		if (old_cached < old_slot)
			underflow_seen = true;
		if (new_sum > max_weight)
			max_weight = new_sum;
	}

	/* Publish the new slot only after every per-nr clear has landed.
	 * From this point producers see the freshly-zeroed slot. */
	__atomic_store_n(&shm->frontier_slot, cur + 1U, __ATOMIC_RELAXED);

	if (max_weight > UINT_MAX)
		max_weight = UINT_MAX;
	__atomic_store_n(&shm->frontier_max_weight_cached,
			 (unsigned int)max_weight, __ATOMIC_RELAXED);

	if (underflow_seen)
		__atomic_add_fetch(&shm->stats.frontier_underflow_prevented,
				   1UL, __ATOMIC_RELAXED);
}

/*
 * Compute the UCB1 score for one arm.  Discounted formulation
 * (D-UCB): the lifetime bandit_pulls[]/bandit_reward_calls[] series
 * is replaced by the rolling exponentially-decayed counters
 * recent_pulls_x1000[]/recent_reward_x1000[] so the picker tracks
 * recent yield instead of the lifetime average.  Kernel coverage
 * discovery is non-stationary -- early windows mine out easy edges
 * and late windows degrade -- so an arm's last few windows are the
 * relevant signal, not its 2024 mean.
 *
 *     score_i = mean_reward_i / norm + c * sqrt(ln(N) / n_i)
 *
 * where:
 *   mean_reward_i = recent_reward_x1000[i] / recent_pulls_x1000[i]
 *                   (the x1000 fixed-point cancels, leaving the
 *                   discounted mean reward in the original calls
 *                   units the lifetime series used)
 *   norm          = max over arms of mean_reward_j (or 1 if all zero)
 *   N             = sum across arms of n_j (effective discounted
 *                   sample size, the D-UCB analogue of total_pulls)
 *   n_i           = recent_pulls_x1000[i] / 1000.0
 *   c             = UCB1_EXPLORATION_C
 *
 * Normalising the exploit term by the largest observed mean keeps it
 * in roughly the same range as the exploration term (~1) regardless
 * of whether per-window rewards are in the hundreds or hundreds of
 * thousands.  Without normalisation, a UCB1 picker over edges-per-
 * window degenerates into "always pick the arm with the highest
 * cumulative average" because the exploit term dwarfs sqrt(ln/n).
 *
 * The reward signal consumed here is still the CALL-COUNT series
 * (recent_reward_x1000[] is the discounted form of
 * bandit_reward_calls[] -- calls-with-≥1-edge plus the weighted CMP
 * novelty term).  The parallel real bucket-count series
 * (bandit_reward_pc_edge_count[]) remains a lifetime diagnostic and
 * does not feed the score; switching the learner to a discounted
 * bucket-count signal is a separate decision once both signals have
 * been observed under discounting against real run data.
 *
 * pulls_x1000 == 0 clamps to 1: an arm whose discounted count
 * decayed all the way to zero (≈140 windows of no selection at
 * gamma=0.95) is by definition starved, the resulting huge explore
 * term is the correct outcome.  The clamp keeps the division
 * well-defined rather than relying on a separate guard.
 */
static double ucb1_score(int arm, double total_n, double norm)
{
	unsigned long pulls_x1000 = shm->recent_pulls_x1000[arm];
	unsigned long reward_x1000 = shm->recent_reward_x1000[arm];
	double n_i, mean, exploit, explore;

	if (pulls_x1000 == 0)
		pulls_x1000 = 1;

	n_i = (double)pulls_x1000 / (double)BANDIT_EMA_SCALE;
	mean = (double)reward_x1000 / (double)pulls_x1000;
	exploit = mean / norm;
	explore = UCB1_EXPLORATION_C * sqrt(log(total_n) / n_i);

	return exploit + explore;
}

/*
 * Pick the arm to run during the next window using the configured
 * arm-selection POLICY only.  Returns an index in [0, NR_STRATEGIES)
 * and writes the reason path through *reason_out.  The caller
 * (maybe_rotate_strategy via select_next_strategy) has already
 * updated bandit_pulls[]/bandit_reward_calls[] (plus the parallel
 * bandit_reward_pc_edge_count[] diagnostic series) AND the
 * discounted recent_pulls_x1000[]/recent_reward_x1000[] series for
 * the just-finished window unless that window was a forced
 * intervention.  UCB1 scoring reads the discounted recent series
 * (D-UCB, see ucb1_score) so non-stationary kernel coverage
 * discovery doesn't let early-run wins dominate late-run picks.
 *
 * Cold-start: any arm with zero LIFETIME pulls wins immediately
 * (UCB1's convention — every arm gets one pull before the score
 * formula makes sense).  Lifetime rather than discounted pulls
 * because cold-start is a once-per-arm trigger; using the decayed
 * count would re-fire after the discount horizon and turn the
 * learner into slow round-robin.  Ties broken in favour of the
 * lower index, which keeps the warm-up deterministic.
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
	double total_n = 0.0;
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

	/* Cold-start uses LIFETIME bandit_pulls -- cold-start is a
	 * "never been observed" trigger, not a "haven't been observed
	 * lately" trigger.  Reading recent_pulls_x1000 here would re-fire
	 * cold-start every ~140 windows for any arm the picker has
	 * stopped choosing (the half-life-driven decay back to zero),
	 * which is just slow round-robin in disguise and defeats the
	 * point of a learner. */
	for (i = 0; i < NR_STRATEGIES; i++) {
		if (!eligible[i])
			continue;
		if (shm->bandit_pulls[i] == 0) {
			*reason_out = SR_COLD_START;
			return i;
		}
	}

	/* total_n: sum of discounted effective-sample counts across
	 * eligible arms.  D-UCB analogue of vanilla UCB1's "total pulls"
	 * in the ln(N) explore-term numerator.  Floor at 1.0 so log()
	 * stays non-negative on a fresh post-cold-start run where the
	 * sum hasn't grown above unity yet. */
	for (i = 0; i < NR_STRATEGIES; i++) {
		if (!eligible[i])
			continue;
		total_n += (double)shm->recent_pulls_x1000[i] /
			   (double)BANDIT_EMA_SCALE;
	}
	if (total_n < 1.0)
		total_n = 1.0;

	/* Normalise by the largest discounted mean-reward across eligible
	 * arms so the exploit term lives in the same numeric range as the
	 * exploration term.  Falls back to 1.0 when every arm has yielded
	 * zero edges in the recent horizon (well-defined and harmless).
	 * Skips arms whose discounted pulls decayed to zero -- their
	 * "mean" is undefined, and they will get a huge explore-term
	 * score from ucb1_score's pulls_x1000==0 clamp so the picker will
	 * re-try them on this pass anyway. */
	for (i = 0; i < NR_STRATEGIES; i++) {
		unsigned long p, r;
		double mean;

		if (!eligible[i])
			continue;
		p = shm->recent_pulls_x1000[i];
		r = shm->recent_reward_x1000[i];
		if (p == 0)
			continue;
		mean = (double)r / (double)p;
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
		s = ucb1_score(i, total_n, max_mean);
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
/*
 * Random-rescue amplification thresholds.  A class must clear an
 * absolute floor (so a handful of stray rescues do not whip the
 * orchestrator around between arms) AND a 2x lead over the second-best
 * class (so two near-tied classes default back to plain RANDOM rather
 * than coin-flipping the intervention).  Both numbers are conservative
 * -- the amplification is a temporary modifier on a single intervention
 * window, easy to recover from on the next rotation if the dominant
 * class shifts.
 */
#define RRC_AMPLIFY_MIN_COUNT  32UL
#define RRC_AMPLIFY_LEAD_RATIO 2UL

/*
 * Compute the dominant rescue class from the cumulative counters.
 * Returns RRC_NR_CLASSES (the "no amplification" sentinel) when no
 * class clears both the floor and the lead-over-second-best threshold.
 * Placeholder classes (RRC_UNUSUAL_FD_PRODUCER, RRC_WRONG_TYPE_FD,
 * RRC_PERSONA_GATED) are scanned so the comparison sees them, but the
 * classifier never credits a rescue to them today so they cannot win;
 * the orchestrator's bias dispatch treats them as plain RANDOM
 * regardless, which is also the behaviour for RRC_UNKNOWN.
 */
static enum random_rescue_class dominant_rescue_class(void)
{
	unsigned long best = 0;
	unsigned long second = 0;
	enum random_rescue_class best_class = RRC_NR_CLASSES;
	int i;

	for (i = 0; i < RRC_NR_CLASSES; i++) {
		unsigned long c = __atomic_load_n(
			&shm->random_rescue_class_count[i], __ATOMIC_RELAXED);
		if (c > best) {
			second = best;
			best = c;
			best_class = (enum random_rescue_class)i;
		} else if (c > second) {
			second = c;
		}
	}

	if (best < RRC_AMPLIFY_MIN_COUNT)
		return RRC_NR_CLASSES;
	if (best < second * RRC_AMPLIFY_LEAD_RATIO)
		return RRC_NR_CLASSES;
	return best_class;
}

/*
 * Map a dominant rescue class to the targeted intervention arm.
 * Defaults to STRATEGY_RANDOM (the historical pre-classifier
 * behaviour) for classes that do not have a structured replay
 * available -- placeholder classes whose underlying infrastructure
 * does not exist yet, the unknown bucket, and the "no class
 * dominant" sentinel.
 *
 * HEALER targeted arms fall back to RANDOM when HEALER is ineligible
 * (compiled out, --no-healer, or the eligibility scan still says no)
 * so the intervention does not stall on an arm that cannot run.  The
 * plateau_active path inside is_strategy_eligible already bypasses
 * the pair-cell threshold, so the eligibility check here is
 * primarily a guard against the no_healer case.
 */
static int amplified_intervention_arm(enum random_rescue_class c)
{
	switch (c) {
	case RRC_MISSING_PAIR:
	case RRC_UNSEEN_SUCCESSOR:
	case RRC_STALE_PAIR:
		if (is_strategy_eligible(STRATEGY_HEALER))
			return STRATEGY_HEALER;
		return STRATEGY_RANDOM;
	case RRC_COLD_SKIP:
		/* Heuristic with cold-skip suppressed -- the set_syscall_nr_
		 * heuristic read of plateau_rescue_amplified_class will
		 * short-circuit the kcov_syscall_cold_skip_pct retry while
		 * the intervention runs. */
		return STRATEGY_HEURISTIC;
	case RRC_CMP_DERIVED:
	case RRC_UNUSUAL_FD_PRODUCER:
	case RRC_WRONG_TYPE_FD:
	case RRC_PERSONA_GATED:
	case RRC_UNKNOWN:
	case RRC_NR_CLASSES:
		break;
	}
	return STRATEGY_RANDOM;
}

int select_next_strategy(int prev,
			 enum strategy_selection_reason *reason_out)
{
	enum picker_mode_t mode;

	mode = __atomic_load_n(&shm->picker_mode, __ATOMIC_RELAXED);

	if (mode == PICKER_BANDIT_UCB1 &&
	    kcov_shm != NULL && kcov_shm->plateau_active) {
		enum random_rescue_class amplified = RRC_NR_CLASSES;
		enum plateau_intervention_mode pim;
		unsigned long rot;
		int arm;

		/* Round-robin among the three intervention modes.  The
		 * fetch_add returns the PREVIOUS counter value, so each
		 * rotation picks a mode cleanly without coordination
		 * between concurrent rotations -- the CAS in
		 * maybe_rotate_strategy already serialises which child
		 * runs select_next_strategy in the first place, but the
		 * fetch_add semantics keep the rotation correct even if a
		 * future refactor lets multiple writers in.
		 *
		 * The counter only ticks during plateau windows, so a
		 * fresh plateau picks up wherever the previous one left
		 * off rather than always starting from PIM_UNIFORM_RANDOM
		 * -- this matters when the plateau detector flaps between
		 * active and inactive across consecutive rotations and an
		 * always-from-zero counter would bias the early windows of
		 * each plateau toward the same mode. */
		rot = __atomic_fetch_add(
			&shm->plateau_intervention_rotation_counter, 1UL,
			__ATOMIC_RELAXED);
		pim = (enum plateau_intervention_mode)(rot % NR_PIM_MODES);

		switch (pim) {
		case PIM_RRC_BIASED:
			/* Random-rescue classifier dispatch path.  Reuses
			 * the existing dominant_rescue_class +
			 * amplified_intervention_arm pair so the classifier-
			 * driven HEALER / HEURISTIC replay shape stays
			 * exactly what landed when amplification was the only
			 * intervention mode -- this commit changes the
			 * SCHEDULING of when it runs, not its internals. */
			amplified = dominant_rescue_class();
			arm = amplified_intervention_arm(amplified);
			break;
		case PIM_ANTI_PRIOR:
			/* Refresh the baseline at the rotation boundary so
			 * the per-call accept gate inside set_syscall_nr_
			 * random reads a value that matches the picker's
			 * CURRENT distribution.  Recomputing every rotation
			 * (rather than once-at-init) lets the bias track the
			 * learned distribution as it drifts across the run.
			 *
			 * STRATEGY_RANDOM is the arm regardless of mode -- the
			 * anti-prior bias rides per-call inside the random
			 * picker, not at the strategy-selection layer. */
			plateau_anti_prior_refresh_baseline();
			arm = STRATEGY_RANDOM;
			break;
		case PIM_UNIFORM_RANDOM:
		default:
			/* Baseline mode: STRATEGY_RANDOM with no per-call
			 * bias.  Kept as the third rotation slot so the A/B
			 * comparison has an anchor -- without it,
			 * "anti-prior helped" and "RRC-bias helped" both
			 * reduce to comparisons against each other rather
			 * than against the historical pre-classifier
			 * intervention shape. */
			arm = STRATEGY_RANDOM;
			break;
		}

		/* Publish the amplified class and intervention mode BEFORE
		 * the reason store on current_selection_reason in
		 * maybe_rotate_strategy.  The rotation site stores
		 * current_selection_reason with RELAXED ordering and pairs
		 * it with the current_strategy RELEASE store, so a child
		 * observing the new strategy also sees both freshly-
		 * published fields on its next pick.  RRC_NR_CLASSES means
		 * "no class dominant"; PIM_UNIFORM_RANDOM is published
		 * outside the intervention branch below so the anti-prior
		 * gate cannot stay latched on after the plateau lifts. */
		__atomic_store_n(&shm->plateau_rescue_amplified_class,
				 (int)amplified, __ATOMIC_RELAXED);
		__atomic_store_n(&shm->plateau_intervention_mode_current,
				 (int)pim, __ATOMIC_RELAXED);
		__atomic_fetch_add(
			&shm->plateau_intervention_mode_windows[pim], 1UL,
			__ATOMIC_RELAXED);
		__atomic_fetch_add(&shm->stats.plateau_forced_windows, 1UL,
				   __ATOMIC_RELAXED);
		*reason_out = SR_PLATEAU_FORCE;
		return arm;
	}

	/* Not in a plateau intervention -- clear the amplification AND the
	 * mode so neither the RRC bias dispatch nor the anti-prior accept
	 * gate can stay latched on after the plateau lifts.  Both reset to
	 * the "no bias" sentinel (RRC_NR_CLASSES / PIM_UNIFORM_RANDOM)
	 * because their hot-path gates short-circuit cleanly on those
	 * values. */
	__atomic_store_n(&shm->plateau_rescue_amplified_class,
			 (int)RRC_NR_CLASSES, __ATOMIC_RELAXED);
	__atomic_store_n(&shm->plateau_intervention_mode_current,
			 (int)PIM_UNIFORM_RANDOM, __ATOMIC_RELAXED);

	return pick_next_strategy(prev, reason_out);
}

const char *strategy_selection_reason_name(enum strategy_selection_reason r)
{
	switch (r) {
	case SR_NORMAL_UCB:	return "NORMAL_UCB";
	case SR_ROUND_ROBIN:	return "ROUND_ROBIN";
	case SR_COLD_START:	return "COLD_START";
	case SR_PLATEAU_FORCE:	return "PLATEAU_FORCE";
	case NR_SELECTION_REASONS:	break;	/* sentinel */
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
 * RRC_COLD_SKIP threshold.  STRATEGY_HEURISTIC's kcov_syscall_cold_skip_pct
 * returns the per-syscall probability the heuristic picker rejects the
 * candidate on the cold-skip retry; 50 is the baseline the heuristic uses
 * for a freshly-cold syscall (see kcov.c).  A SR_PLATEAU_FORCE rescue
 * whose rec->nr scores at or above the baseline would have been skipped
 * by the heuristic at least half the time -- enough that the RANDOM
 * intervention is plausibly the only path that exercised it.
 */
#define RRC_COLD_SKIP_PCT 50U

/*
 * RRC_UNSEEN_SUCCESSOR scan budget.  The classifier walks (pred -> *)
 * looking for at least one hot OUTGOING pair from the same predecessor;
 * the existence proof is enough, no need to count.  Capped so a
 * pathological pred with no hot successors does not turn the rescue
 * path into an O(MAX_NR_SYSCALL) walk under high rescue rate.  The
 * scan starts at (pred + 1) and wraps so the same nr is not inspected
 * twice in a single call.
 */
#define RRC_UNSEEN_SUCCESSOR_SCAN_CAP 256U

/*
 * Minimum HEALER pair weight required for a (pred -> X) cell to count
 * as a "hot outgoing pair" during the RRC_UNSEEN_SUCCESSOR existence
 * scan.  Set above the bare HEALER_STATIC_SEED_WEIGHT=3 floor so the
 * existence proof requires either runtime evidence or a seed-plus-
 * dynamic hit, matching the spirit of the eligibility gate's
 * dynamic_hits-only test (a freshly-seeded pair is not yet evidence
 * the structured picker is actually investing in that branch).
 */
#define RRC_HOT_PAIR_THRESHOLD 4U

bool plateau_rescue_bias_active_for(enum random_rescue_class c)
{
	if (c < 0 || c >= RRC_NR_CLASSES)
		return false;
	if (kcov_shm == NULL || !kcov_shm->plateau_active)
		return false;
	/* ACQUIRE-load current_strategy pairs with the RELEASE-store in
	 * maybe_rotate_strategy.  Callers reach this gate from paths that
	 * may not have done their own acquire (notably the explorer pool,
	 * which short-circuits past set_syscall_nr's hot-picker acquire),
	 * so fence here to guarantee the subsequent relaxed reads of
	 * current_selection_reason and plateau_rescue_amplified_class see
	 * the values the orchestrator published before the rotation. */
	(void)__atomic_load_n(&shm->current_strategy, __ATOMIC_ACQUIRE);
	if (__atomic_load_n(&shm->current_selection_reason, __ATOMIC_RELAXED) !=
	    SR_PLATEAU_FORCE)
		return false;
	return __atomic_load_n(&shm->plateau_rescue_amplified_class,
			       __ATOMIC_RELAXED) == (int)c;
}

/*
 * Anti-prior boost cap.  The acceptance formula is structured so a
 * syscall at the baseline mean accepts at 1/ANTI_PRIOR_MAX_BOOST,
 * cold-end saturates at full uniform acceptance (1.0), and over-picked
 * syscalls bottom out at 1/ANTI_PRIOR_MAX_BOOST^2.  8 keeps the cold-
 * end boost large enough to materially shift the picker's distribution
 * away from its learned priors during the intervention without
 * collapsing the rotation onto a single syscall whose calls=0 reading
 * reflects a genuine broken-in-this-kernel arm rather than picker
 * suppression.  The cap is the SOLE knob trinity exposes against the
 * "100x boost a stuck syscall" pathology the design comment in
 * include/strategy.h warns about.
 */
#define ANTI_PRIOR_MAX_BOOST 8UL

/*
 * Pre-computed threshold range for the rejection-sampling roll.  Held
 * as a literal so the inner-loop divides fold to a single shift on the
 * target ISA; ANTI_PRIOR_MAX_BOOST stays as the human-meaningful knob.
 */
#define ANTI_PRIOR_THRESHOLD_SCALE \
	(ANTI_PRIOR_MAX_BOOST * ANTI_PRIOR_MAX_BOOST)

bool plateau_anti_prior_active(void)
{
	if (kcov_shm == NULL || !kcov_shm->plateau_active)
		return false;
	/* ACQUIRE-load current_strategy pairs with the RELEASE-store in
	 * maybe_rotate_strategy.  Fenced here rather than relying on the
	 * caller because set_syscall_nr_random is also entered from the
	 * explorer path, which bypasses set_syscall_nr's hot-picker
	 * acquire.  Without this fence the subsequent relaxed reads of
	 * current_selection_reason and plateau_intervention_mode_current
	 * could disagree with the just-rotated strategy, e.g. masking an
	 * intended PIM_ANTI_PRIOR window or leaving stale intervention
	 * state visible after a plateau lifts. */
	(void)__atomic_load_n(&shm->current_strategy, __ATOMIC_ACQUIRE);
	if (__atomic_load_n(&shm->current_selection_reason, __ATOMIC_RELAXED) !=
	    SR_PLATEAU_FORCE)
		return false;
	return __atomic_load_n(&shm->plateau_intervention_mode_current,
			       __ATOMIC_RELAXED) == (int)PIM_ANTI_PRIOR;
}

bool plateau_anti_prior_accept(unsigned int nr)
{
	unsigned long baseline;
	uint8_t weight;

	if (nr >= MAX_NR_SYSCALL)
		return true;

	baseline = __atomic_load_n(&shm->plateau_anti_prior_baseline_calls,
				   __ATOMIC_RELAXED);
	/* No baseline yet -- the orchestrator has not selected an
	 * anti-prior rotation in this run.  Pass unconditionally so the
	 * picker degenerates to uniform until the cache is populated.
	 * Also covers the kcov_shm==NULL case: refresh_baseline writes
	 * baseline=0 on that path, so the gate short-circuits without
	 * needing a separate kcov_shm probe here. */
	if (baseline == 0)
		return true;

	/* Read the pre-computed acceptance weight.  Visibility of the
	 * weight table is guaranteed by the caller's prior ACQUIRE-load of
	 * current_strategy (via plateau_anti_prior_active), which pairs
	 * with the RELEASE-store in maybe_rotate_strategy that publishes
	 * every store refresh_baseline made on the rotation path.  See the
	 * weight-array comment in struct shm_s for the publish ordering
	 * contract.  The full inversion math (clamp / divide / cap) lives
	 * in plateau_anti_prior_refresh_baseline so the per-retry inner
	 * loop in set_syscall_nr_random reduces to one relaxed load, one
	 * modulo, and one compare. */
	weight = __atomic_load_n(&shm->plateau_anti_prior_accept_weight[nr],
				 __ATOMIC_RELAXED);

	return (unsigned long)rand() % ANTI_PRIOR_THRESHOLD_SCALE < weight;
}

void plateau_anti_prior_refresh_baseline(void)
{
	unsigned long sum = 0;
	unsigned int i;
	unsigned long baseline;
	unsigned long floor_calls, ceil_calls;

	if (kcov_shm == NULL) {
		__atomic_store_n(&shm->plateau_anti_prior_baseline_calls, 0UL,
				 __ATOMIC_RELAXED);
		return;
	}

	/* Mean across the full per_syscall_calls slot range.  Indexing by
	 * MAX_NR_SYSCALL (not max_nr_syscalls) matches the array
	 * dimension and keeps the baseline stable across biarch builds
	 * where the per_syscall_calls slot is shared by both arches.
	 * O(MAX_NR_SYSCALL) walk on the rotation path, never on the hot
	 * pick path. */
	for (i = 0; i < MAX_NR_SYSCALL; i++)
		sum += __atomic_load_n(&kcov_shm->per_syscall_calls[i],
				       __ATOMIC_RELAXED);
	baseline = sum / MAX_NR_SYSCALL;

	/* Publish at least 1 when the mean truncates to zero so the accept
	 * gate's "baseline=0 short-circuit to pass" branch only fires
	 * before any rotation has populated the cache, not when the fleet
	 * is genuinely too young for any syscall to have averaged a full
	 * call.  Without the floor a cold-start run that hit a plateau
	 * within its first MAX_NR_SYSCALL ops would have the anti-prior
	 * rotation silently degenerate to uniform pick. */
	if (baseline == 0 && sum > 0)
		baseline = 1;

	/* Pre-compute the per-syscall acceptance weights so the hot-path
	 * picker only does one load + modulo + compare per candidate.  The
	 * formula mirrors what plateau_anti_prior_accept used to do per
	 * call, exactly:
	 *
	 *   floor   = max(1, baseline / MAX_BOOST)
	 *   ceil    = baseline * MAX_BOOST
	 *   clamped = clamp(calls, floor, ceil)
	 *   weight  = min((MAX_BOOST * baseline) / clamped,
	 *                 ANTI_PRIOR_THRESHOLD_SCALE)
	 *
	 * For the same baseline and the same per-syscall calls reading,
	 * the resulting weight is bit-identical to what the per-call path
	 * computed.  The only behavioural delta is that calls[nr] is
	 * snapshotted here at rotation time rather than re-read on every
	 * candidate; an intervention window is short relative to the rate
	 * any single syscall's lifetime count can shift, and the
	 * statistical bias the gate imposes is keyed off the baseline-
	 * relative ratio, not the absolute call count.
	 *
	 * weight is bounded by ANTI_PRIOR_THRESHOLD_SCALE (= 64 today, =
	 * MAX_BOOST^2) and never zero, so the uint8_t slot is sufficient.
	 *
	 * The whole array is written under RELAXED ordering; visibility
	 * rides on the RELEASE-store of current_strategy that
	 * maybe_rotate_strategy emits after select_next_strategy returns,
	 * paired with the picker-side ACQUIRE-load inside
	 * plateau_anti_prior_active.  Mirrors the existing publish pattern
	 * for plateau_intervention_mode_current. */
	if (baseline > 0) {
		floor_calls = baseline / ANTI_PRIOR_MAX_BOOST;
		if (floor_calls == 0)
			floor_calls = 1;
		ceil_calls = baseline * ANTI_PRIOR_MAX_BOOST;

		for (i = 0; i < MAX_NR_SYSCALL; i++) {
			unsigned long calls, clamped, weight;

			calls = __atomic_load_n(
				&kcov_shm->per_syscall_calls[i],
				__ATOMIC_RELAXED);
			clamped = calls;
			if (clamped < floor_calls)
				clamped = floor_calls;
			else if (clamped > ceil_calls)
				clamped = ceil_calls;

			weight = (ANTI_PRIOR_MAX_BOOST * baseline) / clamped;
			if (weight > ANTI_PRIOR_THRESHOLD_SCALE)
				weight = ANTI_PRIOR_THRESHOLD_SCALE;

			__atomic_store_n(
				&shm->plateau_anti_prior_accept_weight[i],
				(uint8_t)weight, __ATOMIC_RELAXED);
		}
	}

	__atomic_store_n(&shm->plateau_anti_prior_baseline_calls, baseline,
			 __ATOMIC_RELAXED);
}

const char *plateau_intervention_mode_name(enum plateau_intervention_mode m)
{
	switch (m) {
	case PIM_UNIFORM_RANDOM:	return "UNIFORM_RANDOM";
	case PIM_ANTI_PRIOR:		return "ANTI_PRIOR";
	case PIM_RRC_BIASED:		return "RRC_BIASED";
	case NR_PIM_MODES:		break;	/* sentinel */
	}
	return "?";
}

const char *random_rescue_class_name(enum random_rescue_class c)
{
	switch (c) {
	case RRC_COLD_SKIP:		return "COLD_SKIP";
	case RRC_MISSING_PAIR:		return "MISSING_PAIR";
	case RRC_UNSEEN_SUCCESSOR:	return "UNSEEN_SUCCESSOR";
	case RRC_STALE_PAIR:		return "STALE_PAIR";
	case RRC_UNUSUAL_FD_PRODUCER:	return "UNUSUAL_FD_PRODUCER";
	case RRC_WRONG_TYPE_FD:		return "WRONG_TYPE_FD";
	case RRC_CMP_DERIVED:		return "CMP_DERIVED";
	case RRC_PERSONA_GATED:		return "PERSONA_GATED";
	case RRC_UNKNOWN:		return "UNKNOWN";
	case RRC_NR_CLASSES:		break;	/* sentinel */
	}
	return "?";
}

enum random_rescue_class classify_random_rescue(struct syscallrecord *rec,
						struct childdata *child)
{
	unsigned int prev, curr;
	unsigned int pair_weight, dyn_hits;
	unsigned int static_prior;
	unsigned int arch;

	if (rec == NULL || child == NULL)
		return RRC_UNKNOWN;
	if (rec->nr >= MAX_NR_SYSCALL)
		return RRC_UNKNOWN;

	curr = (unsigned int)rec->nr;
	prev = child->last_syscall_nr;
	/* HEALER's pair table is indexed by the successor call's arch
	 * dimension; classify_random_rescue is reasoning about the rescue
	 * call (rec), so the arch read off rec->do32bit is the right
	 * lookup key for the (prev, curr) cell. */
	arch = healer_arch_id(rec->do32bit);

	/* RRC_COLD_SKIP.  Heuristic picker would have rejected this nr at
	 * least half the time on the cold-skip retry path, so a RANDOM
	 * rescue that lands new edges on it is most plausibly recovering
	 * coverage the heuristic was filtering out.  The check runs against
	 * the same kcov_syscall_cold_skip_pct() the heuristic consults, so
	 * the classifier and the picker can never disagree on what "cold"
	 * means. */
	if (kcov_syscall_cold_skip_pct(curr) >= RRC_COLD_SKIP_PCT)
		return RRC_COLD_SKIP;

	/* HEALER-pair classes need a real predecessor.  EDGEPAIR_NO_PREV is
	 * the first-call-in-a-child sentinel; without it there is no (pred
	 * -> succ) edge to reason about, so the structured-picker
	 * attribution buckets do not apply and the rescue falls through to
	 * the unattributable bucket (or matches CMP_DERIVED below). */
	if (prev != EDGEPAIR_NO_PREV && prev < MAX_NR_SYSCALL) {
		pair_weight = healer_pair_get(arch, prev, curr);
		dyn_hits = healer_pair_dynamic_hits(arch, prev, curr);
		/* healer_pair_get sums static_prior + dynamic_hits; backing
		 * the dynamic component out reconstructs the static prior
		 * without adding a third accessor.  pair_weight >= dyn_hits
		 * by construction (static_prior is unsigned, the sum cannot
		 * underflow). */
		static_prior = pair_weight >= dyn_hits ?
			pair_weight - dyn_hits : 0;

		if (pair_weight == 0) {
			unsigned int scanned;
			unsigned int succ;

			/* RRC_MISSING_PAIR vs RRC_UNSEEN_SUCCESSOR.  No cell
			 * for (prev, curr) at all.  If prev has at least one
			 * hot outgoing pair to some OTHER successor, HEALER
			 * has evidence about this predecessor but is investing
			 * elsewhere; classify as UNSEEN_SUCCESSOR so the
			 * orchestrator's HEALER-boost bias is the right
			 * answer.  Otherwise prev is entirely unattested and
			 * MISSING_PAIR is the narrower truth. */
			succ = (curr + 1) % MAX_NR_SYSCALL;
			for (scanned = 0;
			     scanned < RRC_UNSEEN_SUCCESSOR_SCAN_CAP;
			     scanned++) {
				if (succ != curr &&
				    healer_pair_get(arch, prev, succ) >=
					    RRC_HOT_PAIR_THRESHOLD)
					return RRC_UNSEEN_SUCCESSOR;
				succ = (succ + 1) % MAX_NR_SYSCALL;
				if (succ == ((curr + 1) % MAX_NR_SYSCALL))
					break;
			}
			return RRC_MISSING_PAIR;
		}

		if (dyn_hits == 0 && static_prior > 0) {
			/* Seed bootstrap saw this edge but the runtime
			 * observer never confirmed it (or confirmed it and
			 * decayed back to zero).  HEALER's eligibility gate
			 * counts dynamic_hits only, so this cell looks dead
			 * to the picker even though the static prior is
			 * still on it.  Boosting HEALER eligibility past the
			 * gate during the next intervention is the
			 * structured replay. */
			return RRC_STALE_PAIR;
		}
	}

	/* RRC_CMP_DERIVED.  generate-args.c's ARG_OP / ARG_LIST /
	 * gen_undefined_arg paths roll a 1-in-16 cmp_hints_try_get on every
	 * call; if rec->nr has any hints in its pool, a learned constant
	 * may have carried this RANDOM call past a kernel validation check
	 * the structured pickers were not aware of.  Hint-pool occupancy is
	 * a soft signal (the per-call substitution probability is fixed and
	 * we have no per-call attribution), but a non-empty pool is the
	 * narrowest evidence available without adding per-call tracking. */
	if (cmp_hints_shm != NULL && curr < 1024 &&
	    __atomic_load_n(&cmp_hints_shm->pools[curr].count,
			    __ATOMIC_RELAXED) > 0)
		return RRC_CMP_DERIVED;

	/* RRC_UNUSUAL_FD_PRODUCER / RRC_WRONG_TYPE_FD / RRC_PERSONA_GATED
	 * detection requires per-call fd-source tracking and persona
	 * attribution infrastructure that does not yet exist.  Rescues that
	 * land here fall through to UNKNOWN; the orchestrator's bias
	 * dispatch handles those classes for the future infrastructure to
	 * wire in without an enum reorder. */

	return RRC_UNKNOWN;
}

/*
 * Operator-facing summary, called from dump_stats() at end of run.
 * Always shows the picker mode (cheap context); per-arm pulls and
 * mean reward are printed in both modes whenever any window has
 * completed (total_pulls > 0) -- round-robin runs through
 * bandit_record_pull() too, so its per-arm yield is meaningful even
 * though the picker itself ignores the reward signal.  Suppressed
 * only when total_pulls is zero (run too short for any window to
 * close).
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

	/* HEALER readiness state.  Three-way classification so the
	 * operator can tell whether the strict gate has fired (dynamic
	 * evidence has crossed the threshold), only the static prior is
	 * carrying the signal (eligible under plateau bypass but not the
	 * strict gate), or the table has nothing useful yet.  Suppressed
	 * entirely under --no-healer where the eligibility verdict is
	 * fixed and reporting it would be noise. */
	if (!no_healer) {
		enum healer_readiness r;

		(void)healer_strategy_ready_explicit(&r);
		switch (r) {
		case HEALER_READY_DYNAMIC:
			output(0, "  HEALER eligible (dynamic)\n");
			break;
		case HEALER_READY_SEED_ONLY:
			output(0, "  HEALER eligible (seed only -- plateau bypass eligible, strict gate not yet met)\n");
			break;
		case HEALER_NOT_READY:
			output(0, "  HEALER not ready (pair table carries no usable signal)\n");
			break;
		}
	}

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
		output(0, "  plateau-forced windows: %lu (forced over picker via SR_PLATEAU_FORCE, excluded from UCB learner)\n",
		       plateau_forced);

	/* Plateau intervention mode rotation distribution.  Suppressed when
	 * no plateau-forced window has run yet (plateau_forced == 0); when
	 * it has, the per-mode window counts let the operator divide each
	 * mode's contribution to rescue yield by the windows it actually
	 * ran without reconstructing the rotation history from bandit_
	 * pulls_by_reason.  The current mode line names what the next pick
	 * during a live intervention would run; PIM_UNIFORM_RANDOM is the
	 * resting value outside an intervention so a "current mode:
	 * UNIFORM_RANDOM" reading at end-of-run is correct (the
	 * orchestrator cleared the mode on the last non-intervention
	 * rotation), not the most recent intervention mode. */
	if (plateau_forced > 0) {
		unsigned long mode_windows[NR_PIM_MODES];
		int pim;
		int cur_mode;

		for (pim = 0; pim < NR_PIM_MODES; pim++)
			mode_windows[pim] = __atomic_load_n(
				&shm->plateau_intervention_mode_windows[pim],
				__ATOMIC_RELAXED);

		output(0, "  intervention modes:");
		for (pim = 0; pim < NR_PIM_MODES; pim++)
			output(0, " %s=%lu",
			       plateau_intervention_mode_name(
				       (enum plateau_intervention_mode)pim),
			       mode_windows[pim]);
		output(0, "\n");

		cur_mode = __atomic_load_n(
			&shm->plateau_intervention_mode_current,
			__ATOMIC_RELAXED);
		if (cur_mode >= 0 && cur_mode < NR_PIM_MODES)
			output(0, "  intervention mode current: %s (live during an active plateau, resets to UNIFORM_RANDOM otherwise)\n",
			       plateau_intervention_mode_name(
				       (enum plateau_intervention_mode)cur_mode));

		/* Anti-prior baseline (mean per-syscall call count cached at
		 * the last PIM_ANTI_PRIOR rotation).  Zero means no
		 * anti-prior rotation has fired yet; non-zero means the
		 * accept gate has been live at some point with this
		 * baseline value as the inversion midpoint. */
		{
			unsigned long ap_baseline = __atomic_load_n(
				&shm->plateau_anti_prior_baseline_calls,
				__ATOMIC_RELAXED);
			if (ap_baseline > 0)
				output(0, "  anti-prior baseline: %lu calls/syscall (mean across MAX_NR_SYSCALL at last refresh)\n",
				       ap_baseline);
		}
	}

	/* Random-rescue classifier distribution.  Per-class counts only
	 * accumulate during SR_PLATEAU_FORCE intervention windows, so a
	 * run that never plateaued prints nothing here; on a run that
	 * did, the dominant class plus the currently-published
	 * amplification field together tell the operator which targeted
	 * intervention the orchestrator settled on by run-end.  Zero
	 * buckets are suppressed so the placeholder classes (UNUSUAL_FD_
	 * PRODUCER, WRONG_TYPE_FD, PERSONA_GATED) stay quiet until their
	 * detection infrastructure lands and starts crediting rescues to
	 * them. */
	{
		unsigned long total_rescues = 0;
		int c;

		for (c = 0; c < RRC_NR_CLASSES; c++)
			total_rescues += __atomic_load_n(
				&shm->random_rescue_class_count[c],
				__ATOMIC_RELAXED);

		if (total_rescues > 0) {
			int amp = __atomic_load_n(
				&shm->plateau_rescue_amplified_class,
				__ATOMIC_RELAXED);

			output(0, "  rescue classes: total=%lu", total_rescues);
			for (c = 0; c < RRC_NR_CLASSES; c++) {
				unsigned long count = __atomic_load_n(
					&shm->random_rescue_class_count[c],
					__ATOMIC_RELAXED);
				if (count == 0)
					continue;
				output(0, " %s=%lu",
				       random_rescue_class_name(
					       (enum random_rescue_class)c),
				       count);
			}
			output(0, "\n");

			/* Amplified class is the orchestrator's current
			 * pick; RRC_NR_CLASSES means no class is being
			 * amplified (either the run is not in a plateau
			 * intervention right now or no class cleared the
			 * dominance threshold).  Print the threshold
			 * outcome explicitly so the operator can
			 * distinguish "no amplification because below
			 * floor" from "no amplification because the lead
			 * over the runner-up was too thin". */
			if (amp >= 0 && amp < RRC_NR_CLASSES)
				output(0, "  rescue amplified: %s (next intervention biased toward this class's structured replay)\n",
				       random_rescue_class_name(
					       (enum random_rescue_class)amp));
			else
				output(0, "  rescue amplified: none (no class crossed the %lu-rescue floor with a %lux lead)\n",
				       RRC_AMPLIFY_MIN_COUNT,
				       RRC_AMPLIFY_LEAD_RATIO);
		}
	}

	/* Hybrid bandit/explorer split summary.  Suppressed when the run had
	 * no explorers reserved (explorer_children == 0) -- the bandit-pool
	 * counter still ran but there is nothing to compare it against.
	 *
	 * Framed as a head-to-head competition: both pools feed the same
	 * global KCOV edge bitmap and CMP bloom, so each first-discovery
	 * edge is credited to whichever pool reached it first.  The lead
	 * line shows the direct edge-share split so the operator can see
	 * at a glance whether the always-on STRATEGY_RANDOM baseline is
	 * stealing a disproportionate share of easy coverage from the
	 * learned strategy.  Beyond the head-to-head line this block
	 * derives:
	 *   - per-child rate for each pool (edges / pool size), so the
	 *     larger pool isn't credited just for having more workers
	 *   - explorer fleet share for context against the edge share
	 *   - one-line verdict (over-performing / at parity / under-)
	 *     against the 2x-fleet-share threshold from the design doc.
	 *     Hitting >=2x sustained across multiple runs is the trigger
	 *     for considering per-child bandit (Option C). */
	if (explorer_children > 0) {
		unsigned int bandit_children;
		unsigned long total_edges;
		unsigned long per_explorer, per_bandit;
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

		/* Per-child rate: rounded down to nearest whole edge.  A run
		 * too short for meaningful per-child rates renders as zero
		 * and that's an informative diagnostic. */
		per_explorer = explorer_edges / explorer_children;
		per_bandit = bandit_children > 0 ?
			bandit_edges / bandit_children : 0;

		/* Head-to-head competing-pools line.  The two pools both
		 * feed the same global KCOV edge bitmap and CMP bloom -- a
		 * first-discovery edge is credited to whichever pool reached
		 * it first, so the per-pool counters represent direct
		 * competition for the same coverage surface, not two
		 * independent measurements.  Render them on one line with
		 * the edge-share split as a percentage so the operator can
		 * see the head-to-head outcome at a glance, then break the
		 * components out beneath for the per-child rate. */
		if (total_edges > 0) {
			unsigned long e_share_pct_x10 =
				(explorer_edges * 1000UL) / total_edges;
			unsigned long b_share_pct_x10 = 1000UL - e_share_pct_x10;

			output(0, "  edge race: explorer %lu (%lu.%lu%%) vs bandit %lu (%lu.%lu%%) of %lu first-discovery edges\n",
			       explorer_edges,
			       e_share_pct_x10 / 10, e_share_pct_x10 % 10,
			       bandit_edges,
			       b_share_pct_x10 / 10, b_share_pct_x10 % 10,
			       total_edges);
		} else {
			output(0, "  edge race: explorer %lu vs bandit %lu (no edges yet)\n",
			       explorer_edges, bandit_edges);
		}
		output(0, "    explorer: %u children, %lu edges (%lu per child)\n",
		       explorer_children, explorer_edges, per_explorer);
		output(0, "    bandit:   %u children, %lu edges (%lu per child)\n",
		       bandit_children, bandit_edges, per_bandit);

		/* Edge-share verdict against the fleet-share-normalised
		 * ratio.  Suppressed on a zero-edge run or when there are
		 * no bandit children -- nothing meaningful to compare. */
		if (total_edges > 0 && bandit_children > 0) {
			unsigned int fleet_pct_x10 =
				explorer_children * 1000U / max_children;

			output(0, "    fleet share: explorer %u/%u children (%u.%u%%)\n",
			       explorer_children, max_children,
			       fleet_pct_x10 / 10U, fleet_pct_x10 % 10U);

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
				verdict = "explorer pool under-performing (bandit is winning the easy edges)";
			else
				verdict = "explorer pool at parity";
			output(0, "    verdict: %s (edge-share/fleet-share ratio %lu.%02lux)\n",
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
		unsigned long picks = __atomic_load_n(&shm->strategy_picks[i],
						      __ATOMIC_RELAXED);
		unsigned long bandit_ops = __atomic_load_n(
			&shm->strategy_bandit_pool_ops[i], __ATOMIC_RELAXED);
		unsigned long completed = __atomic_load_n(
			&shm->strategy_completed_calls[i], __ATOMIC_RELAXED);
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

		/* Exposure line: per-arm syscall-level denominators alongside
		 * the window-level reward summary above.  picks is the widest
		 * population (all dispatched syscalls credited to the arm,
		 * explorer included); bandit_ops is the strict bandit-pool
		 * subset (picks - bandit_ops is the explorer contribution,
		 * which is zero for non-RANDOM arms by construction);
		 * completed is the count that reached the end of dispatch_step
		 * without a set_syscall_nr FAIL upstream.  The
		 * completed/picks ratio surfaces arms whose picker policy is
		 * burning picks on unsatisfiable pick-side gates without
		 * actually dispatching a call. */
		if (picks > 0) {
			unsigned long success_x1000 =
				(completed * 1000UL) / picks;
			output(0, "    exposure: picks=%lu bandit_ops=%lu completed=%lu (success=%lu.%lu%%)\n",
			       picks, bandit_ops, completed,
			       success_x1000 / 10UL, success_x1000 % 10UL);
		}

		/* Reason breakdown: split this arm's window count and reward
		 * by selection path.  Walk all reasons but only print the
		 * ones with nonzero pulls so cold paths (e.g. SR_ROUND_ROBIN
		 * under PICKER_BANDIT_UCB1, SR_PLATEAU_FORCE on a run that
		 * never hit a plateau) stay quiet.  PLATEAU_FORCE rewards
		 * appear here even though they are excluded from the
		 * per-arm bandit_pulls / bandit_reward_calls totals above --
		 * the per-reason matrix is exactly where the intervention
		 * cohort's reward goes so the operator can size it against
		 * the policy cohort.  Format: REASON=pulls/reward_calls, one
		 * leading-space-indented continuation line per arm. */
		{
			bool any_reason = false;
			int r;

			for (r = 0; r < NR_SELECTION_REASONS; r++) {
				unsigned long rp = __atomic_load_n(
					&shm->bandit_pulls_by_reason[i][r],
					__ATOMIC_RELAXED);
				unsigned long rr = __atomic_load_n(
					&shm->bandit_reward_calls_by_reason[i][r],
					__ATOMIC_RELAXED);
				if (rp == 0)
					continue;
				if (!any_reason) {
					output(0, "    reasons:");
					any_reason = true;
				}
				output(0, " %s=%lu/%lu",
				       strategy_selection_reason_name(
					       (enum strategy_selection_reason)r),
				       rp, rr);
			}
			if (any_reason)
				output(0, "\n");
		}
	}
}
