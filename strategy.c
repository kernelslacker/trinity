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
	unsigned long now_window;
	int i;

	if (arm < 0 || arm >= NR_STRATEGIES)
		return;

	cmp_term = cmp_new_constants / CMP_BANDIT_REWARD_WEIGHT_RECIPROCAL;
	total = pc_edge_calls + cmp_term;

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
	 * runs alongside the lifetime fields above; the picker still reads
	 * the lifetime fields today and will be flipped to the recent
	 * series in a follow-up commit. */
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
