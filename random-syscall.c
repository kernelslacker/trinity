/*
 * Call a single random syscall with random args.
 */

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "arch.h"	// biarch
#include "arg-decoder.h"
#include "child.h"
#include "cmp_hints.h"
#include "cred_throttle.h"
#include "debug.h"
#include "fd.h"
#include "kcov.h"
#include "locks.h"
#include "minicorpus.h"
#include "params.h"
#include "pids.h"
#include "pre_crash_ring.h"
#include "prop_ring.h"
#include "random.h"
#include "rnd.h"
#include "sequence.h"
#include "shm.h"
#include "signals.h"
#include "sanitise.h"
#include "stats.h"
#include "stats_ring.h"
#include "strategy.h"
#include "syscall.h"
#include "syscall_record.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"

/* The per-pending-index success counter in kcov_shared is sized off
 * REEXEC_PENDING_PICK_HIST_NR (include/kcov.h); the per-call attribution
 * buffer it indexes is sized off MAX_REEXEC_PENDING (include/cmp_hints.h).
 * They MUST stay equal -- a wider counter under-uses the kcov_shm field
 * and a narrower one would let the clamped index drop the last slots'
 * success signal on the floor.  kcov.h does not include cmp_hints.h
 * (to stay self-contained), so the parity check lives here, where both
 * headers are in scope. */
_Static_assert(REEXEC_PENDING_PICK_HIST_NR == MAX_REEXEC_PENDING,
	       "REEXEC_PENDING_PICK_HIST_NR must equal MAX_REEXEC_PENDING");

/*
 * Compression factor for the frontier-weighted acceptance denominator.
 * See the gate in set_syscall_nr_frontier() for the rationale.
 */
#define FRONTIER_SOFT_SCALE 16

/*
 * Acceptance-weight scale for the cold/untried-syscall fallback path in
 * set_syscall_nr_coverage_frontier().  Engaged when the frontier ring
 * is silent (max_weight <= 2) so the picker has a per-syscall signal
 * to steer on instead of degenerating to plain uniform draw -- see the
 * fallback gate for the full rationale.
 *
 * Sized at 256 to give the integer-divide inverse-productivity transform
 * (SCALE - floor(SCALE * edges / calls)) sub-percent discrimination: at
 * the previous SCALE=16, any syscall productive at < 6.25% (= 1/16) of
 * its calls floored the divide to 0 and collapsed to MAX, indistinguishable
 * from a never-tried slot.  At SCALE=256 the same divide resolves down
 * to ~0.4%/step, so syscalls with even a handful of productive calls in
 * the high-thousands range no longer pin at the cold ceiling.  256 is
 * also the Q8.8 unit used by adapt_budget's mult table -- staying on a
 * power-of-two keeps the rnd_modulo_u32(SCALE + 1) draw in the same
 * Lemire fast-path the soft-max path already uses.
 */
#define FRONTIER_COLD_SCALE 256

static inline unsigned ilog2_ul(unsigned long x)
{
	return x ? (unsigned)(63 - __builtin_clzl(x)) : 0;
}

/*
 * This function decides if we're going to be doing a 32bit or 64bit syscall.
 * There are various factors involved here, from whether we're on a 32-bit only arch
 * to 'we asked to do a 32bit only syscall' and more.. Hairy.
 */

/*
 * Biarch-only: pick which syscall table this call uses, refresh the
 * caller's per-child active_syscalls pointer, and return do32.  Uniarch
 * builds bypass this entirely — child->active_syscalls is set once at
 * init time to shm->active_syscalls and never re-evaluated.
 *
 * *nr_syscalls_out receives the current shm->nr_active_*bit_syscalls
 * count, NOT max_nr_*syscalls: the picker samples the compact
 * active_syscalls[0..nr_active) prefix maintained by
 * activate_syscall_in_table()/deactivate_syscall_in_table(), and
 * sampling the full max table on a restricted run (capability filter,
 * -c/-r/-g, runtime deactivation) burns the retry budget on slots known
 * to be zero.  The load is a snapshot — a racing deactivate that lowers
 * the count after we read it is absorbed by the zero-retry guard at the
 * picker (deactivate swap-removes and zeros the LAST slot, so a stale
 * read can see a transient 0 mid-swap).
 */
bool choose_syscall_table(struct childdata *child,
			  unsigned int *nr_syscalls_out)
{
	bool do32 = false;

	/* First, check that we have syscalls enabled in either table.
	 * Read the cached validity bits maintained by validate_syscall_table_*
	 * and the deactivate_syscall{32,64}() paths instead of re-running the
	 * walk on every pick. */
	if (__atomic_load_n(&shm->valid_syscall_table_64, __ATOMIC_RELAXED) == false) {
		use_64bit = false;
		/* If no 64bit syscalls enabled, force 32bit. */
		do32 = true;
	}

	if (__atomic_load_n(&shm->valid_syscall_table_32, __ATOMIC_RELAXED) == false)
		use_32bit = false;

	/* If both tables enabled, pick randomly. */
	if ((use_64bit == true) && (use_32bit == true)) {
		/* 10% possibility of a 32bit syscall */
		if (ONE_IN(10))
			do32 = true;
	}

	if (do32 == false) {
		syscalls = syscalls_64bit;
		child->active_syscalls = shm->active_syscalls64;
		*nr_syscalls_out = __atomic_load_n(&shm->nr_active_64bit_syscalls,
						   __ATOMIC_RELAXED);
	} else {
		syscalls = syscalls_32bit;
		child->active_syscalls = shm->active_syscalls32;
		*nr_syscalls_out = __atomic_load_n(&shm->nr_active_32bit_syscalls,
						   __ATOMIC_RELAXED);
	}
	return do32;
}

/*
 * Validation-failure resilience: a syscallnr drawn by the picker is
 * deactivated only after VALIDATE_FAIL_THRESHOLD consecutive picks of
 * that syscall fail validate_specific_syscall_silent().  A transient
 * flap (e.g. a probe that EAGAIN'd once or briefly tripped a kernel
 * gate) used to permanently kill the entry on the first failure with
 * no log; now the counter has to build up and the deactivation is
 * announced.  The counter (shm->syscall_validation_failures[]) is
 * shared across children so observation accumulates fleet-wide, and
 * resets to 0 on the first successful validation for that slot.
 */
#define VALIDATE_FAIL_THRESHOLD 3

static void note_validation_success(unsigned int syscallnr, bool do32)
{
	unsigned int arch = do32 ? 1 : 0;

	if (__atomic_load_n(&shm->syscall_validation_failures[arch][syscallnr],
			    __ATOMIC_RELAXED) != 0)
		__atomic_store_n(&shm->syscall_validation_failures[arch][syscallnr],
				 0, __ATOMIC_RELAXED);
}

static void note_validation_failure(unsigned int syscallnr, bool do32)
{
	unsigned int arch = do32 ? 1 : 0;
	unsigned int count;
	struct syscallentry *entry;
	const char *name;

	count = (unsigned int)__atomic_add_fetch(
		&shm->syscall_validation_failures[arch][syscallnr], 1,
		__ATOMIC_RELAXED);
	if (count < VALIDATE_FAIL_THRESHOLD)
		return;

	entry = get_syscall_entry(syscallnr, do32);
	name = (entry != NULL) ? entry->name : "<unknown>";
	output(0, "deactivating syscall %s (nr=%u) after %u validation failures\n",
	       name, syscallnr, count);
	__atomic_store_n(&shm->syscall_validation_failures[arch][syscallnr], 0,
			 __ATOMIC_RELAXED);
	deactivate_syscall_locked(syscallnr, do32);
}

/*
 * Check if a syscall entry belongs to the target group.
 * Used by group biasing to filter candidates.
 */
static bool syscall_in_group(unsigned int nr, bool do32, unsigned int target_group)
{
	struct syscallentry *entry;

	entry = get_syscall_entry(nr, do32);
	if (entry == NULL)
		return false;

	return entry->group == target_group;
}

/*
 * Pick the syscall to run under STRATEGY_HEURISTIC: uniform draw from
 * active_syscalls, then layered biases — group affinity (70% prefer last
 * group) and kcov cold-skip (probabilistic).  This is trinity's
 * pre-rotation default behaviour.
 */
static bool set_syscall_nr_heuristic(struct syscallrecord *rec,
				     struct childdata *child)
{
	struct syscallentry *entry;
	unsigned int syscallnr;
	int val;
	bool do32;
	unsigned int group_attempts = 0;
	unsigned int kcov_attempts = 0;
	unsigned int outer_attempts = 0;
	unsigned int nr_syscalls;

	/* Pick the syscall table once per call: in uniarch the do32 result
	 * is a constant; in biarch the do32 dice rolls once per pick.  The
	 * nr_syscalls snapshot is the CURRENT active count
	 * (shm->nr_active_*) so the rnd_modulo_u32() draw indexes directly
	 * into the compact active_syscalls[0..nr_active) prefix and a
	 * restricted run never wastes the retry budget on the sparse-zero
	 * tail of the max table. */
	if (biarch) {
		do32 = choose_syscall_table(child, &nr_syscalls);
	} else {
		do32 = false;
		nr_syscalls = __atomic_load_n(&shm->nr_active_syscalls,
					      __ATOMIC_RELAXED);
	}

retry:
	if (no_syscalls_enabled() == true) {
		output(0, "[%d] No more syscalls enabled. Exiting\n", mypid());
		__atomic_store_n(&shm->exit_reason, EXIT_NO_SYSCALLS_ENABLED, __ATOMIC_RELAXED);
		return FAIL;
	}

	/* Bail if we have spent too many iterations failing to pick a
	 * usable syscall.  Even sampling the compact active prefix, a table
	 * dominated by EXPENSIVE syscalls (kept at 1-in-1000) can wedge
	 * the child in a tight retry loop. */
	if (outer_attempts++ > 10000) {
		output(0, "[%d] set_syscall_nr exceeded retry budget\n", mypid());
		return FAIL;
	}

	syscallnr = rnd_modulo_u32(nr_syscalls);

	/* If we got a syscallnr which is not active repeat the attempt,
	 * since another child has switched that syscall off already.*/
	val = child->active_syscalls[syscallnr];
	if (val == 0)
		goto retry;

	syscallnr = val - 1;

	/*
	 * EXPENSIVE early-out: bitmap test before validate + entry fetch,
	 * so the 999/1000 reject path skips the cache miss on the
	 * syscallentry that the EXPENSIVE block below used to require.
	 */
	if (syscall_is_expensive(syscallnr, do32) && !ONE_IN(1000))
		goto retry;

	if (validate_specific_syscall_silent(syscalls, syscallnr) == false) {
		note_validation_failure(syscallnr, do32);
		goto retry;
	}
	note_validation_success(syscallnr, do32);

	entry = get_syscall_entry(syscallnr, do32);
	if (entry == NULL)
		goto retry;

	/*
	 * Group biasing: when enabled and we have a previous group context,
	 * bias selection toward syscalls in the same group.
	 *
	 * 70% of the time: prefer same group as last call
	 * 25% of the time: accept any syscall (no bias)
	 *  5% of the time: accept any syscall (exploration)
	 *
	 * If we can't find a same-group syscall after 20 attempts,
	 * fall through and accept whatever we picked.
	 */
	if (group_bias && child->last_group != GROUP_NONE) {
		unsigned int dice = rnd_modulo_u32(100);

		if (dice < 70) {
			/* Try to pick from same group */
			if (!syscall_in_group(syscallnr, do32, child->last_group)) {
				group_attempts++;
				if (group_attempts < 20)
					goto retry;
				/* Gave up, accept this one. */
			}
		}
		/* dice >= 70: accept any syscall */
	}

	/* Coverage-guided cold avoidance: if this syscall has stopped
	 * finding new edges, skip it with a probability that grows the
	 * staler it gets — a syscall stuck for one threshold-window gets
	 * the same 50% baseline as before, but one stuck for ten gets
	 * skipped 90% of the time.
	 *
	 * Suppressed inside a SR_PLATEAU_FORCE intervention when the
	 * random-rescue classifier has accumulated enough RRC_COLD_SKIP
	 * evidence to amplify that class: the rescues that have been
	 * carrying the fleet past the plateau are mostly cold-skipped
	 * syscalls, and structured replay means letting the heuristic
	 * actually pick them.  Both gates checked because either alone
	 * is insufficient -- plateau_active without amplification means
	 * a different class won, and amplification cannot stay live
	 * after the plateau lifts (the orchestrator clears the field on
	 * its next non-intervention rotation). */
	if (!plateau_rescue_bias_active_for(RRC_COLD_SKIP)) {
		unsigned int skip_pct = kcov_syscall_cold_skip_pct(syscallnr);

		if (skip_pct > 0 && rnd_modulo_u32(100) < skip_pct) {
			kcov_attempts++;
			if (kcov_attempts < 20)
				goto retry;
		}
	}

	/* --cred-throttle gate.  Returns false unconditionally when the flag
	 * is off (single RELAXED bool load short-circuit, no per-class state
	 * touched) so the default picker distribution is byte-identical.
	 * Placed AFTER validate/EXPENSIVE/group/cold-skip so a rejected pick
	 * shares the existing outer_attempts budget instead of needing its
	 * own retry cap. */
	if (cred_throttle_should_reject(syscallnr, do32))
		goto retry;

	/* publish (nr, do32bit) as a coherent pair. */
	srec_publish_begin(rec);
	rec->do32bit = do32;
	rec->nr = syscallnr;
	srec_publish_end(rec);

	return true;
}

/*
 * Anti-prior reject-retry budget.  The accept gate's per-call rejection
 * rate sits at 1 - 1/MAX_BOOST = 87.5% at the median; over a sparse
 * active table this still resolves in a handful of retries on average,
 * but a pathological mix (e.g. every active syscall sitting at the
 * over-picked saturation point, accept = 1/MAX_BOOST^2) could push past
 * the natural recovery budget.  Bound at 64 so the inner loop never
 * burns more than the per-iteration cost is worth; falling through
 * means accepting whatever the picker happened to land on, which
 * degrades anti-prior gracefully to uniform pick rather than wedging
 * the syscall picker.  Kept well below the outer 10000 budget so the
 * gate cannot starve the rest of the validate / EXPENSIVE gates.
 */
#define ANTI_PRIOR_RETRY_CAP 64U

/*
 * Pick the syscall to run under STRATEGY_RANDOM: uniform draw from
 * active_syscalls with no further biasing.  The "shake the dust off"
 * pass — useless on its own, but exposes paths the heuristic biases
 * systematically suppress (cold syscalls, productive-pair-only flow).
 *
 * Active_syscalls + EXPENSIVE + AVOID_SYSCALL gating remain because
 * those are correctness gates, not selection biases — bypassing them
 * just wastes iterations on calls we know we can't make.
 *
 * Anti-prior plateau intervention: during an SR_PLATEAU_FORCE window
 * the orchestrator may have rotated into PIM_ANTI_PRIOR mode, in which
 * case the per-candidate accept gate inverts the picker's learned
 * per-syscall pick-rate distribution -- syscalls the bandit has been
 * over-selecting get rejected at up to MAX_BOOST^2:1, low-count
 * syscalls accept at full uniform rate.  Outside the intervention the
 * gate's atomic load short-circuits and the picker is the historical
 * pure-uniform draw.
 */
bool set_syscall_nr_random(struct syscallrecord *rec,
			    struct childdata *child)
{
	unsigned int syscallnr;
	int val;
	bool do32;
	unsigned int outer_attempts = 0;
	unsigned int nr_syscalls;
	unsigned int anti_prior_attempts = 0;
	bool anti_prior_on;

	/* See the matching comment in set_syscall_nr_heuristic — the table
	 * pick is a per-call decision, not a per-retry one, and nr_syscalls
	 * is the active-prefix count rather than max_nr_*syscalls. */
	if (biarch) {
		do32 = choose_syscall_table(child, &nr_syscalls);
	} else {
		do32 = false;
		nr_syscalls = __atomic_load_n(&shm->nr_active_syscalls,
					      __ATOMIC_RELAXED);
	}

	/* Latch the anti-prior mode once per pick so the per-retry inner
	 * loop reads a stable answer; a rotation that lands mid-pick is
	 * harmless either way (we either over-shoot one retry budget or
	 * under-shoot one) but caching avoids redoing the relaxed atomic
	 * load on every retry. */
	anti_prior_on = plateau_anti_prior_active();

retry:
	if (no_syscalls_enabled() == true) {
		output(0, "[%d] No more syscalls enabled. Exiting\n", mypid());
		__atomic_store_n(&shm->exit_reason, EXIT_NO_SYSCALLS_ENABLED, __ATOMIC_RELAXED);
		return FAIL;
	}

	if (outer_attempts++ > 10000) {
		output(0, "[%d] set_syscall_nr_random exceeded retry budget\n", mypid());
		return FAIL;
	}

	syscallnr = rnd_modulo_u32(nr_syscalls);

	val = child->active_syscalls[syscallnr];
	if (val == 0)
		goto retry;

	syscallnr = val - 1;

	/* EXPENSIVE early-out: bitmap test before validate + entry fetch,
	 * so the 999/1000 reject path skips the cache miss on the
	 * syscallentry that the EXPENSIVE block below used to require. */
	if (syscall_is_expensive(syscallnr, do32) && !ONE_IN(1000))
		goto retry;

	if (validate_specific_syscall_silent(syscalls, syscallnr) == false) {
		note_validation_failure(syscallnr, do32);
		goto retry;
	}
	note_validation_success(syscallnr, do32);

	/* Anti-prior accept gate.  Applied AFTER the active/validate/
	 * EXPENSIVE correctness gates so a rejected anti-prior candidate
	 * goes back through the uniform pick rather than burning the gate
	 * budget on disabled or AVOID-flagged syscalls.  Bounded retry
	 * budget so an extreme distribution falls back to uniform instead
	 * of wedging the picker. */
	if (anti_prior_on && !plateau_anti_prior_accept(syscallnr)) {
		anti_prior_attempts++;
		if (anti_prior_attempts < ANTI_PRIOR_RETRY_CAP)
			goto retry;
		/* Budget exhausted -- accept the current candidate and let
		 * the next pick re-roll.  The intervention's per-window
		 * shape stays anti-prior on average even if individual
		 * picks fall through. */
	}

	/* --cred-throttle gate.  Same contract as the matching call site in
	 * set_syscall_nr_heuristic above: byte-identical default when the
	 * flag is off, and the outer_attempts budget absorbs the retries. */
	if (cred_throttle_should_reject(syscallnr, do32))
		goto retry;

	srec_publish_begin(rec);
	rec->do32bit = do32;
	rec->nr = syscallnr;
	srec_publish_end(rec);

	return true;
}

/*
 * Cold-syscall weight for the frontier picker's plateau fallback path.
 * Returns a value in [0, FRONTIER_COLD_SCALE] that the accept gate in
 * set_syscall_nr_coverage_frontier() consumes as the bias toward this
 * syscall when the frontier ring has gone silent.  Higher = more biased
 * toward picking this syscall.
 *
 * Three regimes, deliberately distinguished:
 *
 *   calls == 0 (never invoked)
 *     -- return FRONTIER_COLD_SCALE.  Maximum bias.  These are
 *        genuinely under-explored slots the picker should be steering
 *        to.
 *
 *   calls > 0 && edges == 0 (invoked, never productive)
 *     -- return 0.  Minimum bias.  The syscall has had its shot and
 *        failed to produce any new coverage; biasing toward it pulls
 *        the picker into a bug-graveyard where it spends the plateau
 *        re-running calls that already established themselves as
 *        unproductive.  The +1 smoothing on w in the caller's accept
 *        gate keeps these syscalls reachable at the uniform floor
 *        ((0+1)/(SCALE+1)) rather than starving entirely.
 *
 *   calls > 0 && edges > 0 (invoked, some productivity)
 *     -- return SCALE - floor(SCALE * edges / calls).  Linear inverse
 *        productivity, same shape as before but at the new SCALE
 *        resolution: a perfectly productive syscall (edges == calls)
 *        lands at 0, a syscall that has produced a small fraction of
 *        new edges across many calls keeps a near-full weight.
 *        edges <= calls by construction so the subtraction can't
 *        underflow.
 *
 * The previous shape conflated the first two regimes: both never-tried
 * and tried-but-broken returned SCALE, so the plateau-fallback picker
 * weighted the bug-graveyard identically to the genuinely under-explored
 * frontier and burned its picks re-running known dead-ends.  Splitting
 * the two regimes is the headline fix; the SCALE bump (16 -> 256, see
 * the FRONTIER_COLD_SCALE macro comment) is what lets the third regime's
 * integer divide actually distinguish productivity below ~6% from MAX
 * instead of flooring everything in that range to the ceiling.
 *
 * Semantics note: per_syscall_edges has "bumps by 1 per call that
 * discovered >=1 new edge" semantics (see include/kcov.h), not raw
 * bucket-edge counts, so edges <= calls by construction.  Reads are
 * RELAXED -- a stale snapshot is harmless; a racing kcov_collect bump
 * that lands mid-pick only shifts the weight by one step, well inside
 * the slack the outer accept/retry loop already tolerates.
 *
 * Returns the uniform-floor (FRONTIER_COLD_SCALE) when kcov_shm is
 * unavailable so the caller's accept gate degrades to plain uniform
 * pick rather than wedging on a NULL deref -- matches the kcov-less
 * fallback the rest of the codebase already takes (see
 * kcov_syscall_cold_skip_pct in kcov.c for the sibling pattern).
 */
static unsigned long frontier_cold_weight(unsigned int nr,
					  struct childdata *child)
{
	unsigned long edges, calls;
	unsigned long bucket_bits, distinct_pcs;
	unsigned long transition_edges_real_local;
	unsigned long old_weight, blend_weight;
	unsigned long blend_productivity;
	enum kcov_transition_reward_mode trew_mode;

	if (kcov_shm == NULL || nr >= MAX_NR_SYSCALL)
		return FRONTIER_COLD_SCALE;

	calls = __atomic_load_n(&kcov_shm->per_syscall_calls[nr],
				__ATOMIC_RELAXED);

	/* Never invoked: MAX bias, genuinely under-explored.  Bypass the
	 * shadow A/B math entirely -- both formulas agree on
	 * FRONTIER_COLD_SCALE in this case and the early return keeps the
	 * cold-path overhead untouched for syscalls that have never seen
	 * a single call. */
	if (calls == 0)
		return FRONTIER_COLD_SCALE;

	edges = __atomic_load_n(&kcov_shm->per_syscall_edges[nr],
				__ATOMIC_RELAXED);

	/* OLD weight (call-count only): the live-path productivity signal
	 * this function has always returned.  Logic preserved verbatim from
	 * the pre-blend implementation.  Computed unconditionally so the
	 * SHADOW blend below can compare against it, then returned at the
	 * tail so the picker's per-syscall distribution stays byte-
	 * identical to today.
	 *
	 *  edges == 0 -- invoked but never productive (bug-graveyard);
	 *  edges >= calls -- RELAXED-load inversion against the steady-
	 *                    state edges <= calls invariant, treat as
	 *                    fully productive (would otherwise underflow
	 *                    the unsigned subtract).
	 *
	 * The caller's (w+1)/(SCALE+1) accept floor keeps a w == 0
	 * syscall reachable in both regimes. */
	if (edges == 0)
		old_weight = 0;
	else if (edges >= calls)
		old_weight = 0;
	else
		old_weight = FRONTIER_COLD_SCALE -
			     (edges * FRONTIER_COLD_SCALE) / calls;

	/* BLENDED weight (formerly SHADOW-ONLY, now mode-gated): treat
	 * per_syscall_edges (call-count of productive calls) as the stable
	 * backbone and ADD logarithmic credit for three disjoint per-call
	 * yield signals:
	 *
	 *   bucket_bits_real
	 *       PC bit transitions across the AFL-style hit-count buckets
	 *       (per_syscall_diag[].bucket_bits_real).  Fires when a known
	 *       edge moves into a never-seen hit-count bucket -- "new
	 *       behaviour on known code".  Weight 1x.
	 *
	 *   distinct_pcs
	 *       First-sight PC events (per_syscall_diag[].distinct_pcs):
	 *       dedup_inc first-sightings of a PC the global bitmap had
	 *       not seen.  Unambiguous new coverage; weighted 2x to
	 *       reflect higher signal-to-noise than the bucket-bit term.
	 *
	 *   transition_edges_real_local  (THIS COMMIT)
	 *       New transition slots flipped (per_syscall_transition_edges_
	 *       real_local): a 0 -> 1 in the (prev_canon_pc, cur_canon_pc)
	 *       hash, restricted to local-mode traces.  Fires when a new
	 *       ORDERING between two PCs is observed -- can happen on
	 *       warm-known code (a new route through already-mapped
	 *       blocks).  Weight 1x: symmetric to bucket_bits in that a
	 *       transition can fire on already-known edges, so the
	 *       higher-confidence 2x slot stays reserved for distinct_pcs.
	 *
	 * The three terms are STRICTLY DISJOINT discovery signals: a
	 * single PC-edge discovery bumps {edges, bucket_bits_real,
	 * distinct_pcs}; a single transition discovery bumps
	 * {transition_edges_real_local} and (via kcov_collect's separate
	 * branch) {per_syscall_transition_edges_real}.  A call that
	 * discovers both kinds of novelty correctly contributes to both
	 * terms because two distinct novelty events happened -- there is
	 * no double-counting.  Composition with the PC-edge backbone
	 * coordinated with 86ee2986cec8 ("random-syscall: shadow-score
	 * blended frontier cold weight"), which landed the bucket-bits
	 * and distinct-pcs terms; this commit adds the disjoint
	 * transition term and returns blend_weight under COMBINED mode
	 * instead of always returning old_weight.
	 *
	 * Diag counters are split by [nr][do32]; sum both arch slots so
	 * the blend's productivity numerator pairs against the unsplit
	 * per_syscall_calls denominator above -- matches the unsplit
	 * per_syscall_edges shape the old branch uses.  Transitions are
	 * unsplit by [do32] (the per_syscall_transition_edges family
	 * never grew the arch split), so a single load suffices for the
	 * transition term.
	 *
	 * ilog2() is the per-call contribution clamp on each term: a
	 * syscall whose single huge trace dumped a million transition
	 * slots contributes ~20 to the score, not a million, so one
	 * productive call cannot monopolize the frontier window.
	 *
	 * blend_productivity is capped at calls so the SCALE subtraction
	 * cannot underflow -- same invariant the OLD branch above relies
	 * on for the productive range.
	 *
	 * The transition term is folded only when kcov_transition_reward_
	 * mode != OFF.  Under SHADOW_ONLY the term IS folded into
	 * blend_weight (so the A/B counters below measure the divergence
	 * the COMBINED switch would activate); the function still returns
	 * old_weight, so live selection stays byte-identical.  Under OFF
	 * the term is zeroed so blend_weight reproduces the pre-commit
	 * formula exactly, keeping the A/B counters comparable to runs
	 * recorded before this commit landed. */
	trew_mode = __atomic_load_n(&kcov_transition_reward_mode,
				    __ATOMIC_RELAXED);

	bucket_bits = __atomic_load_n(
			&kcov_shm->per_syscall_diag[nr][0].bucket_bits_real,
			__ATOMIC_RELAXED) +
		      __atomic_load_n(
			&kcov_shm->per_syscall_diag[nr][1].bucket_bits_real,
			__ATOMIC_RELAXED);
	distinct_pcs = __atomic_load_n(
			&kcov_shm->per_syscall_diag[nr][0].distinct_pcs,
			__ATOMIC_RELAXED) +
		       __atomic_load_n(
			&kcov_shm->per_syscall_diag[nr][1].distinct_pcs,
			__ATOMIC_RELAXED);
	transition_edges_real_local =
		(trew_mode == KCOV_TRANSITION_REWARD_OFF) ? 0UL :
		__atomic_load_n(
			&kcov_shm->per_syscall_transition_edges_real_local[nr],
			__ATOMIC_RELAXED);

	blend_productivity = edges +
			     (unsigned long)ilog2_ul(bucket_bits + 1UL) +
			     2UL * (unsigned long)ilog2_ul(distinct_pcs + 1UL) +
			     (unsigned long)ilog2_ul(transition_edges_real_local + 1UL);
	if (blend_productivity >= calls)
		blend_weight = 0;
	else
		blend_weight = FRONTIER_COLD_SCALE -
			       (blend_productivity * FRONTIER_COLD_SCALE) /
			       calls;

	/* A/B counters.  Bumped once per call so the operator can read
	 * the run-wide divergence pattern between the OLD (call-count
	 * only) and BLENDED (call-count + ilog2(bucket_bits) +
	 * 2*ilog2(distinct_pcs) + ilog2(transition_edges_real_local))
	 * productivity scores.  Counter names predate the transition
	 * term but the semantics ("how often the blend would steer
	 * differently") are unchanged.  The counters fire from both
	 * arms in lock-step so the would-be divergence stays observable
	 * regardless of which arm the calling child is stamped under;
	 * the LIVE behaviour delta from Arm B's blend_weight promotion
	 * shows up downstream in frontier_silent_picks / per-syscall
	 * pick rates rather than in these sums. */
	__atomic_fetch_add(&shm->stats.frontier_blend_samples, 1UL,
			   __ATOMIC_RELAXED);
	__atomic_fetch_add(&shm->stats.frontier_blend_old_weight_sum,
			   old_weight, __ATOMIC_RELAXED);
	__atomic_fetch_add(&shm->stats.frontier_blend_new_weight_sum,
			   blend_weight, __ATOMIC_RELAXED);
	if (blend_weight < old_weight)
		__atomic_fetch_add(&shm->stats.frontier_blend_new_lower,
				   1UL, __ATOMIC_RELAXED);
	else if (blend_weight > old_weight)
		__atomic_fetch_add(&shm->stats.frontier_blend_new_higher,
				   1UL, __ATOMIC_RELAXED);
	else
		__atomic_fetch_add(&shm->stats.frontier_blend_new_equal,
				   1UL, __ATOMIC_RELAXED);

	/* Per-child A/B arm promotes the blend (now including the
	 * transition term) to the live picker for half the children
	 * (Arm B); the other half (Arm A) returns the historical OLD
	 * weight so the picker's per-syscall distribution stays byte-
	 * identical to the pre-blend baseline for that cohort.  The
	 * frontier_blend_* shm counters above record the would-be
	 * divergence for both arms in lock-step, so the operator can
	 * read the live promotion delta off a single run instead of
	 * gating it on a fleet-wide mode flip.  child==NULL (parent
	 * context, should not reach here under the FRONTIER picker)
	 * falls back to the OLD weight to preserve baseline behaviour. */
	if (child != NULL && child->frontier_blend_arm_b)
		return blend_weight;
	return old_weight;
}

/*
 * Pick the syscall to run under STRATEGY_COVERAGE_FRONTIER: uniform draw
 * from active_syscalls, then biased acceptance against the per-syscall
 * frontier-edge weight via rejection sampling.  Each candidate is
 * accepted with probability (frontier_recent_count(nr) + 1) /
 * (max_weight + 1); the +1 keeps cold syscalls from starving completely
 * and lets the strategy still drive forward when no syscall has
 * produced a frontier edge in the last K windows.
 *
 * max_weight is read once at the top of the function from the cached
 * shm->frontier_max_weight_cached so the bias mass stays stable across
 * the inner retry loop, and so concurrent kcov_collect-driven bumps to
 * frontier_history during the pick don't perturb the acceptance
 * probability mid-call.  The cache is recomputed authoritatively on
 * each window rotation by frontier_window_advance() and ratcheted
 * upward on new-edge bumps by frontier_record_new_edge(), turning what
 * used to be an O(MAX_NR_SYSCALL) walk per pick into a single RELAXED
 * load.
 *
 * Plateau fallback (max_weight <= 2): the frontier ring decays to zero
 * everywhere at the plateau (a window with no new edges ages every slot
 * to 0 within FRONTIER_DECAY_WINDOWS rotations), which is exactly the
 * regime PIM_COVERAGE_FRONTIER pins ~25% of intervention windows on
 * FRONTIER for.  The original code fell through to plain uniform draw
 * in this branch, leaving FRONTIER strictly worse than RANDOM (no
 * anti-prior bias, no explorer-pool backing, no near-coverage signal --
 * nothing to steer on).  The fallback path replaces the bypass with a
 * cold/untried-syscall bias keyed on per_syscall_edges/per_syscall_calls
 * so the picker still steers toward under-explored syscalls when the
 * recent-frontier signal is gone.
 *
 * The validate / EXPENSIVE / AVOID_SYSCALL retry budget mirrors the
 * other set_syscall_nr_* variants because those are correctness gates,
 * not selection biases.
 */
static bool set_syscall_nr_coverage_frontier(struct syscallrecord *rec,
					     struct childdata *child)
{
	unsigned int syscallnr;
	unsigned int val;
	bool do32;
	unsigned int outer_attempts = 0;
	unsigned int nr_syscalls;
	unsigned long max_weight;

	if (biarch) {
		do32 = choose_syscall_table(child, &nr_syscalls);
	} else {
		do32 = false;
		nr_syscalls = __atomic_load_n(&shm->nr_active_syscalls,
					      __ATOMIC_RELAXED);
	}

	max_weight = __atomic_load_n(&shm->frontier_max_weight_cached,
				     __ATOMIC_RELAXED);

retry:
	if (no_syscalls_enabled() == true) {
		output(0, "[%d] No more syscalls enabled. Exiting\n", mypid());
		__atomic_store_n(&shm->exit_reason, EXIT_NO_SYSCALLS_ENABLED, __ATOMIC_RELAXED);
		return FAIL;
	}

	if (outer_attempts++ > 10000) {
		output(0, "[%d] set_syscall_nr_coverage_frontier exceeded retry budget\n", mypid());
		return FAIL;
	}

	syscallnr = rnd_modulo_u32(nr_syscalls);

	val = child->active_syscalls[syscallnr];
	if (val == 0)
		goto retry;

	syscallnr = val - 1;

	/* EXPENSIVE early-out: bitmap test before validate + entry fetch,
	 * so the 999/1000 reject path skips the cache miss on the
	 * syscallentry that the EXPENSIVE block below used to require. */
	if (syscall_is_expensive(syscallnr, do32) && !ONE_IN(1000))
		goto retry;

	if (validate_specific_syscall_silent(syscalls, syscallnr) == false) {
		note_validation_failure(syscallnr, do32);
		goto retry;
	}
	note_validation_success(syscallnr, do32);

	/* --cred-throttle gate.  Same contract as the matching call sites in
	 * set_syscall_nr_heuristic / set_syscall_nr_random above: returns
	 * false unconditionally when the flag is off so the frontier
	 * picker's distribution is byte-identical to today's default. */
	if (cred_throttle_should_reject(syscallnr, do32))
		goto retry;

	/* Frontier-weighted acceptance.  Two regimes share the same
	 * accept-probability shape ((w+1)/(denom+1)) so the inner-loop
	 * retry budget behaves identically across both:
	 *
	 *  - Live ring (max_weight > 2): weight = frontier_recent_count(nr),
	 *    the per-syscall sum across the K-window frontier ring.  Soften
	 *    the denominator via ilog2 so that a single very hot syscall
	 *    (max_weight in the 10k+ range) doesn't compress every cold-but-
	 *    real candidate to a near-zero acceptance probability and burn
	 *    the retry budget.  soft_max = ilog2(max) * SCALE keeps the
	 *    leader winning the majority of rolls while lifting a w=1
	 *    candidate from ~1/max to ~1/soft_max.  The +1 smoothing on w
	 *    is preserved as the uniform floor.
	 *
	 *  - Silent ring (max_weight <= 2): the frontier ring has aged out
	 *    everywhere, the defining state of a coverage plateau.  Without
	 *    a fallback the picker degenerates to a backing-less uniform
	 *    draw and ends up strictly worse than RANDOM (no anti-prior
	 *    bias, no explorer-pool backing, no near-coverage signal --
	 *    nothing to steer on) at exactly the windows the plateau
	 *    intervention pins it to.  Steer on lifetime cumulative ratios
	 *    instead: weight = INVERSE per-syscall productive-call ratio,
	 *    so the picker biases toward syscalls the fleet has under-
	 *    explored and away from the few syscalls that already produced
	 *    most of the saturated coverage. */
	if (max_weight > 2) {
		unsigned long w = frontier_recent_count(syscallnr);
		unsigned long soft_max = (unsigned long)ilog2_ul(max_weight) *
					 FRONTIER_SOFT_SCALE;
		unsigned long denom = soft_max + 1UL;
		unsigned long roll = (unsigned long)rnd_modulo_u32(denom);

		if (roll >= w + 1UL)
			goto retry;

		__atomic_fetch_add(&shm->stats.frontier_live_picks, 1UL,
				   __ATOMIC_RELAXED);
	} else {
		unsigned long w = frontier_cold_weight(syscallnr, child);
		unsigned long denom = (unsigned long)FRONTIER_COLD_SCALE + 1UL;
		unsigned long roll = (unsigned long)rnd_modulo_u32(denom);

		if (roll >= w + 1UL)
			goto retry;

		__atomic_fetch_add(&shm->stats.frontier_silent_picks, 1UL,
				   __ATOMIC_RELAXED);

		/* SHADOW-ONLY silent-streak accounting.  Mirrors the
		 * frontier_silent_picks bump above; counts CONSECUTIVE
		 * silent-regime accepts of this syscall since the last
		 * productive-edge event for it (reset to zero by
		 * frontier_record_new_edge() in strategy.c, the existing
		 * per-syscall new-edge hook in kcov_collect -- no new
		 * collection path is added).  When the post-increment value
		 * crosses FRONTIER_SHADOW_DECAY_STREAK the global
		 * frontier_shadow_decay_candidates counter bumps exactly
		 * once, the headline shadow stat that estimates how many
		 * decay-candidate syscalls a future LIVE silent-decay variant
		 * of this picker would have demoted, without changing any
		 * selection today.  Same MAX_NR_SYSCALL bound the
		 * frontier_picks_per_syscall[] bump below uses.
		 *
		 * Selection-byte-identical contract: the picker accept/retry
		 * math above this point is untouched; the bump runs strictly
		 * after the accept decision and writes only NEW counters
		 * that no live-path code reads.  Mirrors the same
		 * "observation-only, default off-by-construction" shape as
		 * the cred_throttle gate above so the frontier picker's
		 * distribution stays byte-identical to today. */
		if (syscallnr < MAX_NR_SYSCALL) {
			unsigned long streak = __atomic_add_fetch(
				&shm->stats.frontier_silent_streak_per_syscall[syscallnr],
				1UL, __ATOMIC_RELAXED);
			if (streak == FRONTIER_SHADOW_DECAY_STREAK)
				__atomic_fetch_add(
					&shm->stats.frontier_shadow_decay_candidates,
					1UL, __ATOMIC_RELAXED);

			/* SHADOW-ONLY tightened decay predicate.  Pairs with
			 * the looser frontier_shadow_decay_candidates bump
			 * above: the looser counter fires on N-silent alone
			 * (no PC novelty since reset, since the streak is
			 * reset by frontier_record_new_edge() / _transition_
			 * edge() on the PC-edge and transition productive
			 * paths).  The tighter predicate here additionally
			 * requires that NEITHER per-syscall CMP-pool inserts
			 * NOR the SUCCESS-bucket errno count has advanced
			 * since the streak's last reset -- the "no recent
			 * CMP novelty and no useful errno shift" UNLESS
			 * clause that distinguishes a genuinely-stuck
			 * candidate from one whose non-PC novelty stream is
			 * still moving.
			 *
			 * Baseline snapshots are refreshed at every streak
			 * reset (in strategy.c) so a current-vs-baseline
			 * equality test is sufficient -- no per-pick stash
			 * is needed.  Atomic loads under RELAXED ordering:
			 * shadow predicate, racing producer bumps are
			 * tolerated (worst case is a one-pick over/under-
			 * count of the shadow counters, never a perturbation
			 * of live selection).
			 *
			 *  frontier_decay_candidates
			 *      Edge bump: fires on the (streak ==
			 *      FRONTIER_SHADOW_DECAY_STREAK) crossing when
			 *      the UNLESS clause holds, the tighter sibling
			 *      of the frontier_shadow_decay_candidates bump
			 *      above.  Strictly <= the looser counter by
			 *      construction.
			 *  frontier_decay_would_skip
			 *      Cumulative bump on every silent-regime pick
			 *      where the streak is already past threshold
			 *      AND the UNLESS clause holds -- the projected
			 *      demote count a live silent-decay variant of
			 *      this picker would produce. */
			if (streak >= FRONTIER_SHADOW_DECAY_STREAK &&
			    kcov_shm != NULL) {
				unsigned long cmp_now, cmp_base;
				unsigned long errno_now, errno_base;

				cmp_now = __atomic_load_n(
					&kcov_shm->per_syscall_cmp_inserts[syscallnr],
					__ATOMIC_RELAXED);
				cmp_base = __atomic_load_n(
					&shm->stats.frontier_silent_cmp_baseline[syscallnr],
					__ATOMIC_RELAXED);
				errno_now = __atomic_load_n(
					&kcov_shm->per_syscall_errno[syscallnr][ERRNO_BUCKET_SUCCESS],
					__ATOMIC_RELAXED);
				errno_base = __atomic_load_n(
					&shm->stats.frontier_silent_errno_success_baseline[syscallnr],
					__ATOMIC_RELAXED);

				if (cmp_now == cmp_base &&
				    errno_now == errno_base) {
					__atomic_fetch_add(
						&shm->stats.frontier_decay_would_skip,
						1UL, __ATOMIC_RELAXED);
					if (streak == FRONTIER_SHADOW_DECAY_STREAK)
						__atomic_fetch_add(
							&shm->stats.frontier_decay_candidates,
							1UL, __ATOMIC_RELAXED);
				}
			}
		}
	}

	srec_publish_begin(rec);
	rec->do32bit = do32;
	rec->nr = syscallnr;
	srec_publish_end(rec);

	/* Per-syscall accept distribution.  Bumped after both regimes converge
	 * on a successful pick so the array is regime-agnostic; the live/silent
	 * split lives in frontier_{live,silent}_picks.  Guarded on the same
	 * MAX_NR_SYSCALL bound the other per-syscall arrays use. */
	if (syscallnr < MAX_NR_SYSCALL)
		__atomic_fetch_add(
			&shm->stats.frontier_picks_per_syscall[syscallnr],
			1UL, __ATOMIC_RELAXED);

	__atomic_fetch_add(&shm->stats.frontier_strategy_picks, 1UL,
			   __ATOMIC_RELAXED);

	return true;
}

/*
 * Dispatch syscall selection through the active strategy's picker.
 * Reads shm->current_strategy with relaxed atomic, then snapshots the
 * chosen arm into child->strategy_at_pick so the post-syscall reward
 * attribution sites credit the arm that actually picked the syscall --
 * not whichever arm happens to be current_strategy by the time the
 * syscall returns.  Without the stamp, a rotation that lands mid-call
 * (especially common on long or blocking syscalls) would misattribute
 * the reward and contaminate the bandit's learning signal.  Out-of-range
 * guard preserves correctness even if a wild write into shm corrupts
 * the strategy index.
 */
static bool set_syscall_nr(struct syscallrecord *rec, struct childdata *child)
{
	int strat;

	/* Explorer-pool children bypass the bandit's current pick and run
	 * STRATEGY_RANDOM unconditionally -- including when the bandit has
	 * picked STRATEGY_COVERAGE_FRONTIER.  The pool is the always-on
	 * uniform baseline that lets the bandit's reward signal stay honest
	 * even when its winning arm goes stale.  Skip the strategy_at_pick
	 * stamp too: explorer contributions are filtered out of the bandit's
	 * per-arm reward counters in the post-syscall path on is_explorer
	 * alone, and leaving the -1 sentinel here makes that intent explicit
	 * if a future reader forgets the is_explorer gate. */
	if (child->is_explorer) {
		__atomic_fetch_add(&shm->stats.strategy_explorer_picks, 1UL,
				   __ATOMIC_RELAXED);
		/* Explorer-pool exposure: explorers always run STRATEGY_RANDOM
		 * regardless of the bandit's pick.  Bump strategy_picks for
		 * RANDOM directly (strategy_at_pick stays at the -1 sentinel
		 * so the post-syscall PC/CMP reward attribution still skips
		 * explorers as before).  strategy_bandit_pool_ops is NOT
		 * bumped here -- it is a bandit-pool-only sub-counter so the
		 * operator can derive the explorer contribution per arm. */
		__atomic_fetch_add(&shm->strategy_picks[STRATEGY_RANDOM], 1UL,
				   __ATOMIC_RELAXED);
		return set_syscall_nr_random(rec, child);
	}

	/* ACQUIRE pairs with the RELEASE store on current_strategy in
	 * maybe_rotate_strategy below.  Without it, a child observing the
	 * new strategy id is not guaranteed to also see the companion
	 * fields (current_selection_reason, plateau_rescue_amplified_class,
	 * plateau_intervention_mode_current) the orchestrator published
	 * just before the rotation -- the gates downstream that consult
	 * those fields would mis-fire under weak memory. */
	strat = __atomic_load_n(&shm->current_strategy, __ATOMIC_ACQUIRE);

	if (strat < 0 || strat >= NR_STRATEGIES)
		strat = STRATEGY_HEURISTIC;

	/* Stamp the picked arm before dispatching so the post-syscall PC
	 * and CMP reward sites read a stable value even if shm->current_
	 * strategy rotates mid-call.  Written exactly once per pick on the
	 * bandit-pool path; explorers (handled above) leave the -1 sentinel
	 * from clean_childdata in place. */
	child->strategy_at_pick = strat;

	/* Bandit-pool exposure: bump both the wide picks counter and the
	 * bandit-pool-only sub-counter so post-run analysis can separate
	 * bandit dispatches from explorer dispatches per arm.  Bumped
	 * before the picker-specific set_syscall_nr_* call -- a FAIL from
	 * that path still counts as a pick attributed to this arm; the
	 * matching strategy_completed_calls bump in dispatch_step lets
	 * the operator read off the per-arm dispatch success rate. */
	__atomic_fetch_add(&shm->strategy_picks[strat], 1UL, __ATOMIC_RELAXED);
	__atomic_fetch_add(&shm->strategy_bandit_pool_ops[strat], 1UL,
			   __ATOMIC_RELAXED);

	switch (strat) {
	case STRATEGY_HEURISTIC:
		return set_syscall_nr_heuristic(rec, child);
	case STRATEGY_RANDOM:
		return set_syscall_nr_random(rec, child);
	case STRATEGY_COVERAGE_FRONTIER:
		return set_syscall_nr_coverage_frontier(rec, child);
	default:
		__builtin_unreachable();
	}
}

/*
 * Probability (in percent) that, when a substitute retval is offered by
 * the sequence-chain executor, one randomly-chosen arg slot is overwritten
 * with it.  Exposed here (rather than in sequence.c) because the substitution
 * itself happens between argument generation and dispatch, which lives in
 * this file.  Tunable independently of the chain length distribution.
 */
#define CHAIN_SUBST_PCT 30

/*
 * Substituting the previous syscall's return value (almost always a
 * small integer — fd, retval, error code) into a pointer-typed arg
 * slot produces a wild pointer.  The rendering path then SEGVs in
 * printf("%s", small_int) → strlen(0x402), or the kernel deref'es a
 * wild address, depending on which slot got stomped.  Restrict
 * substitution to slots whose argtype legitimately accepts a numeric
 * value.
 */
static bool argtype_accepts_numeric_substitute(enum argtype t)
{
	switch (t) {
	case ARG_UNDEFINED:
	case ARG_FD:
	case ARG_LEN:
	case ARG_MODE_T:
	case ARG_PID:
	case ARG_KEY_SERIAL:
	case ARG_TIMERID:
	case ARG_AIO_CTX:
	case ARG_SEM_ID:
	case ARG_MSG_ID:
	case ARG_SYSV_SHM:
	case ARG_RANGE:
	case ARG_OP:
	case ARG_LIST:
	case ARG_CPU:
	case ARG_NUMA_NODE:
	case ARG_IOVECLEN:
	case ARG_SOCKADDRLEN:
	case ARG_STRUCT_SIZE:
	case ARG_BUF_LEN:
	case ARG_FD_BPF_BTF:
	case ARG_FD_BPF_LINK:
	case ARG_FD_BPF_MAP:
	case ARG_FD_BPF_PROG:
	case ARG_FD_EPOLL:
	case ARG_FD_EVENTFD:
	case ARG_FD_FANOTIFY:
	case ARG_FD_FS_CTX:
	case ARG_FD_INOTIFY:
	case ARG_FD_IO_URING:
	case ARG_FD_LANDLOCK:
	case ARG_FD_MEMFD:
	case ARG_FD_MOUNT:
	case ARG_FD_MQ:
	case ARG_FD_PERF:
	case ARG_FD_PIDFD:
	case ARG_FD_PIPE:
	case ARG_FD_SIGNALFD:
	case ARG_FD_SOCKET:
	case ARG_FD_TIMERFD:
		return true;
	case ARG_ADDRESS:
	case ARG_NON_NULL_ADDRESS:
	case ARG_PATHNAME:
	case ARG_XATTR_NAME:
	case ARG_FSTYPE_NAME:
	case ARG_TIMESPEC:
	case ARG_ITIMERVAL:
	case ARG_ITIMERSPEC:
	case ARG_TIMEVAL:
	case ARG_NODEMASK:
	case ARG_CPUMASK:
	case ARG_BUF_SIZED:
	case ARG_IOVEC:
	case ARG_IOVEC_IN:
	case ARG_SOCKADDR:
	case ARG_MMAP:
	case ARG_SOCKETINFO:
	case ARG_STRUCT_PTR_IN:
	case ARG_STRUCT_PTR_OUT:
	case ARG_STRUCT_PTR_INOUT:
		return false;
	}
	return false;
}

/*
 * Build the numeric-substitute slot bitmap for entry's argtype[] table.
 * Called once per syscallentry at table-init time from
 * copy_syscall_table() in tables.c; the cached mask in
 * entry->numeric_substitute_mask then drives apply_chain_substitution()
 * below without re-walking argtype[] or re-running the 23-case
 * argtype_accepts_numeric_substitute() switch on every chain step.
 * Bit k (k=0..5) set means slot (k+1) accepts a numeric substitute.
 */
uint8_t compute_numeric_substitute_mask(const struct syscallentry *entry)
{
	uint8_t mask = 0;
	unsigned int i;

	if (entry == NULL)
		return 0;

	for (i = 0; i < entry->num_args && i < 6; i++) {
		if (argtype_accepts_numeric_substitute(entry->argtype[i]))
			mask |= (uint8_t)(1u << i);
	}
	return mask;
}

/*
 * Apply Phase 1 retval substitution to rec in place.  Used by both the
 * fresh-args path (random_syscall_step) and the corpus-replay path
 * (replay_syscall_step) so the chain semantics — substituted args reach
 * the kernel and show up in the trace — are identical regardless of
 * where the args came from.  No-op when no substitute is offered, the
 * dice roll comes up against, the syscall takes zero args, or no arg
 * slot has a numeric-substitute-compatible argtype.
 */
static void apply_chain_substitution(struct syscallrecord *rec,
				     struct syscallentry *entry,
				     bool have_substitute,
				     unsigned long substitute_retval)
{
	unsigned int nsafe, pick, slot, i;
	uint8_t mask;

	if (!have_substitute)
		return;
	if (entry == NULL || entry->num_args == 0)
		return;
	if (rnd_modulo_u32(100) >= CHAIN_SUBST_PCT)
		return;

	mask = entry->numeric_substitute_mask;
	if (mask == 0)
		return;
	if (substitute_retval == (unsigned long)mainpid) {
		for (i = 0; i < entry->num_args && i < 6; i++) {
			if (entry->argtype[i] == ARG_PID)
				mask &= (uint8_t)~(1u << i);
		}
		if (mask == 0)
			return;
	}

	/*
	 * Same defence for protected fds (kcov PC/cmp, STDERR_FILENO, the
	 * stderr capture memfd).  sanitise_dup2 picks newfd from
	 * [256, 4095) and other ranges that overlap those slots; a
	 * successful dup2() to one of them silently closes the protected
	 * fd, and propagating its number into a downstream
	 * close()/close_range()/dup2() arg via the chain substitute
	 * finishes the job.  Mask the fd slots when substitute_retval
	 * names a protected fd so the chain steers the substitute to a
	 * non-fd slot (or skips this step entirely).
	 */
	if (fd_is_protected((int)substitute_retval)) {
		for (i = 0; i < entry->num_args && i < 6; i++) {
			if (is_fdarg(entry->argtype[i]))
				mask &= (uint8_t)~(1u << i);
		}
		if (mask == 0)
			return;
	}

	/*
	 * Pick uniformly from the eligible-slot set: count the active
	 * bits in mask, draw a uniform index in [0, nsafe), then walk
	 * mask to find the index-th set bit.  A raw __builtin_ctz(mask)
	 * pick would bias hard toward low-numbered slots -- bit 0 wins
	 * with p=0.5, bit 1 with p=0.25, and so on -- so the explicit
	 * rank walk is required to keep the draw uniform.
	 */
	nsafe = (unsigned int)__builtin_popcount(mask);
	pick = rnd_modulo_u32(nsafe);
	slot = 0;
	for (i = 0; i < 6; i++) {
		if ((mask & (1u << i)) == 0)
			continue;
		if (pick == 0) {
			slot = i + 1;
			break;
		}
		pick--;
	}

	switch (slot) {
	case 1: rec->a1 = substitute_retval; break;
	case 2: rec->a2 = substitute_retval; break;
	case 3: rec->a3 = substitute_retval; break;
	case 4: rec->a4 = substitute_retval; break;
	case 5: rec->a5 = substitute_retval; break;
	case 6: rec->a6 = substitute_retval; break;
	}
	if (minicorpus_shm != NULL)
		__atomic_fetch_add(&minicorpus_shm->chain_substitution_count,
				   1, __ATOMIC_RELAXED);
}

/*
 * Check the rotation boundary and, if crossed, atomically claim the
 * switch and update shm->current_strategy to whatever the configured
 * picker (round-robin or UCB1 bandit, see strategy.h) selects next.
 *
 * The rotation clock is shm_published->fleet_op_count, which mirrors
 * the parent-private fleet op_count (every child contributes ticks at
 * the same rate, including non-syscall alt-ops).  A child that observes
 * (op_count - syscalls_at_last_switch) >= STRATEGY_WINDOW tries to CAS
 * syscalls_at_last_switch forward to the current op_count; the CAS
 * winner performs the switch and emits the
 * stats line, the losers fall through and continue with the new strategy
 * on their next syscall pick.
 *
 * Per-strategy attribution: the just-finished window's call-count delta
 * is pc_edge_calls_by_strategy[prev] - pc_edge_calls_at_window_start and
 * the parallel real bucket-count delta is pc_edge_count_by_strategy[prev]
 * - pc_edge_count_at_window_start.  After the switch, both *at_window_start
 * snapshots are reseeded from the new strategy's current cumulative
 * counters, so the next switch will compute the deltas correctly even if
 * other strategies' counters are bumped during the grace period.
 */
static void maybe_rotate_strategy(void)
{
	unsigned long now;
	unsigned long last;
	int prev, next;
	int prev_reason_raw;
	enum strategy_selection_reason prev_reason;
	enum strategy_selection_reason next_reason = SR_NORMAL_UCB;
	unsigned long calls_now, calls_in_window;
	unsigned long edges_now, edges_in_window;
	unsigned long syscalls_in_window;
	unsigned long cmp_now, cmp_in_window;
	unsigned long warn_now = 0;
	unsigned long warn_in_window = 0;
	bool was_chaos;

	/* Read fleet op_count off the parent-published mirror page; the
	 * canonical aggregate is parent-private and not visible to children.
	 * The mirror is republished once per parent main_loop iteration so
	 * a stale read here only delays the rotation by drain cadence. */
	now = (shm_published != NULL)
	      ? __atomic_load_n(&shm_published->fleet_op_count, __ATOMIC_RELAXED)
	      : 0;
	last = __atomic_load_n(&shm->syscalls_at_last_switch, __ATOMIC_RELAXED);

	/* Tighten the rotation window while the plateau detector is latched
	 * on, so the plateau-intervention layer (SR_PLATEAU_FORCE etc.) re-
	 * applies many times inside one 600s detector window rather than
	 * ~1.6 times.  ACQUIRE pairs with the parent's RELEASE-store of
	 * plateau_active in kcov_plateau_check(); kcov_shm may be NULL when
	 * kcov is disabled, fall back to the healthy-run cadence. */
	{
		unsigned long window = STRATEGY_WINDOW;

		if (kcov_shm != NULL &&
		    __atomic_load_n(&kcov_shm->plateau_active,
				    __ATOMIC_ACQUIRE))
			window = PLATEAU_STRATEGY_WINDOW;

		if (now - last < window)
			return;
	}

	if (!__atomic_compare_exchange_n(&shm->syscalls_at_last_switch,
					 &last, now,
					 false,
					 __ATOMIC_RELAXED, __ATOMIC_RELAXED))
		return;

	prev = __atomic_load_n(&shm->current_strategy, __ATOMIC_RELAXED);
	if (prev < 0 || prev >= NR_STRATEGIES)
		prev = STRATEGY_HEURISTIC;

	/* Selection reason for the just-finished window -- the intervention
	 * orchestrator stamped this when it picked prev.  Treated as raw int
	 * across the shm boundary and re-validated here so a wild write
	 * landing on the field falls back to the "policy chose this" path
	 * rather than skipping the learner update spuriously. */
	prev_reason_raw = __atomic_load_n(&shm->current_selection_reason,
					  __ATOMIC_RELAXED);
	switch (prev_reason_raw) {
	case SR_NORMAL_UCB:
	case SR_ROUND_ROBIN:
	case SR_COLD_START:
	case SR_PLATEAU_FORCE:
		prev_reason = (enum strategy_selection_reason)prev_reason_raw;
		break;
	default:
		prev_reason = SR_NORMAL_UCB;
		break;
	}

	calls_now = __atomic_load_n(&shm->pc_edge_calls_by_strategy[prev],
				    __ATOMIC_RELAXED);
	calls_in_window = calls_now -
		__atomic_load_n(&shm->pc_edge_calls_at_window_start,
				__ATOMIC_RELAXED);
	edges_now = __atomic_load_n(&shm->pc_edge_count_by_strategy[prev],
				    __ATOMIC_RELAXED);
	edges_in_window = edges_now -
		__atomic_load_n(&shm->pc_edge_count_at_window_start,
				__ATOMIC_RELAXED);
	syscalls_in_window = now - last;

	/* CMP-novelty delta: number of comparison constants the active arm
	 * exposed for the first time within CMP_NOVELTY_DECAY_WINDOWS this
	 * window.  Folded into the bandit reward by bandit_record_pull as
	 * a 0.25-weight secondary signal so an arm whose PC growth has
	 * plateaued but whose validation surface is still mutating doesn't
	 * lose to a noisier arm on PC delta alone. */
	cmp_now = __atomic_load_n(&shm->bandit_cmp_new_constants[prev],
				  __ATOMIC_RELAXED);
	cmp_in_window = cmp_now -
		__atomic_load_n(&shm->bandit_cmp_at_window_start,
				__ATOMIC_RELAXED);

	/* WARN-fires delta + chaos-cohort snapshot for the chaos-mode V2
	 * attribution.  warn_now reads the live counter kmsg-monitor bumps
	 * on every classified kernel diagnostic; the at-window-start
	 * snapshot was reseeded at the bottom of the previous rotation (or
	 * is zero on the very first window).  was_chaos samples
	 * cmp_hints_chaos_active BEFORE cmp_hints_chaos_tick advances the
	 * schedule below, so it reflects the chaos state that was in effect
	 * across the just-finished window -- which is the cohort the delta
	 * should be attributed to.  Skipped when kcov_shm is NULL (kcov
	 * unavailable, no kmsg counter to read): the delta is zero and the
	 * cohort sample becomes a no-op for that window. */
	if (kcov_shm != NULL) {
		warn_now = __atomic_load_n(&kcov_shm->kmsg_warn_fires,
					   __ATOMIC_RELAXED);
		warn_in_window = warn_now -
			__atomic_load_n(&shm->kmsg_warn_fires_at_window_start,
					__ATOMIC_RELAXED);
	} else {
		warn_in_window = 0UL;
	}
	was_chaos = cmp_hints_chaos_query();

	/* Feed the just-finished window into the bandit before asking
	 * the picker to choose the next arm, so UCB1 sees up-to-date
	 * pulls/reward when scoring.  The learner consumes the call-count
	 * delta as today; the real bucket-count delta is recorded into the
	 * parallel diagnostic reward series so the operator can compare the
	 * two reward shapes without changing the learner's behaviour.
	 * Round-robin mode ignores the counters but the bookkeeping is
	 * harmless and lets the end-of-run summary print pulls under either
	 * picker.
	 *
	 * Called on EVERY window including SR_PLATEAU_FORCE.  The
	 * per-arm-per-reason bucketing inside bandit_record_pull captures
	 * every cohort (forced included) so dump-side analysis can split
	 * each arm's exposure by selection path, while the learner-facing
	 * update (bandit_pulls[] / bandit_reward_calls[] / EMA) skips
	 * SR_PLATEAU_FORCE internally to keep the UCB scorer's view of
	 * RANDOM uncontaminated.  All other bookkeeping
	 * (bandit_window_count tick, frontier ring advance, window-start
	 * snapshot reseed) runs unconditionally -- those are coverage-side
	 * structures and must stay aligned with the rotation cadence. */
	bandit_record_pull(prev, prev_reason, calls_in_window,
			   edges_in_window, cmp_in_window,
			   warn_in_window, was_chaos);

	/* Tick the rotation counter so bandit_cmp_observe()'s per-syscall
	 * bloom decay sees the new window index on subsequent calls.
	 * Bumped after bandit_record_pull so a concurrent observer racing
	 * the rotation either sees the old (still-valid) window or the
	 * fresh one — both attribute correctly. */
	__atomic_fetch_add(&shm->bandit_window_count, 1UL, __ATOMIC_RELAXED);

	/* Roll the per-syscall frontier-edge ring forward and zero the new
	 * slot so it represents only edges discovered in the upcoming
	 * window.  Same K-window decay horizon as the CMP-novelty bloom
	 * above. */
	frontier_window_advance();

	/* Advance the cmp_hints chaos-mode window counter.  Flips the
	 * hint-suppression toggle on every CHAOS_WINDOW_MODULO'th window
	 * so random-arg generation gets a fair shot at the
	 * invalid-combination space that the kernel-validated cmp_hints
	 * pool otherwise biases away from. */
	cmp_hints_chaos_tick();

	next = select_next_strategy(prev, &next_reason);
	if (next < 0 || next >= NR_STRATEGIES) {
		next = (prev + 1) % NR_STRATEGIES;
		next_reason = SR_ROUND_ROBIN;
	}

	__atomic_store_n(&shm->pc_edge_calls_at_window_start,
			 __atomic_load_n(&shm->pc_edge_calls_by_strategy[next],
					 __ATOMIC_RELAXED),
			 __ATOMIC_RELAXED);
	__atomic_store_n(&shm->pc_edge_count_at_window_start,
			 __atomic_load_n(&shm->pc_edge_count_by_strategy[next],
					 __ATOMIC_RELAXED),
			 __ATOMIC_RELAXED);
	__atomic_store_n(&shm->bandit_cmp_at_window_start,
			 __atomic_load_n(&shm->bandit_cmp_new_constants[next],
					 __ATOMIC_RELAXED),
			 __ATOMIC_RELAXED);
	/* Reseed the transition reward window-start snapshots so the per-
	 * window delta bandit_record_pull reads on the next rotation
	 * matches the (next, this-window) cohort.  Same RELAXED cadence
	 * and single-writer ordering as the pc_edge_*_at_window_start
	 * pair above; consumed by bandit_record_pull under COMBINED mode
	 * (it folds (transition_edge_count_by_strategy[arm] - this
	 * snapshot) / TRANSITION_BANDIT_REWARD_WEIGHT_RECIPROCAL into the
	 * per-arm reward total).  Reseeded unconditionally so OFF/SHADOW_
	 * ONLY runs keep the snapshot fresh; COMBINED can be flipped on
	 * mid-run without the bandit reading a stale window-start. */
	__atomic_store_n(&shm->stats.transition_edge_count_at_window_start,
			 __atomic_load_n(&shm->stats.transition_edge_count_by_strategy[next],
					 __ATOMIC_RELAXED),
			 __ATOMIC_RELAXED);
	__atomic_store_n(&shm->stats.transition_edge_calls_at_window_start,
			 __atomic_load_n(&shm->stats.transition_edge_calls_by_strategy[next],
					 __ATOMIC_RELAXED),
			 __ATOMIC_RELAXED);
	/* Reseed the kmsg_warn_fires snapshot from the live counter (not a
	 * per-strategy mirror -- the underlying counter is global).  A
	 * future commit in this stack reads this snapshot at the top of the
	 * rotation handler to compute the per-window WARN delta and feeds
	 * it through bandit_record_pull for chaos cohort attribution.
	 * Reseeded under RELAXED matching the other *_at_window_start stores
	 * above; the snapshot tolerates a race between read and store
	 * because the delta is a coarse cohort-level signal, not a precise
	 * per-call attribution. */
	__atomic_store_n(&shm->kmsg_warn_fires_at_window_start,
			 kcov_shm != NULL ?
				 __atomic_load_n(&kcov_shm->kmsg_warn_fires,
						 __ATOMIC_RELAXED) :
				 0UL,
			 __ATOMIC_RELAXED);
	/* Publish the selection reason BEFORE current_strategy: the RELEASE
	 * store on current_strategy below pairs with the picker's and the
	 * plateau gates' ACQUIRE loads of current_strategy, making the
	 * reason and the companion plateau fields (published earlier under
	 * RELAXED in select_next_strategy) visible to any child that
	 * observes the new strategy. */
	__atomic_store_n(&shm->current_selection_reason,
			 (int)next_reason, __ATOMIC_RELAXED);
	__atomic_store_n(&shm->current_strategy, next, __ATOMIC_RELEASE);

	output(0, "strategy: switched to %s (%d) [%s] (prev %s (%d) [%s]: edge_calls=%lu, edge_count=%lu, syscalls=%lu, cmp_novel=%lu%s)\n",
	       strategy_name(next), next,
	       strategy_selection_reason_name(next_reason),
	       strategy_name(prev), prev,
	       strategy_selection_reason_name(prev_reason),
	       calls_in_window, edges_in_window, syscalls_in_window,
	       cmp_in_window,
	       prev_reason == SR_PLATEAU_FORCE ?
	       ", learner-update skipped" : "");
}

/*
 * Greedy CMP RedQueen re-exec helper.  Forward-declared so dispatch_step's
 * tail can call it; definition lives after replay_syscall_step where the
 * fresh-args-then-pin-slot story is symmetric with the replay contract.
 *
 * pending_idx is the position in child->reexec_pending[] that the
 * consumer at the dispatch_step tail picked (0..reexec_pending_count);
 * carried through to the inner_new_cmp > 0 success block so the
 * per-pending-index success counter (kcov_shm->reexec_pending_pick_success[])
 * can be bumped at the chosen index without retaining the index in
 * per-child scratch.
 */
static bool redqueen_reexec_step(struct childdata *child,
				 const struct reexec_pending *p,
				 unsigned int pending_idx);

/*
 * Dispatch a fully-prepared syscallrecord and run the per-call
 * post-dispatch bookkeeping: kcov collection / cmp-hint collection,
 * edge-pair recording, mutator-attribution commit, mini-corpus save,
 * trace output, fd-ring update, group/last_syscall_nr tracking.
 *
 * Caller has already populated rec->nr, rec->do32bit, rec->a1..a6, the
 * postbuffer is already cleared, and any chain substitution has been
 * applied.  The two callers (random_syscall_step and replay_syscall_step)
 * differ only in how they got the args into rec; everything from
 * output_syscall_prefix forward is shared.
 */
static bool dispatch_step(struct childdata *child, struct syscallentry *entry,
			  bool *found_new, unsigned long *new_cmp_out)
{
	struct syscallrecord *rec = &child->syscall;
	bool new_edges;
	unsigned long new_edge_count = 0;

	/* Stamp the resolved entry on the rec so .sanitise / .post handlers
	 * (and helpers like this_syscallname()) can reach it without
	 * re-running get_syscall_entry(nr, do32bit) on every probe. */
	rec->entry = entry;

	/* Clear the per-call validator-reject flag.  do_syscall() sets this
	 * when validate_arg_coupling() rejects the call before the kernel is
	 * entered; the kcov_collect() gate below reads it to skip the
	 * total_calls / per_syscall_calls[nr] bumps that would otherwise
	 * poison kcov_syscall_cold_skip_pct() for strict-validator syscalls. */
	rec->validator_rejected = false;

	output_syscall_prefix(rec, entry);

	/* PC mode: per-child kcov fd collects edge coverage, optionally
	 * via KCOV_REMOTE_ENABLE to also pick up softirq / threaded-irq /
	 * kthread coverage triggered by this syscall.  CMP mode: per-child
	 * cmp fd collects comparison-operand records that feed the
	 * cmp_hints pool.  Mode is fixed at child init; remote_mode is
	 * only meaningful in PC mode (KCOV_REMOTE_ENABLE applies to the PC
	 * fd, not the cmp fd).
	 *
	 * Sample rate is per-syscall: calls whose interesting kernel work
	 * is deferred to kthreads / workqueues / softirqs (netlink async
	 * delivery, io_uring workers, BPF attach, mount workqueues, cgroup
	 * migration, namespace setup) are flagged with KCOV_REMOTE_HEAVY
	 * and sampled at the heavier 1-in-KCOV_REMOTE_RATIO_HEAVY rate so
	 * those deferred-work edges don't get stuck cold; everything else
	 * uses the default 1-in-KCOV_REMOTE_RATIO trickle. */
	if (child->kcov.mode == KCOV_MODE_PC) {
		unsigned int remote_reciprocal =
			(entry->flags & KCOV_REMOTE_HEAVY) ?
				KCOV_REMOTE_RATIO_HEAVY : KCOV_REMOTE_RATIO;
		child->kcov.remote_mode = child->kcov.remote_capable &&
					  ONE_IN(remote_reciprocal);
	} else {
		child->kcov.remote_mode = false;
	}

	do_syscall(rec, entry, &child->kcov, child);

	/* kcov_collect() returns the real per-call bucket-edge count via the
	 * out-param alongside its bool found_new return.  Diff-ing the global
	 * kcov_shm->edges_found around the call would race other children's
	 * concurrent increments and over-attribute their edges to this
	 * syscall; the per-call count is the authoritative number.
	 *
	 * CMP-mode children contribute zero PC edges (their PC fd is never
	 * enabled), so new_edge_count stays 0 and the per-strategy edge
	 * attribution block below naturally skips on its `new_edge_count > 0`
	 * gate.  Frontier ring updates and bandit reward attribution also
	 * skip cleanly via `if (new_edges)` further down -- CMP-mode
	 * children deliberately don't contribute to those PC-edge concepts.
	 *
	 * CMP-source corpus saves are the exception: kcov_collect_cmp
	 * returns the per-call count of bloom-novel KCOV_CMP_CONST
	 * comparisons, captured here in new_cmp.  Under a PC-edge plateau
	 * (cmp_rising_pc_flat) that count is the only available novelty
	 * signal -- the save gate below widens to `new_edges || new_cmp
	 * > 0` so the corpus can still grow and mutator wins can still be
	 * credited, breaking the self-reinforcing
	 * PC-plateau->no-saves->no-mutator-wins loop.  See
	 * investigations/corpus-mutator-zero-wins-2026-05-20 for the full
	 * analysis. */
	unsigned long new_cmp = 0;

	/* Snapshot the rescue classifier's cold-skip-pct input BEFORE
	 * kcov_collect runs.  On a new edge kcov_collect bumps
	 * last_edge_at[rec->nr] to the current total_calls, after which
	 * kcov_syscall_cold_skip_pct(rec->nr) returns 0 -- the exact case
	 * classify_random_rescue exists to recognise as RRC_COLD_SKIP.
	 * Reading it here, at draw time, keeps the classifier's "would the
	 * picker have skipped this?" question pinned to the picker's actual
	 * pre-call state.  Only meaningful in PC mode; the CMP path never
	 * reaches the classifier (new_edges stays false there). */
	unsigned int rescue_cold_skip_pct_before = 0;

	/* Initialised here so the transition-attribution block below (which
	 * runs unconditionally on the CMP-mode side too, gated on
	 * pcres.transition_edges_real_local > 0) sees a clean zero when
	 * the kcov_collect path is skipped. */
	struct kcov_pc_result pcres = { 0 };

	if (child->kcov.mode == KCOV_MODE_PC) {
		rescue_cold_skip_pct_before =
			kcov_syscall_cold_skip_pct(rec->nr);
		/* Pre-validation reject in do_syscall() -- the kernel was never
		 * entered, so there is no coverage to collect and bumping
		 * total_calls / per_syscall_calls[nr] inside kcov_collect()
		 * would poison kcov_syscall_cold_skip_pct() on syscalls whose
		 * validators are strict.  last_edge_at[] only moves on the
		 * found_new branch and stays correctly frozen here. */
		if (rec->validator_rejected)
			new_edges = false;
		else
			/* Pass &pcres (not NULL) so the per-strategy
			 * transition reward attribution below has access to
			 * pcres.transition_edges_real_local.  The bucket_bits
			 * / distinct_edges / local_distinct_pcs fields are
			 * also populated but the existing PC-edge attribution
			 * path consumes new_edge_count instead, so they are
			 * written but not read here -- the extra struct stores
			 * are zero-atomics and unmeasurable on the per-call
			 * cost. */
			new_edges = kcov_collect(&child->kcov, rec->nr,
						 rec->do32bit,
						 &new_edge_count, &pcres);
	} else {
		new_cmp = kcov_collect_cmp(&child->kcov, rec->nr,
					   rec->do32bit,
					   child->is_explorer,
					   child->strategy_at_pick);
		new_edges = false;

		/* A/B cohort denominators for the reexec_* lift signal.
		 * This is the parent CMP call: every CMP-mode child reaches
		 * here exactly once per dispatch, and child->redqueen_enabled
		 * is the stable per-fork stamp that partitions CMP-mode
		 * children 50/50 into the enabled vs control arms.  Bumping
		 * once per parent call (and accumulating new_cmp into the
		 * matching cohort sum) gives the missing denominator the
		 * existing reexec_* numerator counters need so the per-
		 * parent-call lift question is answerable from the periodic
		 * dump.  Bump unconditionally on the cohort path -- even a
		 * parent call that returned new_cmp == 0 is a parent-call
		 * the re-exec gate could have sampled, so excluding it would
		 * bias the denominator. */
		if (kcov_shm != NULL) {
			if (child->redqueen_enabled) {
				__atomic_fetch_add(&kcov_shm->cmp_parent_calls_enabled,
						   1UL, __ATOMIC_RELAXED);
				if (new_cmp > 0)
					__atomic_fetch_add(
						&kcov_shm->cmp_parent_new_cmps_enabled,
						new_cmp, __ATOMIC_RELAXED);
			} else {
				__atomic_fetch_add(&kcov_shm->cmp_parent_calls_control,
						   1UL, __ATOMIC_RELAXED);
				if (new_cmp > 0)
					__atomic_fetch_add(
						&kcov_shm->cmp_parent_new_cmps_control,
						new_cmp, __ATOMIC_RELAXED);
			}
		}
	}

	/* Per-syscall new-edge attribution split by strategy pool.  Skipped
	 * when the call produced no new edges (the dump only consumes the
	 * positive delta side) and when rec->nr falls outside the table.
	 * Biarch attribution follows the same raw-rec->nr indexing the
	 * existing kcov_shm->per_syscall_edges array uses; the dump iterates
	 * only the active 64-bit table when biarch, so 32-bit calls are
	 * effectively ignored there as they are everywhere else. */
	if (new_edge_count > 0 && rec->nr < MAX_NR_SYSCALL) {
		unsigned long *bucket = child->is_explorer
			? shm->stats.edges_per_syscall_explorer
			: shm->stats.edges_per_syscall_bandit;
		__atomic_fetch_add(&bucket[rec->nr], new_edge_count,
				   __ATOMIC_RELAXED);
	}

	/* Surface this step's new-coverage signal to the chain executor
	 * (when called via run_sequence_chain). */
	if (found_new != NULL)
		*found_new = new_edges;

	/* CMP-bloom novelty is an equivalent corpus-save / mutator-win
	 * signal alongside PC-edge novelty.  Under a PC-edge plateau the
	 * PC-only gate fires for ~0% of calls; the OR-with-CMP gate keeps
	 * the corpus growing on arg neighbourhoods that exercise new
	 * compile-time-constant comparisons (the cmp_rising_pc_flat
	 * frontier).  PC-edge-specific bookkeeping below (frontier ring,
	 * snapshot cadence, per-strategy edge attribution, explorer/bandit
	 * pool edge counters) STAYS gated on new_edges -- those are
	 * PC-edge concepts by definition and contaminating them with
	 * CMP-source events would silently bias the bandit reward and
	 * corrupt the plateau diagnostics. */
	bool found_something = new_edges || (new_cmp > 0);

	/* If the win signal came from CMP novelty rather than PC novelty,
	 * tag the pending mutator attribution.  Tag-before-commit + the
	 * unconditional clear inside commit() together mean a stale tag
	 * from a !found_something path never leaks into the next call. */
	if (new_cmp > 0)
		minicorpus_mut_attrib_set_cmp_source();

	/* Credit each mutator case picked during this call's arg
	 * generation, with wins iff this call produced ANY novelty
	 * signal (PC-edge OR CMP-bloom).  PC-only credit was the matching
	 * half of the PC-only save gate; expanding both together keeps
	 * mutator productivity stats and corpus growth in lockstep. */
	minicorpus_mut_attrib_commit(found_something);

	/*
	 * SHADOW per-entry cmp-hint feedback scoring ([11-feedback-loop]
	 * PHASE 4).  Drain the per-child stash that cmp_hints_try_get_ex
	 * pushed onto during arg generation; credit per-entry pool wins/
	 * misses on the matching pool entries and bump the flat
	 * cmp_hint_wins / cmp_hint_misses / cmp_hint_cmp_novelty_wins
	 * counters.  Exactly ONE drain per parent dispatch:
	 *  - PC mode: credit_pc(true) on new_edges, credit_pc(false) on
	 *    no-edge.  PC-edge is the win signal the follow-up live-pick
	 *    weight will read.
	 *  - CMP mode with new_cmp > 0: credit_cmp_novelty (SEPARATE
	 *    counter; spec mandate -- CMP novelty must not masquerade as
	 *    PC-edge conversion).
	 *  - CMP mode with new_cmp == 0: just reset the stash, no credit
	 *    (PC-mode score is undefined for a CMP-mode call, and CMP
	 *    novelty did not fire).
	 *
	 * SHADOW: live pool selection in cmp_hints_try_get is UNCHANGED
	 * this commit; only the per-entry scores and the flat counters
	 * record outcomes.  The follow-up A/B-gated commit will turn the
	 * scores into the weighted live pick.
	 *
	 * Gated on !child->in_reexec so the inner re-exec dispatch does
	 * not credit the outer parent's stash a second time.  The outer
	 * dispatch_step already credited and reset the stash above; the
	 * inner generate_syscall_args under in_reexec did not push (the
	 * stash helper gates on the same flag), so the inner stash is
	 * provably empty here.  Belt-and-braces vs an accidental future
	 * push that forgets the gate.
	 */
	if (!child->in_reexec) {
		if (child->kcov.mode == KCOV_MODE_PC) {
			cmp_hints_feedback_credit_pc(new_edges);
		} else if (new_cmp > 0) {
			cmp_hints_feedback_credit_cmp_novelty();
		} else {
			cmp_hints_feedback_reset_stash();
		}
	}

	/* Save args that produced any novelty signal, but only for
	 * syscalls without sanitise (which may stash pointers).  Tag with
	 * the source so saves_by_reason[] separates PC-promoted from
	 * CMP-promoted entries; PC wins the tag on calls where both
	 * signals fire so the historical accounting is preserved. */
	if (unlikely(found_something)) {
		if (entry->sanitise == NULL)
			minicorpus_save_with_reason(rec,
				new_edges ? CORPUS_SAVE_REASON_PC
					  : CORPUS_SAVE_REASON_CMP);
	}

	/* PC-edge-only bookkeeping below.  Deliberately separate from the
	 * found_something save block above so CMP-source saves can't
	 * trigger snapshot cadence, per-strategy edge attribution, or
	 * pool edge counters -- see comment above on why those must
	 * stay PC-only. */
	if (unlikely(new_edges)) {
		/* Coverage-delta-triggered persistence: snapshot the
		 * minicorpus to disk every MINICORPUS_SNAPSHOT_EDGES
		 * fleet-wide edges so a crash mid-run only loses the
		 * last cadence window of state, not the whole run.
		 * Cheap fast path when the gap isn't reached; only one
		 * caller per window actually runs the save. */
		minicorpus_maybe_snapshot();

		if (child->is_explorer) {
			/* Explorer-pool discoveries are real edges and count
			 * toward the run-wide fleet totals, but skip the
			 * per-strategy reward attribution: explorers always
			 * run STRATEGY_RANDOM, so feeding their edges into
			 * the bandit's current arm would either inflate a
			 * non-RANDOM arm's reward (when the bandit picked
			 * something else) or double-count when the bandit
			 * also picked RANDOM. */
			__atomic_fetch_add(&shm->stats.explorer_pool_edges_discovered,
					   1, __ATOMIC_RELAXED);
		} else {
			/* Attribute this new-edge call to the strategy that
			 * PICKED the syscall, not whichever strategy happens
			 * to be shm->current_strategy by the time the syscall
			 * has returned and we got around to scoring the
			 * reward.  The two values can disagree any time a
			 * rotation lands between set_syscall_nr() and here,
			 * which is frequent for long or blocking syscalls;
			 * reading the pick-time stamp keeps the bandit's
			 * reward signal pointed at the arm that actually
			 * earned the credit.
			 *
			 * Two parallel cumulative counters:
			 * pc_edge_calls_by_strategy[] bumps by 1 (the
			 * historical "edges_by_strategy[]" signal under its
			 * honest name -- calls-with-≥1-edge) and
			 * pc_edge_count_by_strategy[] bumps by the real
			 * bucket-edge count from kcov_collect().  Window
			 * deltas are computed by maybe_rotate_strategy against
			 * the matching *_at_window_start snapshots. */
			int strat = child->strategy_at_pick;
			if (strat >= 0 && strat < NR_STRATEGIES) {
				__atomic_fetch_add(&shm->pc_edge_calls_by_strategy[strat],
						   1, __ATOMIC_RELAXED);
				__atomic_fetch_add(&shm->pc_edge_count_by_strategy[strat],
						   new_edge_count,
						   __ATOMIC_RELAXED);
			}
			__atomic_fetch_add(&shm->stats.bandit_pool_edges_discovered,
					   1, __ATOMIC_RELAXED);

			/* Random-rescue classification.  Only meaningful when
			 * the current window is a SR_PLATEAU_FORCE intervention
			 * -- the classifier exists to explain why a forced
			 * RANDOM rescue produced the edge a structured picker
			 * missed.  Reading current_selection_reason rather than
			 * stamping it at pick-time is fine here: the
			 * intervention windows are long (~100 sec at 10K
			 * iter/sec) and a child whose syscall straddled a
			 * rotation boundary is rare enough that misattributing
			 * a handful of rescues per rotation is below the
			 * noise floor on the per-class counts.  The orchestrator
			 * reads the cumulative distribution at the next
			 * rotation boundary to decide which class to amplify. */
			if (__atomic_load_n(&shm->current_selection_reason,
					    __ATOMIC_RELAXED) ==
			    SR_PLATEAU_FORCE) {
				enum random_rescue_class rrc =
					classify_random_rescue(rec, child,
						rescue_cold_skip_pct_before);
				if (rrc >= 0 && rrc < RRC_NR_CLASSES)
					__atomic_fetch_add(
						&shm->random_rescue_class_count[rrc],
						1UL, __ATOMIC_RELAXED);
			}
		}
	}

	/* Per-strategy transition-reward attribution.  Independent of the
	 * new_edges gate above: a call can flip transition slots (a new
	 * ordering between two PCs) without flipping any new bucket bit
	 * -- the canonical "transition fires on warm-known PCs through a
	 * new route" case is exactly the signal the operator wants
	 * separated from the PC-edge stream.  The kcov_collect path
	 * already filters pcres.transition_edges_real_local on
	 * !kc->remote_mode and on kcov_transition_reward_mode != OFF
	 * (see the result-population branch in kcov_collect), so a
	 * non-zero value here means a local-mode call earned a reward-
	 * eligible transition delta.
	 *
	 * Explorer-pool calls are skipped for the same reason PC-edge
	 * attribution skips them above: explorers always run STRATEGY_
	 * RANDOM, so crediting the active bandit arm here would either
	 * inflate a non-RANDOM arm's reward (when the bandit picked
	 * something else) or double-count when both pools picked RANDOM.
	 *
	 * The raw transition count is capped at TRANSITION_PER_CALL_
	 * REWARD_CAP before being added to transition_edge_count_by_
	 * strategy[] so a single pathological trace (e.g. a syscall that
	 * opens a brand-new control-flow region and flips thousands of
	 * transition slots in one call) cannot monopolize the per-window
	 * delta the bandit reads as reward.  The uncapped real-flip
	 * counter per_syscall_transition_edges_real keeps reporting the
	 * full magnitude for the stats-dump top-N; the cap only applies
	 * to the reward-attribution path. */
	if (pcres.transition_edges_real_local > 0 &&
	    !child->is_explorer && rec->nr < MAX_NR_SYSCALL) {
		int strat = child->strategy_at_pick;

		if (strat >= 0 && strat < NR_STRATEGIES) {
			unsigned long capped =
				pcres.transition_edges_real_local;

			if (capped > TRANSITION_PER_CALL_REWARD_CAP)
				capped = TRANSITION_PER_CALL_REWARD_CAP;
			__atomic_fetch_add(
				&shm->stats.transition_edge_calls_by_strategy[strat],
				1UL, __ATOMIC_RELAXED);
			__atomic_fetch_add(
				&shm->stats.transition_edge_count_by_strategy[strat],
				capped, __ATOMIC_RELAXED);
		}
	}

	/* COMBINED-mode only: bump the per-syscall frontier-edge ring on
	 * the transition-discovery path so syscalls producing transitions
	 * (a new ordering through warm-known code) but no fresh PC bucket
	 * bits still earn frontier credit -- this is the whole point of
	 * promoting the signal, since the empirically-observed regime is
	 * one where transition discovery is healthy while PC-edge
	 * discovery has plateaued.  In SHADOW_ONLY (the default) the ring
	 * stays driven only by frontier_record_new_edge() so the
	 * silent-regime picker distribution remains byte-identical to the
	 * pre-knob baseline.  Same is_explorer + nr-bounds guards as the
	 * attribution block above. */
	if (pcres.transition_edges_real_local > 0 &&
	    !child->is_explorer && rec->nr < MAX_NR_SYSCALL &&
	    __atomic_load_n(&kcov_transition_reward_mode,
			    __ATOMIC_RELAXED) ==
	    KCOV_TRANSITION_REWARD_COMBINED)
		frontier_record_transition_edge((unsigned int)rec->nr);

	output_syscall_postfix(rec);

	handle_syscall_ret(rec, entry);

	/* Snapshot the completed call into the per-child ring so the parent
	 * has a chronological window of recent activity if a kernel taint
	 * fires before the next syscall. */
	child_syscall_ring_push(&child->syscall_ring, rec);

	/* Also append a compact record to the per-child pre-crash ring,
	 * dumped on __BUG() to attribute the assertion to a specific
	 * recent syscall.  rec->tp was just refreshed in do_syscall(). */
	pre_crash_ring_record(child, rec, &rec->tp);

	/* Single combined enqueue: op_count + success/failure +
	 * syscall_category_count[] all ride on one STATS_FIELD_CALL_COMPLETE
	 * slot.  The drain expands it back into three logical bumps.
	 * Result class is derived post-handle_syscall_ret(), which has
	 * already coerced rec->retval for retfd_rejected and is the
	 * canonical settle point for rec->state. */
	{
		enum stats_result_class result;

		if (__atomic_load_n(&rec->state, __ATOMIC_ACQUIRE) != AFTER)
			result = STATS_RESULT_INCOMPLETE;
		else if (rec->retval == (unsigned long)-1L)
			result = STATS_RESULT_FAILURE;
		else
			result = STATS_RESULT_SUCCESS;

		stats_ring_enqueue_call_complete(child->stats_ring,
						 (uint16_t)entry->syscall_category,
						 result);

		/* childop_split telemetry: attribute this syscall to the
		 * in-childop or random-syscall bucket based on the per-child
		 * flag set by child_process()'s per-op bracket.  Set when
		 * random_syscall() was reached from inside an alt-op op_fn
		 * (e.g. sched_cycler's inner loop), clear otherwise (direct
		 * CHILD_OP_SYSCALL fallthrough via run_sequence_chain).
		 * RELAXED add-fetch: cumulative diagnostic, lost-update races
		 * are tolerated.  Owner is the only writer of in_childop so
		 * no read race -- this child either is or isn't inside its
		 * own op_fn at this point. */
		if (child->in_childop) {
			__atomic_add_fetch(&shm->stats.syscalls_in_childops,
					   1UL, __ATOMIC_RELAXED);
		} else {
			__atomic_add_fetch(&shm->stats.syscalls_random,
					   1UL, __ATOMIC_RELAXED);
		}
	}

	/* FD leak tracking: count successful fd-creating and
	 * fd-closing syscalls per child for leak diagnosis. */
	if (rec->retval != -1UL) {
		if (entry->rettype == RET_FD) {
			child->fd_created++;
			if (entry->group < NR_GROUPS)
				child->fd_created_by_group[entry->group]++;
			/* Track returned fd for preferential reuse in arg generation. */
			if ((int)rec->retval > 2)
				child_fd_ring_push(&child->live_fds, (int)rec->retval);
		}
		if (entry->is_close_syscall)
			child->fd_closed++;
	}

	/* Track the group for biasing. */
	if (group_bias)
		child->last_group = entry->group;

	/* Per-arm completion exposure: bump the arm this call was attributed
	 * to.  Two distinct cases reach here with strategy_at_pick == -1:
	 *
	 *   - Explorer-pool children: set_syscall_nr() leaves the sentinel
	 *     in place and bumps strategy_picks[STRATEGY_RANDOM] directly.
	 *     The completion bump mirrors that pick by crediting RANDOM
	 *     here so picks and completions stay symmetric for the explorer
	 *     contribution.
	 *
	 *   - Replay steps from run_sequence_chain(): replay_syscall_step()
	 *     deliberately clears strategy_at_pick to -1 to avoid crediting
	 *     replay work to whichever arm started the chain.  Replays did
	 *     not bump strategy_picks[] either, so the completion bump must
	 *     skip them to keep picks and completions paired.
	 *
	 * Gate the fallback on child->is_explorer specifically rather than
	 * sap < 0 so the two cases stay separated.  Replay-step visibility
	 * lives in chain_corpus_shm->replay_steps_dispatched. */
	{
		int sap = child->strategy_at_pick;
		if (sap < 0 && child->is_explorer)
			sap = STRATEGY_RANDOM;
		if (sap >= 0 && sap < NR_STRATEGIES)
			__atomic_fetch_add(
				&shm->strategy_completed_calls[sap],
				1UL, __ATOMIC_RELAXED);
	}

	/*
	 * CMP RedQueen greedy re-exec tail.  Fires after the
	 * parent call's handle_syscall_ret has settled so .post / .cleanup
	 * are done before the re-exec dispatch reuses rec.  A single
	 * insertion point in dispatch_step so all callers
	 * (random_syscall_step, replay_syscall_step, sequence-chain step)
	 * inherit re-exec coverage automatically.
	 *
	 * Gates (ALL must pass):
	 *   - !in_reexec     -- recursion guard; otherwise we'd self-reinforce
	 *     a runaway loop.
	 *   - redqueen_enabled -- A/B-comparison stamp.
	 *   - kcov.mode == KCOV_MODE_CMP -- PC-mode children produce no
	 *     attribution.  Defensive: redqueen_enabled is only stamped
	 *     true on CMP-mode children today, but the gate keeps the
	 *     dispatch invariant local to this site.
	 *   - !in_chain_mid_step -- chains save their step sequence for
	 *     replay; a mid-chain re-exec is not part of that contract
	 *     and would double-count the step against the chain depth.
	 *   - new_cmp > 0 -- the parent must have produced at least one
	 *     bloom-novel CMP record.  A call that only re-harvested
	 *     known constants adds no information for re-exec.
	 *   - reexec_pending_count > 0 -- attribution scan in the parent's
	 *     cmp_hints_collect actually found a slot match.
	 *   - rate gate: ONE_IN(REDQUEEN_REEXEC_GATE_DENOM) baseline,
	 *     always-on while the plateau detector classifies the run as
	 *     CMP_RISING_PC_FLAT.  Combines low-cost steady-state lift
	 *     with full intensification under the diagnostic this re-exec
	 *     was designed to break.
	 */
	{
		/* Per-call gate disposition bucketing (PHASE 0 measurement-
		 * correctness): every dispatch_step that reaches this tail
		 * bumps EXACTLY ONE counter, partitioning the gap between
		 * reexec_attribution_found and reexec_attempts.  The
		 * evaluation order below mirrors the original short-circuited
		 * compound `if`; gate_skipped holds the counter address for
		 * the first failing gate (NULL == all gates cleared, the
		 * re-exec actually fired).  Behaviour is unchanged -- the
		 * reexec call site and rate-gate semantics are identical to
		 * the prior code; only the accounting around it is new. */
		unsigned long *gate_skipped = NULL;
		bool gate_passed = false;
		bool plateau_burst = false;

		if (child->in_reexec) {
			gate_skipped = (kcov_shm != NULL)
				? &kcov_shm->reexec_gate_skip_in_reexec
				: NULL;
		} else if (!child->redqueen_enabled) {
			gate_skipped = (kcov_shm != NULL)
				? &kcov_shm->reexec_gate_skip_disabled
				: NULL;
		} else if (child->kcov.mode != KCOV_MODE_CMP) {
			gate_skipped = (kcov_shm != NULL)
				? &kcov_shm->reexec_gate_skip_mode
				: NULL;
		} else if (child->in_chain_mid_step) {
			gate_skipped = (kcov_shm != NULL)
				? &kcov_shm->reexec_gate_skip_chain_mid
				: NULL;
		} else if (new_cmp == 0) {
			gate_skipped = (kcov_shm != NULL)
				? &kcov_shm->reexec_gate_skip_no_new_cmp
				: NULL;
		} else if (child->reexec_pending_count == 0) {
			gate_skipped = (kcov_shm != NULL)
				? &kcov_shm->reexec_gate_skip_no_pending
				: NULL;
		} else {
			/* All boolean gates cleared; the rate gate
			 * (ONE_IN(N) baseline plus always-on during a
			 * CMP_RISING_PC_FLAT plateau) decides between
			 * gate_pass and the rate-skip bucket. */
			if (kcov_shm != NULL &&
			    __atomic_load_n(&kcov_shm->plateau_active,
					    __ATOMIC_RELAXED)) {
				int h = __atomic_load_n(
					&shm->plateau_current_hypothesis,
					__ATOMIC_RELAXED);

				if (h == PLATEAU_HYPOTHESIS_CMP_RISING_PC_FLAT)
					plateau_burst = true;
			}

			if (plateau_burst ||
			    ONE_IN(REDQUEEN_REEXEC_GATE_DENOM)) {
				/* Per-call cap C-1: drain a single
				 * attribution per parent dispatch.  The
				 * --redqueen-pending-pick A/B flag
				 * (params.c) selects which entry of the
				 * per-call reexec_pending[] census to
				 * drain:
				 *   FIRST  -- always entry 0, the first-
				 *             emitted (earliest CMP
				 *             record's first-matching arg
				 *             slot).  Prior behaviour;
				 *             biases hard toward early
				 *             validation checks.
				 *   RANDOM -- uniform pick over
				 *             [0, reexec_pending_count)
				 *             via trinity's Lemire-debiased
				 *             rnd_modulo_u32() (NEVER libc
				 *             rand()).  Surfaces signal
				 *             from any pending entry, not
				 *             just the trace-order winner.
				 * The reexec_pending_count==0 short-
				 * circuit above guarantees count > 0 here,
				 * so the rnd_modulo_u32(count) argument is
				 * safe (and the helper's own n==0 guard
				 * would just return 0 anyway).
				 * Per-pending-index success counters
				 * (kcov_shm->reexec_pending_pick_success[])
				 * are bumped inside redqueen_reexec_step
				 * on inner_new_cmp > 0 in BOTH modes, so
				 * an A/B run reads directly whether
				 * entry-0's trace-order bias under FIRST
				 * actually costs signal vs RANDOM. */
				unsigned int pending_idx;
				struct reexec_pending p;

				if (redqueen_pending_pick_mode_arg ==
				    REDQUEEN_PENDING_PICK_RANDOM)
					pending_idx = rnd_modulo_u32(
						child->reexec_pending_count);
				else
					pending_idx = 0;

				p = child->reexec_pending[pending_idx];

				child->in_reexec = true;
				redqueen_reexec_step(child, &p, pending_idx);
				child->in_reexec = false;
				gate_passed = true;
			} else {
				gate_skipped = (kcov_shm != NULL)
					? &kcov_shm->reexec_gate_skip_rate
					: NULL;
			}
		}

		if (kcov_shm != NULL) {
			if (gate_passed)
				__atomic_fetch_add(
					&kcov_shm->reexec_gate_pass,
					1UL, __ATOMIC_RELAXED);
			else if (gate_skipped != NULL)
				__atomic_fetch_add(gate_skipped,
						   1UL, __ATOMIC_RELAXED);
		}
	}

	/* Per-call attribution scratch is single-use: drained or not, the
	 * next call starts with a clean slate so a stale slot from the
	 * previous call cannot bleed into this call's attribution census. */
	child->reexec_pending_count = 0;

	/* Cheap end-of-call check for the strategy rotation boundary.
	 * Two relaxed loads + a compare in the common case; the CAS only
	 * fires once per ~STRATEGY_WINDOW ops fleet-wide. */
	maybe_rotate_strategy();

	if (new_cmp_out != NULL)
		*new_cmp_out = new_cmp;

	return true;
}

bool random_syscall_step(struct childdata *child,
			 bool have_substitute,
			 unsigned long substitute_retval,
			 bool *found_new)
{
	struct syscallrecord *rec = &child->syscall;
	struct syscallentry *entry;

	if (set_syscall_nr(rec, child) == FAIL)
		return FAIL;

	rec->postbuffer[0] = '\0';

	/* Generate arguments, print them out */
	generate_syscall_args(rec);

	/* Sequence-chain substitution.  When the previous step in the chain
	 * returned a usable value, with CHAIN_SUBST_PCT probability splice
	 * it into one randomly-chosen arg slot of this call, overwriting
	 * whatever the generator produced.  Done after generate_syscall_args
	 * so the substituted value is what the kernel actually sees, and
	 * before output_syscall_prefix so the trace reflects the real call. */
	entry = get_syscall_entry(rec->nr, rec->do32bit);
	apply_chain_substitution(rec, entry, have_substitute, substitute_retval);

	return dispatch_step(child, entry, found_new, NULL);
}

bool random_syscall(struct childdata *child)
{
	return random_syscall_step(child, false, 0, NULL);
}

/*
 * Replay a saved chain step: stage the saved (nr, do32bit, args) into
 * rec, run the saved args through the per-arg mutator chain, apply any
 * Phase 1 retval substitution from the prior step, and dispatch through
 * the same path random_syscall_step uses.  Returns FAIL when the saved
 * syscall is no longer callable in this run (deactivated, AVOID_SYSCALL,
 * needs root we don't have, or has a sanitise that would stash stale
 * pointers); the chain executor falls back to fresh args in that case.
 *
 * The mutator call goes to minicorpus_mutate_args, which is the same
 * splice + weighted-stack-mutate engine the per-syscall mini-corpus
 * replay uses.  Sharing the mutator means chain replay automatically
 * inherits productivity tuning from the existing weighted scheduler
 * rather than duplicating the mutation logic with its own counters.
 */
bool replay_syscall_step(struct childdata *child,
			 const struct chain_step *saved,
			 bool have_substitute,
			 unsigned long substitute_retval,
			 bool *found_new)
{
	struct syscallrecord *rec = &child->syscall;
	struct syscallentry *entry;
	unsigned long args[6];

	if (saved->nr >= MAX_NR_SYSCALL)
		return FAIL;

	entry = get_syscall_entry(saved->nr, saved->do32bit);
	if (entry == NULL)
		return FAIL;

	/* sanitise-bearing syscalls allocate and stash heap pointers into
	 * arg slots during generic_sanitise; replay would feed stale args
	 * to those slots.  Same gate the mini-corpus uses for the same
	 * reason. */
	if (entry->sanitise != NULL)
		return FAIL;

	/* The syscall may have been deactivated since the chain was saved
	 * (returned ENOSYS, hit AVOID_SYSCALL, lost a CAP_*).  Bail out
	 * rather than replay an inert call. */
	if (!validate_specific_syscall_silent(
			saved->do32bit ? syscalls_32bit :
			(biarch ? syscalls_64bit : syscalls),
			(int)saved->nr))
		return FAIL;

	memcpy(args, saved->args, sizeof(args));
	minicorpus_mutate_args(args, entry, saved->nr);

	/* Replay steps bypass set_syscall_nr() (which is where the bandit's
	 * per-arm pick stamp normally lands), so the child still holds the
	 * strategy_at_pick value from whichever fresh pick started the
	 * chain.  Letting that stale stamp ride through dispatch_step would
	 * credit replay-step PC/CMP novelty -- and the per-arm completion
	 * bump -- to an arm that did not actually pick the replayed syscall,
	 * contaminating the reward signal the bandit is meant to learn
	 * from.  Reset to the -1 sentinel so the existing strategy_at_pick
	 * gates at the consumer sites (kcov_collect_cmp / bandit_cmp_observe,
	 * the PC-edge per-strategy attribution in dispatch_step, the per-arm
	 * completion bump) all skip attribution for this step.
	 *
	 * The next fresh set_syscall_nr() overwrites strategy_at_pick
	 * unconditionally on the bandit-pool path, so leaving -1 here does
	 * not leak into subsequent non-replay calls. */
	child->strategy_at_pick = -1;

	if (chain_corpus_shm != NULL)
		__atomic_fetch_add(&chain_corpus_shm->replay_steps_dispatched,
				   1UL, __ATOMIC_RELAXED);

	/* Publish the (nr, do32bit) advance, the arg writes, the
	 * postbuffer reset, and the chain substitution as one coherent
	 * step.  An outside reader (watchdog thread, parent inspecting
	 * via shm, pre_crash_ring decode) that samples rec mid-step must
	 * not see the new (nr, do32bit) paired with the previous
	 * syscall's a1..a6 — that torn pairing miscredits args to the
	 * wrong syscall in divergence stats and crash-ring reconstruction.
	 * apply_chain_substitution writes rec->aN, so the publish_end
	 * has to come after it. */
	srec_publish_begin(rec);
	rec->do32bit = saved->do32bit;
	rec->nr = saved->nr;

	rec->a1 = args[0];
	rec->a2 = args[1];
	rec->a3 = args[2];
	rec->a4 = args[3];
	rec->a5 = args[4];
	rec->a6 = args[5];

	rec->postbuffer[0] = '\0';

	apply_chain_substitution(rec, entry, have_substitute, substitute_retval);
	srec_publish_end(rec);

	return dispatch_step(child, entry, found_new, NULL);
}

/*
 * Pin a single arg slot to a learned-constant value.  Slot is 1-based
 * (matches the rec->aN naming and reexec_pending::slot encoding).  Out-
 * of-range slots are dropped silently -- the caller validated against
 * the entry's num_args at attribution emit time, but defensive against
 * a corrupted pending entry that survived the slot bound check.
 */
static void redqueen_pin_slot(struct syscallrecord *rec, unsigned int slot,
			      unsigned long value)
{
	switch (slot) {
	case 1: rec->a1 = value; break;
	case 2: rec->a2 = value; break;
	case 3: rec->a3 = value; break;
	case 4: rec->a4 = value; break;
	case 5: rec->a5 = value; break;
	case 6: rec->a6 = value; break;
	default: break;
	}
}

/*
 * Field-scoped pin ([11-field-scoped]).  Unlike redqueen_pin_slot, the
 * targeted slot holds a POINTER to a freshly-regenerated fixed-size
 * struct; pin a single field inside that buffer and leave the rest of
 * the generated struct intact, so a kernel comparison that fired on one
 * field is satisfied without clobbering the whole arg.  Slot is 1-based.
 *
 * The buffer pointer is read AFTER generate_syscall_args() has run, so
 * it is whatever the generator just produced -- which for ARG_TIMESPEC
 * is either a valid pool pointer or the generator's ~10% NULL arm.  A
 * NULL / implausibly small pointer is left unpinned (the re-exec still
 * runs with fresh args, just without the field pin); the per-window cap
 * bounds the wasted budget.  Only the ARG_TIMESPEC tv_sec/tv_nsec pair
 * is wired today.
 */
static void redqueen_pin_field(struct syscallrecord *rec,
			       const struct reexec_pending *p)
{
	unsigned long ptr;
	struct timespec *ts;

	switch (p->slot) {
	case 1: ptr = rec->a1; break;
	case 2: ptr = rec->a2; break;
	case 3: ptr = rec->a3; break;
	case 4: ptr = rec->a4; break;
	case 5: ptr = rec->a5; break;
	case 6: ptr = rec->a6; break;
	default: return;
	}

	if (ptr < 4096)
		return;

	switch (p->field_kind) {
	case REEXEC_FIELD_TIMESPEC_SEC:
		ts = (struct timespec *) ptr;
		ts->tv_sec = (time_t) p->value;
		break;
	case REEXEC_FIELD_TIMESPEC_NSEC:
		ts = (struct timespec *) ptr;
		ts->tv_nsec = (long) p->value;
		break;
	case REEXEC_FIELD_NONE:
	default:
		break;
	}
}

/*
 * Greedy CMP RedQueen re-exec step.  Mirrors replay_syscall_step's
 * contract: resolve the entry, gate on sanitise-free (heap-pointer-
 * laundering inside generic_sanitise would either resurrect freed
 * slots or stomp the pin), gate on AVOID_REEXEC (auditable opt-out
 * for sanitise-free destructive entries -- see include/syscall.h),
 * gate on validate_specific_syscall_silent (caller may have lost a
 * cap / hit AVOID_SYSCALL / been deactivated since dispatch).  Then
 * regenerate fresh args via generate_syscall_args, overwrite the
 * targeted slot with the captured kernel-side constant, and re-enter
 * dispatch_step for the actual call.  Rec state is snapshotted on
 * entry and restored on exit so the chain-corpus save in sequence.c
 * (which reads rec->a1..a6 after dispatch_step returns) sees the
 * ORIGINAL dispatched args, not the re-exec's args.
 *
 * Per-call cap is enforced at the dispatch_step tail (C-1: 1 re-exec
 * per parent); per-window cap is enforced here so a corrupted /
 * misbehaving caller can't bypass it by calling the helper directly.
 */
static bool redqueen_reexec_step(struct childdata *child,
				 const struct reexec_pending *p,
				 unsigned int pending_idx)
{
	struct syscallrecord *rec = &child->syscall;
	struct syscallentry *entry;
	unsigned long saved_a[6];
	unsigned long saved_retval, saved_post_state;
	int saved_errno_post;
	bool ok;

	/* Per-window cap.  Reset to a fresh window
	 * once REDQUEEN_REEXEC_WINDOW_OPS child iterations have elapsed
	 * since the last reset; cap exceedance within a window short-
	 * circuits before any of the more expensive entry resolution. */
	if (child->op_nr - child->reexec_window_start_op >=
	    REDQUEEN_REEXEC_WINDOW_OPS) {
		child->reexec_window_start_op = child->op_nr;
		child->reexec_count_window = 0;
	}
	if (child->reexec_count_window >= REDQUEEN_REEXEC_WINDOW_CAP) {
		if (kcov_shm != NULL)
			__atomic_fetch_add(&kcov_shm->reexec_window_cap_hit,
					   1UL, __ATOMIC_RELAXED);
		return FAIL;
	}

	entry = get_syscall_entry(rec->nr, rec->do32bit);
	if (entry == NULL)
		return FAIL;

	/* Destructive-syscall gate: sanitise-bearing entries replay would
	 * either re-allocate (and leak) heap state for slots whose previous
	 * sanitise has already been freed by .cleanup, or stomp the captured
	 * pin with the re-sanitise's preferred value.  Same gate
	 * replay_syscall_step uses for the same reason.  Layered with the
	 * AVOID_REEXEC denylist for sanitise-free entries whose effects are
	 * still destructive to the calling child or to global state. */
	if (entry->sanitise != NULL || (entry->flags & AVOID_REEXEC)) {
		if (kcov_shm != NULL)
			__atomic_fetch_add(&kcov_shm->reexec_skipped_destructive,
					   1UL, __ATOMIC_RELAXED);
		return FAIL;
	}

	if (!validate_specific_syscall_silent(
			rec->do32bit ? syscalls_32bit :
			(biarch ? syscalls_64bit : syscalls),
			(int)rec->nr)) {
		if (kcov_shm != NULL)
			__atomic_fetch_add(&kcov_shm->reexec_skipped_validate_silent,
					   1UL, __ATOMIC_RELAXED);
		return FAIL;
	}

	if (p->slot == 0 || p->slot > entry->num_args)
		return FAIL;

	/* Snapshot the rec fields the re-exec's dispatch_step will rewrite.
	 * Restore on exit so a caller that reads rec after the helper
	 * returns -- the chain-corpus save in sequence.c being the
	 * load-bearing one -- sees the original dispatched call's args /
	 * retval, not the re-exec's.  nr / do32bit are NOT in the snapshot
	 * set: redqueen always dispatches the same (nr, do32) as the
	 * parent, so those fields stay invariant across the helper. */
	saved_a[0] = rec->a1;
	saved_a[1] = rec->a2;
	saved_a[2] = rec->a3;
	saved_a[3] = rec->a4;
	saved_a[4] = rec->a5;
	saved_a[5] = rec->a6;
	saved_retval = rec->retval;
	saved_post_state = rec->post_state;
	saved_errno_post = rec->errno_post;

	/* Coherent re-publish of the re-exec dispatch state.  Same (nr,
	 * do32bit) as the parent, but generate_syscall_args is about to
	 * overwrite rec->aN and the prebuffer/postbuffer, so wrap the
	 * preparation in a publish bracket so any out-of-band reader
	 * (parent watchdog, pre_crash decoder) sees the new args paired
	 * with the original nr rather than a torn mid-mutation view. */
	srec_publish_begin(rec);
	rec->postbuffer[0] = '\0';
	srec_publish_end(rec);

	generate_syscall_args(rec);
	if (p->field_kind == REEXEC_FIELD_NONE)
		redqueen_pin_slot(rec, p->slot, p->value);
	else
		redqueen_pin_field(rec, p);

	/* Don't credit the bandit for re-exec wins -- same rationale as
	 * replay_syscall_step.  -1 sentinel makes the per-strategy
	 * attribution and per-arm completion sites skip this dispatch. */
	child->strategy_at_pick = -1;

	if (kcov_shm != NULL) {
		unsigned int op_type = (unsigned int)child->op_type;

		__atomic_fetch_add(&kcov_shm->reexec_attempts, 1UL,
				   __ATOMIC_RELAXED);
		/* per-nr partition of the re-exec attempt
		 * counter.  Reaching this site means the destructive /
		 * validate_silent / slot-bounds gates above already cleared,
		 * so the bump is attributed to the same syscall that the
		 * inner dispatch_step will actually re-run. */
		if (rec->nr < MAX_NR_SYSCALL)
			__atomic_fetch_add(
				&kcov_shm->reexec_attempts_by_syscall[rec->nr],
				1UL, __ATOMIC_RELAXED);
		/* per-childop partition of the re-exec attempt counter,
		 * sibling of the per-syscall bump above.  Lets a re-exec
		 * driven by a non-OP_SYSCALL childop (recipe runner, io_uring
		 * flood, etc.) be counted separately from the same nr fired
		 * from the default OP_SYSCALL flow. */
		if (op_type < KCOV_CHILDOP_NR_MAX)
			__atomic_fetch_add(
				&kcov_shm->reexec_attempts_by_childop[op_type],
				1UL, __ATOMIC_RELAXED);
	}
	child->reexec_count_window++;

	{
		unsigned long inner_new_cmp = 0;

		/* The re-exec's lift signal is the inner dispatch's per-call
		 * bloom-novel CMP count -- the authoritative value
		 * kcov_collect_cmp() returns to dispatch_step's local new_cmp.
		 * Surfacing it via the out-param avoids sampling the shared
		 * cmp_records_collected counter around the call: those relaxed
		 * loads race other CMP children's increments (over-attributing
		 * their records to this re-exec) and count raw duplicate
		 * records (not just novel ones), the same bug class avoided
		 * for PC edges via kcov_collect()'s new_edge_count out-param. */
		ok = dispatch_step(child, entry, NULL, &inner_new_cmp);

		if (kcov_shm != NULL && inner_new_cmp > 0) {
			unsigned int op_type = (unsigned int)child->op_type;

			__atomic_fetch_add(&kcov_shm->reexec_new_cmps_total,
					   inner_new_cmp, __ATOMIC_RELAXED);
			if (rec->nr < MAX_NR_SYSCALL)
				__atomic_fetch_add(
					&kcov_shm->per_syscall_cmp_novelty_reexec[rec->nr],
					inner_new_cmp, __ATOMIC_RELAXED);
			/* per-childop partition of the re-exec lift signal,
			 * sibling of the per-syscall sibling above.  Same
			 * inner_new_cmp accumulation; the childop dimension
			 * answers "which non-OP_SYSCALL childops are
			 * harvesting the bulk of the re-exec CMP novelty". */
			if (op_type < KCOV_CHILDOP_NR_MAX)
				__atomic_fetch_add(
					&kcov_shm->per_childop_cmp_novelty_reexec[op_type],
					inner_new_cmp, __ATOMIC_RELAXED);
			/* per-slot success counter.  Pair
			 * with reexec_attribution_slot_hist (the per-slot
			 * attempt-attribution histogram) to read per-slot
			 * success rate -- a slot that attracts the bulk of
			 * attributions but produces no novelty wins is
			 * wasted re-exec budget.  p->slot is 1-based and
			 * was bounds-checked at the consumer-side
			 * (p->slot <= entry->num_args) gate above. */
			if (p->slot >= 1 &&
			    p->slot <= CMP_REDQUEEN_SLOT_HIST_NR)
				__atomic_fetch_add(
					&kcov_shm->reexec_success_by_slot[p->slot - 1],
					1UL, __ATOMIC_RELAXED);
			/* Per-pending-buffer-index success counter, the
			 * A/B signal for --redqueen-pending-pick.  The
			 * caller's pick site clamps pending_idx to
			 * [0, child->reexec_pending_count) and the
			 * reexec_pending_count==0 short-circuit one level
			 * above guarantees count > 0 there, so a sane
			 * caller always lands in range -- the explicit
			 * REEXEC_PENDING_PICK_HIST_NR clamp here is
			 * defence in depth against a future caller
			 * passing an out-of-range index (or a corrupted
			 * reexec_pending_count value reaching
			 * rnd_modulo_u32 and rolling past the bound). */
			if (pending_idx < REEXEC_PENDING_PICK_HIST_NR)
				__atomic_fetch_add(
					&kcov_shm->reexec_pending_pick_success[pending_idx],
					1UL, __ATOMIC_RELAXED);
		}
	}

	/* Restore the dispatched-call state so downstream readers (the
	 * chain-corpus save in particular) see the parent's args / retval,
	 * not the re-exec's.  Wrap in a publish bracket so a watchdog
	 * sampling rec mid-restore does not catch the rec halfway between
	 * the re-exec values and the parent values. */
	srec_publish_begin(rec);
	rec->a1 = saved_a[0];
	rec->a2 = saved_a[1];
	rec->a3 = saved_a[2];
	rec->a4 = saved_a[3];
	rec->a5 = saved_a[4];
	rec->a6 = saved_a[5];
	rec->retval = saved_retval;
	rec->post_state = saved_post_state;
	rec->errno_post = saved_errno_post;
	srec_publish_end(rec);

	return ok;
}
