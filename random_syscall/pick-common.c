/*
 * Table selection and validation helpers shared by the three picker
 * arms (set_syscall_nr_heuristic, set_syscall_nr_random,
 * set_syscall_nr_coverage_frontier) in random_syscall/pickers.c.
 * choose_syscall_table is public via include/syscall.h; the rest are
 * cross-cluster private and declared in
 * include/random-syscall-internal.h.
 */

#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#include "arch.h"	// biarch
#include "arg-decoder.h"
#include "child.h"
#include "cmp-frontier.h"
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
#include "random-syscall-internal.h"
#include "reach-band.h"
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

/*
 * Checked loader for the shared active-syscall counts.  All three
 * picker arms (set_syscall_nr_heuristic / _random / _coverage_frontier
 * in pickers.c) and the biarch table-selector (choose_syscall_table
 * below) load one of shm->nr_active_syscalls, nr_active_32bit_syscalls,
 * or nr_active_64bit_syscalls under RELAXED, feed it to rnd_modulo_u32
 * (), and index child->active_syscalls[] -- which points into the
 * shm->active_syscalls*[MAX_NR_SYSCALL] arrays (include/shm.h).  A
 * stomped count that exceeds MAX_NR_SYSCALL walks the flat draw off
 * the SHM mapping.  Same failure class as the cmp-hints pool count
 * (see cmp_hints_pool_corrupted() in cmp_hints/pool.c and the
 * cmp_hints_count_oob counter in include/kcov.h).
 *
 * Centralise the load + validate + log here so every consumer trips
 * the same self-corrupt marker with a uniform arch label, and so
 * follow-up work that grows the observability surface (e.g. a
 * per-arch shm counter modelled after cmp_hints_count_oob) has one
 * site to bump.  Callers detect corruption via the returned value
 * being > MAX_NR_SYSCALL and take their existing FAIL / skip path;
 * the raw observed value is returned so forensics from the log line
 * and the caller's decision are consistent.
 *
 * A zero count is NOT corrupt and is deliberately not touched here:
 * rnd_modulo_u32(0) is defined to return 0, no_syscalls_enabled()
 * bails on the sustained-zero case, and a transient zero from a
 * racing deactivate is absorbed by the picker's existing val==0
 * retry guard.  The picked-syscall-number bound (syscallnr <
 * MAX_NR_SYSCALL) is guarded at its own indexing sites and is not
 * this helper's concern.
 *
 * RELAXED matches the pre-existing pick-hot-path atomic shape (no
 * ordering is inferred from the count against the active_syscalls[]
 * slot loads; the val == 0 retry absorbs any tear on the paired
 * entry).  Consumes no RNG so seeded-run determinism is preserved.
 *
 * Prototype duplicated in pickers.c (the other caller): not hoisted
 * into random-syscall-internal.h yet -- promote when a caller
 * appears outside this two-file cluster.  The local prototype
 * silences -Wmissing-prototypes for the non-static definition
 * without dragging a header edit into this fix.
 */
unsigned int load_active_syscall_count(const unsigned int *shm_count,
				       const char *arch_label);
unsigned int load_active_syscall_count(const unsigned int *shm_count,
				       const char *arch_label)
{
	unsigned int nr = __atomic_load_n(shm_count, __ATOMIC_RELAXED);

	if (nr > MAX_NR_SYSCALL) {
		output(0,
		       "[%d] active-syscall count self-corrupt: %s=%u exceeds cap %u\n",
		       mypid(), arch_label, nr,
		       (unsigned int)MAX_NR_SYSCALL);
	}
	return nr;
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
		*nr_syscalls_out = load_active_syscall_count(
			&shm->nr_active_64bit_syscalls,
			"nr_active_64bit_syscalls");
	} else {
		syscalls = syscalls_32bit;
		child->active_syscalls = shm->active_syscalls32;
		*nr_syscalls_out = load_active_syscall_count(
			&shm->nr_active_32bit_syscalls,
			"nr_active_32bit_syscalls");
	}
	/* Return signal reserved for do32 by the public signature in
	 * include/syscall.h; a corrupt count arrives at the caller via
	 * *nr_syscalls_out > MAX_NR_SYSCALL and each picker arm turns
	 * that into its existing FAIL path. */
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

void note_validation_success(unsigned int syscallnr, bool do32)
{
	unsigned int arch = do32 ? 1 : 0;

	if (__atomic_load_n(&shm->syscall_validation_failures[arch][syscallnr],
			    __ATOMIC_RELAXED) != 0)
		__atomic_store_n(&shm->syscall_validation_failures[arch][syscallnr],
				 0, __ATOMIC_RELAXED);
}

void note_validation_failure(unsigned int syscallnr, bool do32)
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

	if ((do_specific_syscall || random_selection ||
	     desired_group != GROUP_NONE) &&
	    no_syscalls_enabled() == true)
		outputerr("%s was the last syscall in the targeted set; "
			  "depleted via %u validation failures\n",
			  name, VALIDATE_FAIL_THRESHOLD);
}

/*
 * Default OFF: see the enum comment in include/kcov.h for the mode
 * contract.  Read RELAXED at the helper site -- parse-time configured,
 * never mutated at runtime, so a tear is impossible. */
enum expensive_adaptive_mode expensive_adaptive_mode =
	EXPENSIVE_ADAPTIVE_MODE_OFF;

/*
 * Default OFF: see the enum comment in include/reach-band.h for the
 * mode contract.  Read RELAXED at the frontier_cold_weight() hook --
 * parse-time configured, never mutated at runtime, so a tear is
 * impossible. */
enum reach_band_mode reach_band_mode = REACH_BAND_OFF;

/*
 * Default OFF: see the enum comment in include/cmp-frontier.h for the
 * mode contract.  Read RELAXED at the silent-regime accept gate in
 * set_syscall_nr_coverage_frontier() -- parse-time configured, never
 * mutated at runtime, so a tear is impossible.
 */
enum cmp_frontier_mode cmp_frontier_mode = CMP_FRONTIER_OFF;

/* Static (today's) accept denominator for EXPENSIVE-flagged syscalls.
 * In OFF / NULL-kcov / SHADOW_ONLY the live accept ALWAYS draws
 * ONE_IN(EXPENSIVE_ADAPTIVE_FLOOR) so the pick stream matches the
 * pre-helper `!ONE_IN(1000)` expression bit-for-bit. */
#define EXPENSIVE_ADAPTIVE_FLOOR        1000U
/* Most aggressive accept denominator under COMBINED.  1/50 is the
 * tunable ceiling end of the productivity-to-N map -- a perfectly
 * productive EXPENSIVE syscall earns ~20x its static rate; the floor
 * still caps fleet wall-cost on the dead end. */
#define EXPENSIVE_ADAPTIVE_CEILING      50U
/* Cold-warmup gate: until cumulative calls (current run + warm-loaded
 * prior) cross this, leave the rate at the floor.  Matches KCOV_SAT_
 * CAP_CALLS so the warmup horizon and the saturation-cap horizon stay
 * in lock-step. */
#define EXPENSIVE_ADAPTIVE_WARMUP_CALLS 200UL
/* Stale-decay step count: this many contiguous KCOV_COLD_THRESHOLD-
 * sized gap steps slide n_adaptive all the way back to the floor.
 * Matches the +10pct-per-step cadence of kcov_syscall_cold_skip_pct
 * (its 50%->90% over four steps is the same one-tenth-per-step shape,
 * just from a lower starting bias). */
#define EXPENSIVE_ADAPTIVE_DECAY_STEPS  10U

/*
 * Adaptive accept-rate for the EXPENSIVE early-out gate -- factored
 * out of the three set_syscall_nr_*() call sites so the policy lives
 * in one place.  See the expensive_adaptive_mode enum in include/
 * kcov.h for the OFF / SHADOW_ONLY / COMBINED contract.
 *
 * Returns true to ACCEPT the candidate (caller proceeds to validate),
 * false to reject (caller does goto retry).
 *
 * Correctness invariants:
 *
 *   OFF byte-identity.  When mode is OFF the function MUST behave
 *   exactly like `syscall_is_expensive(nr, do32) && !ONE_IN(1000)` --
 *   same control flow AND same RNG draw order.  Specifically: if the
 *   syscall is not EXPENSIVE, no RNG draw fires (matches the short-
 *   circuit half of the original `&&`); if it is EXPENSIVE, exactly
 *   one ONE_IN(EXPENSIVE_ADAPTIVE_FLOOR) call fires, consuming the
 *   same number of rnd_u32() draws as the original.  The OFF / NULL-
 *   kcov / bad-index branches short-circuit before any kcov_shm read
 *   for that reason.
 *
 *   SHADOW_ONLY pick parity.  Under SHADOW_ONLY the adaptive compute
 *   path runs (so the cost is exercised today and a follow-up row
 *   adding shadow counters has somewhere to hook), but the LIVE accept
 *   still draws ONE_IN(EXPENSIVE_ADAPTIVE_FLOOR) -- pick stream stays
 *   identical to OFF for a given seed.  The compute path does not
 *   consume RNG, so SHADOW_ONLY and OFF draw the same rnd_u32() count
 *   at this site.
 *
 *   Unsigned-subtract / divide-by-zero guards.  per_syscall_edges /
 *   per_syscall_calls are RELAXED separate loads; the semantic edges
 *   <= calls invariant (see include/kcov.h) can be violated by a
 *   load-tear across the two atomics, so the productivity divide
 *   guards edges_total < calls_total before dividing.  The cold-
 *   warmup branch guarantees calls_total >= WARMUP > 0 by the time
 *   the divide is reached, so calls_total == 0 cannot underflow it
 *   either.  total_calls -- last_edge_at is a similar RELAXED-RELAXED
 *   subtract; guard total > last before subtracting.  EXPENSIVE_
 *   ADAPTIVE_FLOOR -- n_adaptive is guarded by n_adaptive <
 *   EXPENSIVE_ADAPTIVE_FLOOR.
 *
 *   Degrade-safe fallback.  When kcov_shm is unavailable (no-kcov
 *   build / startup ordering / nr out of range), return the static
 *   1/EXPENSIVE_ADAPTIVE_FLOOR rate -- matches the kcov-less fallback
 *   the rest of the file already takes (frontier_cold_weight returns
 *   FRONTIER_COLD_SCALE in the same shape).
 */
bool expensive_accept(unsigned int nr, bool do32)
{
	enum expensive_adaptive_mode mode;
	unsigned long edges, calls, edges_total, calls_total;
	unsigned long total, last, gap;
	unsigned int n_adaptive;
	unsigned int n_live;
	unsigned long productivity_recip;
	bool accept;

	/* Not EXPENSIVE-flagged: accept unconditionally with no RNG
	 * draw.  Mirrors the short-circuit half of the original
	 * `syscall_is_expensive && !ONE_IN(1000)` expression. */
	if (!syscall_is_expensive(nr, do32))
		return true;

	mode = __atomic_load_n(&expensive_adaptive_mode, __ATOMIC_RELAXED);

	/* OFF / NULL-kcov / bad-index: draw against the static floor.
	 * Equivalent to `!ONE_IN(EXPENSIVE_ADAPTIVE_FLOOR)` being false,
	 * i.e. `ONE_IN(FLOOR)` -- one rnd_modulo_u32(1000) draw, same
	 * shape as the original expression's right-hand side. */
	if (mode == EXPENSIVE_ADAPTIVE_MODE_OFF || kcov_shm == NULL ||
	    nr >= MAX_NR_SYSCALL)
		return ONE_IN(EXPENSIVE_ADAPTIVE_FLOOR);

	/* Denominator for the adaptive-gate observability triad.  Bumped
	 * once per entry past the OFF / NULL-kcov / out-of-range early-
	 * return -- i.e. once per call into the adaptive compute path
	 * under SHADOW_ONLY or COMBINED.  See the expensive_adaptive_*
	 * field-comment block in include/stats.h. */
	__atomic_fetch_add(&shm->stats.expensive_adaptive.samples, 1UL,
			   __ATOMIC_RELAXED);

	/* Sum current-run counters with the warm-loaded priors so the
	 * adaptive math benefits from cross-session evidence (same shape
	 * kcov_syscall_cold_skip_pct uses for the saturation cap).  The
	 * _prior arrays are frozen at warm-start (see include/kcov.h),
	 * so a plain read is sufficient. */
	edges = per_syscall_edges_total(nr);
	calls = per_syscall_calls_total(nr);
	edges_total = edges + per_syscall_edges_prior_total(nr);
	calls_total = calls + per_syscall_calls_prior_total(nr);

	/* Cold-warmup and barren both pin to the floor.  The warmup
	 * branch also guarantees calls_total > 0 by the time the divide
	 * below runs, so the productivity branch cannot hit a
	 * divide-by-zero on calls_total. */
	if (calls_total < EXPENSIVE_ADAPTIVE_WARMUP_CALLS ||
	    edges_total == 0) {
		n_adaptive = EXPENSIVE_ADAPTIVE_FLOOR;
	} else {
		/* Productive regime.  edges_total <= calls_total is a
		 * semantic invariant (per_syscall_edges bumps by one per
		 * call that discovered >=1 new edge), but the two RELAXED
		 * atomic loads can tear across each other, so clamp before
		 * dividing.  Smaller calls/edges = better productivity =
		 * smaller N = higher accept rate. */
		if (edges_total >= calls_total)
			productivity_recip = 1UL;
		else
			productivity_recip = calls_total / edges_total;

		if (productivity_recip <= EXPENSIVE_ADAPTIVE_CEILING)
			n_adaptive = EXPENSIVE_ADAPTIVE_CEILING;
		else if (productivity_recip >= EXPENSIVE_ADAPTIVE_FLOOR)
			n_adaptive = EXPENSIVE_ADAPTIVE_FLOOR;
		else
			n_adaptive = (unsigned int)productivity_recip;

		/* Stale-decay: once-productive but no recent edge slides
		 * n_adaptive back toward the floor.  Re-uses kcov_syscall
		 * _cold_skip_pct's total_calls -- last_edge_at gap shape:
		 * each KCOV_COLD_THRESHOLD-sized step erases one tenth of
		 * the remaining cheap-rate grant, so EXPENSIVE_ADAPTIVE_
		 * DECAY_STEPS=10 contiguous steps fully demote.  Load-bearing:
		 * the floor caps wall-cost, so the cheaper rate MUST decay
		 * once productivity stops.
		 *
		 * Unsigned-subtract guard: total_calls and last_edge_at[]
		 * are monotonic by construction (no decrement path in
		 * kcov_collect), but the two RELAXED loads sample the
		 * fields independently and can observe last > total under a
		 * concurrent kcov_collect update.  Treat that case as zero
		 * gap (skip the decay) instead of underflowing the
		 * subtract. */
		total = __atomic_load_n(&kcov_shm->total_calls,
					__ATOMIC_RELAXED);
		last = __atomic_load_n(&kcov_shm->last_edge_at[nr],
				       __ATOMIC_RELAXED);
		if (total > last) {
			gap = total - last;
			if (gap > KCOV_COLD_THRESHOLD &&
			    n_adaptive < EXPENSIVE_ADAPTIVE_FLOOR) {
				unsigned long steps = gap / KCOV_COLD_THRESHOLD;
				unsigned long range, decay;
				unsigned int n_pre = n_adaptive;

				range = (unsigned long)EXPENSIVE_ADAPTIVE_FLOOR
					- (unsigned long)n_adaptive;
				if (steps >= EXPENSIVE_ADAPTIVE_DECAY_STEPS) {
					n_adaptive = EXPENSIVE_ADAPTIVE_FLOOR;
				} else {
					decay = (range * steps) /
						EXPENSIVE_ADAPTIVE_DECAY_STEPS;
					n_adaptive = (unsigned int)
						((unsigned long)n_adaptive +
						 decay);
				}
				/* Stale-decay re-cap actually fired: the
				 * cheaper sub-floor n_adaptive was pushed
				 * back up toward the floor.  Guard against
				 * the integer-truncation no-op where range *
				 * steps / DECAY_STEPS rounds to 0 (e.g.
				 * n_adaptive close to the floor with a small
				 * step count) -- a check that leaves N
				 * unchanged is not a demote and must not
				 * inflate the counter.  See the expensive_
				 * adaptive_demotes field comment in include/
				 * stats.h. */
				if (n_adaptive != n_pre)
					__atomic_fetch_add(
						&shm->stats.expensive_adaptive.demotes,
						1UL, __ATOMIC_RELAXED);
			}
		}
	}

	/* SHADOW_ONLY: compute path above ran, but the live accept stays
	 * at the floor so the pick stream is identical to OFF.  COMBINED
	 * is the only mode that lets n_adaptive drive the draw. */
	if (mode == EXPENSIVE_ADAPTIVE_MODE_SHADOW_ONLY)
		n_live = EXPENSIVE_ADAPTIVE_FLOOR;
	else
		n_live = n_adaptive;

	/* Shadow-only mass: count sub-floor opportunities deterministically
	 * (no extra RNG draw, so SHADOW_ONLY pick parity vs OFF is
	 * preserved).  The live ONE_IN(FLOOR) below would have to be a
	 * second draw against n_adaptive to give a per-event observation;
	 * the field comment in include/stats.h explains the unit-of-
	 * measure asymmetry vs the COMBINED bump below. */
	if (mode == EXPENSIVE_ADAPTIVE_MODE_SHADOW_ONLY &&
	    n_adaptive < EXPENSIVE_ADAPTIVE_FLOOR)
		__atomic_fetch_add(&shm->stats.expensive_adaptive.extra_accepts,
				   1UL, __ATOMIC_RELAXED);

	accept = ONE_IN(n_live);

	/* COMBINED: a real sub-floor accept just fired.  See the
	 * expensive_adaptive_extra_accepts field comment in include/
	 * stats.h for the convergence-to-true-extras semantics. */
	if (accept && mode == EXPENSIVE_ADAPTIVE_MODE_COMBINED &&
	    n_adaptive < EXPENSIVE_ADAPTIVE_FLOOR)
		__atomic_fetch_add(&shm->stats.expensive_adaptive.extra_accepts,
				   1UL, __ATOMIC_RELAXED);

	return accept;
}

/*
 * Cost-pool one-shot selector SHADOW observer.  Called once per
 * HEURISTIC / RANDOM pick entry (after choose_syscall_table but
 * before the live rnd_modulo_u32 draw) so the per-pool expected
 * fractions are attributed against the SAME arch table the live
 * picker will draw from.
 *
 * OFF is the fast path: a single RELAXED mode load, short-circuit,
 * return.  No shm loads, no divide, no shadow-counter atomics --
 * the pick's byte-identity to a pre-row build depends on this
 * being the ONLY side effect the OFF branch has.
 *
 * SHADOW_ONLY / COMBINED: read the arch-specific per-pool live
 * counts under RELAXED (parse-time constants R and 1_000_000
 * elided into the divide), compute the section 4.1 closed-form
 * expected-expensive-fraction scaled to parts-per-million, and
 * accumulate under RELAXED.  ZERO rnd_u32() draws so the live pick
 * stream is preserved bit-for-bit regardless of mode.  Divide-by-
 * zero guard: skipped when both per-pool counts are zero (arch
 * table has no active syscalls; the flat picker's outer_attempts
 * budget will bail anyway).
 *
 * See the enum cost_pool_selector_mode comment in include/strategy.h
 * for the mode contract and the cost_pool_selector_shadow_* field
 * comments in include/stats.h for the counter semantics.
 */
void cost_pool_selector_shadow_note(bool do32)
{
	enum cost_pool_selector_mode mode;
	unsigned int n_cheap, n_exp;
	unsigned long denom;
	unsigned long ppm;

	mode = __atomic_load_n(&cost_pool_selector_mode, __ATOMIC_RELAXED);
	if (mode == COST_POOL_SELECTOR_MODE_OFF)
		return;

	if (biarch) {
		if (do32) {
			n_cheap = __atomic_load_n(
				&shm->nr_active_cheap_32bit,
				__ATOMIC_RELAXED);
			n_exp = __atomic_load_n(
				&shm->nr_active_exp_32bit,
				__ATOMIC_RELAXED);
		} else {
			n_cheap = __atomic_load_n(
				&shm->nr_active_cheap_64bit,
				__ATOMIC_RELAXED);
			n_exp = __atomic_load_n(
				&shm->nr_active_exp_64bit,
				__ATOMIC_RELAXED);
		}
	} else {
		n_cheap = __atomic_load_n(&shm->nr_active_cheap,
					  __ATOMIC_RELAXED);
		n_exp = __atomic_load_n(&shm->nr_active_exp,
					__ATOMIC_RELAXED);
	}

	/* Both empty -- no active syscalls on the chosen arch table; the
	 * flat picker's outer_attempts loop will bail on nr_syscalls == 0
	 * and never draw a syscall here.  Skip the divide (would be a
	 * divide-by-zero) and the shadow bump (there is no pick event
	 * to attribute). */
	denom = (unsigned long)n_cheap * (unsigned long)EXPENSIVE_ADAPTIVE_FLOOR
		+ (unsigned long)n_exp;
	if (denom == 0)
		return;

	/* 1_000_000 * n_exp fits in a 64-bit unsigned long comfortably
	 * for any n_exp <= MAX_NR_SYSCALL (~2 k on Linux); ppm is at
	 * most 1_000_000 (when n_cheap == 0). */
	ppm = (1000000UL * (unsigned long)n_exp) / denom;

	__atomic_fetch_add(&shm->stats.cost_pool_selector.shadow_picks,
			   1UL, __ATOMIC_RELAXED);
	__atomic_fetch_add(
		&shm->stats.cost_pool_selector.shadow_expensive_ppm_sum,
		ppm, __ATOMIC_RELAXED);
}

/*
 * Cost-pool one-shot selector LIVE-accept attribution.  Called from
 * the pick-finalise site in set_syscall_nr_heuristic and
 * set_syscall_nr_random (immediately before srec_publish_begin so
 * downstream gates that reject cannot double-count) with the
 * finalised (nr, do32) the child will execute.
 *
 * OFF short-circuits before any shm read or atomic so a build with
 * cost_pool_selector_mode == OFF is bit-for-bit identical to a
 * pre-row build (no ppc_call_ratio drift from an added __atomic_
 * fetch_add per pick, no torn snapshot of the live counters, no
 * stale-cacheline contention on the pick hot path).  SHADOW_ONLY /
 * COMBINED bump the arch-appropriate live-accept counter; the cost
 * class comes from the read-only EXPENSIVE bitmap (via
 * syscall_is_expensive()) that select_syscall_tables() builds once
 * at init, so a scribbled entry->flags cannot mis-attribute.
 */
void cost_pool_selector_live_note(unsigned int nr, bool do32)
{
	enum cost_pool_selector_mode mode =
		__atomic_load_n(&cost_pool_selector_mode, __ATOMIC_RELAXED);

	if (mode == COST_POOL_SELECTOR_MODE_OFF)
		return;

	if (syscall_is_expensive(nr, do32))
		__atomic_fetch_add(
			&shm->stats.cost_pool_selector.live_expensive_picks,
			1UL, __ATOMIC_RELAXED);
	else
		__atomic_fetch_add(
			&shm->stats.cost_pool_selector.live_cheap_picks,
			1UL, __ATOMIC_RELAXED);
}

/*
 * Cost-pool one-shot selector PRE-GATE draw attribution.  Called from
 * the HEURISTIC / RANDOM picker arms immediately after the flat
 * uniform draw survives expensive_accept() -- i.e. once the expensive
 * throttle has accepted the candidate but BEFORE any downstream
 * picker gate (validate_specific_syscall_silent, anti_prior, cred-
 * throttle) has had a chance to reject or re-roll it.
 *
 * This is the exact population the shadow closed-form models:
 * uniform draw over the active table + expensive_accept at 1/1000,
 * with no post-hoc enrichment.  The live_ pair fires at pick-
 * finalise (after all downstream gates) and therefore cannot be
 * compared directly to the shadow analytical fraction on runs where
 * anti_prior is on -- it enriches the accepted stream in rare /
 * expensive syscalls ~3x.  The predraw_ pair closes that gap so a
 * `--cost-pool-selector=shadow-only` validation run can compare
 * apples to apples.
 *
 * OFF short-circuits before any shm read or atomic so a build with
 * cost_pool_selector_mode == OFF is bit-for-bit identical to a pre-
 * row build (no per-draw atomic add, no torn snapshot, no stale-
 * cacheline contention on the pick hot path).  RNG-neutral in every
 * mode -- no rnd_* calls added.
 */
void cost_pool_selector_predraw_note(unsigned int nr, bool do32)
{
	enum cost_pool_selector_mode mode =
		__atomic_load_n(&cost_pool_selector_mode, __ATOMIC_RELAXED);

	if (mode == COST_POOL_SELECTOR_MODE_OFF)
		return;

	if (syscall_is_expensive(nr, do32))
		__atomic_fetch_add(
			&shm->stats.cost_pool_selector.predraw_expensive_picks,
			1UL, __ATOMIC_RELAXED);
	else
		__atomic_fetch_add(
			&shm->stats.cost_pool_selector.predraw_cheap_picks,
			1UL, __ATOMIC_RELAXED);
}

/*
 * Check if a syscall entry belongs to the target group.
 * Used by group biasing to filter candidates.
 */
bool syscall_in_group(unsigned int nr, bool do32, unsigned int target_group)
{
	struct syscallentry *entry;

	entry = get_syscall_entry(nr, do32);
	if (entry == NULL)
		return false;

	return entry->group == target_group;
}
