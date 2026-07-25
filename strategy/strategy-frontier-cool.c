/*
 * Coverage-frontier saturation and barren-demote cooldown helpers.
 * Split from strategy-frontier.c.
 */

#include <stdbool.h>

#include "kcov.h"
#include "object-types.h"	/* OBJ_NONE */
#include "shm.h"
#include "stats.h"
#include "strategy.h"
#include "syscall.h"		/* MAX_NR_SYSCALL, struct syscallentry */
#include "tables.h"		/* get_syscall_entry */

/*
 * SHADOW-ONLY saturation-cooldown predicate, extracted from the silent-
 * regime accept site in random-syscall.c.  Gated by
 * --frontier-saturation-cooldown != off.  Sibling of the silent-streak
 * decay block and the errno-plateau block at the call site; this one
 * targets the same wasteful-silent-pick shape but uses the windowed
 * frontier-edge ring (frontier_recent_count, decays by construction
 * via the per-rotation slot zero + CAS-decrement of
 * frontier_recent_count_cached in frontier_window_advance) for the
 * plateau trigger, and the corrected first-success-TRANSITION +
 * distinct-CMP-insert spare lanes for the under-explored struct-arg
 * backlog.  See the enum frontier_saturation_cooldown_mode comment in
 * include/strategy.h for the predicate contract, the
 * FRONTIER_SATCOOL_CMIN comment for the magnitude-gate rationale, and
 * the per-counter struct comments in include/stats.h for semantics.
 *
 * Why this gate exists alongside the silent-streak decay at the call
 * site: that gate's UNLESS clause keys on raw ERRNO_BUCKET_SUCCESS
 * count, which advances on every successful return.  A syscall that
 * succeeds on every call (syncfs / sendfile with valid args / writev
 * to /dev/null) bumps the success bucket monotonically and the
 * existing UNLESS clause's baseline-equality test never trips -- the
 * streak decay cannot cool the single biggest reclaim target.  Keying
 * plateau on the windowed edge ring instead (which ages out old
 * productivity by construction) and gating the spare lane on a
 * first-success TRANSITION (errno_base == 0 AND errno_now > 0) rather
 * than a raw success-count delta closes the gap; the magnitude gate +
 * ret_objtype exemption keep the under-explored struct-arg backlog
 * (removexattrat / futex / fcntl) and the object-producers (openat /
 * socket / memfd_create / mmap / io_uring_setup / bpf) out of the
 * demote set.
 *
 * SHADOW-ONLY by construction: the helper computes the predicate and
 * bumps the frontier_satcool_* shadow counters but never reaches a
 * goto-retry at the call site, so the picker's accept distribution
 * stays byte-identical to the default-off baseline regardless of which
 * non-OFF mode is selected.  Wiring the COMBINED live reject is a
 * deliberate follow-up after a SHADOW_ONLY run validates the demote
 * mass concentrates on syncfs / sendfile / semget / writev and is ~0
 * on removexattrat / futex / io_uring_setup / bpf.
 *
 * Outer guard keeps the OFF path byte-identical to a build before the
 * feature: no kcov_shm load, no bitmap lookup, no atomic loads beyond
 * the single RELAXED mode read.  The MAX_NR_SYSCALL bound mirrors the
 * existing silent-streak block's bound at the call site so the per-
 * syscall would-skip array index is safe.
 *
 * Byte-identical to the pre-extraction inline shape: the candidate
 * gate is (calls_total >= FRONTIER_SATCOOL_CMIN AND windowed_edges
 * == 0); a windowed_edges != 0 nr early-returns from the shared
 * spare-lane decide function with FRONTIER_SPARE_WINDOWED_EDGES, which
 * this wrapper treats as the same "no bump" outcome the original
 * candidate-gate early-return produced.  The arggen-wins-over-
 * objproducer precedence in the bump cascade is preserved by the
 * lane-order in frontier_spare_lane_decide above.
 */
void frontier_satcool_spare(unsigned int syscallnr, bool do32)
{
	enum frontier_saturation_cooldown_mode satcool_mode;
	enum frontier_spare_reason reason;
	unsigned long calls_total;

	satcool_mode = __atomic_load_n(&frontier_saturation_cooldown_mode,
				       __ATOMIC_RELAXED);
	if (satcool_mode == FRONTIER_SATURATION_COOLDOWN_MODE_OFF)
		return;
	if (kcov_shm == NULL)
		return;
	if (syscallnr >= MAX_NR_SYSCALL)
		return;

	calls_total = per_syscall_calls_total(syscallnr);
	if (calls_total < FRONTIER_SATCOOL_CMIN)
		return;

	reason = frontier_spare_lane_decide(syscallnr, do32);

	/*
	 * Windowed-edges spare is folded into the early-return path the
	 * pre-extraction shape used (the original candidate gate required
	 * windowed_edges == 0).  Preserving that early-return keeps the
	 * satcool counter cascade byte-identical: a windowed-nonzero nr
	 * never bumped candidates / spared_arggen / spared_objproducer
	 * before extraction and still does not after.
	 */
	if (reason == FRONTIER_SPARE_WINDOWED_EDGES)
		return;

	__atomic_fetch_add(&shm->stats.frontier.saturation.satcool_candidates,
			   1UL, __ATOMIC_RELAXED);

	if (reason == FRONTIER_SPARE_ARGGEN) {
		__atomic_fetch_add(&shm->stats.frontier.saturation.satcool_spared_arggen,
				   1UL, __ATOMIC_RELAXED);
	} else if (reason == FRONTIER_SPARE_OBJPRODUCER) {
		__atomic_fetch_add(
			&shm->stats.frontier.saturation.satcool_spared_objproducer,
			1UL, __ATOMIC_RELAXED);
	} else {
		__atomic_fetch_add(&shm->stats.frontier.saturation.satcool_would_skip,
				   1UL, __ATOMIC_RELAXED);
		__atomic_fetch_add(
			&shm->stats.frontier.per_syscall.satcool_would_skip_per_syscall[syscallnr],
			1UL, __ATOMIC_RELAXED);
		/*
		 * COMBINED live-reject would sit here gated on satcool_mode
		 * == COMBINED; intentionally NOT wired in this commit.  The
		 * block is observability-only regardless of mode so the
		 * SHADOW_ONLY counters can be validated against a real run
		 * before any live divergence is introduced.  See the enum
		 * comment in include/strategy.h for the ramp discipline.
		 */
	}
}

/*
 * SHADOW-ONLY floored-barren sub-floor demote helper.  Sibling of
 * frontier_satcool_spare above; targets the pure zero-arg getter set
 * whose lifetime PC-edge yield has plateaued to a hard floor rather
 * than the windowed-plateau-of-saturated-productive set the satcool
 * predicate owns.  The two shadow projections are disjoint by
 * construction: the barren predicate requires lifetime edges == 0
 * (never productive) at a small calls floor, the satcool predicate
 * requires the FRONTIER_SATCOOL_CMIN 10000-call magnitude and keys
 * plateau on the K-window ring going flat for a syscall that HAS
 * produced.
 *
 * Vetted skeleton: num_args == 0 excludes struct-arg backlogs whose
 * yield is gated by arg-gen progress; ret_objtype == OBJ_NONE excludes
 * the object-producer set (openat / socket / memfd_create / mmap /
 * io_uring_setup / bpf) whose payoff is delayed and credited
 * downstream to the consumer; sanitise == NULL excludes state-
 * mutators (munlockall / setsid / sched_yield) whose payoff sits in
 * post-call side effects, not in the syscall's own edge yield; reach
 * <= FRONTIER_BARREN_MAX_REACH excludes slots that have already
 * earned productivity, which the reach-band picker's HIGH-band boost
 * owns.  num_args == 0 alone is NECESSARY but NOT SUFFICIENT --
 * without the vetting layer above the predicate would swallow
 * inotify_init (object producer), sched_yield (state mutator), and
 * rseq (heuristic-arm spike source).
 *
 * Sub-floor mechanism a COMBINED live variant would apply: swap the
 * silent-branch accept denominator from (FRONTIER_COLD_SCALE + 1) to
 * (FRONTIER_COLD_SCALE * FRONTIER_BARREN_DEMOTE_MULT + 1), leaving
 * the +1 numerator intact so a demoted slot keeps a residual sample
 * rather than starving.  The errno-success lane is intentionally
 * ignored -- for a no-arg getter with no producer and no mutator,
 * "success" is information-free; only a real PC-edge or transition
 * reset (already wired via frontier_record_new_edge in strategy.c)
 * releases the demote.
 *
 * Called from the silent-regime accept site in random-syscall.c
 * immediately after frontier_satcool_spare so the two shadow
 * projections sit alongside each other in the pick path and share
 * the outer MAX_NR_SYSCALL bound the caller already established.
 *
 * Counter cascade:
 *   frontier_barren_candidates
 *      Cumulative: one bump per silent-regime pick where the vetted
 *      skeleton matches (num_args == 0 AND ret_objtype == OBJ_NONE
 *      AND sanitise == NULL AND reach <= MAX_REACH AND calls >
 *      C_MIN).  The candidate set the demote lane peels from.
 *   frontier_barren_would_skip
 *      Cumulative: subset of candidates whose full demote predicate
 *      also holds (lifetime edges == 0 AND windowed edges == 0) --
 *      the mass a COMBINED sub-floor variant would demote.  Ratio
 *      against frontier_silent_picks is the projected silent-regime
 *      pick share the demote reclaims.
 *   frontier_barren_would_skip_per_syscall[nr]
 *      Per-syscall split of the scalar above; the headline
 *      diagnostic for SHADOW_ONLY.  Read by no live-path code.
 *
 * NULL entry (out-of-range nr or empty table slot) is treated as
 * "not a barren candidate" and short-circuits before any counter
 * bump -- matches get_syscall_entry()'s out-of-range NULL contract
 * and mirrors the NULL-safe shape the sibling producer-observer
 * bitmap builder above uses.
 *
 * Outer OFF guard keeps the byte-identical pre-feature path: no
 * get_syscall_entry() lookup, no kcov_shm loads, no ring reads --
 * only the single RELAXED mode load, matching the discipline
 * frontier_satcool_spare / frontier_live_cool_spare use.
 */
void frontier_barren_demote(unsigned int syscallnr, bool do32)
{
	enum frontier_barren_demote_mode mode;
	struct syscallentry *entry;
	unsigned long calls, edges, reach;

	mode = __atomic_load_n(&frontier_barren_demote_mode,
			       __ATOMIC_RELAXED);
	if (mode == FRONTIER_BARREN_DEMOTE_MODE_OFF)
		return;
	if (kcov_shm == NULL)
		return;
	if (syscallnr >= MAX_NR_SYSCALL)
		return;

	entry = get_syscall_entry(syscallnr, do32);
	if (entry == NULL)
		return;
	if (entry->num_args != 0)
		return;
	if (entry->ret_objtype != OBJ_NONE)
		return;
	if (entry->sanitise != NULL)
		return;

	/* Single hoisted per_syscall_edges load: the reach comparison and
	 * the "lifetime edges == 0" full-predicate check both consume the
	 * same lifetime count, and reloading under RELAXED atomics would
	 * open a race window where reach reads > MAX_REACH but a second
	 * load reads 0 (or vice versa) and races the candidates/would_skip
	 * cascade out of lock-step.  One load, both checks. */
	edges = per_syscall_edges_total(syscallnr);
	reach = edges + per_syscall_edges_prior_total(syscallnr);
	if (reach > FRONTIER_BARREN_MAX_REACH)
		return;

	calls = per_syscall_calls_total(syscallnr);
	if (calls <= FRONTIER_BARREN_C_MIN)
		return;

	__atomic_fetch_add(&shm->stats.frontier.saturation.barren_candidates,
			   1UL, __ATOMIC_RELAXED);

	if (edges != 0)
		return;
	if (frontier_recent_count(syscallnr) != 0)
		return;

	__atomic_fetch_add(&shm->stats.frontier.saturation.barren_would_skip,
			   1UL, __ATOMIC_RELAXED);
	__atomic_fetch_add(
		&shm->stats.frontier.per_syscall.barren_would_skip_per_syscall[syscallnr],
		1UL, __ATOMIC_RELAXED);

	/*
	 * COMBINED sub-floor demote would sit here gated on mode ==
	 * COMBINED, swapping the caller's silent-branch accept
	 * denominator to (FRONTIER_COLD_SCALE * FRONTIER_BARREN_DEMOTE_
	 * MULT + 1); intentionally NOT wired in this commit.  The
	 * block is observability-only regardless of mode so the
	 * SHADOW_ONLY counters can be validated against a real run
	 * before any live divergence is introduced.  See the enum
	 * comment in include/strategy.h for the ramp discipline.
	 */
}
