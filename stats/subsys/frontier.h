#ifndef _TRINITY_STATS_SUBSYS_FRONTIER_H
#define _TRINITY_STATS_SUBSYS_FRONTIER_H

#include "child-api.h"		/* NR_CHILD_OP_TYPES */
#include "syscall.h"		/* MAX_NR_SYSCALL */

/*
 * STRATEGY_COVERAGE_FRONTIER picker observability -- pick regimes,
 * per-syscall pick / miss / productive-win distributions, silent-streak
 * decay shadow predicates, saturation-cooldown / barren-demote /
 * live-cooldown / group-antilock shadow lanes, errno-plateau decay,
 * cold-weight blend A/B, plus the group-count enum needed for the
 * frseq per-group breakdown.
 *
 * Bespoke (non-category) RAW group.  All bumps RELAXED on shm->stats
 * from strategy-frontier.c / random-syscall.c / kcov.c; the shadow
 * predicates are strictly observability-only (no live-path code reads
 * any of these counters).  The surrounding struct stats_s composes an
 * instance of struct frontier_stats as its "frontier" member.
 */
struct frontier_stats {
	/* Number of syscall picks completed under STRATEGY_COVERAGE_FRONTIER.
	 * Bumped on the success path of set_syscall_nr_coverage_frontier --
	 * surfaces how many calls the frontier-weighted picker actually
	 * accepted (roulette-wheel rejections are absorbed into the inner
	 * retry loop and not counted here).  Compared against bandit
	 * pulls for the COVERAGE_FRONTIER arm, this ratio also approximates
	 * the average accepted picks per window the arm ran. */
	unsigned long strategy_picks;

	/* Number of times the ring rotation's per-nr subtract against
	 * frontier_recent_count_cached would have produced a negative value
	 * (i.e. the value being aged out was larger than the cached running
	 * sum) and was clamped to zero instead.  Should normally be zero;
	 * non-zero indicates either a producer/rotator interleaving we did
	 * not anticipate or accounting drift large enough to invert the
	 * sum.  Bumped from frontier_window_advance(); read alongside
	 * frontier_strategy_picks to gauge whether the picker is being fed
	 * a sane weight signal. */
	unsigned long underflow_prevented;

	/* Number of plateau-intervention rotations that selected the
	 * STRATEGY_COVERAGE_FRONTIER arm -- via either the unconditional
	 * PIM_COVERAGE_FRONTIER slot or the PIM_RRC_BIASED dispatch when
	 * amplified_intervention_arm() routes the dominant rescue class
	 * to the frontier picker.  Deliberately separate from the
	 * learner-facing bandit_pulls[STRATEGY_COVERAGE_FRONTIER]:
	 * intervention picks are forced over the top of the bandit while
	 * plateau_active is set and must NOT enter the discounted reward
	 * series, because D-UCB's exploration bonus assumes pulls reflect
	 * the picker's policy choice rather than a rescue.  Folding
	 * intervention picks into the learner's series would shift the
	 * frontier arm's apparent yield toward the intervention cohort
	 * for the rest of the run.  Bumped RELAXED from the rotation
	 * site in select_next_strategy(); paired with the snapshot-side
	 * fold-in so the plateau classifier sees all frontier activity
	 * regardless of selection path. */
	unsigned long intervention_pulls;

	/* Number of plateau-intervention rotations where the round-robin
	 * landed on PIM_COVERAGE_FRONTIER but the per-syscall frontier rings
	 * had aged out everywhere (frontier_max_weight_cached == 0) and the
	 * rotation substituted PIM_UNIFORM_RANDOM instead.  Bumped from
	 * select_next_strategy() at the substitution site.
	 *
	 * A non-zero value alongside plateau_forced_windows says the cold-
	 * ring deweight is firing inside live plateaus -- expected during
	 * deep stalls where the ring has decayed everywhere.  The companion
	 * frontier_intervention_pulls counter only counts rotations that
	 * actually ran FRONTIER, so the substitution is invisible there.
	 * The (skipped / forced_windows) ratio tells the operator what
	 * fraction of the rescue's FRONTIER slots were deweighted; a high
	 * ratio sustained across plateaus means the rescue is leaning on
	 * UNIFORM and ANTI_PRIOR while the frontier ring stays cold, the
	 * design intent under deep-plateau conditions. */
	unsigned long intervention_cold_skipped;

	/* Accept-regime split of frontier_strategy_picks.  Bumped at the two
	 * accept paths inside set_syscall_nr_coverage_frontier so the operator
	 * can tell which regime is steering the picks:
	 *
	 *   frontier_live_picks   -- max_weight > 2, the K-window frontier
	 *                            ring still carries signal and the picker
	 *                            is biasing off frontier_recent_count().
	 *   frontier_silent_picks -- max_weight <= 2, the ring has aged out
	 *                            everywhere (defining state of a coverage
	 *                            plateau).  The picker falls back to the
	 *                            cold-weight path keyed on lifetime
	 *                            per_syscall_edges / per_syscall_calls --
	 *                            i.e. the plateau-fallback bias is doing
	 *                            the steering.
	 *
	 * Sum equals frontier_strategy_picks.  A run where silent dominates
	 * but the cold-weight fallback finds nothing means the fallback's
	 * weight function is the next thing to tune. */
	unsigned long live_picks;
	unsigned long silent_picks;

	/* SHADOW-ONLY observability counter, paired with the silent-regime
	 * fallback above.  Number of (syscall_nr,
	 * FRONTIER_SHADOW_DECAY_STREAK)-crossing events seen since startup --
	 * bumped exactly once when a per-syscall silent-streak in
	 * frontier_silent_streak_per_syscall[] transitions through the
	 * threshold value from below.  The same syscall plateauing repeatedly
	 * across a run contributes one bump per plateau episode (the streak
	 * has to be reset by a productive-edge event and grow back to the
	 * threshold), not one bump per silent pick.
	 *
	 * Observability only: the live frontier picker accept/retry math in
	 * set_syscall_nr_coverage_frontier() does NOT read this counter or
	 * its per-syscall feeder, so the value can be tallied freely without
	 * perturbing selection.  Reading it alongside frontier_silent_picks
	 * gives the operator a rough estimate of "how many decay-candidate
	 * syscalls would a live silent-decay variant of the picker have
	 * demoted by now?" -- the shadow signal needed before any change to
	 * the live picker. */
	unsigned long shadow_decay_candidates;

	/* Per-syscall pick distribution under STRATEGY_COVERAGE_FRONTIER.
	 * Bumped once per accepted pick inside set_syscall_nr_coverage_frontier
	 * (same site as the frontier_strategy_picks bump), indexed by the
	 * resolved syscall nr.  Surfaces which syscalls eat the frontier
	 * picks regardless of which accept regime (live / silent) owned the
	 * pick -- the regime split lives in frontier_live_picks /
	 * frontier_silent_picks above.
	 *
	 * Surfaced only via top_syscalls_periodic_dump(), same shape and
	 * cadence as edges_per_syscall_bandit / _explorer (also MAX_NR_SYSCALL
	 * sized, also too wide for the JSON path).  Without this array a
	 * frontier arm that has collapsed to picking the same handful of
	 * leaders is indistinguishable from one steering across a broad
	 * surface -- the headline pick total looks identical, only the
	 * per-syscall distribution separates them. */
	unsigned long picks_per_syscall[MAX_NR_SYSCALL];

	/* SHADOW-ONLY per-syscall silent-streak counter.  Bumped at the
	 * silent-regime accept site in set_syscall_nr_coverage_frontier()
	 * (alongside the existing frontier_silent_picks bump), reset to zero
	 * by frontier_record_new_edge() on the per-syscall new-edge
	 * productive path in kcov_collect.  Carries the current count of
	 * CONSECUTIVE silent-regime picks since the last productive-edge
	 * event for that syscall.
	 *
	 * Read by no production-path code -- observability only; the picker
	 * accept/retry math at the bump site does not consume this value, so
	 * any drift in it cannot perturb selection.  Crossing the
	 * FRONTIER_SHADOW_DECAY_STREAK threshold edge-triggers a one-time
	 * bump of the global frontier_shadow_decay_candidates above, which
	 * is the headline number for downstream consumers; the per-syscall
	 * array is kept for top-N attribution of which syscalls are the
	 * shadow-decay candidates.
	 *
	 * Sized and bounds-guarded the same way the sibling
	 * frontier_picks_per_syscall[] above is.  Surfaced only via the
	 * periodic stats dump alongside that array. */
	unsigned long silent_streak_per_syscall[MAX_NR_SYSCALL];

	/* SHADOW-ONLY no-novelty baselines paired with the silent-streak
	 * counter above.  Snapshotted at every streak reset (in
	 * frontier_record_new_edge() and frontier_record_transition_edge(),
	 * the two existing per-syscall productive-event hooks) from the
	 * matching kcov_shm counters, so the silent-regime accept site can
	 * cheaply ask "has any non-PC-edge novelty fired for this syscall
	 * since the streak last reset?" via a current-vs-baseline equality
	 * test -- no new collection path is added, only the snapshot.
	 *
	 *  frontier_silent_cmp_baseline[nr]
	 *      Mirror of kcov_shm->per_syscall_cmp_inserts[nr] at the most
	 *      recent streak reset.  Current > baseline means at least one
	 *      distinct CMP insert/evict-replace event landed for this
	 *      syscall during the silent streak -- CMP novelty the PC-edge
	 *      reset path did not see.
	 *  frontier_silent_errno_success_baseline[nr]
	 *      Mirror of kcov_shm->per_syscall_errno[nr][ERRNO_BUCKET_
	 *      SUCCESS] at the most recent streak reset.  Current > baseline
	 *      means the syscall transitioned from error-only to producing
	 *      a successful return at least once during the silent streak --
	 *      a coarse "useful errno shift" signal.  Only the SUCCESS slot
	 *      is mirrored (not the full 8-bucket histogram) so the snapshot
	 *      is one ulong per syscall, same shape as the streak counter.
	 *
	 * Read by no production-path code -- the silent-regime accept site
	 * is the sole consumer.  The picker's accept/retry math does not
	 * consume either baseline, so drift in them cannot perturb live
	 * selection.  Sized and bounds-guarded the same way the sibling
	 * frontier_silent_streak_per_syscall[] above is. */
	unsigned long silent_cmp_baseline[MAX_NR_SYSCALL];
	unsigned long silent_errno_success_baseline[MAX_NR_SYSCALL];

	/* Per-syscall frontier yield accounting (kill-list feedstock).  The
	 * scalar siblings frontier_live_picks / frontier_silent_picks above
	 * tell the operator the fleet-wide regime split; these per-syscall
	 * arrays tell them WHICH syscalls eat the picks under each regime and
	 * whether those picks ever earn a new edge.  Surfaces the "warm but
	 * zero-edge" syscalls (mlock / unshare / mincore et al) the live
	 * picker repeatedly accepts under the live regime but which never
	 * convert -- a kill-list candidate set the future suppression lever
	 * scores against.
	 *
	 *  frontier_live_picks_per_syscall[nr]
	 *      Per-syscall split of the scalar frontier_live_picks counter.
	 *      Bumped at the live-regime accept site in set_syscall_nr_
	 *      coverage_frontier alongside the scalar bump, indexed by the
	 *      resolved syscall nr.  Same MAX_NR_SYSCALL bound the sibling
	 *      frontier_picks_per_syscall[] uses.
	 *  frontier_silent_picks_per_syscall[nr]
	 *      Per-syscall split of the scalar frontier_silent_picks counter.
	 *      Bumped at the silent-regime accept site in the same picker,
	 *      same bound.  Together with the live array sums to exactly
	 *      frontier_picks_per_syscall[nr] (modulo the brief race between
	 *      the live/silent bump and the regime-agnostic bump that follows
	 *      the two accept branches).
	 *  frontier_productive_wins_per_syscall[nr]
	 *      Per-syscall count of frontier picks (any regime) that earned
	 *      at least one new PC edge.  Bumped from the dispatch_step
	 *      post-call attribution path on the new_edge_count > 0 branch
	 *      when the per-call child->frontier_pick_regime stamp shows the
	 *      pick came from the frontier strategy (NONE leaves the slot
	 *      untouched, so non-frontier strategy picks do not contribute).
	 *      The conversion-rate denominator is frontier_picks_per_syscall.
	 *  frontier_live_misses_per_syscall[nr]
	 *      Per-syscall count of LIVE-regime frontier picks that produced
	 *      zero PC edges (the headline kill-list signal: a syscall the
	 *      live ring keeps biasing toward but that never converts).  Bumped
	 *      from the same post-call path on the no-edge branch when the
	 *      stamp is FRONTIER_PICK_LIVE.  Silent-regime misses are NOT
	 *      tallied here -- silent picks are by definition operating in the
	 *      plateau-fallback regime where low yield is the expected
	 *      baseline; rolling them into the same counter would bury the
	 *      live-regime signal under the silent-regime steady-state noise.
	 *  frontier_last_productive_window_per_syscall[nr]
	 *      Snapshot of shm->bandit_window_count taken at the moment a
	 *      productive_win was attributed to this syscall.  Compared
	 *      against the current bandit_window_count by the kill-list
	 *      analyser to gauge "windows since last productive frontier pick
	 *      on this syscall" without having to retain a per-window time
	 *      series.  Monotonically non-decreasing per slot under the
	 *      RELAXED store; the readers tolerate the brief race the same
	 *      way the surrounding RELAXED add-fetch counters do.
	 *
	 * ADDITIVE / SHADOW: no production-path code reads any of the five
	 * arrays -- the picker's accept/retry math is byte-identical to the
	 * pre-row baseline, the bumps fire strictly AFTER accept (at the two
	 * accept sites) and strictly AFTER the per-call attribution decision
	 * (at the post-call site), and the per-child frontier_pick_regime
	 * stamp is owner-only.  Sized and bounds-guarded the same way the
	 * sibling frontier_picks_per_syscall[] above is.  shm cost is
	 * 5 * MAX_NR_SYSCALL * sizeof(unsigned long) ~= 40 KiB. */
	unsigned long live_picks_per_syscall[MAX_NR_SYSCALL];
	unsigned long silent_picks_per_syscall[MAX_NR_SYSCALL];
	unsigned long productive_wins_per_syscall[MAX_NR_SYSCALL];
	unsigned long live_misses_per_syscall[MAX_NR_SYSCALL];
	unsigned long last_productive_window_per_syscall[MAX_NR_SYSCALL];

	/* SHADOW-ONLY per-syscall LIVE-regime miss-streak counter.  Bumped
	 * at the post-call frontier yield attribution path in
	 * random_syscall_step (alongside the existing
	 * frontier_live_misses_per_syscall[] bump) whenever a LIVE-regime
	 * frontier pick of this syscall earned zero PC edges; reset to zero
	 * by frontier_record_new_edge() / frontier_record_transition_edge()
	 * on the per-syscall productive-event hooks already established for
	 * the silent-streak counter above.  Carries the run-length of
	 * CONSECUTIVE zero-edge LIVE-regime picks since the syscall last
	 * earned coverage.
	 *
	 * Read by no production-path code -- observability only; the picker
	 * accept/retry math at the bump site does not consume this value, so
	 * any drift in it cannot perturb selection.  Crossing the
	 * FRONTIER_LIVE_MISS_COOLDOWN threshold edge-triggers a one-time
	 * bump of the global frontier_live_cooldown_candidates counter; every
	 * pick past the threshold bumps frontier_live_would_skip
	 * cumulatively.  The per-syscall array is kept for top-N attribution
	 * of which syscalls are the cooldown candidates.
	 *
	 * Sized and bounds-guarded the same way the sibling
	 * frontier_silent_streak_per_syscall[] above is.  Surfaced only via
	 * the periodic stats dump alongside that array. */
	unsigned long live_miss_streak_per_syscall[MAX_NR_SYSCALL];

	/* SHADOW-ONLY per-syscall saturation-cooldown would-skip counter.
	 * Bumped at the silent-regime accept site alongside the scalar
	 * frontier_satcool_would_skip whenever the corrected predicate
	 * (plateau AND magnitude AND no-spare-lane) fires for this syscall.
	 * The headline diagnostic for SHADOW_ONLY: a single run's top
	 * entries should be the saturated-rich set (syncfs / sendfile /
	 * semget / writev) with the under-explored struct-arg backlog
	 * (removexattrat / futex / io_uring_setup / bpf) reading ~0; if
	 * removexattrat / futex / io_uring_setup / bpf show a nonzero
	 * count the spare lanes (cmp / first-success / ret_objtype) are
	 * mis-tuned and COMBINED MUST NOT be promoted.
	 *
	 * Sized and bounds-guarded the same way the sibling per-syscall
	 * arrays above are.  Read by no live-path code -- observability
	 * only, surfaced via the periodic stats dump's top-N attribution
	 * for the saturation cooldown. */
	unsigned long satcool_would_skip_per_syscall[MAX_NR_SYSCALL];

	/* SHADOW-ONLY per-syscall floored-barren sub-floor demote would-
	 * skip counter.  Bumped at the silent-regime accept site alongside
	 * the scalar frontier_barren_would_skip whenever the full vetted
	 * predicate fires for this syscall.  The headline diagnostic for
	 * SHADOW_ONLY: a single run's top entries should be the pure
	 * zero-arg getter cohort whose lifetime PC-edge yield has genuinely
	 * plateaued to a hard floor; any object-producer, state-mutator,
	 * or heuristic-arm spike source appearing here indicates the
	 * vetted skeleton (num_args, ret_objtype, sanitise, reach) is mis-
	 * gated and COMBINED MUST NOT be promoted.
	 *
	 * Sized and bounds-guarded the same way the sibling per-syscall
	 * arrays above are.  Read by no live-path code -- observability
	 * only, surfaced via the periodic stats dump's top-N attribution
	 * for the floored-barren demote. */
	unsigned long barren_would_skip_per_syscall[MAX_NR_SYSCALL];

	/* SHADOW-ONLY LIVE-regime cooldown accounting, paired with the
	 * frontier_live_miss_streak_per_syscall[] counter above.  Mirrors
	 * the SHADOW silent-streak decay scalars (frontier_decay_candidates
	 * / frontier_decay_would_skip) for the LIVE-regime cooldown lever:
	 * the threshold-crossing edge bumps frontier_live_cooldown_candidates
	 * once per episode, and frontier_live_would_skip tallies every
	 * subsequent LIVE-regime miss past the threshold that a live
	 * cooldown variant of the picker would have rejected.  Used together
	 * with the frontier_live_misses_per_syscall[] kill-list signal so
	 * the operator can A/B compare the streak-based predicate against
	 * the raw miss-count predicate before any change to the live picker.
	 *
	 *  frontier_live_cooldown_candidates
	 *      Edge-triggered: one bump per (syscallnr) crossing of
	 *      FRONTIER_LIVE_MISS_COOLDOWN at the post-call attribution
	 *      path.  Counts distinct cooldown episodes since startup -- a
	 *      syscall whose streak grows back to threshold after a
	 *      productive event contributes a fresh bump.
	 *  frontier_live_would_skip
	 *      Cumulative: one bump per LIVE-regime miss that finds the
	 *      streak already at-or-past FRONTIER_LIVE_MISS_COOLDOWN after
	 *      the post-call increment -- the projected demote count a live
	 *      cooldown variant of the picker would produce.  Read alongside
	 *      frontier_live_picks to read the projected saving fraction.
	 *
	 * Observability only: live frontier selection in
	 * set_syscall_nr_coverage_frontier() is byte-identical to today's
	 * behaviour; these counters bump strictly AFTER the per-call
	 * attribution decision (in random_syscall_step) and no live-path
	 * code reads them.  Mirrors the off-by-construction discipline the
	 * sibling frontier_decay_* / frontier_blend_* counters use. */
	unsigned long live_cooldown_candidates;
	unsigned long live_would_skip;

	/* SHADOW-ONLY per-syscall LIVE-regime cooldown would-skip counter.
	 * Bumped at the post-call LIVE-regime miss attribution path
	 * alongside the scalar frontier_live_would_skip whenever the post-
	 * increment miss-streak for this syscall is at-or-past
	 * FRONTIER_LIVE_MISS_COOLDOWN -- the per-syscall distribution of
	 * the projected demote count a live cooldown variant of the picker
	 * would produce.  The LIVE regime carries far more pick volume than
	 * the silent regime, so this is the bigger reclaim lever; the top-N
	 * exposes which syscalls drive the projection so a future live
	 * cooldown variant can be tuned against the right set (and the
	 * spare-lane and reject-rate decisions can be checked against the
	 * same backlog the satcool per-syscall array surfaces).
	 *
	 * Sized and bounds-guarded the same way the sibling per-syscall
	 * arrays above are; the bump shares the rec->nr < MAX_NR_SYSCALL
	 * guard the surrounding LIVE-regime miss block already enforces.
	 * Read by no live-path code -- observability only, surfaced via the
	 * periodic stats dump's top-N attribution alongside the scalar
	 * frontier_live_* rows.
	 *
	 * Unlike the satcool per-syscall counter, the writer here is NOT
	 * gated by a mode flag: the scalar frontier_live_would_skip is
	 * bumped unconditionally on every LIVE-regime miss past the
	 * threshold, so the per-syscall array populates on every run and
	 * no run-mode flag is needed to surface the distribution. */
	unsigned long live_would_skip_per_syscall[MAX_NR_SYSCALL];

	/* Did-decay counter for the LIVE-regime early ring-decay path in
	 * frontier_window_advance().  One bump per (nr, rotation) where
	 * the per-syscall LIVE-regime miss-streak was at-or-past
	 * FRONTIER_LIVE_MISS_COOLDOWN AND the rotation actually reduced
	 * the cached frontier_recent_count for that nr (i.e. the new sum
	 * was non-zero before the halving step).  Tallies how often the
	 * early decay actually moved the wall, paired with the F3
	 * frontier_live_would_skip projection to measure the live
	 * behaviour delta the cooldown path is producing.
	 *
	 * Observability only: the bump happens inside the rotation hot path
	 * but no selection or scoring code reads it.  Mirrors the off-by-
	 * construction discipline the sibling frontier_underflow_prevented
	 * counter uses for its rotation-loop bump. */
	unsigned long live_cooldown_decays;

	/* Live reject count for the blanket LIVE-regime probabilistic
	 * pick-reject gate (FRONTIER_LIVE_DECAY_REJECT_DENOM).  One bump
	 * per LIVE-regime pick that passed the frontier-weight roll above
	 * but lost the 1 / FRONTIER_LIVE_DECAY_REJECT_DENOM probabilistic
	 * filter and fell through to retry -- the headline behaviour
	 * delta for the safe down-payment that reclaims ~3% of live-ring
	 * picks without depending on the per-syscall cooldown predicate.
	 *
	 * Counted strictly AFTER the frontier-weight accept decision so
	 * the value is the projected reclaim on accepted-by-weight picks;
	 * frontier-weight rejections fall through to retry before this
	 * gate fires and do not contribute.  Read alongside
	 * frontier_live_picks (which excludes rejected picks, see the
	 * call-site comment) for the reject rate against accepted picks:
	 * the ratio reject / (reject + live_picks) should converge to
	 * 1 / FRONTIER_LIVE_DECAY_REJECT_DENOM.
	 *
	 * Counter is independent of the F3 shadow streak / cooldown
	 * candidate signal: this gate is unconditional, the cooldown
	 * signal is per-syscall.  The targeted variant that gates the
	 * reject on the cooldown predicate is a SEPARATE later commit;
	 * comparing this reject's rate against frontier_live_would_skip
	 * gives the operator the headroom estimate for that variant
	 * (would_skip / (live_picks + reject) vs the blanket
	 * 1 / REJECT_DENOM rate). */
	unsigned long live_decay_live_rejects;

	/* SHADOW-ONLY decay-candidate accounting, paired with the silent-
	 * streak counter and the no-novelty baselines above.  Tighter
	 * variant of frontier_shadow_decay_candidates: the threshold-
	 * crossing edge bumps the candidate counter ONLY when the no-
	 * novelty UNLESS clause holds (no CMP insert and no SUCCESS-bucket
	 * errno shift since the streak's most recent reset), and a separate
	 * counter tallies every silent-regime pick a live decay variant
	 * would have demoted.  Used together with the looser sibling above
	 * so the operator can A/B compare the two predicates before any
	 * change to the live picker.
	 *
	 *  frontier_decay_candidates
	 *      Edge-triggered: one bump per (syscallnr) crossing of
	 *      FRONTIER_SHADOW_DECAY_STREAK where the no-novelty UNLESS
	 *      clause holds at the crossing pick.  Strictly <=
	 *      frontier_shadow_decay_candidates by construction; the gap
	 *      between the two values is the candidate set the CMP/errno
	 *      tightening would have spared.
	 *  frontier_decay_would_skip
	 *      Cumulative: one bump per silent-regime pick where the
	 *      streak is already >= FRONTIER_SHADOW_DECAY_STREAK AND the
	 *      no-novelty UNLESS clause holds -- the projected demote count
	 *      a live silent-decay variant of the picker would produce.
	 *      Read alongside frontier_silent_picks to read the projected
	 *      saving fraction.
	 *
	 * Observability only: live frontier selection in set_syscall_nr_
	 * coverage_frontier() is byte-identical to today's behaviour; these
	 * counters bump strictly AFTER the accept decision and no live-path
	 * code reads them.  Mirrors the off-by-construction discipline the
	 * sibling frontier-blend A/B counters use. */
	unsigned long decay_candidates;
	unsigned long decay_would_skip;

	/* Live arm-B reject count for the silent-streak decay above.  Pairs
	 * with frontier_decay_would_skip (the both-arms shadow count of every
	 * silent-regime pick the predicate fires for) as the headline arm-B
	 * behaviour delta: one bump per arm-B pick the live REJECT_DENOM-1 /
	 * REJECT_DENOM probabilistic gate at the picker site actually rejected.
	 * Strictly <= frontier_decay_would_skip restricted to arm-B picks.
	 * Arm A NEVER bumps this counter (it has no live reject path) so the
	 * value is the pure Arm-B demote count, comparable against the Arm-B
	 * silent-pick throughput recoverable from frontier_silent_picks
	 * normalised by frontier_silent_decay_arm_b_children / total cohort
	 * split (kcov_shm).  Mirrors the frontier_errno_decay_live_rejects
	 * shape below so the two live-decay deltas read side by side. */
	unsigned long silent_decay_live_rejects;

	/* SHADOW-ONLY saturation-cooldown predicate accounting (gated by
	 * frontier_saturation_cooldown_mode != OFF).  Sibling of the
	 * frontier_decay_* / frontier_errno_decay_* shadow predicates above;
	 * this one targets the same wasteful-silent-pick shape but uses the
	 * windowed frontier-edge ring (frontier_recent_count, decays by
	 * construction) for the plateau trigger AND the corrected
	 * first-success-TRANSITION + distinct-CMP-insert spare lanes for the
	 * under-explored struct-arg backlog.  See the enum
	 * frontier_saturation_cooldown_mode comment in include/strategy.h and
	 * the FRONTIER_SATCOOL_CMIN magnitude-gate comment for the predicate
	 * contract.
	 *
	 *  frontier_satcool_candidates
	 *      Cumulative: one bump per silent-regime pick where the plateau
	 *      trigger (windowed frontier-edge ring sum == 0) AND the
	 *      magnitude gate (lifetime per_syscall_calls > FRONTIER_SATCOOL_
	 *      CMIN) BOTH hold for the picked syscall -- the candidate set
	 *      the spare lanes get to peel from.  Sum of would_skip +
	 *      spared_arggen + spared_objproducer.
	 *  frontier_satcool_would_skip
	 *      Cumulative: subset of candidates a live variant would actually
	 *      reject (neither spare lane fired).  Ratio against frontier_
	 *      silent_picks is the projected silent-regime pick share a
	 *      live satcool reject would demote.
	 *  frontier_satcool_spared_arggen
	 *      Cumulative: subset of candidates spared because the per-
	 *      syscall arg-gen-progress lane fired -- either a distinct
	 *      CMP-insert landed since the streak's last reset (per_syscall_
	 *      cmp_inserts advanced past frontier_silent_cmp_baseline), or
	 *      a FIRST-SUCCESS transition fired (errno-SUCCESS bucket was
	 *      zero at the last reset and is now > 0).  CRITICAL: this is
	 *      NOT the existing decay's raw-success-count delta; it is a
	 *      first-success-TRANSITION test (errno_base == 0 AND errno_now
	 *      > 0) so a perpetually-succeeding syscall like syncfs cannot
	 *      spare itself by raw success accumulation.
	 *  frontier_satcool_spared_objproducer
	 *      Cumulative: subset of candidates spared because the syscall
	 *      entry's ret_objtype is != OBJ_NONE -- an object-producer
	 *      (openat / socket / memfd_create / mmap / io_uring_setup /
	 *      bpf) whose payoff is delayed and credited downstream to the
	 *      consumer of the produced object, not to the producer's own
	 *      PC-edge yield.  Evaluated after spared_arggen, so a
	 *      candidate that fired both lanes is counted as spared_arggen
	 *      (the more specific signal); spared_objproducer is the
	 *      ret_objtype-only catch.
	 *
	 * Observability only in this commit: the predicate-evaluation block
	 * is added inside the silent-regime accept path with NO live reject
	 * wired, so live selection in set_syscall_nr_coverage_frontier()
	 * stays byte-identical to today regardless of which mode is
	 * selected.  COMBINED is reserved in the enum for a follow-up that
	 * wires the live reject after SHADOW_ONLY validates the predicate
	 * against a real run.  Mirrors the off-by-construction discipline
	 * the sibling frontier_decay_* / frontier_errno_decay_* counters
	 * use. */
	unsigned long satcool_candidates;
	unsigned long satcool_would_skip;
	unsigned long satcool_spared_arggen;
	unsigned long satcool_spared_objproducer;

	/* SHADOW-ONLY floored-barren sub-floor demote accounting (gated
	 * by --frontier-barren-demote != off).  Sibling of the
	 * frontier_satcool_* counters above; targets the pure zero-arg
	 * getter set whose lifetime PC-edge yield has plateaued to a
	 * hard floor rather than the windowed-plateau of the saturated-
	 * productive set the satcool predicate owns.  Disjoint from the
	 * satcool projection by construction: the barren predicate
	 * requires lifetime edges == 0 at the small FRONTIER_BARREN_C_MIN
	 * floor, satcool requires FRONTIER_SATCOOL_CMIN 10000 magnitude
	 * plus the K-window ring going flat for a syscall that HAS
	 * produced.
	 *
	 *  frontier_barren_candidates
	 *      Cumulative: one bump per silent-regime pick where the
	 *      vetted skeleton matches (num_args == 0 AND ret_objtype ==
	 *      OBJ_NONE AND sanitise == NULL AND reach <= FRONTIER_
	 *      BARREN_MAX_REACH AND calls > FRONTIER_BARREN_C_MIN).
	 *      The candidate set the demote lane peels from.
	 *  frontier_barren_would_skip
	 *      Cumulative: subset of candidates whose full demote
	 *      predicate also holds (lifetime edges == 0 AND windowed
	 *      edges == 0) -- the mass a COMBINED sub-floor variant
	 *      would demote by swapping the silent-branch accept
	 *      denominator to (FRONTIER_COLD_SCALE * FRONTIER_BARREN_
	 *      DEMOTE_MULT + 1).  Ratio against frontier_silent_picks is
	 *      the projected silent-regime pick share the sub-floor
	 *      reclaims.
	 *
	 * CRITICAL: the vetted skeleton is what keeps object-producers
	 * (inotify_init), state-mutators (munlockall / setsid / sched_
	 * yield), and heuristic-arm spike sources (rseq) OUT of the
	 * demote set -- num_args == 0 alone is NECESSARY but NOT
	 * SUFFICIENT.  The excluded classes are left to the softer
	 * sibling plateau decay, not un-cooled.
	 *
	 * Observability only in this commit: the predicate-evaluation
	 * block is added inside the silent-regime accept path with NO
	 * live sub-floor divergence wired, so live selection in
	 * set_syscall_nr_coverage_frontier() stays byte-identical to
	 * today regardless of which mode is selected.  COMBINED is
	 * reserved in the enum for a follow-up that wires the sub-floor
	 * accept-denominator swap after SHADOW_ONLY validates the
	 * predicate against a real run.  Mirrors the off-by-construction
	 * discipline the sibling frontier_satcool_* counters use. */
	unsigned long barren_candidates;
	unsigned long barren_would_skip;

	/* SHADOW-ONLY LIVE-regime cooldown discriminator accounting
	 * (gated by --frontier-live-cooldown-mode != off).  Sibling of
	 * the frontier_satcool_* counters above; this row ports the
	 * satcool spare-lane predicate INTO the LIVE-regime cooldown
	 * decision so the live cooldown cools only the truly-barren /
	 * saturated and SPARES the productive set (bpf / openat /
	 * io_uring_setup / io_setup whose K-window ring is still
	 * nonzero, futex / setxattrat mid-penetration of their struct
	 * args, ret_objtype producers whose payoff is delayed and
	 * credited downstream).  See the enum frontier_live_cooldown_
	 * mode comment in include/strategy.h for the predicate
	 * contract, the FRONTIER_LIVE_COOL_CMIN comment for the low-
	 * floor magnitude rationale, and the implementation in
	 * strategy-frontier.c::frontier_live_cool_spare for the full
	 * lane semantics.
	 *
	 * Why this counter row sits alongside the frontier_live_would_
	 * skip / frontier_live_would_skip_per_syscall[] block above:
	 * those project the UNDISCRIMINATED LIVE-regime cooldown demote
	 * mass (miss-streak alone, no spare lanes); this row projects
	 * the DISCRIMINATED demote mass (miss-streak AND magnitude
	 * floor AND no spare lane fires).  The (live_cool_would_skip /
	 * live_would_skip) ratio reads off exactly how much over-cool
	 * the discriminator removes -- the SHADOW_ONLY measurement the
	 * ramp discipline needs before flipping COMBINED.
	 *
	 *  frontier_live_cool_candidates
	 *      Cumulative: one bump per LIVE-regime miss-streak
	 *      crossing (streak >= FRONTIER_LIVE_MISS_COOLDOWN) where
	 *      the lifetime per_syscall_calls clears FRONTIER_LIVE_
	 *      COOL_CMIN -- the candidate set the spare lanes get to
	 *      peel from.  Sum of would_skip + spared_windowed +
	 *      spared_arggen + spared_objproducer.
	 *  frontier_live_cool_would_skip
	 *      Cumulative: subset of candidates a live discriminator
	 *      would actually demote (no spare lane fired).  Compare
	 *      against the undiscriminated frontier_live_would_skip
	 *      above for the over-cool reclaim.
	 *  frontier_live_cool_spared_windowed
	 *      Cumulative: subset of candidates spared because the per-
	 *      syscall K-window frontier-edge ring (frontier_recent_
	 *      count) is nonzero -- the bpf-class backstop the design
	 *      note's §3.2 (c) names.  A syscall whose ring still
	 *      holds edges is recently productive regardless of every
	 *      other signal; the windowed lane wins over arggen /
	 *      objproducer in the spare cascade.
	 *  frontier_live_cool_spared_arggen
	 *      Cumulative: subset of candidates spared because the per-
	 *      syscall arg-gen-progress lane fired -- distinct CMP-
	 *      insert landed since the streak's last reset or first-
	 *      SUCCESS transition fired (errno_base == 0 AND errno_now
	 *      > 0).  Catches futex / setxattrat mid-penetration of
	 *      their struct args.  Same first-success-TRANSITION key
	 *      the satcool sibling uses, NOT raw success-count delta,
	 *      so a perpetually-succeeding syscall cannot spare itself
	 *      by accumulation.
	 *  frontier_live_cool_spared_objproducer
	 *      Cumulative: subset of candidates spared because the
	 *      syscall entry's ret_objtype is != OBJ_NONE -- an
	 *      object-producer (openat / socket / memfd_create / mmap
	 *      / io_uring_setup / bpf) whose payoff is delayed and
	 *      credited downstream to the consumer of the produced
	 *      object, not to the producer's own PC-edge yield.
	 *      Evaluated AFTER spared_windowed and spared_arggen so a
	 *      candidate that fires multiple lanes is attributed to
	 *      the more specific signal first.
	 *  frontier_live_cool_would_skip_per_syscall[MAX_NR_SYSCALL]
	 *      Cumulative per-nr: bumped at the gate keyed on the
	 *      candidate syscall being evaluated at the would_skip
	 *      event.  The headline SHADOW_ONLY diagnostic: top
	 *      entries should be the legitimately-barren getter set
	 *      (gettid / sched_get_priority_max / sched_yield et al)
	 *      with the productive set (bpf / io_uring_setup / openat
	 *      / io_setup / futex / setxattrat) reading ~0; if those
	 *      productive syscalls show meaningful would_skip mass the
	 *      discriminator is mis-targeting and COMBINED MUST NOT be
	 *      promoted.
	 *  frontier_live_cool_would_spare_per_syscall[MAX_NR_SYSCALL]
	 *      Cumulative per-nr: bumped at the gate keyed on the
	 *      candidate syscall whenever ANY spare lane fired (the
	 *      partition sum of spared_windowed / spared_arggen /
	 *      spared_objproducer for this nr).  Compares directly
	 *      against the per-syscall would_skip array above: a
	 *      productive syscall the discriminator is sparing CORRECTLY
	 *      reads as high would_spare AND zero would_skip; a getter
	 *      the discriminator is COOLING correctly reads as zero
	 *      would_spare AND nonzero would_skip; a productive syscall
	 *      with nonzero would_skip indicates the discriminator is
	 *      under-sparing it and the COMBINED ramp must wait.
	 *
	 * Observability only in this commit: the discriminator-
	 * evaluation block is added inside the LIVE-regime miss
	 * attribution path with NO live divergence wired, so live
	 * selection in set_syscall_nr_coverage_frontier() and the
	 * rotation-loop halving in frontier_window_advance stay byte-
	 * identical to today regardless of which mode is selected.
	 * COMBINED is reserved in the enum for a follow-up that wires
	 * the live divergence after SHADOW_ONLY validates the demote
	 * distribution against a real run.  Mirrors the off-by-
	 * construction discipline the sibling frontier_satcool_*
	 * counters above use. */
	unsigned long live_cool_candidates;
	unsigned long live_cool_would_skip;
	unsigned long live_cool_spared_windowed;
	unsigned long live_cool_spared_arggen;
	unsigned long live_cool_spared_objproducer;
	unsigned long live_cool_would_skip_per_syscall[MAX_NR_SYSCALL];
	unsigned long live_cool_would_spare_per_syscall[MAX_NR_SYSCALL];

	/* SHADOW-ONLY group-bias anti-lock-in damper accounting (gated by
	 * frontier_group_antilock_mode != OFF AND --group-bias on the
	 * fleet invocation -- the predicate state only advances under the
	 * existing group_bias-gated last_group write site).  Sibling of
	 * the frontier_satcool_* counters above; this row targets the
	 * heuristic-arm group_bias gate's barren-pin lock-in (one no-arg
	 * / never-fail GROUP_PROCESS member absorbing ~20-28k calls/run
	 * via the sticky last_group + shared retry budget defeating the
	 * existing cold-skip), the partner reclaim site to the frontier-
	 * arm windowed-edge cooldown the satcool row owns.  See the enum
	 * frontier_group_antilock_mode comment in include/strategy.h for
	 * the predicate contract and the FRONTIER_FRSEQ_MIN_STREAK /
	 * FRONTIER_FRSEQ_COV_WINDOW comments for the threshold rationale.
	 *
	 * Why this counter row sits alongside the frontier_satcool_*
	 * row: the two are the two-arm partition of the same no-input
	 * call budget reclaim -- satcool reclaims the frontier-arm
	 * windowed silent pick (each getter's ~2.1k/run frontier-floor
	 * share) and frseq reclaims the heuristic-arm group_bias spike
	 * (the ~20-28k single-syscall lock-in), with the same
	 * windowed-productivity discriminator (last_cov_at_streak
	 * watermark) keyed on per-pin state instead of per-nr state.
	 * Both rows feed the same per-syscall top-N attribution shape so
	 * the operator can read which reclaim site is doing the work
	 * from one stats dump.
	 *
	 *  frontier_frseq_candidates
	 *      Cumulative: one bump per heuristic-arm group_bias gate
	 *      hit where the predicate is evaluable (last_group !=
	 *      GROUP_NONE and frontier_group_antilock_mode != OFF) --
	 *      the candidate set the windowed-pin predicate gets to
	 *      peel from.  Sum of would_skip + (candidates - would_
	 *      skip) where the difference is the population the
	 *      predicate spared (pin_warm spare, pin still building
	 *      live state) or where pin_stale did not yet hold (streak
	 *      still inside MIN_STREAK / COV_WINDOW).
	 *  frontier_frseq_would_skip
	 *      Cumulative: subset of candidates where pin_stale &&
	 *      !pin_warm both hold -- the projected pin-release count
	 *      a live frseq damper would fire under COMBINED.  Ratio
	 *      against frontier_frseq_candidates is the projected
	 *      release rate; ratio against the heuristic-arm pick
	 *      total is the projected reclaim share.
	 *  frontier_frseq_would_skip_per_syscall[MAX_NR_SYSCALL]
	 *      Cumulative per-nr: bumped at the gate keyed on the
	 *      candidate syscall being evaluated at the would_skip
	 *      event.  The headline SHADOW_ONLY diagnostic: a single
	 *      run's top entries should be the pure-getter / no-op
	 *      yield set (rseq_slice_yield / getpgrp / sched_yield /
	 *      getppid / getegid / geteuid) with the stateful-sequence
	 *      members (socket / sendto / openat / read / close)
	 *      reading ~0; if socket / sendto / openat show a nonzero
	 *      count the COV_WINDOW is too narrow / MIN_STREAK is too
	 *      low / pin_warm spare is mis-detecting and COMBINED MUST
	 *      NOT be promoted.
	 *  frontier_frseq_would_skip_per_group[NR_GROUPS]
	 *      Cumulative per-group: bumped at the gate keyed on the
	 *      child->last_group value (which pin is being released)
	 *      at the would_skip event.  Confirms the demote mass
	 *      concentrates on GROUP_PROCESS (=5) and is ~0 on the
	 *      stateful-sequence groups (GROUP_NET / GROUP_VFS /
	 *      GROUP_IO_URING) before any live flip; if the
	 *      stateful-sequence groups show meaningful release mass
	 *      the predicate is mis-targeting and COMBINED MUST NOT be
	 *      promoted.
	 *
	 * Observability only in this commit: the predicate-evaluation
	 * block is added inside the group_bias gate (random-syscall.c
	 * heuristic-arm set_syscall_nr) with NO live release wired, so
	 * live selection stays byte-identical to today regardless of
	 * which mode is selected.  COMBINED is reserved in the enum
	 * for a follow-up that wires the live pin release after
	 * SHADOW_ONLY validates the predicate against a real run.
	 * Mirrors the off-by-construction discipline the sibling
	 * frontier_satcool_* counters above use. */
	unsigned long frseq_candidates;
	unsigned long frseq_would_skip;
	unsigned long frseq_would_skip_per_syscall[MAX_NR_SYSCALL];
	unsigned long frseq_would_skip_per_group[NR_GROUPS];

	/* SHADOW + per-child A/B accounting for the errno-plateau decay at the
	 * coverage-frontier picker's silent-regime accept site.  Predicate is
	 * frontier_errno_plateau_should_decay() in strategy.c -- see the
	 * FRONTIER_ERRNO_PLATEAU_* constants in include/strategy.h for the
	 * threshold contract and the cred-throttle coordination.
	 *
	 *  frontier_errno_decay_would_skip
	 *      Cumulative: one bump per silent-regime pick where the predicate
	 *      fires, BUMPED FOR BOTH A/B ARMS in lock-step so the would-be
	 *      divergence stays observable regardless of which arm the calling
	 *      child is stamped under.  Ratio against frontier_silent_picks is
	 *      the projected silent-regime pick share the live decay would
	 *      demote.
	 *  frontier_errno_decay_live_rejects
	 *      Cumulative: one bump per arm-B pick that the live REJECT_DENOM-1
	 *      / REJECT_DENOM probabilistic gate actually rejected -- the
	 *      headline live-arm behaviour delta.  Strictly <= frontier_errno_
	 *      decay_would_skip restricted to arm-B picks.  Arm A NEVER bumps
	 *      this counter (it has no live reject path) so the value is the
	 *      pure Arm-B demote count, comparable against the Arm-B silent-pick
	 *      throughput recoverable from frontier_silent_picks normalised by
	 *      frontier_errno_decay_arm_b_children / total cohort split.
	 *  frontier_errno_decay_overlap_silent
	 *      Cumulative: one bump per pick where the errno-plateau predicate
	 *      fires AND the existing silent-streak shadow predicate (the
	 *      frontier_decay_* counters above) is also past its threshold for
	 *      the same syscall -- i.e. the two SHADOW decay families would
	 *      both have demoted this pick.  Measures the overlap so the
	 *      operator can read the orthogonal coverage of the errno-plateau
	 *      predicate vs the consecutive-silent-pick predicate: (would_skip
	 *      - overlap_silent) is the errno-plateau-only contribution.
	 *
	 * Observability + A/B: arm A is byte-identical to the pre-row picker.
	 * Arm B adds the live reject; the shadow counters above stay symmetric
	 * across arms so the would-be decay rate is comparable across cohorts.
	 * Mirrors the off-by-construction discipline the sibling
	 * frontier_blend_* / cred_throttle counters use. */
	unsigned long errno_decay_would_skip;
	unsigned long errno_decay_live_rejects;
	unsigned long errno_decay_overlap_silent;

	/* SHADOW-ONLY A/B scoring for the frontier-blend cold-weight
	 * blend.  See the frontier_cold_weight() comment in random-syscall.c
	 * for the experimental formula.
	 *
	 * Bumped once per frontier_cold_weight() call on the
	 * productive-signal path (calls > 0) so the operator can A/B
	 * compare the OLD weight (call-count only:
	 * per_syscall_edges/per_syscall_calls) against the BLENDED weight
	 * (productive_calls + ilog2(real_bucket_bits+1) +
	 * 2*ilog2(distinct_edges+1), capped at calls) without changing
	 * what the live picker selects.  The set_syscall_nr_coverage_
	 * frontier accept/retry math consumes frontier_cold_weight()'s
	 * return value, which stays the OLD weight; nothing in the
	 * selection path reads any of the shadow stats below, so the
	 * picker's per-syscall distribution stays byte-identical to today.
	 *
	 *  frontier_blend_samples
	 *      Total computations.  Denominator for the average-weight
	 *      ratios below; the calls==0 fast path bypasses the blend
	 *      entirely (both formulas agree on FRONTIER_COLD_SCALE) so
	 *      never-invoked syscalls are excluded -- the counter
	 *      measures only informative samples.
	 *  frontier_blend_new_lower
	 *  frontier_blend_new_higher
	 *  frontier_blend_new_equal
	 *      Per-sample comparison disposition.  Sum equals
	 *      frontier_blend_samples.  A high _lower count means the
	 *      blend would have demoted syscalls the old formula treats
	 *      as cold -- i.e. the syscall has been productive in ways
	 *      (deep raw-edge yield, distinct first-sight PCs) the call-
	 *      count signal alone misses.  A high _higher count means the
	 *      blend would have promoted them; this is the headline
	 *      "would a live silent-regime variant of the picker steer
	 *      differently" signal.
	 *  frontier_blend_old_weight_sum
	 *  frontier_blend_new_weight_sum
	 *      Per-sample weight sums.  Each divided by
	 *      frontier_blend_samples gives the regime's average weight;
	 *      the OLD vs NEW gap summarises whether the blend skews
	 *      colder or hotter at the fleet level.  Each addend is
	 *      bounded by FRONTIER_COLD_SCALE (256) so overflow needs
	 *      ~2^56 samples -- comfortable for any fuzz horizon. */
	unsigned long blend_samples;
	unsigned long blend_new_lower;
	unsigned long blend_new_higher;
	unsigned long blend_new_equal;
	unsigned long blend_old_weight_sum;
	unsigned long blend_new_weight_sum;
};

#endif	/* _TRINITY_STATS_SUBSYS_FRONTIER_H */
