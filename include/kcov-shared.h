#pragma once

/* struct kcov_shared, its extern pointer, and per-nr accessors.
 * Split out of include/kcov.h.  Storage layout of struct kcov_shared
 * is offset-sensitive: consumers snapshot fields via __atomic_load_n
 * and stats/kcov/cmp/ indexes into fixed-length arrays here.  Do not
 * add alignment attributes, reorder fields, or insert nested structs
 * without matching updates in every consumer.  New fields are always
 * appended at the tail so existing offsets stay stable.
 *
 * Per-member documentation for the aggregated group structs lives in
 * the include/kcov-groups/<group>.h header that defines each type.
 * Cross-cutting design narrative (why the group exists, how it plugs
 * into the rest of the pipeline, A/B methodology, etc.) lives in
 * Documentation/kcov-shared-layout.md, anchored by member name. */

#include <stddef.h>	/* offsetof */

#include "kcov-types.h"
#include "kcov-groups/coverage.h"
#include "kcov-groups/cmp_records.h"
#include "kcov-groups/dedup.h"
#include "kcov-groups/hints_flat.h"
#include "kcov-groups/kmsg.h"
#include "kcov-groups/hints_canary.h"
#include "kcov-groups/cohorts.h"
#include "kcov-groups/child_mode.h"
#include "kcov-groups/childop_kcov.h"
#include "kcov-groups/per_syscall.h"
#include "kcov-groups/pc_ctx.h"
#include "kcov-groups/remote_enable.h"
#include "kcov-groups/errno_state.h"
#include "kcov-groups/per_syscall_cmp.h"
#include "kcov-groups/plateau.h"
#include "kcov-groups/covjump.h"
#include "kcov-groups/reexec_flat.h"
#include "kcov-groups/transitions.h"
#include "kcov-groups/cmp_hint_ps.h"
#include "kcov-groups/hint_callsite.h"
#include "kcov-groups/hint_flat.h"
#include "kcov-groups/reexec_pending_hist.h"
#include "kcov-groups/cmp_parent.h"
#include "kcov-groups/hint_reject.h"
#include "kcov-groups/reexec_gate.h"
#include "kcov-groups/cmp_field_attr.h"
#include "kcov-groups/cmp_boring.h"
#include "kcov-groups/cmp_recent.h"
#include "kcov-groups/field_consumer.h"
#include "kcov-groups/field_consumer_guard.h"
#include "kcov-groups/field_consumer_prove.h"
#include "kcov-groups/hint_tier.h"
#include "kcov-groups/hyp_flat.h"
#include "kcov-groups/reexec_step.h"
#include "kcov-groups/cmp_hyp_lifecycle.h"
#include "kcov-groups/cmp_hint_pool.h"
#include "kcov-groups/cmp_hyp_results.h"
#include "kcov-groups/childop_cmp.h"
#include "kcov-groups/cmp_shared_tier.h"
#include "kcov-groups/childop_cmp_consume.h"
#include "kcov-groups/cmp_nonconst.h"
#include "kcov-groups/cmp_width_pin.h"
#include "kcov-groups/cmp_hyp_shadow.h"
#include "kcov-groups/field_consumer_shadow.h"
#include "kcov-groups/cmp_shared_tier_shadow.h"
#include "kcov-groups/reexec_arms.h"

/* Shared coverage state, allocated in shared memory. */
struct kcov_shared {
	/* Per-edge bucket-seen mask; a child's atomic-OR that flips a
	 * never-seen bucket bit is the "new coverage" signal. */
	unsigned char bucket_seen[KCOV_NUM_EDGES];
	/* Coverage-core aggregate counters: bucket-flip volume, distinct
	 * edges, warm-start baselines, PC/call totals, truncation. */
	struct kcov_coverage_core coverage;
	/* CMP-trace collection totals from second-fd KCOV_TRACE_CMP. */
	struct kcov_cmp_records cmp_records;
	/* Dedup-table health -- probe-chain overflow + hi-water. */
	struct kcov_dedup dedup;
	/* Flat CMP-hint pipeline funnel: bloom/strip skips, unique
	 * inserts, injections, chaos gate. */
	struct kcov_hints_flat hints_flat;
	/* Kernel-log-monitor signals surfaced from health/kmsg-monitor.c. */
	struct kcov_kmsg kmsg;
	/* Wild-write / SHM-pool corruption detectors for cmp_hints. */
	struct kcov_hints_canary hints_canary;
	/* A/B cohort child-stamp population + per-arm fire counts. */
	struct kcov_ab_cohorts cohorts;
	/* Child-context CMP/PC diagnostic writes; child's stdout has
	 * already been dup2'd to /dev/null by KCOV setup time. */
	struct kcov_cmp_diag cmp_diag;
	struct kcov_pc_diag pc_diag;
	/* Per-mode child population counters, one bump per child. */
	struct kcov_child_mode_pop child_mode;
	/* Childop KCOV bracket attempt / skip / trace-truncation counters.
	 * See kcov-groups/childop_kcov.h for the per-op partition invariant
	 *   attempts == bracketed + skipped_cmp + skipped_nested
	 *             + skipped_inactive
	 * that also holds on the flat aggregates. */
	struct kcov_childop_kcov childop_kcov;
	/* Per-syscall coverage / call / warm-known / extrafork / prior /
	 * SHADOW-noisy accounting arrays sized to MAX_NR_SYSCALL. */
	struct kcov_per_syscall per_syscall;
	/* Per-syscall / per-childop split of kcov_collect() activity by
	 * local vs remote collection mode.  See
	 * Documentation/kcov-shared-layout.md#pc_ctx for why the split
	 * exists (a remote-sampled syscall lands in a different mode and
	 * a static policy can spend budget on the wrong side). */
	struct kcov_pc_ctx pc_ctx;
	/* Per-syscall accounting of the KCOV_REMOTE_ENABLE attempt path.
	 * See Documentation/kcov-shared-layout.md#remote_enable for the
	 * enable/succeeded/failed/fallback partition and how it lets a
	 * genuinely zero-yield remote call be told apart from EBADF. */
	struct kcov_remote_enable remote_enable;
	/* Per-syscall 8-bucket errno histogram; bumped once per completed
	 * syscall in handle_syscall_ret().  Sized bucket enum lives inline
	 * below this header's static asserts. */
	struct kcov_errno_state errno_state;
	/* Per-syscall counterpart of cmp_hints_unique_inserts; drives the
	 * "top syscalls by CMP unique inserts" block in dump_stats(). */
	struct kcov_per_syscall_cmp per_syscall_cmp;
	/* Sliding-window edge-rate plateau detector state.  See
	 * Documentation/kcov-shared-layout.md#plateau for the entry/clear
	 * contract and the strategy consumer wiring. */
	struct kcov_plateau plateau;
	/* Coverage-jump breadcrumb state.  See KCOV_COVJUMP_* constants for
	 * the detector contract.  Pure diagnostic. */
	struct kcov_covjump covjump;
	/* Greedy CMP RedQueen re-exec funnel.  Invariant per attempt:
	 *   attribution_found -> attempts -> new_cmps_total
	 *                                 -> skipped_destructive
	 *                                 -> skipped_validate_silent
	 *                                 -> window_cap_hit
	 * See Documentation/kcov-shared-layout.md#reexec_flat for the
	 * width-match vs found split and its noise contract. */
	struct kcov_reexec_flat reexec_flat;
	/* Shadow transition-coverage map and counters.  See
	 * KCOV_NUM_TRANSITIONS and the kcov_transition_coverage_mode enum
	 * for the design; Documentation/kcov-shared-layout.md#transitions
	 * covers the remote-mode contract and the frontier blend usage. */
	struct kcov_transitions transitions;
	/* Per-syscall CMP-hint pipeline observability -- partition of the
	 * flat cmp_hints_injected funnel by syscall slot. */
	struct kcov_cmp_hint_ps cmp_hint_ps;
	/* Per-callsite total cmp-hint injections, indexed by
	 * enum cmp_hint_callsite. */
	struct kcov_hint_callsite hint_callsite;
	/* SHADOW feedback scoring counters for cmp-hints
	 * (consumed/wins/misses/novelty/overflow/evicted). */
	struct kcov_hint_flat hint_flat;
	/* RedQueen re-exec observability sibling of the flat family --
	 * per-syscall / per-slot partitions of attempts, ambiguity, and
	 * success. */
	struct kcov_reexec_pending_hist reexec_pending_hist;
	/* RedQueen A/B cohort denominators (calls_enabled/control +
	 * new_cmps_enabled/control) so re-exec lift is measurable per
	 * parent call rather than as an unpaired numerator. */
	struct kcov_cmp_parent cmp_parent;
	/* Per-reason granular counters for the cmp-hint save/persist
	 * reject funnel (nonconst / uninteresting / sentinel / dup / cap).
	 * Reasons are mutually exclusive per record. */
	struct kcov_hint_reject hint_reject;
	/* Measurement-correctness counters for the RedQueen attribution +
	 * re-exec funnel: per-syscall / per-childop partitions of the head,
	 * eight mutually-exclusive gate-cause buckets at the tail, plus
	 * snapshot-availability counters.  See
	 * Documentation/kcov-shared-layout.md#reexec_gate for the per-call
	 * partition invariant
	 *   sum(reexec_gate_skip_*) + reexec_gate_pass
	 *       == every dispatch_step that reached the re-exec tail. */
	struct kcov_reexec_gate reexec_gate;
	/* Field-scoped CMP attribution counters (PHASE 3 narrow MVP).
	 * Field lane is counted separately from the scalar tally so its
	 * signal-to-noise stays legible. */
	struct kcov_cmp_field_attr cmp_field_attr;
	/* A/B counter for the substitution-pool "uninteresting constant"
	 * drop mask (Arm A ~3UL, Arm B ~7UL).  Bumped only in the [4,7]
	 * band where the two arms diverge. */
	struct kcov_cmp_boring cmp_boring;
	/* Observability for the run-local CMP "recent" pool tier.  Sampled
	 * first on a CMP_RISING_PC_FLAT plateau; the pair of would-pick
	 * counters + live-picks sizes served vs opportunity. */
	struct kcov_cmp_recent cmp_recent;
	/* SHADOW counters for the field-scoped CMP hint consumer.  Active
	 * in both arms so an A/B run reads the same shadow rates a future
	 * live arm will eventually consume. */
	struct kcov_field_consumer field_consumer;
	/* Per-reason skip counters for the generator-invariant guard on
	 * the field consumer would-pick path. */
	struct kcov_field_consumer_guard field_consumer_guard;
	/* Prove-overlay baseline for the field consumer: eligible-pick
	 * denominator + three "_at_pick" numerators for a later live-arm
	 * diff. */
	struct kcov_field_consumer_prove field_consumer_prove;
	/* CMP-hint freshness / tier observability -- per-tier and per-age
	 * partitions of wins/misses/consumed so conversion rate per
	 * (tier, age-bucket) is directly readable. */
	struct kcov_hint_tier hint_tier;
	/* SHADOW typed-CMP-hypothesis store counters.  Consumer-side wins
	 * stay at zero until the follow-up unit lands. */
	struct kcov_hyp_flat hyp_flat;
	/* Per-entry early-FAIL skip counters inside redqueen_reexec_step:
	 * closes the per-entry skip partition once the per-call gate has
	 * already passed. */
	struct kcov_reexec_step reexec_step;
	/* Per-kind flat census of typed CMP hypothesis insertions.
	 * SHADOW telemetry only -- no consumer reads it. */
	struct kcov_cmp_hyp_lifecycle cmp_hyp_lifecycle;
	/* SHADOW old-flat-pool conversion baseline, partitioned by pool
	 * kind so the per-syscall pool and field-scoped pool are directly
	 * comparable.  Counters bump per stashed entry (not per parent
	 * dispatch) so SUM by pool can exceed the matching flat counter. */
	struct kcov_cmp_hint_pool cmp_hint_pool;
	/* Corruption-channel sibling of cmp_hyp_pool_full; any non-zero
	 * delta here means a writer scribbled the per-syscall pool out
	 * of bounds. */
	struct kcov_cmp_hyp_results cmp_hyp_results;
	/* Childop CMP harvest SHADOW counters; wired to a quarantined
	 * childop lane so no childop constant can evict a random-syscall
	 * constant until per-nr promotion is earned. */
	struct kcov_childop_cmp childop_cmp;
	/* SHADOW counters for the fleet-wide shared cmp_ip tier
	 * (cmp_hints_shared.shared_tier[]).  All six OFF-mode counters
	 * stay at zero; see include/cmp_hints.h for the tier's shape. */
	struct kcov_cmp_shared_tier cmp_shared_tier;
	/* SHADOW consume-side counters for the childop CMP path.  All
	 * would_* counters SIZE what a future live consume WOULD do; the
	 * pick stream stays byte-identical to a build without the knob. */
	struct kcov_childop_cmp_consume childop_cmp_consume;
	/* SHADOW measurement of the non-const relational CMP drop site --
	 * sizes headroom for a future relational attribution lane. */
	struct kcov_cmp_nonconst cmp_nonconst;
	/* SHADOW measurement of a high-bit-preserving replacement for the
	 * width-masked CMP RedQueen pin. */
	struct kcov_cmp_width_pin cmp_width_pin;
	/* SHADOW measurement of a POW2 / alignment probe class in the
	 * typed-hypothesis derive.  Nothing on the live pick path reads
	 * these; sizes the coverage headroom of promoting the class. */
	struct kcov_cmp_hyp_shadow cmp_hyp_shadow;
	/* SHADOW win-scalar for the field-scoped CMP inject arm.  Bumped
	 * on the would_pick subset where the pool value differs from what
	 * the generator was about to write. */
	struct kcov_field_consumer_shadow field_consumer_shadow;
	/* SHADOW would-confirm win-scalar for the shared-tier cold-serve
	 * arm.  Election is READ-ONLY, no-RNG, deterministic; sizes the
	 * fraction of opportunities already corroborated by this nr's
	 * native pool. */
	struct kcov_cmp_shared_tier_shadow cmp_shared_tier_shadow;
	/* RedQueen plateau_burst per-call drain-cap A/B measure arm
	 * counters.  Distinct-edge lift domain, not CMP-record domain --
	 * see Documentation/kcov-shared-layout.md#reexec_arms. */
	struct kcov_reexec_arms reexec_arms;
};

extern struct kcov_shared *kcov_shm;

/* Combined per-nr accessors for the [nr][do32?1:0]-split productivity
 * arrays.  Readers that want the pre-split scalar sum both arch dims
 * with RELAXED atomics -- a torn pair across the two loads is a
 * one-bump skew, well inside the slack the picker accept/retry loop
 * already tolerates.  Callers gate on kcov_shm != NULL and nr <
 * MAX_NR_SYSCALL themselves; these helpers do not re-check. */
static inline unsigned long per_syscall_edges_total(unsigned int nr)
{
	unsigned long total = 0;
	unsigned int ctx;

	for (ctx = 0; ctx < PICKER_NCTX; ctx++) {
		total += __atomic_load_n(
				&kcov_shm->per_syscall.per_syscall_edges[nr][ctx][0],
				__ATOMIC_RELAXED);
		total += __atomic_load_n(
				&kcov_shm->per_syscall.per_syscall_edges[nr][ctx][1],
				__ATOMIC_RELAXED);
	}
	return total;
}
static inline unsigned long per_syscall_calls_total(unsigned int nr)
{
	unsigned long total = 0;
	unsigned int ctx;

	for (ctx = 0; ctx < PICKER_NCTX; ctx++) {
		total += __atomic_load_n(
				&kcov_shm->per_syscall.per_syscall_calls[nr][ctx][0],
				__ATOMIC_RELAXED);
		total += __atomic_load_n(
				&kcov_shm->per_syscall.per_syscall_calls[nr][ctx][1],
				__ATOMIC_RELAXED);
	}
	return total;
}
static inline unsigned long per_syscall_edges_previous_total(unsigned int nr)
{
	return kcov_shm->per_syscall.per_syscall_edges_previous[nr][0] +
	       kcov_shm->per_syscall.per_syscall_edges_previous[nr][1];
}
static inline unsigned long per_syscall_edges_prior_total(unsigned int nr)
{
	return kcov_shm->per_syscall.per_syscall_edges_prior[nr][0] +
	       kcov_shm->per_syscall.per_syscall_edges_prior[nr][1];
}
static inline unsigned long per_syscall_calls_prior_total(unsigned int nr)
{
	return kcov_shm->per_syscall.per_syscall_calls_prior[nr][0] +
	       kcov_shm->per_syscall.per_syscall_calls_prior[nr][1];
}


/* Storage-neutrality asserts.  These pin sizeof(struct kcov_shared)
 * and offsetof for a set of load-bearing fields so an accidental
 * reorder or padding-introducing edit fails to compile instead of
 * silently shifting layout across a wide set of readers. */
/* Adding coverage.trace_loss (+8) and childop_kcov.{skipped_sample,
 * op_skipped_sample[KCOV_CHILDOP_NR_MAX]} (+8 +1280 = +1288) shifts
 * every offset after each addition:
 *   - trace_loss lives at the tail of struct kcov_coverage_core, so
 *     every subsequent group offset shifts by +8.
 *   - childop_kcov new fields append to struct kcov_childop_kcov, so
 *     every group offset AFTER childop_kcov (per_syscall.., reexec_arms
 *     tail, sizeof) shifts by an additional +1288.
 * Absolute deltas:
 *   sizeof:                     25946080 + 8 + 1288 = 25947376
 *   cmp_records..:              8388672  + 8        = 8388680
 *   hints_flat..:               8388728  + 8        = 8388736
 *   per_syscall.per_syscall_edges: 8400280 + 8 + 1288 = 8401576
 *   reexec_arms..:              25946064 + 8 + 1288 = 25947360 */
_Static_assert(sizeof(struct kcov_shared) == 25947376UL,
	"struct kcov_shared sizeof drifted -- audit layout before updating this");
_Static_assert(offsetof(struct kcov_shared, bucket_seen) == 0UL,
	"kcov_shared.bucket_seen must remain the first field");
_Static_assert(offsetof(struct kcov_shared, cmp_records.cmp_records_collected) == 8388680UL,
	"kcov_shared.cmp_records.cmp_records_collected offset drifted");
_Static_assert(offsetof(struct kcov_shared, hints_flat.cmp_hints_injected) == 8388736UL,
	"kcov_shared.hints_flat.cmp_hints_injected offset drifted");
_Static_assert(offsetof(struct kcov_shared, per_syscall.per_syscall_edges) == 8401576UL,
	"kcov_shared.per_syscall.per_syscall_edges offset drifted");
_Static_assert(offsetof(struct kcov_shared, reexec_arms.reexec_new_edges_by_arm) == 25947360UL,
	"kcov_shared last-field offset drifted -- append-only tail broken");
