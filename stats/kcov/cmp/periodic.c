/*
 * KCOV CMP periodic dump orchestrator.
 *
 * Owns the single public entry point kcov_cmp_stats_periodic_dump(),
 * called from main/loop.c's run_periodic_surfaces() tick.  Loads the
 * current shm/parent_stats snapshot, arms the first-window state,
 * checks the elapsed-time gate, computes per-window deltas, gates the
 * emit on any-delta, then fans out to the render helpers in the
 * sibling stats/kcov/cmp/ TUs (base, redqueen, pool, hyp, childop,
 * cohort, diag) and commits the previous-window snapshot.
 *
 * All static previous-window state and per-counter locals stay local
 * to this TU; the render helpers live in their per-domain siblings and
 * are declared in stats/kcov/cmp/internal.h.
 */

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stddef.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "arch.h"
#include "arg-len-semantics.h"
#include "breadcrumb_ring.h"
#include "child-api.h"
#include "cmp_hints.h"
#include "cred_throttle.h"
#include "fd.h"
#include "kcov.h"
#include "minicorpus.h"
#include "params.h"
#include "pc_format.h"
#include "pids.h"
#include "reach-band.h"
#include "sequence.h"
#include "shm.h"
#include "stats.h"
#include "stats-internal.h"
#include "stats_ring.h"
#include "syscall.h"
#include "tables.h"
#include "taint.h"
#include "trinity.h"
#include "utils.h"
#include "version.h"

#include "stats/kcov/cmp/internal.h"

/*
 * Surface the KCOV CMP counters in the same 600s periodic stats-log-file
 * dump as periodic_counter_rates_dump.  Without this the cmp counters
 * are only visible from dump_stats() (run shutdown) and the JSON dump
 * (on enable), so a long run produces one shutdown snapshot with
 * nothing in between, making it impossible to correlate cmp_hints
 * effectiveness with edge-discovery cadence over the run.
 *
 * Three sub-blocks, each gated independently so a healthy run that has
 * no DIAG errnos doesn't carry an empty "DIAG:" line into the log:
 *  - per-window deltas + rates + cumulative totals for the three cmp
 *    counters, formatted to match periodic_counter_rates_dump;
 *  - per-mode child population (cumulative) so the realised PC/CMP
 *    mode mix is visible in the time series, not only at shutdown;
 *  - first-failure-wins errno/count per cmp-init/runtime site.
 */
void __cold kcov_cmp_stats_periodic_dump(void)
{
	static unsigned long prev_records;
	static unsigned long prev_truncated;
	static unsigned long prev_bloom_skipped;
	static unsigned long prev_strip_skipped;
	static unsigned long prev_unique;
	static unsigned long prev_try_get_attempts;
	static unsigned long prev_try_get_returned;
	static unsigned long prev_injected;
	static unsigned long prev_prop_injected;
	static unsigned long prev_chaos_suppressed;
	static unsigned long prev_count_oob;
	static unsigned long prev_canary_lock_post;
	static unsigned long prev_canary_pre;
	static unsigned long prev_canary_post;
	static unsigned long prev_reexec_attempts;
	static unsigned long prev_reexec_attempts_with_new_cmp;
	static unsigned long prev_reexec_attribution_found;
	static unsigned long prev_reexec_attribution_ambiguous;
	static unsigned long prev_reexec_attribution_width_match;
	static unsigned long prev_reexec_new_cmps_total;
	static unsigned long prev_reexec_new_edges_total;
	static unsigned long prev_reexec_attempts_by_arm[2];
	static unsigned long prev_reexec_new_cmps_by_arm[2];
	static unsigned long prev_reexec_new_edges_by_arm[2];
	static unsigned long prev_reexec_skipped_destructive;
	static unsigned long prev_reexec_skipped_validate_silent;
	static unsigned long prev_reexec_window_cap_hit;
	static unsigned long prev_reexec_pending_dropped;
	static unsigned long prev_reexec_gate_skip_in_reexec;
	static unsigned long prev_reexec_gate_skip_disabled;
	static unsigned long prev_reexec_gate_skip_mode;
	static unsigned long prev_reexec_gate_skip_chain_mid;
	static unsigned long prev_reexec_gate_skip_no_new_cmp;
	static unsigned long prev_reexec_gate_skip_no_pending;
	static unsigned long prev_reexec_gate_skip_rate;
	static unsigned long prev_reexec_gate_pass;
	static unsigned long prev_cmp_parent_calls_enabled;
	static unsigned long prev_cmp_parent_calls_control;
	static unsigned long prev_cmp_parent_new_cmps_enabled;
	static unsigned long prev_cmp_parent_new_cmps_control;
	static unsigned long prev_cmp_hint_callsite[CMP_HINT_CALLSITE_NR];
	static unsigned long prev_cmp_hint_callsite_pc_wins[CMP_HINT_CALLSITE_NR];
	static unsigned long prev_cmp_hint_callsite_misses[CMP_HINT_CALLSITE_NR];
	static unsigned long prev_prop_injected_callsite[PROP_INJECTED_CALLSITE_NR];
	static unsigned long prev_save_reject_nonconst;
	static unsigned long prev_save_reject_uninteresting;
	static unsigned long prev_save_reject_sentinel;
	static unsigned long prev_save_reject_dup;
	static unsigned long prev_save_reject_cap;
	static unsigned long prev_cmp_hints_consumed;
	static unsigned long prev_cmp_hint_wins;
	static unsigned long prev_cmp_hint_misses;
	static unsigned long prev_cmp_hint_cmp_novelty_wins;
	static unsigned long prev_cmp_hint_stash_overflow;
	static unsigned long prev_cmp_hint_credit_entry_evicted;
	static unsigned long prev_cmp_recent_inserts;
	static unsigned long prev_cmp_recent_evicts;
	static unsigned long prev_cmp_recent_would_pick;
	static unsigned long prev_cmp_recent_would_miss;
	static unsigned long prev_cmp_recent_live_picks;
	static unsigned long prev_cmp_inject_arm_a_baseline_fires;
	static unsigned long prev_cmp_inject_arm_b_baseline_fires;
	static unsigned long prev_cmp_inject_denom_diverged;
	static unsigned long prev_prop_ring_argop_arm_b_fires;
	static unsigned long prev_frontier_blend_samples;
	static unsigned long prev_remote_adaptive_samples;
	static unsigned long prev_mut_structured_shadow_divergences;
	static struct timespec last_dump;
	struct timespec now;
	long elapsed;
	unsigned long cur_records, cur_truncated, cur_bloom_skipped, cur_unique;
	unsigned long cur_strip_skipped;
	unsigned long cur_try_get_attempts, cur_try_get_returned, cur_injected;
	unsigned long cur_prop_injected;
	unsigned long cur_chaos_suppressed;
	unsigned long cur_count_oob, cur_canary_lock_post, cur_canary_pre, cur_canary_post;
	unsigned long cur_reexec_attempts, cur_reexec_attribution_found;
	unsigned long cur_reexec_attempts_with_new_cmp;
	unsigned long cur_reexec_attribution_ambiguous, cur_reexec_new_cmps_total;
	unsigned long cur_reexec_new_edges_total;
	unsigned long cur_reexec_attempts_by_arm[2];
	unsigned long cur_reexec_new_cmps_by_arm[2];
	unsigned long cur_reexec_new_edges_by_arm[2];
	unsigned long cur_reexec_attribution_width_match;
	unsigned long cur_reexec_skipped_destructive, cur_reexec_skipped_validate_silent;
	unsigned long cur_reexec_window_cap_hit;
	unsigned long cur_reexec_pending_dropped;
	unsigned long cur_reexec_gate_skip_in_reexec;
	unsigned long cur_reexec_gate_skip_disabled;
	unsigned long cur_reexec_gate_skip_mode;
	unsigned long cur_reexec_gate_skip_chain_mid;
	unsigned long cur_reexec_gate_skip_no_new_cmp;
	unsigned long cur_reexec_gate_skip_no_pending;
	unsigned long cur_reexec_gate_skip_rate;
	unsigned long cur_reexec_gate_pass;
	unsigned long cur_cmp_parent_calls_enabled, cur_cmp_parent_calls_control;
	unsigned long cur_cmp_parent_new_cmps_enabled, cur_cmp_parent_new_cmps_control;
	unsigned long cur_cmp_hint_callsite[CMP_HINT_CALLSITE_NR];
	unsigned long cur_cmp_hint_callsite_pc_wins[CMP_HINT_CALLSITE_NR];
	unsigned long cur_cmp_hint_callsite_misses[CMP_HINT_CALLSITE_NR];
	unsigned long cur_prop_injected_callsite[PROP_INJECTED_CALLSITE_NR];
	unsigned long cur_save_reject_nonconst, cur_save_reject_uninteresting;
	unsigned long cur_save_reject_sentinel, cur_save_reject_dup, cur_save_reject_cap;
	unsigned long delta_save_reject_nonconst, delta_save_reject_uninteresting;
	unsigned long delta_save_reject_sentinel, delta_save_reject_dup, delta_save_reject_cap;
	unsigned long delta_records, delta_truncated, delta_bloom_skipped, delta_unique;
	unsigned long delta_strip_skipped;
	unsigned long delta_try_get_attempts, delta_try_get_returned, delta_injected;
	unsigned long delta_prop_injected;
	unsigned long delta_chaos_suppressed;
	unsigned long delta_count_oob, delta_canary_lock_post, delta_canary_pre, delta_canary_post;
	unsigned long delta_reexec_attempts, delta_reexec_attribution_found;
	unsigned long delta_reexec_attempts_with_new_cmp;
	unsigned long delta_reexec_attribution_ambiguous, delta_reexec_new_cmps_total;
	unsigned long delta_reexec_new_edges_total;
	unsigned long delta_reexec_attempts_by_arm[2];
	unsigned long delta_reexec_new_cmps_by_arm[2];
	unsigned long delta_reexec_new_edges_by_arm[2];
	unsigned long delta_reexec_attribution_width_match;
	unsigned long delta_reexec_skipped_destructive, delta_reexec_skipped_validate_silent;
	unsigned long delta_reexec_window_cap_hit;
	unsigned long delta_reexec_pending_dropped;
	unsigned long delta_reexec_gate_skip_in_reexec;
	unsigned long delta_reexec_gate_skip_disabled;
	unsigned long delta_reexec_gate_skip_mode;
	unsigned long delta_reexec_gate_skip_chain_mid;
	unsigned long delta_reexec_gate_skip_no_new_cmp;
	unsigned long delta_reexec_gate_skip_no_pending;
	unsigned long delta_reexec_gate_skip_rate;
	unsigned long delta_reexec_gate_pass;
	unsigned long delta_cmp_parent_calls_enabled, delta_cmp_parent_calls_control;
	unsigned long delta_cmp_parent_new_cmps_enabled, delta_cmp_parent_new_cmps_control;
	unsigned long delta_cmp_hint_callsite[CMP_HINT_CALLSITE_NR];
	unsigned long delta_cmp_hint_callsite_pc_wins[CMP_HINT_CALLSITE_NR];
	unsigned long delta_cmp_hint_callsite_misses[CMP_HINT_CALLSITE_NR];
	unsigned long delta_prop_injected_callsite[PROP_INJECTED_CALLSITE_NR];
	unsigned long cur_cmp_hints_consumed, cur_cmp_hint_wins, cur_cmp_hint_misses;
	unsigned long cur_cmp_hint_cmp_novelty_wins;
	unsigned long cur_cmp_hint_stash_overflow, cur_cmp_hint_credit_entry_evicted;
	unsigned long cur_cmp_recent_inserts, cur_cmp_recent_evicts;
	unsigned long cur_cmp_recent_would_pick, cur_cmp_recent_would_miss;
	unsigned long cur_cmp_recent_live_picks;
	unsigned long delta_cmp_hints_consumed, delta_cmp_hint_wins, delta_cmp_hint_misses;
	unsigned long delta_cmp_hint_cmp_novelty_wins;
	unsigned long delta_cmp_hint_stash_overflow, delta_cmp_hint_credit_entry_evicted;
	unsigned long delta_cmp_recent_inserts, delta_cmp_recent_evicts;
	unsigned long delta_cmp_recent_would_pick, delta_cmp_recent_would_miss;
	unsigned long delta_cmp_recent_live_picks;
	unsigned long cur_cmp_inject_arm_a_baseline_fires, cur_cmp_inject_arm_b_baseline_fires;
	unsigned long cur_cmp_inject_denom_diverged;
	unsigned long delta_cmp_inject_arm_a_baseline_fires, delta_cmp_inject_arm_b_baseline_fires;
	unsigned long delta_cmp_inject_denom_diverged;
	unsigned int  cur_cmp_inject_arm_a_children, cur_cmp_inject_arm_b_children;
	unsigned long cur_prop_ring_argop_arm_b_fires, delta_prop_ring_argop_arm_b_fires;
	unsigned int  cur_prop_ring_argop_arm_a_children, cur_prop_ring_argop_arm_b_children;
	unsigned long cur_frontier_blend_samples, delta_frontier_blend_samples;
	unsigned int  cur_frontier_blend_arm_a_children, cur_frontier_blend_arm_b_children;
	unsigned long cur_remote_adaptive_samples, delta_remote_adaptive_samples;
	unsigned long cur_remote_adaptive_would_demote;
	unsigned long cur_remote_adaptive_would_promote;
	unsigned long cur_remote_adaptive_would_force;
	unsigned long cur_remote_adaptive_would_gate_promote;
	unsigned long cur_remote_adaptive_agree;
	unsigned long cur_arg_meta_addr_with_meta;
	unsigned long cur_arg_meta_addr_without_meta;
	unsigned long cur_arg_meta_argtype_stale;
	unsigned long cur_arg_meta_scrub_would_destroy_in;
	unsigned long cur_arg_meta_scrub_would_preserve_out;
	unsigned long cur_blanket_address_scrub_slots_walked;
	unsigned int  cur_remote_adaptive_arm_a_children, cur_remote_adaptive_arm_b_children;
	unsigned long cur_mut_structured_shadow_samples;
	unsigned long cur_mut_structured_shadow_divergences;
	unsigned long delta_mut_structured_shadow_divergences;
	unsigned int  cur_mut_structured_arm_a_children, cur_mut_structured_arm_b_children;
	bool any_callsite_delta = false;
	bool any_callsite_wins_delta = false;
	bool any_prop_callsite_delta = false;

	if (kcov_shm == NULL)
		return;

	clock_gettime(CLOCK_MONOTONIC, &now);

	cur_records       = __atomic_load_n(&kcov_shm->cmp_records.cmp_records_collected,   __ATOMIC_RELAXED);
	cur_truncated     = __atomic_load_n(&kcov_shm->cmp_records.cmp_trace_truncated,     __ATOMIC_RELAXED);
	cur_bloom_skipped = __atomic_load_n(&kcov_shm->hints_flat.cmp_hints_bloom_skipped, __ATOMIC_RELAXED);
	cur_strip_skipped = __atomic_load_n(&kcov_shm->hints_flat.cmp_hints_strip_skipped, __ATOMIC_RELAXED);
	cur_unique        = __atomic_load_n(&kcov_shm->hints_flat.cmp_hints_unique_inserts, __ATOMIC_RELAXED);
	/* Source from parent_stats: cmp_hints_try_get_ex() now enqueues
	 * +1 per attempt/return via the per-child stats_ring; the kcov_shm
	 * scalars are gone, removing a fuzzer-visible wild-write target. */
	cur_try_get_attempts = parent_stats.cmp_hints_try_get_attempts;
	cur_try_get_returned = parent_stats.cmp_hints_try_get_returned;
	cur_injected         = __atomic_load_n(&kcov_shm->hints_flat.cmp_hints_injected,         __ATOMIC_RELAXED);
	cur_prop_injected    = __atomic_load_n(&kcov_shm->hints_flat.propagation_injected,       __ATOMIC_RELAXED);
	cur_chaos_suppressed = __atomic_load_n(&kcov_shm->hints_flat.cmp_hints_chaos_suppressed, __ATOMIC_RELAXED);
	cur_count_oob        = __atomic_load_n(&kcov_shm->hints_canary.cmp_hints_count_oob,               __ATOMIC_RELAXED);
	cur_canary_lock_post = __atomic_load_n(&kcov_shm->hints_canary.cmp_hints_canary_lock_post_corrupt, __ATOMIC_RELAXED);
	cur_canary_pre       = __atomic_load_n(&kcov_shm->hints_canary.cmp_hints_canary_pre_corrupt,      __ATOMIC_RELAXED);
	cur_canary_post      = __atomic_load_n(&kcov_shm->hints_canary.cmp_hints_canary_post_corrupt,     __ATOMIC_RELAXED);
	cur_reexec_attempts                = __atomic_load_n(&kcov_shm->reexec_flat.reexec_attempts,                __ATOMIC_RELAXED);
	cur_reexec_attempts_with_new_cmp   = __atomic_load_n(&kcov_shm->reexec_flat.reexec_attempts_with_new_cmp,   __ATOMIC_RELAXED);
	cur_reexec_attribution_found       = __atomic_load_n(&kcov_shm->reexec_flat.reexec_attribution_found,       __ATOMIC_RELAXED);
	cur_reexec_attribution_ambiguous   = __atomic_load_n(&kcov_shm->reexec_flat.reexec_attribution_ambiguous,   __ATOMIC_RELAXED);
	cur_reexec_attribution_width_match = __atomic_load_n(&kcov_shm->reexec_flat.reexec_attribution_width_match, __ATOMIC_RELAXED);
	cur_reexec_new_cmps_total          = __atomic_load_n(&kcov_shm->reexec_flat.reexec_new_cmps_total,          __ATOMIC_RELAXED);
	cur_reexec_new_edges_total         = __atomic_load_n(&kcov_shm->reexec_new_edges_total,         __ATOMIC_RELAXED);
	cur_reexec_attempts_by_arm[0]      = __atomic_load_n(&kcov_shm->reexec_attempts_by_arm[0],      __ATOMIC_RELAXED);
	cur_reexec_attempts_by_arm[1]      = __atomic_load_n(&kcov_shm->reexec_attempts_by_arm[1],      __ATOMIC_RELAXED);
	cur_reexec_new_cmps_by_arm[0]      = __atomic_load_n(&kcov_shm->reexec_new_cmps_by_arm[0],      __ATOMIC_RELAXED);
	cur_reexec_new_cmps_by_arm[1]      = __atomic_load_n(&kcov_shm->reexec_new_cmps_by_arm[1],      __ATOMIC_RELAXED);
	cur_reexec_new_edges_by_arm[0]     = __atomic_load_n(&kcov_shm->reexec_new_edges_by_arm[0],     __ATOMIC_RELAXED);
	cur_reexec_new_edges_by_arm[1]     = __atomic_load_n(&kcov_shm->reexec_new_edges_by_arm[1],     __ATOMIC_RELAXED);
	cur_reexec_skipped_destructive     = __atomic_load_n(&kcov_shm->reexec_flat.reexec_skipped_destructive,     __ATOMIC_RELAXED);
	cur_reexec_skipped_validate_silent = __atomic_load_n(&kcov_shm->reexec_flat.reexec_skipped_validate_silent, __ATOMIC_RELAXED);
	cur_reexec_window_cap_hit          = __atomic_load_n(&kcov_shm->reexec_flat.reexec_window_cap_hit,          __ATOMIC_RELAXED);
	cur_reexec_pending_dropped         = __atomic_load_n(&kcov_shm->reexec_pending_hist.reexec_pending_dropped,         __ATOMIC_RELAXED);
	cur_reexec_gate_skip_in_reexec     = __atomic_load_n(&kcov_shm->reexec_gate_skip_in_reexec,     __ATOMIC_RELAXED);
	cur_reexec_gate_skip_disabled      = __atomic_load_n(&kcov_shm->reexec_gate_skip_disabled,      __ATOMIC_RELAXED);
	cur_reexec_gate_skip_mode          = __atomic_load_n(&kcov_shm->reexec_gate_skip_mode,          __ATOMIC_RELAXED);
	cur_reexec_gate_skip_chain_mid     = __atomic_load_n(&kcov_shm->reexec_gate_skip_chain_mid,     __ATOMIC_RELAXED);
	cur_reexec_gate_skip_no_new_cmp    = __atomic_load_n(&kcov_shm->reexec_gate_skip_no_new_cmp,    __ATOMIC_RELAXED);
	cur_reexec_gate_skip_no_pending    = __atomic_load_n(&kcov_shm->reexec_gate_skip_no_pending,    __ATOMIC_RELAXED);
	cur_reexec_gate_skip_rate          = __atomic_load_n(&kcov_shm->reexec_gate_skip_rate,          __ATOMIC_RELAXED);
	cur_reexec_gate_pass               = __atomic_load_n(&kcov_shm->reexec_gate_pass,               __ATOMIC_RELAXED);
	cur_cmp_parent_calls_enabled       = __atomic_load_n(&kcov_shm->cmp_parent.cmp_parent_calls_enabled,       __ATOMIC_RELAXED);
	cur_cmp_parent_calls_control       = __atomic_load_n(&kcov_shm->cmp_parent.cmp_parent_calls_control,       __ATOMIC_RELAXED);
	cur_cmp_parent_new_cmps_enabled    = __atomic_load_n(&kcov_shm->cmp_parent.cmp_parent_new_cmps_enabled,    __ATOMIC_RELAXED);
	cur_cmp_parent_new_cmps_control    = __atomic_load_n(&kcov_shm->cmp_parent.cmp_parent_new_cmps_control,    __ATOMIC_RELAXED);
	cur_save_reject_nonconst      = __atomic_load_n(&kcov_shm->hint_reject.cmp_hints_save_reject_nonconst,      __ATOMIC_RELAXED);
	cur_save_reject_uninteresting = __atomic_load_n(&kcov_shm->hint_reject.cmp_hints_save_reject_uninteresting, __ATOMIC_RELAXED);
	cur_save_reject_sentinel      = __atomic_load_n(&kcov_shm->hint_reject.cmp_hints_save_reject_sentinel,      __ATOMIC_RELAXED);
	cur_save_reject_dup           = __atomic_load_n(&kcov_shm->hint_reject.cmp_hints_save_reject_dup,           __ATOMIC_RELAXED);
	cur_save_reject_cap           = __atomic_load_n(&kcov_shm->hint_reject.cmp_hints_save_reject_cap,           __ATOMIC_RELAXED);
	{
		unsigned int cs;
		for (cs = 0; cs < CMP_HINT_CALLSITE_NR; cs++)
			cur_cmp_hint_callsite[cs] = __atomic_load_n(
				&kcov_shm->hint_callsite.cmp_hint_callsite_injected[cs],
				__ATOMIC_RELAXED);
	}
	{
		unsigned int cs;
		for (cs = 0; cs < CMP_HINT_CALLSITE_NR; cs++) {
			cur_cmp_hint_callsite_pc_wins[cs] = __atomic_load_n(
				&kcov_shm->hint_callsite.cmp_hint_callsite_pc_wins[cs],
				__ATOMIC_RELAXED);
			cur_cmp_hint_callsite_misses[cs] = __atomic_load_n(
				&kcov_shm->hint_callsite.cmp_hint_callsite_misses[cs],
				__ATOMIC_RELAXED);
		}
	}
	{
		unsigned int cs;
		for (cs = 0; cs < PROP_INJECTED_CALLSITE_NR; cs++)
			cur_prop_injected_callsite[cs] = __atomic_load_n(
				&kcov_shm->hints_flat.propagation_injected_callsite[cs],
				__ATOMIC_RELAXED);
	}
	cur_cmp_hints_consumed             = __atomic_load_n(&kcov_shm->hint_flat.cmp_hints_consumed,             __ATOMIC_RELAXED);
	cur_cmp_hint_wins                  = __atomic_load_n(&kcov_shm->hint_flat.cmp_hint_wins,                  __ATOMIC_RELAXED);
	cur_cmp_hint_misses                = __atomic_load_n(&kcov_shm->hint_flat.cmp_hint_misses,                __ATOMIC_RELAXED);
	cur_cmp_hint_cmp_novelty_wins      = __atomic_load_n(&kcov_shm->hint_flat.cmp_hint_cmp_novelty_wins,      __ATOMIC_RELAXED);
	cur_cmp_hint_stash_overflow        = __atomic_load_n(&kcov_shm->hint_flat.cmp_hint_stash_overflow,        __ATOMIC_RELAXED);
	cur_cmp_hint_credit_entry_evicted  = __atomic_load_n(&kcov_shm->hint_flat.cmp_hint_credit_entry_evicted,  __ATOMIC_RELAXED);
	cur_cmp_recent_inserts             = __atomic_load_n(&kcov_shm->cmp_recent_inserts,             __ATOMIC_RELAXED);
	cur_cmp_recent_evicts              = __atomic_load_n(&kcov_shm->cmp_recent_evicts,              __ATOMIC_RELAXED);
	cur_cmp_recent_would_pick          = __atomic_load_n(&kcov_shm->cmp_recent_would_pick,          __ATOMIC_RELAXED);
	cur_cmp_recent_would_miss          = __atomic_load_n(&kcov_shm->cmp_recent_would_miss,          __ATOMIC_RELAXED);
	cur_cmp_recent_live_picks          = __atomic_load_n(&kcov_shm->cmp_recent_live_picks,          __ATOMIC_RELAXED);
	cur_cmp_inject_arm_a_baseline_fires = __atomic_load_n(&kcov_shm->cohorts.cmp_inject_arm_a_baseline_fires, __ATOMIC_RELAXED);
	cur_cmp_inject_arm_b_baseline_fires = __atomic_load_n(&kcov_shm->cohorts.cmp_inject_arm_b_baseline_fires, __ATOMIC_RELAXED);
	cur_cmp_inject_denom_diverged       = __atomic_load_n(&kcov_shm->cohorts.cmp_inject_denom_diverged,       __ATOMIC_RELAXED);
	cur_cmp_inject_arm_a_children       = __atomic_load_n(&kcov_shm->cohorts.cmp_inject_arm_a_children,       __ATOMIC_RELAXED);
	cur_cmp_inject_arm_b_children       = __atomic_load_n(&kcov_shm->cohorts.cmp_inject_arm_b_children,       __ATOMIC_RELAXED);
	cur_prop_ring_argop_arm_b_fires     = __atomic_load_n(&kcov_shm->cohorts.prop_ring_argop_arm_b_fires,     __ATOMIC_RELAXED);
	cur_prop_ring_argop_arm_a_children  = __atomic_load_n(&kcov_shm->cohorts.prop_ring_argop_arm_a_children,  __ATOMIC_RELAXED);
	cur_prop_ring_argop_arm_b_children  = __atomic_load_n(&kcov_shm->cohorts.prop_ring_argop_arm_b_children,  __ATOMIC_RELAXED);
	/* frontier_blend_samples lives in shm->stats (bumped per fire from
	 * both arms in lock-step), the cohort children counters live in
	 * kcov_shm (bumped once per child).  Read both here so the cohort
	 * dump row can be delta-gated on the fire counter, matching the
	 * prop_ring_argop template. */
	cur_frontier_blend_samples          = __atomic_load_n(&shm->stats.frontier.plateau.blend_samples,         __ATOMIC_RELAXED);
	cur_frontier_blend_arm_a_children   = __atomic_load_n(&kcov_shm->cohorts.frontier_blend_arm_a_children,   __ATOMIC_RELAXED);
	cur_frontier_blend_arm_b_children   = __atomic_load_n(&kcov_shm->cohorts.frontier_blend_arm_b_children,   __ATOMIC_RELAXED);
	cur_remote_adaptive_samples         = __atomic_load_n(&shm->stats.remote_adaptive.samples,        __ATOMIC_RELAXED);
	cur_remote_adaptive_would_demote    = __atomic_load_n(&shm->stats.remote_adaptive.would_demote,   __ATOMIC_RELAXED);
	cur_remote_adaptive_would_promote   = __atomic_load_n(&shm->stats.remote_adaptive.would_promote,  __ATOMIC_RELAXED);
	cur_remote_adaptive_would_force     = __atomic_load_n(&shm->stats.remote_adaptive.would_force,    __ATOMIC_RELAXED);
	cur_remote_adaptive_would_gate_promote = __atomic_load_n(&shm->stats.remote_adaptive.would_gate_promote, __ATOMIC_RELAXED);
	cur_remote_adaptive_agree           = __atomic_load_n(&shm->stats.remote_adaptive.agree,          __ATOMIC_RELAXED);
	cur_remote_adaptive_arm_a_children  = __atomic_load_n(&kcov_shm->cohorts.remote_adaptive_arm_a_children,  __ATOMIC_RELAXED);
	cur_remote_adaptive_arm_b_children  = __atomic_load_n(&kcov_shm->cohorts.remote_adaptive_arm_b_children,  __ATOMIC_RELAXED);
	cur_arg_meta_addr_with_meta            = __atomic_load_n(&shm->stats.arg.meta_addr_with_meta,            __ATOMIC_RELAXED);
	cur_arg_meta_addr_without_meta         = __atomic_load_n(&shm->stats.arg.meta_addr_without_meta,         __ATOMIC_RELAXED);
	cur_arg_meta_argtype_stale             = __atomic_load_n(&shm->stats.arg.meta_argtype_stale,             __ATOMIC_RELAXED);
	cur_arg_meta_scrub_would_destroy_in    = __atomic_load_n(&shm->stats.arg.meta_scrub_would_destroy_in,    __ATOMIC_RELAXED);
	cur_arg_meta_scrub_would_preserve_out  = __atomic_load_n(&shm->stats.arg.meta_scrub_would_preserve_out,  __ATOMIC_RELAXED);
	cur_blanket_address_scrub_slots_walked = __atomic_load_n(&shm->stats.arg.blanket_address_scrub_slots_walked, __ATOMIC_RELAXED);
	/* SHADOW structure-aware picker A/B cohort + divergence counters live
	 * in minicorpus_shm rather than kcov_shm because the picker is a
	 * mutate_arg concern, not a kcov-cmp concern.  Guard the load so a
	 * degenerate run with kcov on but minicorpus unmapped does not chase
	 * a NULL pointer; the dump row's delta gate keeps a zero from
	 * polluting the kcov-cmp window output. */
	if (minicorpus_shm != NULL) {
		cur_mut_structured_shadow_samples     = __atomic_load_n(&minicorpus_shm->mut_structured_shadow_samples,     __ATOMIC_RELAXED);
		cur_mut_structured_shadow_divergences = __atomic_load_n(&minicorpus_shm->mut_structured_shadow_divergences, __ATOMIC_RELAXED);
		cur_mut_structured_arm_a_children     = __atomic_load_n(&minicorpus_shm->mut_structured_arm_a_children,     __ATOMIC_RELAXED);
		cur_mut_structured_arm_b_children     = __atomic_load_n(&minicorpus_shm->mut_structured_arm_b_children,     __ATOMIC_RELAXED);
	} else {
		cur_mut_structured_shadow_samples     = 0;
		cur_mut_structured_shadow_divergences = 0;
		cur_mut_structured_arm_a_children     = 0;
		cur_mut_structured_arm_b_children     = 0;
	}

	/* First call: arm the window so any pre-existing counts carried
	 * over from earlier in the run are not mis-attributed to the
	 * first window, mirroring periodic_counter_rates_dump. */
	if (last_dump.tv_sec == 0) {
		last_dump = now;
		prev_records       = cur_records;
		prev_truncated     = cur_truncated;
		prev_bloom_skipped = cur_bloom_skipped;
		prev_strip_skipped = cur_strip_skipped;
		prev_unique        = cur_unique;
		prev_try_get_attempts = cur_try_get_attempts;
		prev_try_get_returned = cur_try_get_returned;
		prev_injected         = cur_injected;
		prev_prop_injected    = cur_prop_injected;
		prev_chaos_suppressed = cur_chaos_suppressed;
		prev_count_oob        = cur_count_oob;
		prev_canary_lock_post = cur_canary_lock_post;
		prev_canary_pre       = cur_canary_pre;
		prev_canary_post      = cur_canary_post;
		prev_reexec_attempts                = cur_reexec_attempts;
		prev_reexec_attempts_with_new_cmp   = cur_reexec_attempts_with_new_cmp;
		prev_reexec_attribution_found       = cur_reexec_attribution_found;
		prev_reexec_attribution_ambiguous   = cur_reexec_attribution_ambiguous;
		prev_reexec_attribution_width_match = cur_reexec_attribution_width_match;
		prev_reexec_new_cmps_total          = cur_reexec_new_cmps_total;
		prev_reexec_new_edges_total         = cur_reexec_new_edges_total;
		prev_reexec_attempts_by_arm[0]      = cur_reexec_attempts_by_arm[0];
		prev_reexec_attempts_by_arm[1]      = cur_reexec_attempts_by_arm[1];
		prev_reexec_new_cmps_by_arm[0]      = cur_reexec_new_cmps_by_arm[0];
		prev_reexec_new_cmps_by_arm[1]      = cur_reexec_new_cmps_by_arm[1];
		prev_reexec_new_edges_by_arm[0]     = cur_reexec_new_edges_by_arm[0];
		prev_reexec_new_edges_by_arm[1]     = cur_reexec_new_edges_by_arm[1];
		prev_reexec_skipped_destructive     = cur_reexec_skipped_destructive;
		prev_reexec_skipped_validate_silent = cur_reexec_skipped_validate_silent;
		prev_reexec_window_cap_hit          = cur_reexec_window_cap_hit;
		prev_reexec_pending_dropped         = cur_reexec_pending_dropped;
		prev_reexec_gate_skip_in_reexec     = cur_reexec_gate_skip_in_reexec;
		prev_reexec_gate_skip_disabled      = cur_reexec_gate_skip_disabled;
		prev_reexec_gate_skip_mode          = cur_reexec_gate_skip_mode;
		prev_reexec_gate_skip_chain_mid     = cur_reexec_gate_skip_chain_mid;
		prev_reexec_gate_skip_no_new_cmp    = cur_reexec_gate_skip_no_new_cmp;
		prev_reexec_gate_skip_no_pending    = cur_reexec_gate_skip_no_pending;
		prev_reexec_gate_skip_rate          = cur_reexec_gate_skip_rate;
		prev_reexec_gate_pass               = cur_reexec_gate_pass;
		prev_cmp_parent_calls_enabled       = cur_cmp_parent_calls_enabled;
		prev_cmp_parent_calls_control       = cur_cmp_parent_calls_control;
		prev_cmp_parent_new_cmps_enabled    = cur_cmp_parent_new_cmps_enabled;
		prev_cmp_parent_new_cmps_control    = cur_cmp_parent_new_cmps_control;
		prev_save_reject_nonconst      = cur_save_reject_nonconst;
		prev_save_reject_uninteresting = cur_save_reject_uninteresting;
		prev_save_reject_sentinel      = cur_save_reject_sentinel;
		prev_save_reject_dup           = cur_save_reject_dup;
		prev_save_reject_cap           = cur_save_reject_cap;
		{
			unsigned int cs;
			for (cs = 0; cs < CMP_HINT_CALLSITE_NR; cs++) {
				prev_cmp_hint_callsite[cs] = cur_cmp_hint_callsite[cs];
				prev_cmp_hint_callsite_pc_wins[cs] =
					cur_cmp_hint_callsite_pc_wins[cs];
				prev_cmp_hint_callsite_misses[cs] =
					cur_cmp_hint_callsite_misses[cs];
			}
		}
		{
			unsigned int cs;
			for (cs = 0; cs < PROP_INJECTED_CALLSITE_NR; cs++)
				prev_prop_injected_callsite[cs] = cur_prop_injected_callsite[cs];
		}
		prev_cmp_hints_consumed             = cur_cmp_hints_consumed;
		prev_cmp_hint_wins                  = cur_cmp_hint_wins;
		prev_cmp_hint_misses                = cur_cmp_hint_misses;
		prev_cmp_hint_cmp_novelty_wins      = cur_cmp_hint_cmp_novelty_wins;
		prev_cmp_hint_stash_overflow        = cur_cmp_hint_stash_overflow;
		prev_cmp_hint_credit_entry_evicted  = cur_cmp_hint_credit_entry_evicted;
		prev_cmp_recent_inserts             = cur_cmp_recent_inserts;
		prev_cmp_recent_evicts              = cur_cmp_recent_evicts;
		prev_cmp_recent_would_pick          = cur_cmp_recent_would_pick;
		prev_cmp_recent_would_miss          = cur_cmp_recent_would_miss;
		prev_cmp_recent_live_picks          = cur_cmp_recent_live_picks;
		prev_cmp_inject_arm_a_baseline_fires = cur_cmp_inject_arm_a_baseline_fires;
		prev_cmp_inject_arm_b_baseline_fires = cur_cmp_inject_arm_b_baseline_fires;
		prev_cmp_inject_denom_diverged       = cur_cmp_inject_denom_diverged;
		prev_prop_ring_argop_arm_b_fires     = cur_prop_ring_argop_arm_b_fires;
		prev_frontier_blend_samples          = cur_frontier_blend_samples;
		prev_remote_adaptive_samples         = cur_remote_adaptive_samples;
		prev_mut_structured_shadow_divergences = cur_mut_structured_shadow_divergences;
		return;
	}

	elapsed = now.tv_sec - last_dump.tv_sec;
	if (elapsed < DEFENSE_DUMP_INTERVAL_SEC)
		return;

	delta_records       = sat_sub_ul(cur_records,       prev_records);
	delta_truncated     = sat_sub_ul(cur_truncated,     prev_truncated);
	delta_bloom_skipped = sat_sub_ul(cur_bloom_skipped, prev_bloom_skipped);
	delta_strip_skipped = sat_sub_ul(cur_strip_skipped, prev_strip_skipped);
	delta_unique        = sat_sub_ul(cur_unique,        prev_unique);
	delta_try_get_attempts = sat_sub_ul(cur_try_get_attempts, prev_try_get_attempts);
	delta_try_get_returned = sat_sub_ul(cur_try_get_returned, prev_try_get_returned);
	delta_injected         = sat_sub_ul(cur_injected,         prev_injected);
	delta_prop_injected    = sat_sub_ul(cur_prop_injected,    prev_prop_injected);
	delta_chaos_suppressed = sat_sub_ul(cur_chaos_suppressed, prev_chaos_suppressed);
	delta_count_oob        = sat_sub_ul(cur_count_oob,        prev_count_oob);
	delta_canary_lock_post = sat_sub_ul(cur_canary_lock_post, prev_canary_lock_post);
	delta_canary_pre       = sat_sub_ul(cur_canary_pre,       prev_canary_pre);
	delta_canary_post      = sat_sub_ul(cur_canary_post,      prev_canary_post);
	delta_reexec_attempts                = sat_sub_ul(cur_reexec_attempts,                prev_reexec_attempts);
	delta_reexec_attempts_with_new_cmp   = sat_sub_ul(cur_reexec_attempts_with_new_cmp,   prev_reexec_attempts_with_new_cmp);
	delta_reexec_attribution_found       = sat_sub_ul(cur_reexec_attribution_found,       prev_reexec_attribution_found);
	delta_reexec_attribution_ambiguous   = sat_sub_ul(cur_reexec_attribution_ambiguous,   prev_reexec_attribution_ambiguous);
	delta_reexec_attribution_width_match = sat_sub_ul(cur_reexec_attribution_width_match, prev_reexec_attribution_width_match);
	delta_reexec_new_cmps_total          = sat_sub_ul(cur_reexec_new_cmps_total,          prev_reexec_new_cmps_total);
	delta_reexec_new_edges_total         = sat_sub_ul(cur_reexec_new_edges_total,         prev_reexec_new_edges_total);
	delta_reexec_attempts_by_arm[0]      = sat_sub_ul(cur_reexec_attempts_by_arm[0],      prev_reexec_attempts_by_arm[0]);
	delta_reexec_attempts_by_arm[1]      = sat_sub_ul(cur_reexec_attempts_by_arm[1],      prev_reexec_attempts_by_arm[1]);
	delta_reexec_new_cmps_by_arm[0]      = sat_sub_ul(cur_reexec_new_cmps_by_arm[0],      prev_reexec_new_cmps_by_arm[0]);
	delta_reexec_new_cmps_by_arm[1]      = sat_sub_ul(cur_reexec_new_cmps_by_arm[1],      prev_reexec_new_cmps_by_arm[1]);
	delta_reexec_new_edges_by_arm[0]     = sat_sub_ul(cur_reexec_new_edges_by_arm[0],     prev_reexec_new_edges_by_arm[0]);
	delta_reexec_new_edges_by_arm[1]     = sat_sub_ul(cur_reexec_new_edges_by_arm[1],     prev_reexec_new_edges_by_arm[1]);
	delta_reexec_skipped_destructive     = sat_sub_ul(cur_reexec_skipped_destructive,     prev_reexec_skipped_destructive);
	delta_reexec_skipped_validate_silent = sat_sub_ul(cur_reexec_skipped_validate_silent, prev_reexec_skipped_validate_silent);
	delta_reexec_window_cap_hit          = sat_sub_ul(cur_reexec_window_cap_hit,          prev_reexec_window_cap_hit);
	delta_reexec_pending_dropped         = sat_sub_ul(cur_reexec_pending_dropped,         prev_reexec_pending_dropped);
	delta_reexec_gate_skip_in_reexec     = sat_sub_ul(cur_reexec_gate_skip_in_reexec,     prev_reexec_gate_skip_in_reexec);
	delta_reexec_gate_skip_disabled      = sat_sub_ul(cur_reexec_gate_skip_disabled,      prev_reexec_gate_skip_disabled);
	delta_reexec_gate_skip_mode          = sat_sub_ul(cur_reexec_gate_skip_mode,          prev_reexec_gate_skip_mode);
	delta_reexec_gate_skip_chain_mid     = sat_sub_ul(cur_reexec_gate_skip_chain_mid,     prev_reexec_gate_skip_chain_mid);
	delta_reexec_gate_skip_no_new_cmp    = sat_sub_ul(cur_reexec_gate_skip_no_new_cmp,    prev_reexec_gate_skip_no_new_cmp);
	delta_reexec_gate_skip_no_pending    = sat_sub_ul(cur_reexec_gate_skip_no_pending,    prev_reexec_gate_skip_no_pending);
	delta_reexec_gate_skip_rate          = sat_sub_ul(cur_reexec_gate_skip_rate,          prev_reexec_gate_skip_rate);
	delta_reexec_gate_pass               = sat_sub_ul(cur_reexec_gate_pass,               prev_reexec_gate_pass);
	delta_cmp_parent_calls_enabled       = sat_sub_ul(cur_cmp_parent_calls_enabled,       prev_cmp_parent_calls_enabled);
	delta_cmp_parent_calls_control       = sat_sub_ul(cur_cmp_parent_calls_control,       prev_cmp_parent_calls_control);
	delta_cmp_parent_new_cmps_enabled    = sat_sub_ul(cur_cmp_parent_new_cmps_enabled,    prev_cmp_parent_new_cmps_enabled);
	delta_cmp_parent_new_cmps_control    = sat_sub_ul(cur_cmp_parent_new_cmps_control,    prev_cmp_parent_new_cmps_control);
	delta_save_reject_nonconst      = sat_sub_ul(cur_save_reject_nonconst,      prev_save_reject_nonconst);
	delta_save_reject_uninteresting = sat_sub_ul(cur_save_reject_uninteresting, prev_save_reject_uninteresting);
	delta_save_reject_sentinel      = sat_sub_ul(cur_save_reject_sentinel,      prev_save_reject_sentinel);
	delta_save_reject_dup           = sat_sub_ul(cur_save_reject_dup,           prev_save_reject_dup);
	delta_save_reject_cap           = sat_sub_ul(cur_save_reject_cap,           prev_save_reject_cap);
	{
		unsigned int cs;
		for (cs = 0; cs < CMP_HINT_CALLSITE_NR; cs++) {
			delta_cmp_hint_callsite[cs] =
				sat_sub_ul(cur_cmp_hint_callsite[cs], prev_cmp_hint_callsite[cs]);
			if (delta_cmp_hint_callsite[cs] != 0)
				any_callsite_delta = true;
			delta_cmp_hint_callsite_pc_wins[cs] =
				sat_sub_ul(cur_cmp_hint_callsite_pc_wins[cs],
					   prev_cmp_hint_callsite_pc_wins[cs]);
			delta_cmp_hint_callsite_misses[cs] =
				sat_sub_ul(cur_cmp_hint_callsite_misses[cs],
					   prev_cmp_hint_callsite_misses[cs]);
			if (delta_cmp_hint_callsite_pc_wins[cs] != 0 ||
			    delta_cmp_hint_callsite_misses[cs] != 0)
				any_callsite_wins_delta = true;
		}
	}
	{
		unsigned int cs;
		for (cs = 0; cs < PROP_INJECTED_CALLSITE_NR; cs++) {
			delta_prop_injected_callsite[cs] =
				sat_sub_ul(cur_prop_injected_callsite[cs], prev_prop_injected_callsite[cs]);
			if (delta_prop_injected_callsite[cs] != 0)
				any_prop_callsite_delta = true;
		}
	}
	delta_cmp_hints_consumed             = sat_sub_ul(cur_cmp_hints_consumed,             prev_cmp_hints_consumed);
	delta_cmp_hint_wins                  = sat_sub_ul(cur_cmp_hint_wins,                  prev_cmp_hint_wins);
	delta_cmp_hint_misses                = sat_sub_ul(cur_cmp_hint_misses,                prev_cmp_hint_misses);
	delta_cmp_hint_cmp_novelty_wins      = sat_sub_ul(cur_cmp_hint_cmp_novelty_wins,      prev_cmp_hint_cmp_novelty_wins);
	delta_cmp_hint_stash_overflow        = sat_sub_ul(cur_cmp_hint_stash_overflow,        prev_cmp_hint_stash_overflow);
	delta_cmp_hint_credit_entry_evicted  = sat_sub_ul(cur_cmp_hint_credit_entry_evicted,  prev_cmp_hint_credit_entry_evicted);
	delta_cmp_recent_inserts             = sat_sub_ul(cur_cmp_recent_inserts,             prev_cmp_recent_inserts);
	delta_cmp_recent_evicts              = sat_sub_ul(cur_cmp_recent_evicts,              prev_cmp_recent_evicts);
	delta_cmp_recent_would_pick          = sat_sub_ul(cur_cmp_recent_would_pick,          prev_cmp_recent_would_pick);
	delta_cmp_recent_would_miss          = sat_sub_ul(cur_cmp_recent_would_miss,          prev_cmp_recent_would_miss);
	delta_cmp_recent_live_picks          = sat_sub_ul(cur_cmp_recent_live_picks,          prev_cmp_recent_live_picks);
	delta_cmp_inject_arm_a_baseline_fires = sat_sub_ul(cur_cmp_inject_arm_a_baseline_fires, prev_cmp_inject_arm_a_baseline_fires);
	delta_cmp_inject_arm_b_baseline_fires = sat_sub_ul(cur_cmp_inject_arm_b_baseline_fires, prev_cmp_inject_arm_b_baseline_fires);
	delta_cmp_inject_denom_diverged       = sat_sub_ul(cur_cmp_inject_denom_diverged,       prev_cmp_inject_denom_diverged);
	delta_prop_ring_argop_arm_b_fires     = sat_sub_ul(cur_prop_ring_argop_arm_b_fires,     prev_prop_ring_argop_arm_b_fires);
	delta_frontier_blend_samples          = sat_sub_ul(cur_frontier_blend_samples,          prev_frontier_blend_samples);
	delta_remote_adaptive_samples         = sat_sub_ul(cur_remote_adaptive_samples,         prev_remote_adaptive_samples);
	delta_mut_structured_shadow_divergences = sat_sub_ul(cur_mut_structured_shadow_divergences, prev_mut_structured_shadow_divergences);

	if ((delta_records | delta_truncated | delta_bloom_skipped | delta_strip_skipped |
	     delta_unique | delta_try_get_attempts | delta_try_get_returned |
	     delta_injected | delta_prop_injected |
	     delta_chaos_suppressed | delta_count_oob |
	     delta_canary_lock_post |
	     delta_canary_pre | delta_canary_post |
	     delta_reexec_attempts | delta_reexec_attempts_with_new_cmp |
	     delta_reexec_attribution_found |
	     delta_reexec_attribution_ambiguous | delta_reexec_attribution_width_match |
	     delta_reexec_new_cmps_total |
	     delta_reexec_new_edges_total |
	     delta_reexec_attempts_by_arm[0] | delta_reexec_attempts_by_arm[1] |
	     delta_reexec_new_cmps_by_arm[0] | delta_reexec_new_cmps_by_arm[1] |
	     delta_reexec_new_edges_by_arm[0] | delta_reexec_new_edges_by_arm[1] |
	     delta_reexec_skipped_destructive | delta_reexec_skipped_validate_silent |
	     delta_reexec_window_cap_hit | delta_reexec_pending_dropped |
	     delta_reexec_gate_skip_in_reexec | delta_reexec_gate_skip_disabled |
	     delta_reexec_gate_skip_mode | delta_reexec_gate_skip_chain_mid |
	     delta_reexec_gate_skip_no_new_cmp | delta_reexec_gate_skip_no_pending |
	     delta_reexec_gate_skip_rate | delta_reexec_gate_pass |
	     delta_cmp_parent_calls_enabled | delta_cmp_parent_calls_control |
	     delta_cmp_parent_new_cmps_enabled | delta_cmp_parent_new_cmps_control |
	     delta_save_reject_nonconst | delta_save_reject_uninteresting |
	     delta_save_reject_sentinel | delta_save_reject_dup |
	     delta_save_reject_cap |
	     delta_cmp_hints_consumed | delta_cmp_hint_wins | delta_cmp_hint_misses |
	     delta_cmp_hint_cmp_novelty_wins | delta_cmp_hint_stash_overflow |
	     delta_cmp_hint_credit_entry_evicted |
	     delta_cmp_recent_inserts | delta_cmp_recent_evicts |
	     delta_cmp_recent_would_pick | delta_cmp_recent_would_miss |
	     delta_cmp_recent_live_picks |
	     delta_cmp_inject_arm_a_baseline_fires |
	     delta_cmp_inject_arm_b_baseline_fires |
	     delta_cmp_inject_denom_diverged |
	     delta_prop_ring_argop_arm_b_fires |
	     delta_remote_adaptive_samples |
	     delta_mut_structured_shadow_divergences) != 0 ||
	    any_callsite_delta || any_callsite_wins_delta ||
	    any_prop_callsite_delta) {
		stats_log_write("KCOV CMP stats over last %lds:\n", elapsed);

		kcov_cmp_rate_line(elapsed, "cmp_records_collected", delta_records, cur_records);
		kcov_cmp_rate_line(elapsed, "cmp_trace_truncated", delta_truncated, cur_truncated);
		kcov_cmp_rate_line(elapsed, "cmp_hints_bloom_skipped", delta_bloom_skipped, cur_bloom_skipped);
		kcov_cmp_rate_line(elapsed, "cmp_hints_strip_skipped", delta_strip_skipped, cur_strip_skipped);
		kcov_cmp_rate_line(elapsed, "cmp_hints_unique_inserts", delta_unique, cur_unique);
		kcov_cmp_rate_line(elapsed, "cmp_hints_save_reject_nonconst", delta_save_reject_nonconst, cur_save_reject_nonconst);
		kcov_cmp_rate_line(elapsed, "cmp_hints_save_reject_uninteresting", delta_save_reject_uninteresting, cur_save_reject_uninteresting);
		kcov_cmp_rate_line(elapsed, "cmp_hints_save_reject_sentinel", delta_save_reject_sentinel, cur_save_reject_sentinel);
		kcov_cmp_rate_line(elapsed, "cmp_hints_save_reject_dup", delta_save_reject_dup, cur_save_reject_dup);
		kcov_cmp_rate_line(elapsed, "cmp_hints_save_reject_cap", delta_save_reject_cap, cur_save_reject_cap);
		kcov_cmp_rate_line(elapsed, "cmp_hints_try_get_attempts", delta_try_get_attempts, cur_try_get_attempts);
		kcov_cmp_rate_line(elapsed, "cmp_hints_try_get_returned", delta_try_get_returned, cur_try_get_returned);
		kcov_cmp_rate_line(elapsed, "cmp_hints_injected", delta_injected, cur_injected);
		kcov_cmp_rate_line(elapsed, "propagation_injected", delta_prop_injected, cur_prop_injected);
		if (delta_chaos_suppressed) {
			unsigned long rate_milli = (delta_chaos_suppressed * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu, chaos_active=%d)\n",
					"cmp_hints_chaos_suppressed", delta_chaos_suppressed,
					rate_milli / 1000, rate_milli % 1000, cur_chaos_suppressed,
					cmp_hints_chaos_query() ? 1 : 0);
		}
		kcov_cmp_render_wild_write_delta(elapsed,
						 delta_count_oob, cur_count_oob,
						 delta_canary_lock_post, cur_canary_lock_post,
						 delta_canary_pre, cur_canary_pre,
						 delta_canary_post, cur_canary_post);
		kcov_cmp_rate_line(elapsed, "reexec_attempts", delta_reexec_attempts, cur_reexec_attempts);
		kcov_cmp_rate_line(elapsed, "reexec_attempts_with_new_cmp", delta_reexec_attempts_with_new_cmp, cur_reexec_attempts_with_new_cmp);
		kcov_cmp_rate_line(elapsed, "reexec_attribution_found", delta_reexec_attribution_found, cur_reexec_attribution_found);
		kcov_cmp_rate_line(elapsed, "reexec_attribution_ambiguous", delta_reexec_attribution_ambiguous, cur_reexec_attribution_ambiguous);
		kcov_cmp_rate_line(elapsed, "reexec_attribution_width_match", delta_reexec_attribution_width_match, cur_reexec_attribution_width_match);
		kcov_cmp_rate_line(elapsed, "reexec_new_cmps_total", delta_reexec_new_cmps_total, cur_reexec_new_cmps_total);
		kcov_cmp_rate_line(elapsed, "reexec_new_edges_total", delta_reexec_new_edges_total, cur_reexec_new_edges_total);
		/* Plateau-burst per-call drain-cap A/B cohort split.  Renders
		 * arm-A (control, drain-all baseline) and arm-B (measure,
		 * capped at REDQUEEN_REEXEC_BURST_DRAIN during plateau) side-
		 * by-side so the shadow success criterion
		 *   (edges/attempt B) >= (edges/attempt A)
		 * can be read directly off the periodic dump.  Attempts are
		 * the denominator across both novelty axes; the block only
		 * fires when at least one arm bumped an attempt this window
		 * to keep the render quiet under CMP-off / non-plateau runs. */
		if (delta_reexec_attempts_by_arm[0] |
		    delta_reexec_attempts_by_arm[1] |
		    delta_reexec_new_cmps_by_arm[0] |
		    delta_reexec_new_cmps_by_arm[1] |
		    delta_reexec_new_edges_by_arm[0] |
		    delta_reexec_new_edges_by_arm[1]) {
			stats_log_write("  reexec burst_drain_arm cohort (A=drain-all, B=drain<=%u during plateau):\n",
					REDQUEEN_REEXEC_BURST_DRAIN);
			stats_log_write("    %-20s A +%lu (total %lu)   B +%lu (total %lu)\n",
					"attempts_by_arm",
					delta_reexec_attempts_by_arm[0],
					cur_reexec_attempts_by_arm[0],
					delta_reexec_attempts_by_arm[1],
					cur_reexec_attempts_by_arm[1]);
			stats_log_write("    %-20s A +%lu (total %lu)   B +%lu (total %lu)\n",
					"new_cmps_by_arm",
					delta_reexec_new_cmps_by_arm[0],
					cur_reexec_new_cmps_by_arm[0],
					delta_reexec_new_cmps_by_arm[1],
					cur_reexec_new_cmps_by_arm[1]);
			stats_log_write("    %-20s A +%lu (total %lu)   B +%lu (total %lu)\n",
					"new_edges_by_arm",
					delta_reexec_new_edges_by_arm[0],
					cur_reexec_new_edges_by_arm[0],
					delta_reexec_new_edges_by_arm[1],
					cur_reexec_new_edges_by_arm[1]);
		}
		kcov_cmp_rate_line(elapsed, "reexec_skipped_destructive", delta_reexec_skipped_destructive, cur_reexec_skipped_destructive);
		kcov_cmp_rate_line(elapsed, "reexec_skipped_validate_silent", delta_reexec_skipped_validate_silent, cur_reexec_skipped_validate_silent);
		kcov_cmp_rate_line(elapsed, "reexec_window_cap_hit", delta_reexec_window_cap_hit, cur_reexec_window_cap_hit);
		kcov_cmp_rate_line(elapsed, "reexec_pending_dropped", delta_reexec_pending_dropped, cur_reexec_pending_dropped);
		kcov_cmp_render_reexec_skip_reason_breakdown(elapsed,
							     delta_reexec_gate_skip_in_reexec, cur_reexec_gate_skip_in_reexec,
							     delta_reexec_gate_skip_disabled, cur_reexec_gate_skip_disabled,
							     delta_reexec_gate_skip_mode, cur_reexec_gate_skip_mode,
							     delta_reexec_gate_skip_chain_mid, cur_reexec_gate_skip_chain_mid,
							     delta_reexec_gate_skip_no_new_cmp, cur_reexec_gate_skip_no_new_cmp,
							     delta_reexec_gate_skip_no_pending, cur_reexec_gate_skip_no_pending,
							     delta_reexec_gate_skip_rate, cur_reexec_gate_skip_rate,
							     delta_reexec_gate_pass, cur_reexec_gate_pass);
		kcov_cmp_rate_line(elapsed, "cmp_parent_calls_enabled", delta_cmp_parent_calls_enabled, cur_cmp_parent_calls_enabled);
		kcov_cmp_rate_line(elapsed, "cmp_parent_calls_control", delta_cmp_parent_calls_control, cur_cmp_parent_calls_control);
		kcov_cmp_rate_line(elapsed, "cmp_parent_new_cmps_enabled", delta_cmp_parent_new_cmps_enabled, cur_cmp_parent_new_cmps_enabled);
		kcov_cmp_rate_line(elapsed, "cmp_parent_new_cmps_control", delta_cmp_parent_new_cmps_control, cur_cmp_parent_new_cmps_control);
		if (any_callsite_delta || any_callsite_wins_delta) {
			static const char * const callsite_names[CMP_HINT_CALLSITE_NR] = {
				[CMP_HINT_CALLSITE_ARG_OP]          = "ARG_OP",
				[CMP_HINT_CALLSITE_ARG_LIST]        = "ARG_LIST",
				[CMP_HINT_CALLSITE_ARG_UNDEFINED]   = "ARG_UNDEFINED",
				[CMP_HINT_CALLSITE_ARG_STRUCT_SIZE] = "ARG_STRUCT_SIZE",
				[CMP_HINT_CALLSITE_STRUCT_FIELD]    = "STRUCT_FIELD",
				[CMP_HINT_CALLSITE_OTHER]           = "OTHER",
				[CMP_HINT_CALLSITE_ARG_RANGE]       = "ARG_RANGE",
			};
			unsigned int cs;

			if (any_callsite_delta) {
				stats_log_write("  cmp_hint_callsite_injected (per-callsite delta / cumulative):\n");
				for (cs = 0; cs < CMP_HINT_CALLSITE_NR; cs++) {
					if (delta_cmp_hint_callsite[cs] == 0 &&
					    cur_cmp_hint_callsite[cs] == 0)
						continue;
					stats_log_write("    %-20s +%lu  (total %lu)\n",
							callsite_names[cs],
							delta_cmp_hint_callsite[cs],
							cur_cmp_hint_callsite[cs]);
				}
			}
			/* PC-mode WIN/MISS partition by callsite -- sibling of
			 * the injected split above.  Field-pool pulls (stamped
			 * CMP_HINT_CALLSITE_NR) are not attributed here, so
			 * sum(pc_wins/misses) can be less than the flat
			 * cmp_hint_wins / cmp_hint_misses. */
			if (any_callsite_wins_delta) {
				stats_log_write("  cmp_hint_callsite_pc_wins/_misses (per-callsite PC-mode outcome delta / cumulative):\n");
				for (cs = 0; cs < CMP_HINT_CALLSITE_NR; cs++) {
					if (delta_cmp_hint_callsite_pc_wins[cs] == 0 &&
					    delta_cmp_hint_callsite_misses[cs] == 0 &&
					    cur_cmp_hint_callsite_pc_wins[cs] == 0 &&
					    cur_cmp_hint_callsite_misses[cs] == 0)
						continue;
					stats_log_write("    %-20s wins +%lu (total %lu)  misses +%lu (total %lu)\n",
							callsite_names[cs],
							delta_cmp_hint_callsite_pc_wins[cs],
							cur_cmp_hint_callsite_pc_wins[cs],
							delta_cmp_hint_callsite_misses[cs],
							cur_cmp_hint_callsite_misses[cs]);
				}
			}
		}
		if (any_prop_callsite_delta) {
			static const char * const prop_callsite_names[PROP_INJECTED_CALLSITE_NR] = {
				[PROP_INJECTED_CALLSITE_ARG_OP]        = "ARG_OP",
				[PROP_INJECTED_CALLSITE_ARG_UNDEFINED] = "ARG_UNDEFINED",
			};
			unsigned int cs;

			stats_log_write("  propagation_injected_callsite (per-callsite delta / cumulative):\n");
			for (cs = 0; cs < PROP_INJECTED_CALLSITE_NR; cs++) {
				if (delta_prop_injected_callsite[cs] == 0 &&
				    cur_prop_injected_callsite[cs] == 0)
					continue;
				stats_log_write("    %-20s +%lu  (total %lu)\n",
						prop_callsite_names[cs],
						delta_prop_injected_callsite[cs],
						cur_prop_injected_callsite[cs]);
			}
		}
		kcov_cmp_render_per_entry_feedback_scoring(elapsed,
							   delta_cmp_hints_consumed, cur_cmp_hints_consumed,
							   delta_cmp_hint_wins, cur_cmp_hint_wins,
							   delta_cmp_hint_misses, cur_cmp_hint_misses,
							   delta_cmp_hint_cmp_novelty_wins, cur_cmp_hint_cmp_novelty_wins,
							   delta_cmp_hint_stash_overflow, cur_cmp_hint_stash_overflow,
							   delta_cmp_hint_credit_entry_evicted, cur_cmp_hint_credit_entry_evicted);
		kcov_cmp_render_recent_cmp_pool_tier(elapsed,
						     delta_cmp_recent_inserts, cur_cmp_recent_inserts,
						     delta_cmp_recent_evicts, cur_cmp_recent_evicts,
						     delta_cmp_recent_would_pick, cur_cmp_recent_would_pick,
						     delta_cmp_recent_would_miss, cur_cmp_recent_would_miss,
						     delta_cmp_recent_live_picks, cur_cmp_recent_live_picks);
		kcov_cmp_render_ab_baseline_inject_denom(elapsed,
							 delta_cmp_inject_arm_a_baseline_fires, cur_cmp_inject_arm_a_baseline_fires,
							 delta_cmp_inject_arm_b_baseline_fires, cur_cmp_inject_arm_b_baseline_fires,
							 delta_cmp_inject_denom_diverged, cur_cmp_inject_denom_diverged,
							 cur_cmp_inject_arm_a_children,
							 cur_cmp_inject_arm_b_children);
		kcov_cmp_render_handle_arg_op_prop_ring_cohort(elapsed,
							       delta_prop_ring_argop_arm_b_fires,
							       cur_prop_ring_argop_arm_b_fires,
							       cur_prop_ring_argop_arm_a_children,
							       cur_prop_ring_argop_arm_b_children);
		kcov_cmp_render_frontier_cold_weight_blend_cohort(elapsed,
								  delta_frontier_blend_samples,
								  cur_frontier_blend_samples,
								  cur_frontier_blend_arm_a_children,
								  cur_frontier_blend_arm_b_children);
		kcov_cmp_render_adaptive_remote_kcov_cohort(elapsed,
							    delta_remote_adaptive_samples,
							    cur_remote_adaptive_samples,
							    cur_remote_adaptive_arm_a_children,
							    cur_remote_adaptive_arm_b_children,
							    cur_remote_adaptive_would_demote,
							    cur_remote_adaptive_would_promote,
							    cur_remote_adaptive_would_force,
							    cur_remote_adaptive_would_gate_promote,
							    cur_remote_adaptive_agree);
		kcov_cmp_render_per_arg_ownership_sidecar(cur_blanket_address_scrub_slots_walked,
							  cur_arg_meta_addr_with_meta,
							  cur_arg_meta_addr_without_meta,
							  cur_arg_meta_argtype_stale,
							  cur_arg_meta_scrub_would_destroy_in,
							  cur_arg_meta_scrub_would_preserve_out);
		kcov_cmp_render_structure_aware_picker_cohort(elapsed,
							      delta_mut_structured_shadow_divergences,
							      cur_mut_structured_shadow_divergences,
							      cur_mut_structured_shadow_samples,
							      cur_mut_structured_arm_a_children,
							      cur_mut_structured_arm_b_children);
	}

	kcov_cmp_render_hyp_shadow_stats_block(elapsed);

	kcov_cmp_render_hyp_would_pick_block(elapsed);

	kcov_cmp_render_childop_cmp_consume_shadow_block(elapsed);

	kcov_cmp_render_hyp_live_inject_block(elapsed);

	kcov_cmp_render_hyp_live_inject_reasons_block(elapsed);

	kcov_cmp_render_hyp_boundary_scorecard_block(elapsed);

	kcov_cmp_render_hyp_would_promote_demote_block(elapsed);

	kcov_cmp_render_hyp_score_bucket_block(elapsed);

	kcov_cmp_render_hyp_probe_class_hist_block(elapsed);

	kcov_cmp_render_hyp_per_hypothesis_aggregates_block(elapsed);

	/*
	 * Standalone grep-friendly cumulative lines for counters whose only
	 * stat output above is delta-gated (skipped at zero) and whose bare
	 * tokens recur in narrative -- JSON dumps, header comments, atomic
	 * fetch sites -- so `grep -c <counter>` against a long-running log
	 * counts narrative occurrences rather than the counter, the same
	 * triage trap post_handler_corrupt_ptr_cumulative was added to
	 * close.  Emit one line per dump window per counter (even at zero
	 * so trend tracking has a t=0 anchor) with a distinctive
	 * _cumulative suffix; operators can `grep <counter>_cumulative
	 * out.log | tail -1` for the current total or grep -c the suffix
	 * to count windows.  Placed outside the delta-gated block above so
	 * they fire every window regardless of cmp activity.
	 */
	output(0, "[main] cmp_hints_chaos_suppressed_cumulative=%lu\n",
	       cur_chaos_suppressed);
	output(0, "[main] propagation_injected_cumulative=%lu\n",
	       cur_prop_injected);

	kcov_cmp_render_modes_block();

	kcov_cmp_render_diag_errnos_block();

	kcov_cmp_render_pc_diag_block();

	kcov_cmp_observability_block_render(elapsed);
	kcov_redqueen_observability_block_render(elapsed);
	kcov_cmp_oldpool_vs_shadow_block_render(elapsed);
	kcov_cmp_render_pc_win_conversion_split_block(elapsed);
	kcov_cmp_hyp_saturation_block_render(elapsed);

	prev_records       = cur_records;
	prev_truncated     = cur_truncated;
	prev_bloom_skipped = cur_bloom_skipped;
	prev_strip_skipped = cur_strip_skipped;
	prev_unique        = cur_unique;
	prev_try_get_attempts = cur_try_get_attempts;
	prev_try_get_returned = cur_try_get_returned;
	prev_injected         = cur_injected;
	prev_prop_injected    = cur_prop_injected;
	prev_chaos_suppressed = cur_chaos_suppressed;
	prev_count_oob        = cur_count_oob;
	prev_canary_lock_post = cur_canary_lock_post;
	prev_canary_pre       = cur_canary_pre;
	prev_canary_post      = cur_canary_post;
	prev_reexec_attempts                = cur_reexec_attempts;
	prev_reexec_attempts_with_new_cmp   = cur_reexec_attempts_with_new_cmp;
	prev_reexec_attribution_found       = cur_reexec_attribution_found;
	prev_reexec_attribution_ambiguous   = cur_reexec_attribution_ambiguous;
	prev_reexec_attribution_width_match = cur_reexec_attribution_width_match;
	prev_reexec_new_cmps_total          = cur_reexec_new_cmps_total;
	prev_reexec_new_edges_total         = cur_reexec_new_edges_total;
	prev_reexec_attempts_by_arm[0]      = cur_reexec_attempts_by_arm[0];
	prev_reexec_attempts_by_arm[1]      = cur_reexec_attempts_by_arm[1];
	prev_reexec_new_cmps_by_arm[0]      = cur_reexec_new_cmps_by_arm[0];
	prev_reexec_new_cmps_by_arm[1]      = cur_reexec_new_cmps_by_arm[1];
	prev_reexec_new_edges_by_arm[0]     = cur_reexec_new_edges_by_arm[0];
	prev_reexec_new_edges_by_arm[1]     = cur_reexec_new_edges_by_arm[1];
	{
		unsigned int cs;
		for (cs = 0; cs < PROP_INJECTED_CALLSITE_NR; cs++)
			prev_prop_injected_callsite[cs] = cur_prop_injected_callsite[cs];
	}
	prev_reexec_skipped_destructive     = cur_reexec_skipped_destructive;
	prev_reexec_skipped_validate_silent = cur_reexec_skipped_validate_silent;
	prev_reexec_window_cap_hit          = cur_reexec_window_cap_hit;
	prev_reexec_pending_dropped         = cur_reexec_pending_dropped;
	prev_reexec_gate_skip_in_reexec     = cur_reexec_gate_skip_in_reexec;
	prev_reexec_gate_skip_disabled      = cur_reexec_gate_skip_disabled;
	prev_reexec_gate_skip_mode          = cur_reexec_gate_skip_mode;
	prev_reexec_gate_skip_chain_mid     = cur_reexec_gate_skip_chain_mid;
	prev_reexec_gate_skip_no_new_cmp    = cur_reexec_gate_skip_no_new_cmp;
	prev_reexec_gate_skip_no_pending    = cur_reexec_gate_skip_no_pending;
	prev_reexec_gate_skip_rate          = cur_reexec_gate_skip_rate;
	prev_reexec_gate_pass               = cur_reexec_gate_pass;
	prev_cmp_parent_calls_enabled       = cur_cmp_parent_calls_enabled;
	prev_cmp_parent_calls_control       = cur_cmp_parent_calls_control;
	prev_cmp_parent_new_cmps_enabled    = cur_cmp_parent_new_cmps_enabled;
	prev_cmp_parent_new_cmps_control    = cur_cmp_parent_new_cmps_control;
	prev_save_reject_nonconst      = cur_save_reject_nonconst;
	prev_save_reject_uninteresting = cur_save_reject_uninteresting;
	prev_save_reject_sentinel      = cur_save_reject_sentinel;
	prev_save_reject_dup           = cur_save_reject_dup;
	prev_save_reject_cap           = cur_save_reject_cap;
	{
		unsigned int cs;
		for (cs = 0; cs < CMP_HINT_CALLSITE_NR; cs++) {
			prev_cmp_hint_callsite[cs] = cur_cmp_hint_callsite[cs];
			prev_cmp_hint_callsite_pc_wins[cs] =
				cur_cmp_hint_callsite_pc_wins[cs];
			prev_cmp_hint_callsite_misses[cs] =
				cur_cmp_hint_callsite_misses[cs];
		}
	}
	prev_cmp_hints_consumed             = cur_cmp_hints_consumed;
	prev_cmp_hint_wins                  = cur_cmp_hint_wins;
	prev_cmp_hint_misses                = cur_cmp_hint_misses;
	prev_cmp_hint_cmp_novelty_wins      = cur_cmp_hint_cmp_novelty_wins;
	prev_cmp_hint_stash_overflow        = cur_cmp_hint_stash_overflow;
	prev_cmp_hint_credit_entry_evicted  = cur_cmp_hint_credit_entry_evicted;
	prev_cmp_recent_inserts             = cur_cmp_recent_inserts;
	prev_cmp_recent_evicts              = cur_cmp_recent_evicts;
	prev_cmp_recent_would_pick          = cur_cmp_recent_would_pick;
	prev_cmp_recent_would_miss          = cur_cmp_recent_would_miss;
	prev_cmp_recent_live_picks          = cur_cmp_recent_live_picks;
	prev_cmp_inject_arm_a_baseline_fires = cur_cmp_inject_arm_a_baseline_fires;
	prev_cmp_inject_arm_b_baseline_fires = cur_cmp_inject_arm_b_baseline_fires;
	prev_cmp_inject_denom_diverged       = cur_cmp_inject_denom_diverged;
	prev_prop_ring_argop_arm_b_fires     = cur_prop_ring_argop_arm_b_fires;
	prev_frontier_blend_samples          = cur_frontier_blend_samples;
	prev_remote_adaptive_samples         = cur_remote_adaptive_samples;
	prev_mut_structured_shadow_divergences = cur_mut_structured_shadow_divergences;
	last_dump = now;
}
