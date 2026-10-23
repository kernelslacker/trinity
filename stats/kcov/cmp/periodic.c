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
 * The window state is gathered into struct cmp_window (the counters the
 * dump differences) and struct cmp_levels (the values it prints as they
 * stand), both local to this TU.  The plain rate lines are listed in the
 * rate-row tables; the rest of the fan-out is the render helpers in their
 * per-domain siblings declared in stats/kcov/cmp/internal.h, plus the
 * burst-drain and callsite blocks, which no sibling owns: static helpers
 * above the entry point that take their counters as explicit arguments.
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

#include "stats/kcov/cmp/internal.h"

static void kcov_cmp_render_reexec_burst_drain_cohort(const unsigned long delta_reexec_attempts_by_arm[2],
						      const unsigned long cur_reexec_attempts_by_arm[2],
						      const unsigned long delta_reexec_new_cmps_by_arm[2],
						      const unsigned long cur_reexec_new_cmps_by_arm[2],
						      const unsigned long delta_reexec_new_edges_by_arm[2],
						      const unsigned long cur_reexec_new_edges_by_arm[2])
{
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
}

static void kcov_cmp_render_cmp_hint_callsites(bool any_callsite_delta, bool any_callsite_wins_delta,
					       const unsigned long delta_cmp_hint_callsite[CMP_HINT_CALLSITE_NR],
					       const unsigned long cur_cmp_hint_callsite[CMP_HINT_CALLSITE_NR],
					       const unsigned long delta_cmp_hint_callsite_pc_wins[CMP_HINT_CALLSITE_NR],
					       const unsigned long cur_cmp_hint_callsite_pc_wins[CMP_HINT_CALLSITE_NR],
					       const unsigned long delta_cmp_hint_callsite_misses[CMP_HINT_CALLSITE_NR],
					       const unsigned long cur_cmp_hint_callsite_misses[CMP_HINT_CALLSITE_NR])
{
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
		 * the injected split above.  Stash entries clamped to
		 * CMP_HINT_CALLSITE_NR are not attributed here, so
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
}

static void kcov_cmp_render_prop_injected_callsite(bool any_prop_callsite_delta,
						   const unsigned long delta_prop_injected_callsite[PROP_INJECTED_CALLSITE_NR],
						   const unsigned long cur_prop_injected_callsite[PROP_INJECTED_CALLSITE_NR])
{
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
}

/*
 * The counters the dump differences from one window to the next.  The
 * current snapshot, the previous one and the delta share this shape, so
 * arming and committing a window are struct copies.  Every member is an
 * unsigned long, so a window also reads as an array of words: the delta
 * is one subtraction per word and the any-delta gate one scan over all
 * of them, wherever a member sits in the struct.
 */
struct cmp_window {
	unsigned long records, truncated, bloom_skipped, strip_skipped, unique;
	unsigned long try_get_attempts, try_get_returned, injected, prop_injected;
	unsigned long chaos_suppressed;
	unsigned long count_oob, canary_lock_post, canary_pre, canary_post;
	unsigned long reexec_attempts, reexec_attempts_with_new_cmp;
	unsigned long reexec_attribution_found, reexec_attribution_ambiguous;
	unsigned long reexec_attribution_width_match;
	unsigned long reexec_new_cmps_total, reexec_new_edges_total;
	unsigned long reexec_attempts_by_arm[2];
	unsigned long reexec_new_cmps_by_arm[2];
	unsigned long reexec_new_edges_by_arm[2];
	unsigned long reexec_skipped_destructive, reexec_skipped_validate_silent;
	unsigned long reexec_window_cap_hit, reexec_pending_dropped;
	unsigned long reexec_gate_skip_in_reexec, reexec_gate_skip_disabled;
	unsigned long reexec_gate_skip_mode, reexec_gate_skip_chain_mid;
	unsigned long reexec_gate_skip_no_new_cmp, reexec_gate_skip_no_pending;
	unsigned long reexec_gate_skip_rate, reexec_gate_pass;
	unsigned long cmp_parent_calls_enabled, cmp_parent_calls_control;
	unsigned long cmp_parent_new_cmps_enabled, cmp_parent_new_cmps_control;
	unsigned long cmp_hint_callsite[CMP_HINT_CALLSITE_NR];
	unsigned long cmp_hint_callsite_pc_wins[CMP_HINT_CALLSITE_NR];
	unsigned long cmp_hint_callsite_misses[CMP_HINT_CALLSITE_NR];
	unsigned long prop_injected_callsite[PROP_INJECTED_CALLSITE_NR];
	unsigned long save_reject_nonconst, save_reject_uninteresting;
	unsigned long save_reject_sentinel, save_reject_dup, save_reject_cap;
	unsigned long cmp_hints_consumed, cmp_hint_wins, cmp_hint_misses;
	unsigned long cmp_hint_cmp_novelty_wins;
	unsigned long cmp_hint_stash_overflow, cmp_hint_credit_entry_evicted;
	unsigned long cmp_recent_inserts, cmp_recent_evicts;
	unsigned long cmp_recent_would_pick, cmp_recent_would_miss;
	unsigned long cmp_recent_live_picks;
	unsigned long cmp_inject_arm_a_baseline_fires;
	unsigned long cmp_inject_arm_b_baseline_fires;
	unsigned long cmp_inject_denom_diverged;
	unsigned long prop_ring_argop_arm_b_fires;
	unsigned long frontier_blend_samples;
	unsigned long remote_adaptive_samples;
	unsigned long mut_structured_shadow_divergences;
};

#define CMP_WINDOW_WORDS	(sizeof(struct cmp_window) / sizeof(unsigned long))

_Static_assert(sizeof(struct cmp_window) % sizeof(unsigned long) == 0,
	       "struct cmp_window must be made of unsigned longs alone");

/*
 * Values the dump prints as they stand, with no window delta: the A/B
 * cohort populations and the shadow totals that sit under a cohort row.
 */
struct cmp_levels {
	unsigned int  cmp_inject_arm_a_children, cmp_inject_arm_b_children;
	unsigned int  prop_ring_argop_arm_a_children, prop_ring_argop_arm_b_children;
	unsigned int  frontier_blend_arm_a_children, frontier_blend_arm_b_children;
	unsigned int  remote_adaptive_arm_a_children, remote_adaptive_arm_b_children;
	unsigned int  mut_structured_arm_a_children, mut_structured_arm_b_children;
	unsigned long remote_adaptive_would_demote, remote_adaptive_would_promote;
	unsigned long remote_adaptive_would_force, remote_adaptive_would_gate_promote;
	unsigned long remote_adaptive_agree;
	unsigned long arg_meta_addr_with_meta, arg_meta_addr_without_meta;
	unsigned long arg_meta_argtype_stale;
	unsigned long arg_meta_scrub_would_destroy_in;
	unsigned long arg_meta_scrub_would_preserve_out;
	unsigned long blanket_address_scrub_slots_walked;
	unsigned long mut_structured_shadow_samples;
};

static bool words_nonzero(const unsigned long *w, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++) {
		if (w[i] != 0)
			return true;
	}
	return false;
}

/*
 * The counters that print as a plain "name +delta (rate/s, total)" line,
 * in print order; the rows between two sibling renderers are one table.
 */
struct rate_row {
	const char *name;
	size_t      off;	/* offsetof(struct cmp_window, <counter>) */
};

static const struct rate_row funnel_rows[] = {
	{ "cmp_records_collected", offsetof(struct cmp_window, records) },
	{ "cmp_trace_truncated", offsetof(struct cmp_window, truncated) },
	{ "cmp_hints_bloom_skipped", offsetof(struct cmp_window, bloom_skipped) },
	{ "cmp_hints_strip_skipped", offsetof(struct cmp_window, strip_skipped) },
	{ "cmp_hints_unique_inserts", offsetof(struct cmp_window, unique) },
	{ "cmp_hints_save_reject_nonconst", offsetof(struct cmp_window, save_reject_nonconst) },
	{ "cmp_hints_save_reject_uninteresting", offsetof(struct cmp_window, save_reject_uninteresting) },
	{ "cmp_hints_save_reject_sentinel", offsetof(struct cmp_window, save_reject_sentinel) },
	{ "cmp_hints_save_reject_dup", offsetof(struct cmp_window, save_reject_dup) },
	{ "cmp_hints_save_reject_cap", offsetof(struct cmp_window, save_reject_cap) },
	{ "cmp_hints_try_get_attempts", offsetof(struct cmp_window, try_get_attempts) },
	{ "cmp_hints_try_get_returned", offsetof(struct cmp_window, try_get_returned) },
	{ "cmp_hints_injected", offsetof(struct cmp_window, injected) },
	{ "propagation_injected", offsetof(struct cmp_window, prop_injected) },
};

static const struct rate_row reexec_rows[] = {
	{ "reexec_attempts", offsetof(struct cmp_window, reexec_attempts) },
	{ "reexec_attempts_with_new_cmp", offsetof(struct cmp_window, reexec_attempts_with_new_cmp) },
	{ "reexec_attribution_found", offsetof(struct cmp_window, reexec_attribution_found) },
	{ "reexec_attribution_ambiguous", offsetof(struct cmp_window, reexec_attribution_ambiguous) },
	{ "reexec_attribution_width_match", offsetof(struct cmp_window, reexec_attribution_width_match) },
	{ "reexec_new_cmps_total", offsetof(struct cmp_window, reexec_new_cmps_total) },
	{ "reexec_new_edges_total", offsetof(struct cmp_window, reexec_new_edges_total) },
};

static const struct rate_row reexec_drop_rows[] = {
	{ "reexec_skipped_destructive", offsetof(struct cmp_window, reexec_skipped_destructive) },
	{ "reexec_skipped_validate_silent", offsetof(struct cmp_window, reexec_skipped_validate_silent) },
	{ "reexec_window_cap_hit", offsetof(struct cmp_window, reexec_window_cap_hit) },
	{ "reexec_pending_dropped", offsetof(struct cmp_window, reexec_pending_dropped) },
};

static const struct rate_row cmp_parent_rows[] = {
	{ "cmp_parent_calls_enabled", offsetof(struct cmp_window, cmp_parent_calls_enabled) },
	{ "cmp_parent_calls_control", offsetof(struct cmp_window, cmp_parent_calls_control) },
	{ "cmp_parent_new_cmps_enabled", offsetof(struct cmp_window, cmp_parent_new_cmps_enabled) },
	{ "cmp_parent_new_cmps_control", offsetof(struct cmp_window, cmp_parent_new_cmps_control) },
};

static void emit_rate_rows(long elapsed, const struct cmp_window *cur,
			   const struct cmp_window *delta,
			   const struct rate_row *rows, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		kcov_cmp_rate_line(elapsed, rows[i].name,
				   *(const unsigned long *)((const char *)delta + rows[i].off),
				   *(const unsigned long *)((const char *)cur + rows[i].off));
}

static void cmp_window_snapshot(struct cmp_window *cur, struct cmp_levels *lvl)
{
	cur->records       = __atomic_load_n(&kcov_shm->cmp_records.cmp_records_collected,   __ATOMIC_RELAXED);
	cur->truncated     = __atomic_load_n(&kcov_shm->cmp_records.cmp_trace_truncated,     __ATOMIC_RELAXED);
	cur->bloom_skipped = __atomic_load_n(&kcov_shm->hints_flat.cmp_hints_bloom_skipped, __ATOMIC_RELAXED);
	cur->strip_skipped = __atomic_load_n(&kcov_shm->hints_flat.cmp_hints_strip_skipped, __ATOMIC_RELAXED);
	cur->unique        = __atomic_load_n(&kcov_shm->hints_flat.cmp_hints_unique_inserts, __ATOMIC_RELAXED);
	/* Source from parent_stats: cmp_hints_try_get_ex() now enqueues
	 * +1 per attempt/return via the per-child stats_ring; the kcov_shm
	 * scalars are gone, removing a fuzzer-visible wild-write target. */
	cur->try_get_attempts = parent_stats.cmp_hints_try_get_attempts;
	cur->try_get_returned = parent_stats.cmp_hints_try_get_returned;
	cur->injected         = __atomic_load_n(&kcov_shm->hints_flat.cmp_hints_injected,         __ATOMIC_RELAXED);
	cur->prop_injected    = __atomic_load_n(&kcov_shm->hints_flat.propagation_injected,       __ATOMIC_RELAXED);
	cur->chaos_suppressed = __atomic_load_n(&kcov_shm->hints_flat.cmp_hints_chaos_suppressed, __ATOMIC_RELAXED);
	cur->count_oob        = __atomic_load_n(&kcov_shm->hints_canary.cmp_hints_count_oob,               __ATOMIC_RELAXED);
	cur->canary_lock_post = __atomic_load_n(&kcov_shm->hints_canary.cmp_hints_canary_lock_post_corrupt, __ATOMIC_RELAXED);
	cur->canary_pre       = __atomic_load_n(&kcov_shm->hints_canary.cmp_hints_canary_pre_corrupt,      __ATOMIC_RELAXED);
	cur->canary_post      = __atomic_load_n(&kcov_shm->hints_canary.cmp_hints_canary_post_corrupt,     __ATOMIC_RELAXED);
	cur->reexec_attempts                = __atomic_load_n(&kcov_shm->reexec_flat.reexec_attempts,                __ATOMIC_RELAXED);
	cur->reexec_attempts_with_new_cmp   = __atomic_load_n(&kcov_shm->reexec_flat.reexec_attempts_with_new_cmp,   __ATOMIC_RELAXED);
	cur->reexec_attribution_found       = __atomic_load_n(&kcov_shm->reexec_flat.reexec_attribution_found,       __ATOMIC_RELAXED);
	cur->reexec_attribution_ambiguous   = __atomic_load_n(&kcov_shm->reexec_flat.reexec_attribution_ambiguous,   __ATOMIC_RELAXED);
	cur->reexec_attribution_width_match = __atomic_load_n(&kcov_shm->reexec_flat.reexec_attribution_width_match, __ATOMIC_RELAXED);
	cur->reexec_new_cmps_total          = __atomic_load_n(&kcov_shm->reexec_flat.reexec_new_cmps_total,          __ATOMIC_RELAXED);
	cur->reexec_new_edges_total         = __atomic_load_n(&kcov_shm->reexec_arms.reexec_new_edges_total,         __ATOMIC_RELAXED);
	cur->reexec_attempts_by_arm[0]      = __atomic_load_n(&kcov_shm->reexec_arms.reexec_attempts_by_arm[0],      __ATOMIC_RELAXED);
	cur->reexec_attempts_by_arm[1]      = __atomic_load_n(&kcov_shm->reexec_arms.reexec_attempts_by_arm[1],      __ATOMIC_RELAXED);
	cur->reexec_new_cmps_by_arm[0]      = __atomic_load_n(&kcov_shm->reexec_arms.reexec_new_cmps_by_arm[0],      __ATOMIC_RELAXED);
	cur->reexec_new_cmps_by_arm[1]      = __atomic_load_n(&kcov_shm->reexec_arms.reexec_new_cmps_by_arm[1],      __ATOMIC_RELAXED);
	cur->reexec_new_edges_by_arm[0]     = __atomic_load_n(&kcov_shm->reexec_arms.reexec_new_edges_by_arm[0],     __ATOMIC_RELAXED);
	cur->reexec_new_edges_by_arm[1]     = __atomic_load_n(&kcov_shm->reexec_arms.reexec_new_edges_by_arm[1],     __ATOMIC_RELAXED);
	cur->reexec_skipped_destructive     = __atomic_load_n(&kcov_shm->reexec_flat.reexec_skipped_destructive,     __ATOMIC_RELAXED);
	cur->reexec_skipped_validate_silent = __atomic_load_n(&kcov_shm->reexec_flat.reexec_skipped_validate_silent, __ATOMIC_RELAXED);
	cur->reexec_window_cap_hit          = __atomic_load_n(&kcov_shm->reexec_flat.reexec_window_cap_hit,          __ATOMIC_RELAXED);
	cur->reexec_pending_dropped         = __atomic_load_n(&kcov_shm->reexec_pending_hist.reexec_pending_dropped,         __ATOMIC_RELAXED);
	cur->reexec_gate_skip_in_reexec     = __atomic_load_n(&kcov_shm->reexec_gate.reexec_gate_skip_in_reexec,     __ATOMIC_RELAXED);
	cur->reexec_gate_skip_disabled      = __atomic_load_n(&kcov_shm->reexec_gate.reexec_gate_skip_disabled,      __ATOMIC_RELAXED);
	cur->reexec_gate_skip_mode          = __atomic_load_n(&kcov_shm->reexec_gate.reexec_gate_skip_mode,          __ATOMIC_RELAXED);
	cur->reexec_gate_skip_chain_mid     = __atomic_load_n(&kcov_shm->reexec_gate.reexec_gate_skip_chain_mid,     __ATOMIC_RELAXED);
	cur->reexec_gate_skip_no_new_cmp    = __atomic_load_n(&kcov_shm->reexec_gate.reexec_gate_skip_no_new_cmp,    __ATOMIC_RELAXED);
	cur->reexec_gate_skip_no_pending    = __atomic_load_n(&kcov_shm->reexec_gate.reexec_gate_skip_no_pending,    __ATOMIC_RELAXED);
	cur->reexec_gate_skip_rate          = __atomic_load_n(&kcov_shm->reexec_gate.reexec_gate_skip_rate,          __ATOMIC_RELAXED);
	cur->reexec_gate_pass               = __atomic_load_n(&kcov_shm->reexec_gate.reexec_gate_pass,               __ATOMIC_RELAXED);
	cur->cmp_parent_calls_enabled       = __atomic_load_n(&kcov_shm->cmp_parent.cmp_parent_calls_enabled,       __ATOMIC_RELAXED);
	cur->cmp_parent_calls_control       = __atomic_load_n(&kcov_shm->cmp_parent.cmp_parent_calls_control,       __ATOMIC_RELAXED);
	cur->cmp_parent_new_cmps_enabled    = __atomic_load_n(&kcov_shm->cmp_parent.cmp_parent_new_cmps_enabled,    __ATOMIC_RELAXED);
	cur->cmp_parent_new_cmps_control    = __atomic_load_n(&kcov_shm->cmp_parent.cmp_parent_new_cmps_control,    __ATOMIC_RELAXED);
	cur->save_reject_nonconst      = __atomic_load_n(&kcov_shm->hint_reject.cmp_hints_save_reject_nonconst,      __ATOMIC_RELAXED);
	cur->save_reject_uninteresting = __atomic_load_n(&kcov_shm->hint_reject.cmp_hints_save_reject_uninteresting, __ATOMIC_RELAXED);
	cur->save_reject_sentinel      = __atomic_load_n(&kcov_shm->hint_reject.cmp_hints_save_reject_sentinel,      __ATOMIC_RELAXED);
	cur->save_reject_dup           = __atomic_load_n(&kcov_shm->hint_reject.cmp_hints_save_reject_dup,           __ATOMIC_RELAXED);
	cur->save_reject_cap           = __atomic_load_n(&kcov_shm->hint_reject.cmp_hints_save_reject_cap,           __ATOMIC_RELAXED);
	{
		unsigned int cs;
		for (cs = 0; cs < CMP_HINT_CALLSITE_NR; cs++)
			cur->cmp_hint_callsite[cs] = __atomic_load_n(
				&kcov_shm->hint_callsite.cmp_hint_callsite_injected[cs],
				__ATOMIC_RELAXED);
	}
	{
		unsigned int cs;
		for (cs = 0; cs < CMP_HINT_CALLSITE_NR; cs++) {
			cur->cmp_hint_callsite_pc_wins[cs] = __atomic_load_n(
				&kcov_shm->hint_callsite.cmp_hint_callsite_pc_wins[cs],
				__ATOMIC_RELAXED);
			cur->cmp_hint_callsite_misses[cs] = __atomic_load_n(
				&kcov_shm->hint_callsite.cmp_hint_callsite_misses[cs],
				__ATOMIC_RELAXED);
		}
	}
	{
		unsigned int cs;
		for (cs = 0; cs < PROP_INJECTED_CALLSITE_NR; cs++)
			cur->prop_injected_callsite[cs] = __atomic_load_n(
				&kcov_shm->hints_flat.propagation_injected_callsite[cs],
				__ATOMIC_RELAXED);
	}
	cur->cmp_hints_consumed             = __atomic_load_n(&kcov_shm->hint_flat.cmp_hints_consumed,             __ATOMIC_RELAXED);
	cur->cmp_hint_wins                  = __atomic_load_n(&kcov_shm->hint_flat.cmp_hint_wins,                  __ATOMIC_RELAXED);
	cur->cmp_hint_misses                = __atomic_load_n(&kcov_shm->hint_flat.cmp_hint_misses,                __ATOMIC_RELAXED);
	cur->cmp_hint_cmp_novelty_wins      = __atomic_load_n(&kcov_shm->hint_flat.cmp_hint_cmp_novelty_wins,      __ATOMIC_RELAXED);
	cur->cmp_hint_stash_overflow        = __atomic_load_n(&kcov_shm->hint_flat.cmp_hint_stash_overflow,        __ATOMIC_RELAXED);
	cur->cmp_hint_credit_entry_evicted  = __atomic_load_n(&kcov_shm->hint_flat.cmp_hint_credit_entry_evicted,  __ATOMIC_RELAXED);
	cur->cmp_recent_inserts             = __atomic_load_n(&kcov_shm->cmp_recent.cmp_recent_inserts,             __ATOMIC_RELAXED);
	cur->cmp_recent_evicts              = __atomic_load_n(&kcov_shm->cmp_recent.cmp_recent_evicts,              __ATOMIC_RELAXED);
	cur->cmp_recent_would_pick          = __atomic_load_n(&kcov_shm->cmp_recent.cmp_recent_would_pick,          __ATOMIC_RELAXED);
	cur->cmp_recent_would_miss          = __atomic_load_n(&kcov_shm->cmp_recent.cmp_recent_would_miss,          __ATOMIC_RELAXED);
	cur->cmp_recent_live_picks          = __atomic_load_n(&kcov_shm->cmp_recent.cmp_recent_live_picks,          __ATOMIC_RELAXED);
	cur->cmp_inject_arm_a_baseline_fires = __atomic_load_n(&kcov_shm->cohorts.cmp_inject_arm_a_baseline_fires, __ATOMIC_RELAXED);
	cur->cmp_inject_arm_b_baseline_fires = __atomic_load_n(&kcov_shm->cohorts.cmp_inject_arm_b_baseline_fires, __ATOMIC_RELAXED);
	cur->cmp_inject_denom_diverged       = __atomic_load_n(&kcov_shm->cohorts.cmp_inject_denom_diverged,       __ATOMIC_RELAXED);
	lvl->cmp_inject_arm_a_children       = __atomic_load_n(&kcov_shm->cohorts.cmp_inject_arm_a_children,       __ATOMIC_RELAXED);
	lvl->cmp_inject_arm_b_children       = __atomic_load_n(&kcov_shm->cohorts.cmp_inject_arm_b_children,       __ATOMIC_RELAXED);
	cur->prop_ring_argop_arm_b_fires     = __atomic_load_n(&kcov_shm->cohorts.prop_ring_argop_arm_b_fires,     __ATOMIC_RELAXED);
	lvl->prop_ring_argop_arm_a_children  = __atomic_load_n(&kcov_shm->cohorts.prop_ring_argop_arm_a_children,  __ATOMIC_RELAXED);
	lvl->prop_ring_argop_arm_b_children  = __atomic_load_n(&kcov_shm->cohorts.prop_ring_argop_arm_b_children,  __ATOMIC_RELAXED);
	/* frontier_blend_samples lives in shm->stats (bumped per fire from
	 * both arms in lock-step), the cohort children counters live in
	 * kcov_shm (bumped once per child).  Read both here so the cohort
	 * dump row can be delta-gated on the fire counter, matching the
	 * prop_ring_argop template. */
	cur->frontier_blend_samples          = __atomic_load_n(&shm->stats.frontier.plateau.blend_samples,         __ATOMIC_RELAXED);
	lvl->frontier_blend_arm_a_children   = __atomic_load_n(&kcov_shm->cohorts.frontier_blend_arm_a_children,   __ATOMIC_RELAXED);
	lvl->frontier_blend_arm_b_children   = __atomic_load_n(&kcov_shm->cohorts.frontier_blend_arm_b_children,   __ATOMIC_RELAXED);
	cur->remote_adaptive_samples         = __atomic_load_n(&shm->stats.remote_adaptive.samples,        __ATOMIC_RELAXED);
	lvl->remote_adaptive_would_demote    = __atomic_load_n(&shm->stats.remote_adaptive.would_demote,   __ATOMIC_RELAXED);
	lvl->remote_adaptive_would_promote   = __atomic_load_n(&shm->stats.remote_adaptive.would_promote,  __ATOMIC_RELAXED);
	lvl->remote_adaptive_would_force     = __atomic_load_n(&shm->stats.remote_adaptive.would_force,    __ATOMIC_RELAXED);
	lvl->remote_adaptive_would_gate_promote = __atomic_load_n(&shm->stats.remote_adaptive.would_gate_promote, __ATOMIC_RELAXED);
	lvl->remote_adaptive_agree           = __atomic_load_n(&shm->stats.remote_adaptive.agree,          __ATOMIC_RELAXED);
	lvl->remote_adaptive_arm_a_children  = __atomic_load_n(&kcov_shm->cohorts.remote_adaptive_arm_a_children,  __ATOMIC_RELAXED);
	lvl->remote_adaptive_arm_b_children  = __atomic_load_n(&kcov_shm->cohorts.remote_adaptive_arm_b_children,  __ATOMIC_RELAXED);
	lvl->arg_meta_addr_with_meta            = __atomic_load_n(&shm->stats.arg.meta_addr_with_meta,            __ATOMIC_RELAXED);
	lvl->arg_meta_addr_without_meta         = __atomic_load_n(&shm->stats.arg.meta_addr_without_meta,         __ATOMIC_RELAXED);
	lvl->arg_meta_argtype_stale             = __atomic_load_n(&shm->stats.arg.meta_argtype_stale,             __ATOMIC_RELAXED);
	lvl->arg_meta_scrub_would_destroy_in    = __atomic_load_n(&shm->stats.arg.meta_scrub_would_destroy_in,    __ATOMIC_RELAXED);
	lvl->arg_meta_scrub_would_preserve_out  = __atomic_load_n(&shm->stats.arg.meta_scrub_would_preserve_out,  __ATOMIC_RELAXED);
	lvl->blanket_address_scrub_slots_walked = __atomic_load_n(&shm->stats.arg.blanket_address_scrub_slots_walked, __ATOMIC_RELAXED);
	/* SHADOW structure-aware picker A/B cohort + divergence counters live
	 * in minicorpus_shm rather than kcov_shm because the picker is a
	 * mutate_arg concern, not a kcov-cmp concern.  Guard the load so a
	 * degenerate run with kcov on but minicorpus unmapped does not chase
	 * a NULL pointer; the dump row's delta gate keeps a zero from
	 * polluting the kcov-cmp window output. */
	if (minicorpus_shm != NULL) {
		lvl->mut_structured_shadow_samples     = __atomic_load_n(&minicorpus_shm->mut_structured_shadow_samples,     __ATOMIC_RELAXED);
		cur->mut_structured_shadow_divergences = __atomic_load_n(&minicorpus_shm->mut_structured_shadow_divergences, __ATOMIC_RELAXED);
		lvl->mut_structured_arm_a_children     = __atomic_load_n(&minicorpus_shm->mut_structured_arm_a_children,     __ATOMIC_RELAXED);
		lvl->mut_structured_arm_b_children     = __atomic_load_n(&minicorpus_shm->mut_structured_arm_b_children,     __ATOMIC_RELAXED);
	} else {
		lvl->mut_structured_shadow_samples     = 0;
		cur->mut_structured_shadow_divergences = 0;
		lvl->mut_structured_arm_a_children     = 0;
		lvl->mut_structured_arm_b_children     = 0;
	}
}

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
	static struct cmp_window prev;
	static struct timespec last_dump;
	struct cmp_window cur, delta;
	struct cmp_levels lvl;
	struct timespec now;
	const unsigned long *c = (const unsigned long *)&cur;
	const unsigned long *p = (const unsigned long *)&prev;
	unsigned long *d = (unsigned long *)&delta;
	long elapsed;
	bool any_callsite_delta;
	bool any_callsite_wins_delta;
	bool any_prop_callsite_delta;
	size_t i;

	if (kcov_shm == NULL)
		return;

	clock_gettime(CLOCK_MONOTONIC, &now);
	cmp_window_snapshot(&cur, &lvl);

	/* First call: arm the window so any pre-existing counts carried
	 * over from earlier in the run are not mis-attributed to the
	 * first window, mirroring periodic_counter_rates_dump. */
	if (last_dump.tv_sec == 0) {
		last_dump = now;
		prev = cur;
		return;
	}

	elapsed = now.tv_sec - last_dump.tv_sec;
	if (elapsed < DEFENSE_DUMP_INTERVAL_SEC)
		return;

	for (i = 0; i < CMP_WINDOW_WORDS; i++)
		d[i] = sat_sub_ul(c[i], p[i]);
	any_callsite_delta = words_nonzero(delta.cmp_hint_callsite,
					   CMP_HINT_CALLSITE_NR);
	any_callsite_wins_delta =
		words_nonzero(delta.cmp_hint_callsite_pc_wins, CMP_HINT_CALLSITE_NR) ||
		words_nonzero(delta.cmp_hint_callsite_misses, CMP_HINT_CALLSITE_NR);
	any_prop_callsite_delta = words_nonzero(delta.prop_injected_callsite,
						PROP_INJECTED_CALLSITE_NR);

	if (words_nonzero(d, CMP_WINDOW_WORDS)) {
		stats_log_write("KCOV CMP stats over last %lds:\n", elapsed);

		emit_rate_rows(elapsed, &cur, &delta, funnel_rows, ARRAY_SIZE(funnel_rows));
		if (delta.chaos_suppressed) {
			unsigned long rate_milli = (delta.chaos_suppressed * 1000UL) / (unsigned long)elapsed;
			stats_log_write("  %-32s +%lu  (%lu.%03lu/s, total %lu, chaos_active=%d)\n",
					"cmp_hints_chaos_suppressed", delta.chaos_suppressed,
					rate_milli / 1000, rate_milli % 1000, cur.chaos_suppressed,
					cmp_hints_chaos_query() ? 1 : 0);
		}
		kcov_cmp_render_wild_write_delta(elapsed,
						 delta.count_oob, cur.count_oob,
						 delta.canary_lock_post, cur.canary_lock_post,
						 delta.canary_pre, cur.canary_pre,
						 delta.canary_post, cur.canary_post);
		emit_rate_rows(elapsed, &cur, &delta, reexec_rows, ARRAY_SIZE(reexec_rows));
		kcov_cmp_render_reexec_burst_drain_cohort(delta.reexec_attempts_by_arm,
							  cur.reexec_attempts_by_arm,
							  delta.reexec_new_cmps_by_arm,
							  cur.reexec_new_cmps_by_arm,
							  delta.reexec_new_edges_by_arm,
							  cur.reexec_new_edges_by_arm);
		emit_rate_rows(elapsed, &cur, &delta, reexec_drop_rows, ARRAY_SIZE(reexec_drop_rows));
		kcov_cmp_render_reexec_skip_reason_breakdown(elapsed,
							     delta.reexec_gate_skip_in_reexec, cur.reexec_gate_skip_in_reexec,
							     delta.reexec_gate_skip_disabled, cur.reexec_gate_skip_disabled,
							     delta.reexec_gate_skip_mode, cur.reexec_gate_skip_mode,
							     delta.reexec_gate_skip_chain_mid, cur.reexec_gate_skip_chain_mid,
							     delta.reexec_gate_skip_no_new_cmp, cur.reexec_gate_skip_no_new_cmp,
							     delta.reexec_gate_skip_no_pending, cur.reexec_gate_skip_no_pending,
							     delta.reexec_gate_skip_rate, cur.reexec_gate_skip_rate,
							     delta.reexec_gate_pass, cur.reexec_gate_pass);
		emit_rate_rows(elapsed, &cur, &delta, cmp_parent_rows, ARRAY_SIZE(cmp_parent_rows));
		kcov_cmp_render_cmp_hint_callsites(any_callsite_delta, any_callsite_wins_delta,
						   delta.cmp_hint_callsite, cur.cmp_hint_callsite,
						   delta.cmp_hint_callsite_pc_wins,
						   cur.cmp_hint_callsite_pc_wins,
						   delta.cmp_hint_callsite_misses,
						   cur.cmp_hint_callsite_misses);
		kcov_cmp_render_prop_injected_callsite(any_prop_callsite_delta,
						       delta.prop_injected_callsite,
						       cur.prop_injected_callsite);
		kcov_cmp_render_per_entry_feedback_scoring(elapsed,
							   delta.cmp_hints_consumed, cur.cmp_hints_consumed,
							   delta.cmp_hint_wins, cur.cmp_hint_wins,
							   delta.cmp_hint_misses, cur.cmp_hint_misses,
							   delta.cmp_hint_cmp_novelty_wins, cur.cmp_hint_cmp_novelty_wins,
							   delta.cmp_hint_stash_overflow, cur.cmp_hint_stash_overflow,
							   delta.cmp_hint_credit_entry_evicted, cur.cmp_hint_credit_entry_evicted);
		kcov_cmp_render_recent_cmp_pool_tier(elapsed,
						     delta.cmp_recent_inserts, cur.cmp_recent_inserts,
						     delta.cmp_recent_evicts, cur.cmp_recent_evicts,
						     delta.cmp_recent_would_pick, cur.cmp_recent_would_pick,
						     delta.cmp_recent_would_miss, cur.cmp_recent_would_miss,
						     delta.cmp_recent_live_picks, cur.cmp_recent_live_picks);
		kcov_cmp_render_ab_baseline_inject_denom(elapsed,
							 delta.cmp_inject_arm_a_baseline_fires, cur.cmp_inject_arm_a_baseline_fires,
							 delta.cmp_inject_arm_b_baseline_fires, cur.cmp_inject_arm_b_baseline_fires,
							 delta.cmp_inject_denom_diverged, cur.cmp_inject_denom_diverged,
							 lvl.cmp_inject_arm_a_children,
							 lvl.cmp_inject_arm_b_children);
		kcov_cmp_render_handle_arg_op_prop_ring_cohort(elapsed,
							       delta.prop_ring_argop_arm_b_fires,
							       cur.prop_ring_argop_arm_b_fires,
							       lvl.prop_ring_argop_arm_a_children,
							       lvl.prop_ring_argop_arm_b_children);
		kcov_cmp_render_frontier_cold_weight_blend_cohort(elapsed,
								  delta.frontier_blend_samples,
								  cur.frontier_blend_samples,
								  lvl.frontier_blend_arm_a_children,
								  lvl.frontier_blend_arm_b_children);
		kcov_cmp_render_adaptive_remote_kcov_cohort(elapsed,
							    delta.remote_adaptive_samples,
							    cur.remote_adaptive_samples,
							    lvl.remote_adaptive_arm_a_children,
							    lvl.remote_adaptive_arm_b_children,
							    lvl.remote_adaptive_would_demote,
							    lvl.remote_adaptive_would_promote,
							    lvl.remote_adaptive_would_force,
							    lvl.remote_adaptive_would_gate_promote,
							    lvl.remote_adaptive_agree);
		kcov_cmp_render_per_arg_ownership_sidecar(lvl.blanket_address_scrub_slots_walked,
							  lvl.arg_meta_addr_with_meta,
							  lvl.arg_meta_addr_without_meta,
							  lvl.arg_meta_argtype_stale,
							  lvl.arg_meta_scrub_would_destroy_in,
							  lvl.arg_meta_scrub_would_preserve_out);
		kcov_cmp_render_structure_aware_picker_cohort(elapsed,
							      delta.mut_structured_shadow_divergences,
							      cur.mut_structured_shadow_divergences,
							      lvl.mut_structured_shadow_samples,
							      lvl.mut_structured_arm_a_children,
							      lvl.mut_structured_arm_b_children);
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
	output(0, "cmp_hints_chaos_suppressed_cumulative=%lu\n",
	       cur.chaos_suppressed);
	output(0, "propagation_injected_cumulative=%lu\n",
	       cur.prop_injected);

	kcov_cmp_render_modes_block();

	kcov_cmp_render_diag_errnos_block();

	kcov_cmp_render_pc_diag_block();

	kcov_cmp_observability_block_render(elapsed);
	kcov_redqueen_observability_block_render(elapsed);
	kcov_cmp_oldpool_vs_shadow_block_render(elapsed);
	kcov_cmp_render_pc_win_conversion_split_block(elapsed);
	kcov_cmp_hyp_saturation_block_render(elapsed);

	prev = cur;
	last_dump = now;
}
