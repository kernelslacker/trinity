/*
 * RedQueen and reexec periodic reporting.
 *
 * Owns the RedQueen per-syscall reexec top-N table plus the flat per-slot
 * attribution histograms, and the reexec skip-reason breakdown row set.
 * Both are called only from kcov_cmp_stats_periodic_dump() in
 * stats/kcov/cmp/periodic.c and kept out of the raw cmp-hint pool renderer
 * so RedQueen-shaped questions have one home.
 */

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <sys/utsname.h>
#include <stdio.h>
#include "arch.h"
#include "child-api.h"
#include "cmp_hints.h"
#include "kcov.h"
#include "shm.h"
#include "stats.h"
#include "stats-internal.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"

#include "stats/kcov/cmp/internal.h"

/*
 * RedQueen observability: top-N syscalls by re-exec
 * attempt delta + flat aggregates for the per-slot histograms.  The
 * per-slot histograms stay flat (6 entries each) rather than per-nr to
 * keep the block readable -- the "which arg slot won attribution" and
 * "which arg slot produced novelty" questions are aggregate-shaped, not
 * per-syscall, so the answer is two short rows of counts.  The per-nr
 * partition for attempts and ambiguity is the syscall-shaped half: that
 * goes through the top-N table.
 */
void kcov_redqueen_observability_block_render(long elapsed __unused__)
{
	static unsigned long prev_attempts[MAX_NR_SYSCALL];
	static unsigned long prev_ambiguous[MAX_NR_SYSCALL];
	static bool armed;
	unsigned int top_nr[10];
	unsigned long top_attempts[10];
	unsigned long top_ambiguous[10];
	unsigned int top_count = 0;
	unsigned long slot_hist[CMP_REDQUEEN_SLOT_HIST_NR];
	unsigned long slot_success[CMP_REDQUEEN_SLOT_HIST_NR];
	unsigned long slot_fill[CMP_REDQUEEN_SLOT_HIST_NR];
	bool any_slot = false;
	unsigned long pick_success[REEXEC_PENDING_PICK_HIST_NR];
	bool any_pick_success = false;
	unsigned int nr_syscalls_to_scan;
	const struct syscalltable *table;
	unsigned int i;
	unsigned int j;

	if (kcov_shm == NULL)
		return;

	nr_syscalls_to_scan = biarch ? max_nr_64bit_syscalls : max_nr_syscalls;
	if (nr_syscalls_to_scan > MAX_NR_SYSCALL)
		nr_syscalls_to_scan = MAX_NR_SYSCALL;
	table = biarch ? syscalls_64bit : syscalls;

	memset(top_attempts, 0, sizeof(top_attempts));
	memset(top_ambiguous, 0, sizeof(top_ambiguous));

	for (i = 0; i < nr_syscalls_to_scan; i++) {
		unsigned long cur_attempts = __atomic_load_n(
			&kcov_shm->reexec_attempts_by_syscall[i], __ATOMIC_RELAXED);
		unsigned long cur_ambig = __atomic_load_n(
			&kcov_shm->reexec_ambiguous_by_syscall[i], __ATOMIC_RELAXED);
		unsigned long delta_attempts;
		unsigned long delta_ambig;
		unsigned int k;

		if (!armed) {
			prev_attempts[i] = cur_attempts;
			prev_ambiguous[i] = cur_ambig;
			continue;
		}

		delta_attempts = sat_sub_ul(cur_attempts, prev_attempts[i]);
		delta_ambig    = sat_sub_ul(cur_ambig,    prev_ambiguous[i]);

		prev_attempts[i] = cur_attempts;
		prev_ambiguous[i] = cur_ambig;

		if (delta_attempts == 0)
			continue;

		for (j = top_count; j > 0 && delta_attempts > top_attempts[j - 1]; j--) {
			if (j < 10) {
				top_attempts[j]  = top_attempts[j - 1];
				top_ambiguous[j] = top_ambiguous[j - 1];
				top_nr[j]        = top_nr[j - 1];
			}
		}
		k = j;
		if (k < 10) {
			top_attempts[k]  = delta_attempts;
			top_ambiguous[k] = delta_ambig;
			top_nr[k]        = i;
			if (top_count < 10)
				top_count++;
		}
	}

	for (i = 0; i < CMP_REDQUEEN_SLOT_HIST_NR; i++) {
		slot_hist[i] = __atomic_load_n(
			&kcov_shm->reexec_attribution_slot_hist[i],
			__ATOMIC_RELAXED);
		slot_success[i] = __atomic_load_n(
			&kcov_shm->reexec_success_by_slot[i],
			__ATOMIC_RELAXED);
		slot_fill[i] = __atomic_load_n(
			&kcov_shm->typed_inject_fill_slot_hist[i],
			__ATOMIC_RELAXED);
		if ((slot_hist[i] | slot_success[i] | slot_fill[i]) != 0)
			any_slot = true;
	}

	for (i = 0; i < REEXEC_PENDING_PICK_HIST_NR; i++) {
		pick_success[i] = __atomic_load_n(
			&kcov_shm->reexec_pending_pick_success[i],
			__ATOMIC_RELAXED);
		if (pick_success[i] != 0)
			any_pick_success = true;
	}

	if (!armed) {
		armed = true;
		return;
	}

	if (top_count > 0) {
		stats_log_write("KCOV RedQueen syscalls (top by per-window reexec_attempts delta):\n");
		stats_log_write("  %-24s %12s %12s\n",
				"syscall", "attempts+", "ambiguous+");
		for (j = 0; j < top_count; j++) {
			struct syscallentry *entry = table[top_nr[j]].entry;
			const char *name = entry ? entry->name : "???";

			stats_log_write("  %-24s %12lu %12lu\n",
					name, top_attempts[j], top_ambiguous[j]);
		}
	}

	if (any_slot) {
		stats_log_write("KCOV RedQueen arg-slot attribution (cumulative, slot=index+1):\n");
		stats_log_write("  %-12s %10s %10s %10s %10s %10s %10s\n",
				"counter", "a1", "a2", "a3", "a4", "a5", "a6");
		stats_log_write("  %-12s %10lu %10lu %10lu %10lu %10lu %10lu\n",
				"attribute",
				slot_hist[0], slot_hist[1], slot_hist[2],
				slot_hist[3], slot_hist[4], slot_hist[5]);
		stats_log_write("  %-12s %10lu %10lu %10lu %10lu %10lu %10lu\n",
				"success",
				slot_success[0], slot_success[1], slot_success[2],
				slot_success[3], slot_success[4], slot_success[5]);
		/* Placement-proof fill-slot histogram: the arg slot the
		 * typed-hypothesis LIVE inject actually landed in (bumped
		 * inside the accept-gated commit block in
		 * cmp_try_get_durable_tier).  Rendered on the same row set
		 * as the source-slot attribute row so an operator can read
		 * the (fill vs attribute) divergence directly: an inject
		 * that consistently lands on a different arg slot than the
		 * kernel-side CMP fired on confirms placement is the CMP-
		 * conversion killer. */
		stats_log_write("  %-12s %10lu %10lu %10lu %10lu %10lu %10lu\n",
				"fill",
				slot_fill[0], slot_fill[1], slot_fill[2],
				slot_fill[3], slot_fill[4], slot_fill[5]);
	}

	/* Per-pending-buffer-index success counter (A/B signal for
	 * --redqueen-pending-pick).  Cumulative across both pick modes:
	 * a heavy load at index 0 with a flat tail under the FIRST policy
	 * versus a spread under RANDOM tells whether trace-order bias is
	 * costing signal.  Header is the policy name so an operator
	 * eyeballing the dump knows which arm is currently active. */
	if (any_pick_success) {
		stats_log_write("KCOV RedQueen pending-buffer pick success (cumulative, policy=%s):\n",
				redqueen_pending_pick_name(
					redqueen_pending_pick_mode_arg));
		stats_log_write("  %-12s %10s %10s %10s %10s %10s %10s %10s %10s\n",
				"counter",
				"p0", "p1", "p2", "p3",
				"p4", "p5", "p6", "p7");
		stats_log_write("  %-12s %10lu %10lu %10lu %10lu %10lu %10lu %10lu %10lu\n",
				"success",
				pick_success[0], pick_success[1],
				pick_success[2], pick_success[3],
				pick_success[4], pick_success[5],
				pick_success[6], pick_success[7]);
	}
}
void kcov_cmp_render_reexec_skip_reason_breakdown(long elapsed,
							 unsigned long delta_reexec_gate_skip_in_reexec, unsigned long cur_reexec_gate_skip_in_reexec,
							 unsigned long delta_reexec_gate_skip_disabled, unsigned long cur_reexec_gate_skip_disabled,
							 unsigned long delta_reexec_gate_skip_mode, unsigned long cur_reexec_gate_skip_mode,
							 unsigned long delta_reexec_gate_skip_chain_mid, unsigned long cur_reexec_gate_skip_chain_mid,
							 unsigned long delta_reexec_gate_skip_no_new_cmp, unsigned long cur_reexec_gate_skip_no_new_cmp,
							 unsigned long delta_reexec_gate_skip_no_pending, unsigned long cur_reexec_gate_skip_no_pending,
							 unsigned long delta_reexec_gate_skip_rate, unsigned long cur_reexec_gate_skip_rate,
							 unsigned long delta_reexec_gate_pass, unsigned long cur_reexec_gate_pass)
{
	/* Re-exec gate skip-reason breakdown.  Counters are mutually
	 * exclusive: every dispatch_step that reaches the tail bumps
	 * exactly one of {skip_in_reexec, skip_disabled, skip_mode,
	 * skip_chain_mid, skip_no_new_cmp, skip_no_pending, skip_rate,
	 * pass}.  The sum across the eight is the parent-call
	 * population the gate samples from -- read the per-reason
	 * fractions to see why reexec_attribution_found shrinks to
	 * reexec_attempts (rate-gate skip vs destructive vs pending-
	 * full vs pass), instead of inferring it from a single delta.
	 * Skip-row order mirrors the evaluation order in
	 * random-syscall.c so the funnel reads top-to-bottom. */
	kcov_cmp_rate_line(elapsed, "reexec_gate_skip_in_reexec", delta_reexec_gate_skip_in_reexec, cur_reexec_gate_skip_in_reexec);
	kcov_cmp_rate_line(elapsed, "reexec_gate_skip_disabled", delta_reexec_gate_skip_disabled, cur_reexec_gate_skip_disabled);
	kcov_cmp_rate_line(elapsed, "reexec_gate_skip_mode", delta_reexec_gate_skip_mode, cur_reexec_gate_skip_mode);
	kcov_cmp_rate_line(elapsed, "reexec_gate_skip_chain_mid", delta_reexec_gate_skip_chain_mid, cur_reexec_gate_skip_chain_mid);
	kcov_cmp_rate_line(elapsed, "reexec_gate_skip_no_new_cmp", delta_reexec_gate_skip_no_new_cmp, cur_reexec_gate_skip_no_new_cmp);
	kcov_cmp_rate_line(elapsed, "reexec_gate_skip_no_pending", delta_reexec_gate_skip_no_pending, cur_reexec_gate_skip_no_pending);
	kcov_cmp_rate_line(elapsed, "reexec_gate_skip_rate", delta_reexec_gate_skip_rate, cur_reexec_gate_skip_rate);
	kcov_cmp_rate_line(elapsed, "reexec_gate_pass", delta_reexec_gate_pass, cur_reexec_gate_pass);
}
