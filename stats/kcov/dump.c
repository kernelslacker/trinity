#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stddef.h>
#include <sys/utsname.h>
#include <stdio.h>
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
#include "shadow_promote.h"
#include "shm.h"
#include "stats.h"
#include "stats-internal.h"
#include "stats_ring.h"
#include "strategy.h"		/* frontier_spare_lane_decide, enum frontier_spare_reason */
#include "syscall.h"
#include "tables.h"
#include "taint.h"
#include "trinity.h"
#include "utils.h"
#include "utils-proc.h"
#include "version.h"

#include "dump-internal.h"

static void dump_stats_render_kcov_kcov_dispatch_stats(void)
{
		bool any = false;
		unsigned int c;

		for (c = 0; c < CRED_CLASS_NR; c++) {
			if (__atomic_load_n(&shm->stats.cred_class.calls[c],
					    __ATOMIC_RELAXED) != 0) {
				any = true;
				break;
			}
		}
		if (any) {
			output(0, "Credential-class oracle (--cred-throttle %s):\n",
			       cred_throttle ? "ON" : "OFF");
			output(0, "  %-12s %10s %10s %10s %10s %10s\n",
			       "class", "calls", "success",
			       "EPERM", "EINVAL", "throttled");
			for (c = 0; c < CRED_CLASS_NR; c++) {
				unsigned long calls = __atomic_load_n(
					&shm->stats.cred_class.calls[c],
					__ATOMIC_RELAXED);
				unsigned long succ = __atomic_load_n(
					&shm->stats.cred_class.success[c],
					__ATOMIC_RELAXED);
				unsigned long eperm = __atomic_load_n(
					&shm->stats.cred_class.eperm[c],
					__ATOMIC_RELAXED);
				unsigned long einval = __atomic_load_n(
					&shm->stats.cred_class.einval[c],
					__ATOMIC_RELAXED);
				unsigned long thr = __atomic_load_n(
					&shm->stats.cred_class.throttled[c],
					__ATOMIC_RELAXED);

				if (calls == 0 && thr == 0)
					continue;
				output(0, "  %-12s %10lu %10lu %10lu %10lu %10lu\n",
				       cred_class_name[c], calls,
				       succ, eperm, einval, thr);
			}
		}
}


static void dump_stats_render_kcov_kcov_probe_costs(void)
{
	unsigned int j;

		unsigned int lr_top_op[10];
		unsigned long lr_top_total[10];
		unsigned int lr_top_count = 0;
		unsigned int op;

		memset(lr_top_total, 0, sizeof(lr_top_total));
		for (op = 0; op < KCOV_CHILDOP_NR_MAX; op++) {
			unsigned long lc = __atomic_load_n(
				&kcov_shm->pc_ctx.childop_local_pc_calls[op],
				__ATOMIC_RELAXED);
			unsigned long rc = __atomic_load_n(
				&kcov_shm->pc_ctx.childop_remote_pc_calls[op],
				__ATOMIC_RELAXED);
			unsigned long tot = lc + rc;

			if (tot == 0)
				continue;
			topn_push(lr_top_total, lr_top_op,
				  &lr_top_count, 10, tot, op);
		}
		if (lr_top_count > 0) {
			output(0, "Local vs remote PC yield per childop (top by combined calls):\n");
			output(0, "  %-24s %10s %10s %10s %10s %10s %10s\n",
			       "childop",
			       "loc_calls", "loc_eCalls", "loc_eCount",
			       "rem_calls", "rem_eCalls", "rem_eCount");
			for (j = 0; j < lr_top_count; j++) {
				unsigned int op_id = lr_top_op[j];
				char opname[64];
				unsigned long lc = __atomic_load_n(
					&kcov_shm->pc_ctx.childop_local_pc_calls[op_id],
					__ATOMIC_RELAXED);
				unsigned long lec = __atomic_load_n(
					&kcov_shm->pc_ctx.childop_local_pc_edge_calls[op_id],
					__ATOMIC_RELAXED);
				unsigned long len_ = __atomic_load_n(
					&kcov_shm->pc_ctx.childop_local_pc_edge_count[op_id],
					__ATOMIC_RELAXED);
				unsigned long rc = __atomic_load_n(
					&kcov_shm->pc_ctx.childop_remote_pc_calls[op_id],
					__ATOMIC_RELAXED);
				unsigned long rec = __atomic_load_n(
					&kcov_shm->pc_ctx.childop_remote_pc_edge_calls[op_id],
					__ATOMIC_RELAXED);
				unsigned long ren = __atomic_load_n(
					&kcov_shm->pc_ctx.childop_remote_pc_edge_count[op_id],
					__ATOMIC_RELAXED);

				snprintf(opname, sizeof(opname), "%s",
					 alt_op_name((enum child_op_type)op_id));
				output(0, "  %-24s %10lu %10lu %10lu %10lu %10lu %10lu\n",
				       opname, lc, lec, len_, rc, rec, ren);
			}
		}
}




/* Render the shadow-measurement counter blocks that sit at the tail
 * of dump_stats_render_kcov_base_stats().  Each block surfaces the
 * would_fire / would_win pair for one shadow-only lane and, where
 * applicable, a per-mille ratio.  Split out so the base function no
 * longer carries fourteen shadow-only locals plus a hundred-and-fifty
 * lines of counter formatting; behaviour-neutral by construction --
 * every stat_row call, its gate, and its ordering is preserved. */
void dump_stats_render_kcov_shadow_measurements(void)
{
	unsigned long kc_cmp_save_reject_nonconst      = __atomic_load_n(&kcov_shm->hint_reject.cmp_hints_save_reject_nonconst,      __ATOMIC_RELAXED);
	unsigned long kc_cmp_nonconst_arg1_unique      = __atomic_load_n(&kcov_shm->cmp_nonconst.cmp_nonconst_arg1_unique,           __ATOMIC_RELAXED);
	unsigned long kc_cmp_nonconst_arg2_unique      = __atomic_load_n(&kcov_shm->cmp_nonconst.cmp_nonconst_arg2_unique,           __ATOMIC_RELAXED);
	unsigned long kc_cmp_nonconst_both_match       = __atomic_load_n(&kcov_shm->cmp_nonconst.cmp_nonconst_both_match,            __ATOMIC_RELAXED);
	unsigned long kc_cmp_nonconst_would_attribute  = __atomic_load_n(&kcov_shm->cmp_nonconst.cmp_nonconst_would_attribute,       __ATOMIC_RELAXED);
	unsigned long kc_cmp_nonconst_measured         = __atomic_load_n(&kcov_shm->cmp_nonconst.cmp_nonconst_measured,              __ATOMIC_RELAXED);
	unsigned long kc_cmp_width_pin_total           = __atomic_load_n(&kcov_shm->cmp_width_pin.cmp_width_pin_total,                __ATOMIC_RELAXED);
	unsigned long kc_cmp_width_pin_would_differ    = __atomic_load_n(&kcov_shm->cmp_width_pin.cmp_width_pin_would_differ,         __ATOMIC_RELAXED);
	unsigned long kc_cmp_hyp_pow2_derive_would_fire = __atomic_load_n(&kcov_shm->cmp_hyp_shadow.cmp_hyp_pow2_derive_would_fire,    __ATOMIC_RELAXED);
	unsigned long kc_cmp_hyp_pow2_derive_would_win  = __atomic_load_n(&kcov_shm->cmp_hyp_shadow.cmp_hyp_pow2_derive_would_win,     __ATOMIC_RELAXED);
	unsigned long kc_cmp_hyp_bm_full_or_would_fire     = __atomic_load_n(&kcov_shm->cmp_hyp_shadow.cmp_hyp_bitmask_full_or_would_fire,        __ATOMIC_RELAXED);
	unsigned long kc_cmp_hyp_bm_full_or_would_win      = __atomic_load_n(&kcov_shm->cmp_hyp_shadow.cmp_hyp_bitmask_full_or_would_win,         __ATOMIC_RELAXED);
	unsigned long kc_cmp_hyp_bm_andnot_would_fire      = __atomic_load_n(&kcov_shm->cmp_hyp_shadow.cmp_hyp_bitmask_andnot_toggle_would_fire,  __ATOMIC_RELAXED);
	unsigned long kc_cmp_hyp_bm_andnot_would_win       = __atomic_load_n(&kcov_shm->cmp_hyp_shadow.cmp_hyp_bitmask_andnot_toggle_would_win,   __ATOMIC_RELAXED);

	/* Shadow measurement of the non-const relational drop-site.
	 * Counts records the CMP loop drops today into
	 * cmp_hints_save_reject_nonconst but that a future relational-
	 * attribution lane could plausibly act on.  would_attribute is
	 * the actionable population (exactly one operand uniquely ours,
	 * the other side not ours at all).
	 *
	 * Two ratios are emitted because the denominators mean different
	 * things and neither can be recovered from the other post-hoc:
	 *
	 *   per_mille_dropped  -- share of ALL non-const drops that would
	 *     be actionable.  Denominator (reject_nonconst) includes every
	 *     early-out where rec_num_args==0 and the measurement never
	 *     ran (child==NULL, redqueen disabled, in_reexec, dispatch_
	 *     args invalid, reexec_pending full at entry).  Reads as
	 *     "of the whole drop stream, what fraction is reachable" --
	 *     useful for sizing the drop tax, understates lane hit-rate.
	 *
	 *   per_mille_measured -- share of ADDRESSABLE non-const records
	 *     (those where the shadow loop actually ran) that would be
	 *     actionable.  This is the honest lane hit-rate on the
	 *     population a relational lane could conceivably see. */
	if (kc_cmp_nonconst_arg1_unique > 0)
		stat_row("kcov_coverage", "cmp_nonconst_arg1_unique", kc_cmp_nonconst_arg1_unique);
	if (kc_cmp_nonconst_arg2_unique > 0)
		stat_row("kcov_coverage", "cmp_nonconst_arg2_unique", kc_cmp_nonconst_arg2_unique);
	if (kc_cmp_nonconst_both_match > 0)
		stat_row("kcov_coverage", "cmp_nonconst_both_match", kc_cmp_nonconst_both_match);
	if (kc_cmp_nonconst_would_attribute > 0)
		stat_row("kcov_coverage", "cmp_nonconst_would_attribute", kc_cmp_nonconst_would_attribute);
	if (kc_cmp_nonconst_measured > 0)
		stat_row("kcov_coverage", "cmp_nonconst_measured", kc_cmp_nonconst_measured);
	if (kc_cmp_save_reject_nonconst > 0) {
		unsigned long ratio_milli =
			(kc_cmp_nonconst_would_attribute * 1000UL) /
			kc_cmp_save_reject_nonconst;
		stat_row("kcov_coverage", "cmp_nonconst_would_attribute_per_mille_dropped", ratio_milli);
	}
	if (kc_cmp_nonconst_measured > 0) {
		unsigned long ratio_milli =
			(kc_cmp_nonconst_would_attribute * 1000UL) /
			kc_cmp_nonconst_measured;
		stat_row("kcov_coverage", "cmp_nonconst_would_attribute_per_mille_measured", ratio_milli);
	}

	/* Shadow measurement of a high-bit-preserving replacement for the
	 * width-masked CMP RedQueen pin.  cmp_width_pin_total counts every
	 * unique width-match stamp; cmp_width_pin_would_differ counts the
	 * subset where the matched slot carries non-zero bits outside
	 * width_mask, so a syzkaller-style splice (orig high bits | arg1
	 * low bits) would produce a value different from today's whole-
	 * slot overwrite with arg1.  Ratio in per-mille sizes the headroom
	 * a preserving lever would open up; the live pin is unchanged. */
	if (kc_cmp_width_pin_total > 0)
		stat_row("kcov_coverage", "cmp_width_pin_total", kc_cmp_width_pin_total);
	if (kc_cmp_width_pin_would_differ > 0)
		stat_row("kcov_coverage", "cmp_width_pin_would_differ", kc_cmp_width_pin_would_differ);
	if (kc_cmp_width_pin_total > 0) {
		unsigned long ratio_milli =
			(kc_cmp_width_pin_would_differ * 1000UL) /
			kc_cmp_width_pin_total;
		stat_row("kcov_coverage", "cmp_width_pin_would_differ_per_mille", ratio_milli);
	}

	/* Shadow measurement of a POW2 / alignment probe class in the
	 * typed-hypothesis derive.  cmp_hyp_pow2_derive_would_fire counts
	 * every derive whose callsite is a size / offset-class argtype
	 * (ARG_RANGE / ARG_STRUCT_SIZE) AND whose picked exemplar sits at
	 * or near a power of two, so a pow2 / align probe class would be
	 * eligible to emit.  cmp_hyp_pow2_derive_would_win counts the
	 * subset where at least one candidate from the {C>>1, C, C<<1,
	 * round-to-512, round-to-4096, round-to-page-size} ladder differs
	 * from the value the live derive lane just emitted, so the class
	 * would have contributed a value the existing lanes did not.
	 * The live derive is byte-for-byte unchanged; the ratio in
	 * per-mille sizes the coverage headroom of promoting the class. */
	if (kc_cmp_hyp_pow2_derive_would_fire > 0)
		stat_row("kcov_coverage", "cmp_hyp_pow2_derive_would_fire", kc_cmp_hyp_pow2_derive_would_fire);
	if (kc_cmp_hyp_pow2_derive_would_win > 0)
		stat_row("kcov_coverage", "cmp_hyp_pow2_derive_would_win", kc_cmp_hyp_pow2_derive_would_win);
	if (kc_cmp_hyp_pow2_derive_would_fire > 0) {
		unsigned long ratio_milli =
			(kc_cmp_hyp_pow2_derive_would_win * 1000UL) /
			kc_cmp_hyp_pow2_derive_would_fire;
		stat_row("kcov_coverage", "cmp_hyp_pow2_derive_would_win_per_mille", ratio_milli);
	}

	/* Shadow measurement of BITMASK combination probe classes in the
	 * typed-hypothesis derive.  Extends the live single-bit lane at
	 * (nr, cmp_ip, width) with two combo probes:
	 *
	 *   cmp_hyp_bitmask_full_or_would_fire counts every BITMASK derive
	 *   whose accumulated mask has popcount >= 2 (single-bit lane
	 *   picks ONE bit per fire, so any (flags & A) && (flags & B) gate
	 *   is unreachable structurally); cmp_hyp_bitmask_full_or_would_win
	 *   counts the subset where the full OR differs from the single-
	 *   bit value the live lane just emitted -- i.e. the FULL_OR combo
	 *   would have contributed a value the single-bit lane did not.
	 *
	 *   cmp_hyp_bitmask_andnot_toggle_would_fire counts every BITMASK
	 *   derive where the complement of the observed-bits set inside
	 *   the operand width holds 1..8 bits -- a plausible disallowed-
	 *   bit mask for an `x & ~c` allow-mask check;
	 *   cmp_hyp_bitmask_andnot_toggle_would_win counts the subset
	 *   where at least one (mask | one-disallowed-bit) candidate
	 *   differs from the value the live lane emitted, so a live
	 *   toggle sweep would surface a value the single-bit lane did
	 *   not.  The live derive is byte-for-byte unchanged; ratios in
	 *   per-mille size the coverage headroom of promoting either
	 *   class. */
	if (kc_cmp_hyp_bm_full_or_would_fire > 0)
		stat_row("kcov_coverage", "cmp_hyp_bitmask_full_or_would_fire", kc_cmp_hyp_bm_full_or_would_fire);
	if (kc_cmp_hyp_bm_full_or_would_win > 0)
		stat_row("kcov_coverage", "cmp_hyp_bitmask_full_or_would_win", kc_cmp_hyp_bm_full_or_would_win);
	if (kc_cmp_hyp_bm_full_or_would_fire > 0) {
		unsigned long ratio_milli =
			(kc_cmp_hyp_bm_full_or_would_win * 1000UL) /
			kc_cmp_hyp_bm_full_or_would_fire;
		stat_row("kcov_coverage", "cmp_hyp_bitmask_full_or_would_win_per_mille", ratio_milli);
	}
	if (kc_cmp_hyp_bm_andnot_would_fire > 0)
		stat_row("kcov_coverage", "cmp_hyp_bitmask_andnot_toggle_would_fire", kc_cmp_hyp_bm_andnot_would_fire);
	if (kc_cmp_hyp_bm_andnot_would_win > 0)
		stat_row("kcov_coverage", "cmp_hyp_bitmask_andnot_toggle_would_win", kc_cmp_hyp_bm_andnot_would_win);
	if (kc_cmp_hyp_bm_andnot_would_fire > 0) {
		unsigned long ratio_milli =
			(kc_cmp_hyp_bm_andnot_would_win * 1000UL) /
			kc_cmp_hyp_bm_andnot_would_fire;
		stat_row("kcov_coverage", "cmp_hyp_bitmask_andnot_toggle_would_win_per_mille", ratio_milli);
	}

	/* Walk the shadow-arm promotion registry after the counter
	 * rows have been rendered.  Measure-only: for each registered
	 * arm whose baseline / would-win pair meets the promotion
	 * criterion, one surfacing line is emitted; no generation
	 * path is touched, no live_flag is flipped.  See
	 * cmp_hints/shadow_promote.c for the criterion and the
	 * pilot arm registrations. */
	shadow_promotion_evaluate();
}

void __cold dump_stats_kcov_block(void)
{
	if (kcov_shm != NULL) {
		unsigned int nr_syscalls_to_scan;
		const struct syscalltable *table;

		dump_stats_render_kcov_base_stats();

		/* CMP-hint freshness / tier observability rollup.  See the
		 * counter-block comment in include/kcov.h next to
		 * cmp_hint_tier_recent_wins for the per-counter semantics.
		 * Gates on a non-zero summed value so a run that never
		 * exercised the consumer path stays silent in stats.  Per-
		 * bucket detail rendered as a compact tier_age_<n> row
		 * family so a downstream stats consumer can index by
		 * bucket without parsing a sub-structured value. */
		dump_stats_render_kcov_cmp_hint_tier();

		dump_stats_render_kcov_warm_known_hits();

		dump_stats_render_kcov_reexec();

		dump_stats_render_kcov_ring_replay();

		dump_stats_render_kcov_cmp_field_consumer();

		dump_stats_render_kcov_exit_edge_delta();

		dump_stats_render_kcov_exit_edge_totals();

		/* Setup shared by the top-edges / cold pass below and all
		 * top-N helpers that follow.  The biarch table choice + the
		 * MAX_NR_SYSCALL clamp are the same for every downstream
		 * scan so they're computed here once. */
		nr_syscalls_to_scan = biarch ? max_nr_64bit_syscalls : max_nr_syscalls;
		if (nr_syscalls_to_scan > MAX_NR_SYSCALL)
			nr_syscalls_to_scan = MAX_NR_SYSCALL;
		table = biarch ? syscalls_64bit : syscalls;

		dump_stats_render_kcov_top_edges_and_cold(nr_syscalls_to_scan, table);

		/* Per-syscall errno histogram.  Sibling to the top edge-
		 * producing / cold-syscalls tables above: same MAX_NR_SYSCALL-
		 * indexed walk, same all-zero-row skip, same column-width
		 * convention as the "Top edge-producing syscalls" block.  Eight
		 * buckets in dump order: success, EFAULT, EINVAL, ENOSYS,
		 * EPERM, EBADF, EAGAIN, other.  Bumped from handle_syscall_ret()
		 * next to where the existing entry->failures / entry->errnos[]
		 * tallies are updated.  Sort order matches the top-edges block:
		 * descending by total syscall activity (sum of all eight
		 * buckets) so the syscalls doing the most work appear first. */
		dump_stats_render_kcov_per_syscall_yield_topn(nr_syscalls_to_scan, table);

		/* Credential-class oracle dump.  Always-on observability:
		 * per-class call / success / EPERM / EINVAL / throttled
		 * counts so the operator can spot a class burning attempts
		 * with zero successes (the diagnostic signature the throttle
		 * exists to fix) without grepping the per-syscall errno
		 * histogram for the nine credential names by hand.  The
		 * `throttled` column is bumped only when --cred-throttle is
		 * on and the gate fired; non-zero values double as a "flag
		 * was active and engaged" indicator.  Silent when no class
		 * has any activity. */
		dump_stats_render_kcov_kcov_dispatch_stats();

		/* per-syscall +
		 * per-childop local-vs-remote PC yield, top-N by combined
		 * call count.  Lets the operator see whether a static
		 * remote-sampling policy is spending samples on a mode that
		 * yields no fresh edges -- the global remote_calls counter
		 * above can't answer that question.  Silent when no slot has
		 * any combined activity; columns: calls / edge-calls /
		 * raw-edge-count per mode. */
		dump_stats_render_kcov_per_syscall_dedup_topn(nr_syscalls_to_scan, table);
		dump_stats_render_kcov_kcov_probe_costs();

		/* Per-syscall + per-childop view of remote-edge yield,
		 * sorted by REMOTE edge count.  The combined-calls block
		 * above ranks by traffic; this one ranks by what actually
		 * fell out of remote-mode collection so the operator can
		 * see which slots are paying the cost of remote sampling
		 * vs. which are silent on that arm.  Render-only over the
		 * existing per_syscall/childop local|remote counters.  The
		 * flag column tags rows whose remote eCount is >= 50% of
		 * the leader across both sub-tables (HEAVY); the rate
		 * columns show local and remote edge-call yield (edge
		 * calls per call). */
		dump_stats_render_kcov_remote_edge_producers(nr_syscalls_to_scan, table);

		/* Per-syscall view of slots whose edge-producing calls
		 * arrived EXCLUSIVELY on the remote arm (loc_eCalls == 0
		 * && rem_eCalls > 0), sorted by remote edges per remote
		 * edge-producing call.  The rem_eCount-ranked block above
		 * pulls in any slot the remote arm produces on, including
		 * the ones the local arm also finds, so a slot whose
		 * entire edge signal comes from remote sampling can be
		 * drowned out there.  This block lists those slots in
		 * isolation and orders by yield density (rem_eCount /
		 * rem_eCalls), giving a direct read on which
		 * exclusively-remote syscalls are paying for the cost of
		 * remote-mode collection.  Render-only over the existing
		 * per-syscall local|remote counters; no new shm. */
		dump_stats_render_kcov_per_syscall_last_edge_topn(nr_syscalls_to_scan, table);

		/* Per-syscall remote-enable health, sorted by the
		 * req - succ gap.  The four counters partition the
		 * kcov_enable_remote() path itself: requested is
		 * bumped once control is past the early-out and the
		 * KCOV_REMOTE_ENABLE ioctl is about to be attempted;
		 * succeeded once that ioctl returns 0; failed once
		 * it exhausts its EINTR retries or returns a
		 * non-EINTR error and flips remote_capable=false;
		 * remote_fallback_to_local once the PC-mode fallback
		 * ioctl that follows such a failure itself
		 * succeeds.  The yield-side local|remote split
		 * blocks above can only fold a refused remote enable
		 * into the local-mode column (the same child still
		 * produced PC-mode coverage via fallback), so a
		 * HEAVY-flagged slot whose KCOV_REMOTE_ENABLE
		 * consistently fails reads there as "zero remote
		 * yield" indistinguishable from "remote was sampled
		 * and the kernel ran the work on the calling task".
		 * Looking at req - succ directly per syscall surfaces
		 * the refusal surface the yield columns hide.
		 * Render-only over the existing per-syscall counters
		 * declared in include/kcov.h; no new shm, no
		 * behaviour change. */
		dump_stats_render_kcov_per_syscall_last_efault_topn(nr_syscalls_to_scan, table);

		/* Per-syscall view of slots whose remote-mode enable was
		 * attempted at least REMOTE_WASTE_FLOOR times yet produced
		 * zero remote edges, sorted by remote-enable requested.
		 * The rem_eCount-ranked and remote-only views above pull
		 * in slots that DO yield on the remote arm; this block is
		 * the inverse cut, lifting out the slots where remote
		 * sampling has paid its KCOV_REMOTE_ENABLE / disable
		 * round-trip cost enough times to be statistically
		 * meaningful and earned nothing back, so the operator can
		 * read the demote-candidate list directly.  HEAVY is
		 * surfaced in its own column because the same condition
		 * on a HEAVY-flagged syscall is the loudest signal: the
		 * syscall is paying the heavier sampling rate and still
		 * carrying zero remote yield.  The waste verdict gates on
		 * remote_enable_requested (bumped on entry to the
		 * KCOV_REMOTE_ENABLE attempt) rather than remote_pc_calls
		 * (bumped only on a successful collect) so a syscall whose
		 * enable consistently falls back to local-mode PC coverage
		 * is not hidden by its own refusal surface; succ and fail
		 * are printed alongside so a "wasted" reading can be split
		 * into "sampled enough and produced no edge" vs "rarely
		 * even successfully sampled".  Render-only over the
		 * existing per-syscall counters declared in include/kcov.h;
		 * no new shm, no behaviour change to the collection or
		 * fuzzing path.  No childop variant: the per-childop
		 * remote-enable counters the verdict needs do not exist
		 * (childop enable accounting was intentionally deferred). */
		dump_stats_render_kcov_per_syscall_local_pc_topn(nr_syscalls_to_scan, table);

		/* combined top-N
		 * trace_truncated + cmp_trace_truncated + max_trace_size
		 * table plus a dedup-probe-overflow summary line.  Lets
		 * buffer-policy decisions read off the cross-counter signal
		 * (saturate-without-trunc vs trunc-with-modest-max) that
		 * the per-counter blocks below flatten.  Diagnostic only. */
		kcov_diag_emit_truncation_topn();

		/* Per-syscall KCOV diagnostic blocks.  See kcov_diag_emit_block:
		 * one top-20-non-zero block per counter, alphabetical by
		 * counter name, silent when no syscall has a non-zero
		 * value. */
		kcov_diag_emit_block("bucket_bits_real",
				     KCOV_DIAG_BUCKET_BITS_REAL);
		kcov_diag_emit_block("cmp_trace_truncated",
				     KCOV_DIAG_CMP_TRACE_TRUNCATED);
		kcov_diag_emit_block("dedup_probe_overflow",
				     KCOV_DIAG_DEDUP_PROBE_OVERFLOW);
		kcov_diag_emit_block("distinct_pcs",
				     KCOV_DIAG_DISTINCT_PCS);
		kcov_diag_emit_block("max_trace_size",
				     KCOV_DIAG_MAX_TRACE_SIZE);
		kcov_diag_emit_block("trace_truncated",
				     KCOV_DIAG_TRACE_TRUNCATED);
	}
}
