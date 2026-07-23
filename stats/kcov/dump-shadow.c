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

void dump_stats_render_kcov_kcov_dispatch_stats(void)
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


void dump_stats_render_kcov_kcov_probe_costs(void)
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
	 * width_mask, so an upper-bit-preserving splice (orig high bits |
	 * arg1 low bits) would produce a value different from today's whole-
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
