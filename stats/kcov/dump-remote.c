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

/* Helpers shared by the "Top remote-edge producers" view in
 * dump_stats_kcov_block().  The view emits one row per top syscall
 * AND one row per top childop with the same column shape, so both
 * the flag-lookup and the yield-format live here to keep the two
 * render loops free of duplicated logic. */
static void remote_edge_row_flags(char *buf, size_t bufsz,
				  unsigned long row_remote_ecount,
				  unsigned long max_remote_ecount)
{
	/* HEAVY: row carries >= 50% of the leader's remote eCount.
	 * One max is computed across BOTH the syscall and childop
	 * scans before render, so the H mark means the same thing
	 * in either sub-table. */
	bool heavy = (max_remote_ecount > 0) &&
		     (row_remote_ecount * 2 >= max_remote_ecount);

	snprintf(buf, bufsz, "%s", heavy ? "H" : "-");
}

static void remote_edge_format_yield(char *buf, size_t bufsz,
				     unsigned long edge_calls,
				     unsigned long calls)
{
	unsigned long milli;

	if (calls == 0) {
		snprintf(buf, bufsz, "%s", "  --");
		return;
	}
	milli = (edge_calls * 1000UL) / calls;
	if (milli > 1000)
		milli = 1000;
	snprintf(buf, bufsz, "%lu.%03lu", milli / 1000, milli % 1000);
}
void dump_stats_render_kcov_remote_edge_producers(unsigned int nr_syscalls_to_scan, const struct syscalltable *table)
{
	unsigned int i, j;

		unsigned int re_top_nr[10];
		unsigned long re_top_rec[10];
		unsigned int re_top_count = 0;
		unsigned int op_top_id[10];
		unsigned long op_top_rec[10];
		unsigned int op_top_count = 0;
		unsigned long max_rec = 0;
		unsigned int op;

		memset(re_top_rec, 0, sizeof(re_top_rec));
		memset(op_top_rec, 0, sizeof(op_top_rec));

		for (i = 0; i < nr_syscalls_to_scan; i++) {
			unsigned long rec = __atomic_load_n(
				&kcov_shm->pc_ctx.remote_pc_edge_count[i],
				__ATOMIC_RELAXED);

			if (rec == 0)
				continue;
			if (rec > max_rec)
				max_rec = rec;
			topn_push(re_top_rec, re_top_nr,
				  &re_top_count, 10, rec, i);
		}
		for (op = 0; op < KCOV_CHILDOP_NR_MAX; op++) {
			unsigned long rec = __atomic_load_n(
				&kcov_shm->pc_ctx.childop_remote_pc_edge_count[op],
				__ATOMIC_RELAXED);

			if (rec == 0)
				continue;
			if (rec > max_rec)
				max_rec = rec;
			topn_push(op_top_rec, op_top_id,
				  &op_top_count, 10, rec, op);
		}

		if (re_top_count > 0 || op_top_count > 0) {
			output(0, "Top remote-edge producers (by rem_eCount):\n");
			output(0, "  %-2s %-24s %10s %10s %10s %10s %10s %10s %6s %6s\n",
			       "fl", "entry",
			       "loc_calls", "loc_eCalls", "loc_eCount",
			       "rem_calls", "rem_eCalls", "rem_eCount",
			       "loc_r", "rem_r");
		}

		for (j = 0; j < re_top_count; j++) {
			struct syscallentry *entry =
				table[re_top_nr[j]].entry;
			const char *name = entry ? entry->name : "???";
			unsigned int nr = re_top_nr[j];
			unsigned long lc = __atomic_load_n(
				&kcov_shm->pc_ctx.local_pc_calls[nr],
				__ATOMIC_RELAXED);
			unsigned long lec = __atomic_load_n(
				&kcov_shm->pc_ctx.local_pc_edge_calls[nr],
				__ATOMIC_RELAXED);
			unsigned long len_ = __atomic_load_n(
				&kcov_shm->pc_ctx.local_pc_edge_count[nr],
				__ATOMIC_RELAXED);
			unsigned long rc = __atomic_load_n(
				&kcov_shm->pc_ctx.remote_pc_calls[nr],
				__ATOMIC_RELAXED);
			unsigned long rec = __atomic_load_n(
				&kcov_shm->pc_ctx.remote_pc_edge_calls[nr],
				__ATOMIC_RELAXED);
			unsigned long ren = re_top_rec[j];
			char fbuf[4], lrate[8], rrate[8];

			remote_edge_row_flags(fbuf, sizeof(fbuf),
					      ren, max_rec);
			remote_edge_format_yield(lrate, sizeof(lrate),
						 lec, lc);
			remote_edge_format_yield(rrate, sizeof(rrate),
						 rec, rc);
			output(0, "  %-2s %-24s %10lu %10lu %10lu %10lu %10lu %10lu %6s %6s\n",
			       fbuf, name, lc, lec, len_,
			       rc, rec, ren, lrate, rrate);
		}
		for (j = 0; j < op_top_count; j++) {
			unsigned int op_id = op_top_id[j];
			const char *opname = alt_op_name(
				(enum child_op_type)op_id);
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
			unsigned long ren = op_top_rec[j];
			char fbuf[4], lrate[8], rrate[8];

			remote_edge_row_flags(fbuf, sizeof(fbuf),
					      ren, max_rec);
			remote_edge_format_yield(lrate, sizeof(lrate),
						 lec, lc);
			remote_edge_format_yield(rrate, sizeof(rrate),
						 rec, rc);
			output(0, "  %-2s %-24s %10lu %10lu %10lu %10lu %10lu %10lu %6s %6s\n",
			       fbuf, opname, lc, lec, len_,
			       rc, rec, ren, lrate, rrate);
		}
}
void dump_stats_render_kcov_per_syscall_last_edge_topn(unsigned int nr_syscalls_to_scan, const struct syscalltable *table)
{
	unsigned int i, j;

		unsigned int ro_top_nr[10];
		unsigned long ro_top_rate[10];
		unsigned int ro_top_count = 0;

		memset(ro_top_rate, 0, sizeof(ro_top_rate));

		for (i = 0; i < nr_syscalls_to_scan; i++) {
			unsigned long lec = __atomic_load_n(
				&kcov_shm->pc_ctx.local_pc_edge_calls[i],
				__ATOMIC_RELAXED);
			unsigned long rec = __atomic_load_n(
				&kcov_shm->pc_ctx.remote_pc_edge_calls[i],
				__ATOMIC_RELAXED);
			unsigned long ren, rate;

			if (lec != 0 || rec == 0)
				continue;
			ren = __atomic_load_n(
				&kcov_shm->pc_ctx.remote_pc_edge_count[i],
				__ATOMIC_RELAXED);
			/* rec > 0 here; ren >= rec by
			 * construction so rate is >= 1.000. */
			rate = (ren * 1000UL) / rec;
			topn_push(ro_top_rate, ro_top_nr,
				  &ro_top_count, 10, rate, i);
		}

		if (ro_top_count > 0) {
			output(0, "Remote-only edge winners (by rem_eCount/rem_eCalls):\n");
			output(0, "  %-24s %10s %10s %10s %10s %8s\n",
			       "syscall", "loc_calls", "rem_calls",
			       "rem_eCalls", "rem_eCount", "rate");
			for (j = 0; j < ro_top_count; j++) {
				struct syscallentry *entry =
					table[ro_top_nr[j]].entry;
				const char *name = entry ? entry->name : "???";
				unsigned int nr = ro_top_nr[j];
				unsigned long milli = ro_top_rate[j];
				unsigned long lc = __atomic_load_n(
					&kcov_shm->pc_ctx.local_pc_calls[nr],
					__ATOMIC_RELAXED);
				unsigned long rc = __atomic_load_n(
					&kcov_shm->pc_ctx.remote_pc_calls[nr],
					__ATOMIC_RELAXED);
				unsigned long rec = __atomic_load_n(
					&kcov_shm->pc_ctx.remote_pc_edge_calls[nr],
					__ATOMIC_RELAXED);
				unsigned long ren = __atomic_load_n(
					&kcov_shm->pc_ctx.remote_pc_edge_count[nr],
					__ATOMIC_RELAXED);

				output(0, "  %-24s %10lu %10lu %10lu %10lu %4lu.%03lu\n",
				       name, lc, rc, rec, ren,
				       milli / 1000, milli % 1000);
			}
		}
}
void dump_stats_render_kcov_per_syscall_last_efault_topn(unsigned int nr_syscalls_to_scan, const struct syscalltable *table)
{
	unsigned int i, j;

		unsigned int re_top_nr[10];
		unsigned long re_top_gap[10];
		unsigned int re_top_count = 0;

		memset(re_top_gap, 0, sizeof(re_top_gap));

		for (i = 0; i < nr_syscalls_to_scan; i++) {
			unsigned long req = __atomic_load_n(
				&kcov_shm->remote_enable.remote_enable_requested[i],
				__ATOMIC_RELAXED);
			unsigned long succ;
			unsigned long gap;

			if (req == 0)
				continue;
			succ = __atomic_load_n(
				&kcov_shm->remote_enable.remote_enable_succeeded[i],
				__ATOMIC_RELAXED);
			/* req and succ are bumped on separate
			 * RELAXED stores in kcov_enable_remote();
			 * under pressure a reader can sample
			 * succ ahead of its matching req bump.
			 * Clamp the unsigned subtraction so a
			 * torn sample never wraps to ~ULONG_MAX. */
			gap = succ >= req ? 0 : req - succ;
			topn_push(re_top_gap, re_top_nr,
				  &re_top_count, 10, gap, i);
		}

		if (re_top_count > 0) {
			output(0, "Per-syscall remote-enable health (by req-succ gap):\n");
			output(0, "  %-24s %10s %10s %10s %10s %10s %8s\n",
			       "syscall", "req", "succ", "fail",
			       "fb_loc", "gap", "gRate");
			for (j = 0; j < re_top_count; j++) {
				struct syscallentry *entry =
					table[re_top_nr[j]].entry;
				const char *name = entry ? entry->name : "???";
				unsigned int nr = re_top_nr[j];
				unsigned long req = __atomic_load_n(
					&kcov_shm->remote_enable.remote_enable_requested[nr],
					__ATOMIC_RELAXED);
				unsigned long succ = __atomic_load_n(
					&kcov_shm->remote_enable.remote_enable_succeeded[nr],
					__ATOMIC_RELAXED);
				unsigned long fail = __atomic_load_n(
					&kcov_shm->remote_enable.remote_enable_failed[nr],
					__ATOMIC_RELAXED);
				unsigned long fbl = __atomic_load_n(
					&kcov_shm->remote_enable.remote_fallback_to_local[nr],
					__ATOMIC_RELAXED);
				unsigned long gap = succ >= req ? 0 : req - succ;
				unsigned long milli = (gap * 1000UL) / req;

				output(0, "  %-24s %10lu %10lu %10lu %10lu %10lu %4lu.%03lu\n",
				       name, req, succ, fail, fbl, gap,
				       milli / 1000, milli % 1000);
			}
		}
}
void dump_stats_render_kcov_per_syscall_local_pc_topn(unsigned int nr_syscalls_to_scan, const struct syscalltable *table)
{
	unsigned int i, j;

		unsigned int w_top_nr[10];
		unsigned long w_top_req[10];
		unsigned int w_top_count = 0;

		memset(w_top_req, 0, sizeof(w_top_req));

		for (i = 0; i < nr_syscalls_to_scan; i++) {
			unsigned long req = __atomic_load_n(
				&kcov_shm->remote_enable.remote_enable_requested[i],
				__ATOMIC_RELAXED);
			unsigned long rec;

			if (req < REMOTE_WASTE_FLOOR)
				continue;
			rec = __atomic_load_n(
				&kcov_shm->pc_ctx.remote_pc_edge_calls[i],
				__ATOMIC_RELAXED);
			if (rec != 0)
				continue;
			topn_push(w_top_req, w_top_nr,
				  &w_top_count, 10, req, i);
		}

		if (w_top_count > 0) {
			output(0, "Wasted-remote syscalls (req >= %lu, rem_eCalls == 0):\n",
			       REMOTE_WASTE_FLOOR);
			output(0, "  %-2s %-24s %10s %10s %10s %10s %10s %10s\n",
			       "fl", "syscall",
			       "req", "succ", "fail", "fb_loc",
			       "rem_calls", "rem_eCount");
			for (j = 0; j < w_top_count; j++) {
				struct syscallentry *entry =
					table[w_top_nr[j]].entry;
				const char *name = entry ? entry->name : "???";
				unsigned int nr = w_top_nr[j];
				unsigned long req = w_top_req[j];
				unsigned long succ = __atomic_load_n(
					&kcov_shm->remote_enable.remote_enable_succeeded[nr],
					__ATOMIC_RELAXED);
				unsigned long fail = __atomic_load_n(
					&kcov_shm->remote_enable.remote_enable_failed[nr],
					__ATOMIC_RELAXED);
				unsigned long fbl = __atomic_load_n(
					&kcov_shm->remote_enable.remote_fallback_to_local[nr],
					__ATOMIC_RELAXED);
				unsigned long rc = __atomic_load_n(
					&kcov_shm->pc_ctx.remote_pc_calls[nr],
					__ATOMIC_RELAXED);
				unsigned long ren = __atomic_load_n(
					&kcov_shm->pc_ctx.remote_pc_edge_count[nr],
					__ATOMIC_RELAXED);
				bool heavy = entry &&
					(entry->flags & KCOV_REMOTE_HEAVY);

				output(0, "  %-2s %-24s %10lu %10lu %10lu %10lu %10lu %10lu\n",
				       heavy ? "H" : "-", name,
				       req, succ, fail, fbl, rc, ren);
			}
		}
}
