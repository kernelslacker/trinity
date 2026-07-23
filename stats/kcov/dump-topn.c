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

static void dump_stats_render_kcov_per_syscall_edges_topn(unsigned int nr_syscalls_to_scan, const struct syscalltable *table)
{
	unsigned int i, j;

		unsigned int delta_nr[10];
		unsigned long delta_edges[10];
		unsigned int delta_count = 0;
		bool any_delta = false;

		memset(delta_edges, 0, sizeof(delta_edges));
		for (i = 0; i < nr_syscalls_to_scan; i++) {
			unsigned long prev = per_syscall_edges_previous_total(i);
			unsigned long curr = per_syscall_edges_total(i);
			unsigned long delta = sat_sub_ul(curr, prev);

			if (delta > 0)
				any_delta = true;

			if (delta == 0)
				continue;

			topn_push(delta_edges, delta_nr, &delta_count, 10, delta, i);
		}

		if (any_delta && delta_count > 0) {
			output(0, "Top syscalls by recent edge growth:\n");
			for (j = 0; j < delta_count; j++) {
				struct syscallentry *entry = table[delta_nr[j]].entry;
				const char *name = entry ? entry->name : "???";

				output(0, "  %-24s +%lu\n", name, delta_edges[j]);
			}
		}

		/* Snapshot current counts for the next interval.  Both arch
		 * slots are snapshotted so the [nr][arch] delta stays a pure
		 * subtraction on the next window. */
		for (i = 0; i < nr_syscalls_to_scan; i++) {
			kcov_shm->per_syscall.per_syscall_edges_previous[i][0] =
				__atomic_load_n(
					&kcov_shm->per_syscall.per_syscall_edges[i][0],
					__ATOMIC_RELAXED);
			kcov_shm->per_syscall.per_syscall_edges_previous[i][1] =
				__atomic_load_n(
					&kcov_shm->per_syscall.per_syscall_edges[i][1],
					__ATOMIC_RELAXED);
		}
}
/*
 * SHADOW-only Phase-1 per-syscall attribution-confidence diagnostic
 * dump.  Silent when frontier_noise_sample == 0 (feature off => no
 * samples collected => no rows to render) or when kcov_shm is
 * unavailable.  Prints a top-N by sampled noisy-window count of the
 * per-syscall clean numerator, the sampled global-delta denominator
 * (scaled back up by N so the reported figure estimates the full-
 * population delta), the resulting attribution-confidence ratio
 * (clean_frac = clean / est_noisy, clamped denominator), the local-
 * only clean subset (clean - clean_remote), and the spare-cascade
 * lane the frontier picker would use for this syscall.  Purely
 * observational -- no counter reset, no back-pressure on selection.
 * The spare-lane column consumes frontier_spare_lane_decide from
 * include/strategy.h so this dump and the cooldown helpers stay in
 * lockstep on how a syscall is classified.
 */
static void dump_stats_render_kcov_per_syscall_noisy_topn(unsigned int nr_syscalls_to_scan, const struct syscalltable *table)
{
	unsigned int i, j;
	unsigned int noisy_sample_n;
	unsigned int top_nr[10];
	unsigned long top_samples[10];
	unsigned int top_count = 0;
	bool any_samples = false;

	noisy_sample_n = __atomic_load_n(&frontier_noise_sample,
					 __ATOMIC_RELAXED);
	if (noisy_sample_n == 0 || kcov_shm == NULL)
		return;

	memset(top_samples, 0, sizeof(top_samples));
	for (i = 0; i < nr_syscalls_to_scan; i++) {
		unsigned long samples = __atomic_load_n(
			&kcov_shm->per_syscall.per_syscall_noisy_samples[i],
			__ATOMIC_RELAXED);

		if (samples == 0)
			continue;
		any_samples = true;
		topn_push(top_samples, top_nr, &top_count, 10, samples, i);
	}

	if (!any_samples || top_count == 0)
		return;

	output(0, "Top syscalls by sampled noisy attribution (N=%u, SHADOW):\n",
	       noisy_sample_n);
	output(0, "  %-24s %10s %10s %14s %14s %14s %10s\n",
	       "name", "samples", "clean", "est_noisy",
	       "clean/est_noisy", "clean_local", "spare_lane");
	for (j = 0; j < top_count; j++) {
		struct syscallentry *entry = table[top_nr[j]].entry;
		const char *name = entry ? entry->name : "???";
		unsigned int nr = top_nr[j];
		unsigned long samples = top_samples[j];
		unsigned long clean = per_syscall_edges_total(nr);
		unsigned long clean_remote = __atomic_load_n(
			&kcov_shm->per_syscall.per_syscall_edges_clean_remote[nr],
			__ATOMIC_RELAXED);
		unsigned long noisy_raw = __atomic_load_n(
			&kcov_shm->per_syscall.per_syscall_edges_noisy[nr],
			__ATOMIC_RELAXED);
		unsigned long est_noisy;
		unsigned long clean_local;
		unsigned long frac_permille;
		enum frontier_spare_reason reason;
		const char *lane;

		/* Scale the sampled delta sum back up by N to estimate the
		 * full-population noisy denominator.  samples is guaranteed
		 * non-zero on the topn path. */
		est_noisy = (noisy_raw * (unsigned long) noisy_sample_n) / samples;
		clean_local = (clean >= clean_remote) ? (clean - clean_remote) : 0UL;
		/* Report clean / max(1, est_noisy) as permille (three-digit
		 * fraction so a 12.3% confidence renders as "123"), matching
		 * the tt_call_str shape used in the truncation top-N dump. */
		{
			unsigned long denom = est_noisy > 0 ? est_noisy : 1UL;

			frac_permille = (clean * 1000UL) / denom;
		}
		/* Read the spare-cascade lane for the 64-bit slot (do32=false)
		 * -- the diagnostic dump does not split by arch elsewhere and
		 * the 64-bit slot is the dominant caller for every non-IA32-
		 * only syscall.  Callers reading a biarch nr's IA32 side can
		 * still cross-reference the arch split via per_syscall_edges
		 * total. */
		reason = frontier_spare_lane_decide(nr, false);
		switch (reason) {
		case FRONTIER_SPARE_WINDOWED_EDGES: lane = "windowed"; break;
		case FRONTIER_SPARE_ARGGEN:         lane = "arggen"; break;
		case FRONTIER_SPARE_OBJPRODUCER:    lane = "objprod"; break;
		default:                            lane = "none"; break;
		}

		output(0, "  %-24s %10lu %10lu %14lu %11lu.%1lu%% %14lu %10s\n",
		       name, samples, clean, est_noisy,
		       frac_permille / 10, frac_permille % 10,
		       clean_local, lane);
	}
}
static void dump_stats_render_kcov_per_syscall_calls_topn(unsigned int nr_syscalls_to_scan, const struct syscalltable *table)
{
	unsigned int i, j;

		unsigned int tr_top_nr[10];
		unsigned long tr_top_edges[10];
		unsigned int tr_top_count = 0;
		bool any_tr = false;

		memset(tr_top_edges, 0, sizeof(tr_top_edges));
		for (i = 0; i < nr_syscalls_to_scan; i++) {
			unsigned long tedges = __atomic_load_n(
				&kcov_shm->transitions.per_syscall_transition_edges_real[i],
				__ATOMIC_RELAXED);

			if (tedges == 0)
				continue;
			any_tr = true;
			topn_push(tr_top_edges, tr_top_nr, &tr_top_count,
				  10, tedges, i);
		}

		if (any_tr && tr_top_count > 0) {
			output(0, "Top transition-producing syscalls (shadow):\n");
			for (j = 0; j < tr_top_count; j++) {
				struct syscallentry *entry = table[tr_top_nr[j]].entry;
				const char *name = entry ? entry->name : "???";

				output(0, "  %-24s %lu\n",
				       name, tr_top_edges[j]);
			}
		}
}
static void dump_stats_render_kcov_per_syscall_edge_calls_topn(unsigned int nr_syscalls_to_scan, const struct syscalltable *table)
{
	unsigned int i, j;

		unsigned int tr_delta_nr[10];
		unsigned long tr_delta_edges[10];
		unsigned int tr_delta_count = 0;
		bool any_tr_delta = false;

		memset(tr_delta_edges, 0, sizeof(tr_delta_edges));
		for (i = 0; i < nr_syscalls_to_scan; i++) {
			unsigned long prev = kcov_shm->transitions.per_syscall_transition_edges_previous[i];
			unsigned long curr = __atomic_load_n(
				&kcov_shm->transitions.per_syscall_transition_edges[i],
				__ATOMIC_RELAXED);
			unsigned long delta = sat_sub_ul(curr, prev);

			if (delta > 0)
				any_tr_delta = true;
			if (delta == 0)
				continue;

			topn_push(tr_delta_edges, tr_delta_nr,
				  &tr_delta_count, 10, delta, i);
		}

		if (any_tr_delta && tr_delta_count > 0) {
			output(0, "Top syscalls by recent transition growth (shadow):\n");
			for (j = 0; j < tr_delta_count; j++) {
				struct syscallentry *entry = table[tr_delta_nr[j]].entry;
				const char *name = entry ? entry->name : "???";

				output(0, "  %-24s +%lu\n",
				       name, tr_delta_edges[j]);
			}
		}

		for (i = 0; i < nr_syscalls_to_scan; i++)
			kcov_shm->transitions.per_syscall_transition_edges_previous[i] =
				__atomic_load_n(
					&kcov_shm->transitions.per_syscall_transition_edges[i],
					__ATOMIC_RELAXED);
}
static void dump_stats_render_kcov_per_syscall_cold_topn(unsigned int nr_syscalls_to_scan, const struct syscalltable *table)
{
	unsigned int i, j;

		unsigned int cmp_delta_nr[10];
		unsigned long cmp_delta_inserts[10];
		unsigned int cmp_delta_count = 0;
		bool any_cmp_delta = false;

		memset(cmp_delta_inserts, 0, sizeof(cmp_delta_inserts));
		for (i = 0; i < nr_syscalls_to_scan; i++) {
			unsigned long prev = kcov_shm->per_syscall_cmp.per_syscall_cmp_inserts_previous[i];
			unsigned long curr = __atomic_load_n(&kcov_shm->per_syscall_cmp.per_syscall_cmp_inserts[i], __ATOMIC_RELAXED);
			unsigned long delta = sat_sub_ul(curr, prev);

			if (delta > 0)
				any_cmp_delta = true;

			if (delta == 0)
				continue;

			topn_push(cmp_delta_inserts, cmp_delta_nr, &cmp_delta_count, 10, delta, i);
		}

		if (any_cmp_delta && cmp_delta_count > 0) {
			output(0, "Top syscalls by CMP unique inserts (since last dump):\n");
			for (j = 0; j < cmp_delta_count; j++) {
				struct syscallentry *entry = table[cmp_delta_nr[j]].entry;
				const char *name = entry ? entry->name : "???";

				output(0, "  %-24s +%lu\n", name, cmp_delta_inserts[j]);
			}
		}

		for (i = 0; i < nr_syscalls_to_scan; i++)
			kcov_shm->per_syscall_cmp.per_syscall_cmp_inserts_previous[i] =
				__atomic_load_n(&kcov_shm->per_syscall_cmp.per_syscall_cmp_inserts[i], __ATOMIC_RELAXED);
}
void dump_stats_render_kcov_per_syscall_yield_topn(unsigned int nr_syscalls_to_scan, const struct syscalltable *table)
{
	unsigned int i, j;

		unsigned int errno_top_nr[10];
		unsigned long errno_top_total[10];
		unsigned long errno_top_buckets[10][ERRNO_BUCKET_NR];
		unsigned int errno_top_count = 0;

		memset(errno_top_total, 0, sizeof(errno_top_total));
		memset(errno_top_buckets, 0, sizeof(errno_top_buckets));

		for (i = 0; i < nr_syscalls_to_scan; i++) {
			unsigned long buckets[ERRNO_BUCKET_NR];
			unsigned long total = 0;
			unsigned int b;

			for (b = 0; b < ERRNO_BUCKET_NR; b++) {
				buckets[b] = __atomic_load_n(&kcov_shm->errno_state.per_syscall_errno[i][b],
							     __ATOMIC_RELAXED);
				total += buckets[b];
			}

			/* Skip rows where all eight buckets are zero --
			 * mirrors the top-edges block's `edges == 0`
			 * skip.  A syscall that was never attempted (or
			 * was attempted but never reached AFTER) contributes
			 * nothing and would just be table noise. */
			if (total == 0)
				continue;

			/* Insertion sort, same shape as the top-edges block. */
			for (j = errno_top_count;
			     j > 0 && total > errno_top_total[j - 1]; j--) {
				if (j < 10) {
					errno_top_total[j] = errno_top_total[j - 1];
					errno_top_nr[j] = errno_top_nr[j - 1];
					memcpy(errno_top_buckets[j],
					       errno_top_buckets[j - 1],
					       sizeof(errno_top_buckets[j]));
				}
			}
			if (j < 10) {
				errno_top_total[j] = total;
				errno_top_nr[j] = i;
				memcpy(errno_top_buckets[j], buckets,
				       sizeof(errno_top_buckets[j]));
				if (errno_top_count < 10)
					errno_top_count++;
			}
		}

		if (errno_top_count > 0) {
			output(0, "Top syscalls by errno-histogram activity:\n");
			output(0, "  %-24s %10s %8s %8s %8s %8s %8s %8s %8s\n",
			       "syscall", "ok", "EFAULT", "EINVAL",
			       "ENOSYS", "EPERM", "EBADF", "EAGAIN", "other");
			for (j = 0; j < errno_top_count; j++) {
				struct syscallentry *entry = table[errno_top_nr[j]].entry;
				const char *name = entry ? entry->name : "???";

				output(0, "  %-24s %10lu %8lu %8lu %8lu %8lu %8lu %8lu %8lu\n",
				       name,
				       errno_top_buckets[j][ERRNO_BUCKET_SUCCESS],
				       errno_top_buckets[j][ERRNO_BUCKET_EFAULT],
				       errno_top_buckets[j][ERRNO_BUCKET_EINVAL],
				       errno_top_buckets[j][ERRNO_BUCKET_ENOSYS],
				       errno_top_buckets[j][ERRNO_BUCKET_EPERM],
				       errno_top_buckets[j][ERRNO_BUCKET_EBADF],
				       errno_top_buckets[j][ERRNO_BUCKET_EAGAIN],
				       errno_top_buckets[j][ERRNO_BUCKET_OTHER]);
			}
		}
}
void dump_stats_render_kcov_per_syscall_dedup_topn(unsigned int nr_syscalls_to_scan, const struct syscalltable *table)
{
	unsigned int i, j;

		unsigned int lr_top_nr[10];
		unsigned long lr_top_total[10];
		unsigned int lr_top_count = 0;

		memset(lr_top_total, 0, sizeof(lr_top_total));
		for (i = 0; i < nr_syscalls_to_scan; i++) {
			unsigned long lc = __atomic_load_n(
				&kcov_shm->pc_ctx.local_pc_calls[i],
				__ATOMIC_RELAXED);
			unsigned long rc = __atomic_load_n(
				&kcov_shm->pc_ctx.remote_pc_calls[i],
				__ATOMIC_RELAXED);
			unsigned long tot = lc + rc;

			if (tot == 0)
				continue;
			topn_push(lr_top_total, lr_top_nr,
				  &lr_top_count, 10, tot, i);
		}
		if (lr_top_count > 0) {
			output(0, "Local vs remote PC yield per syscall (top by combined calls):\n");
			output(0, "  %-24s %10s %10s %10s %10s %10s %10s\n",
			       "syscall",
			       "loc_calls", "loc_eCalls", "loc_eCount",
			       "rem_calls", "rem_eCalls", "rem_eCount");
			for (j = 0; j < lr_top_count; j++) {
				struct syscallentry *entry =
					table[lr_top_nr[j]].entry;
				const char *name = entry ? entry->name : "???";
				unsigned int nr = lr_top_nr[j];
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
				unsigned long ren = __atomic_load_n(
					&kcov_shm->pc_ctx.remote_pc_edge_count[nr],
					__ATOMIC_RELAXED);

				output(0, "  %-24s %10lu %10lu %10lu %10lu %10lu %10lu\n",
				       name, lc, lec, len_, rc, rec, ren);
			}
		}
}
/* Find top 10 edge-producing syscalls via insertion sort, then a
 * skip-zero walk over the same table for the "Cold syscalls" tail --
 * both scans share the top_nr / top_edges / top_count / cold_count
 * locals declared here so the cold pass reads the running cold count
 * the top pass tallied without re-scanning. */
void dump_stats_render_kcov_top_edges_and_cold(unsigned int nr_syscalls_to_scan, const struct syscalltable *table)
{
	unsigned int top_nr[10];
	unsigned long top_edges[10];
	unsigned int top_count = 0;
	unsigned int cold_count = 0;
	unsigned int i, j;

	memset(top_edges, 0, sizeof(top_edges));
	for (i = 0; i < nr_syscalls_to_scan; i++) {
		unsigned long edges = per_syscall_edges_total(i);

		if (edges == 0)
			continue;

		if (kcov_syscall_is_cold(i))
			cold_count++;

		topn_push(top_edges, top_nr, &top_count, 10, edges, i);
	}

	if (top_count > 0) {
		output(0, "Top edge-producing syscalls:\n");
		for (j = 0; j < top_count; j++) {
			struct syscallentry *entry = table[top_nr[j]].entry;
			const char *name = entry ? entry->name : "???";

			output(0, "  %-24s %lu\n", name, top_edges[j]);
		}
	}

	/* Top-N by per-interval edge growth (delta since last dump_stats). */
	dump_stats_render_kcov_per_syscall_edges_topn(nr_syscalls_to_scan, table);

	/* SHADOW-only Phase-1 per-syscall attribution-confidence dump.
	 * Silent by default (frontier_noise_sample==0); on any run with
	 * --frontier-noise-sample=N > 0 this renders a top-N with the
	 * clean numerator, the sampled-then-scaled global-delta noisy
	 * denominator, the resulting clean/est_noisy fraction, the
	 * local-only clean subset (clean - clean_remote), and the spare-
	 * cascade lane the frontier picker would consume. */
	dump_stats_render_kcov_per_syscall_noisy_topn(nr_syscalls_to_scan, table);

	/* Shadow transition coverage: top-N by real transition-slot
	 * count (cumulative since process start, not since the last
	 * dump) and top-N by per-interval call-count delta.  Printed
	 * directly beside the PC top-N blocks above so the two
	 * signals can be compared at a glance — a syscall that
	 * appears in the transition top-N but not in the PC top-N is
	 * a candidate for the "new control-flow path through warm
	 * code" pattern that the PC bitmap misses by design.  Both
	 * blocks are silent when transition coverage is OFF: the per-
	 * syscall arrays stay zero, so the any_* gates skip the
	 * headers. */
	dump_stats_render_kcov_per_syscall_calls_topn(nr_syscalls_to_scan, table);

	dump_stats_render_kcov_per_syscall_edge_calls_topn(nr_syscalls_to_scan, table);

	/* Sibling of "Top syscalls by recent edge growth": top-N by
	 * delta of per_syscall_cmp_inserts since the last dump_stats().
	 * A syscall whose CMP-insert rate is high while its edge-growth
	 * rate is flat is producing CMP signal that is not turning into
	 * coverage -- the CMP-rising-PC-flat plateau pattern. */
	dump_stats_render_kcov_per_syscall_cold_topn(nr_syscalls_to_scan, table);

	if (cold_count > 0) {
		unsigned int arch;

		output(0, "Cold syscalls (need better sanitise): %u\n", cold_count);
		/* Split by the per_syscall_edges[nr][arch] arch dim so an
		 * IA32-compat-only edge contribution is not silently folded
		 * into the 64-bit row.  Mirrors the biarch-aware iteration
		 * shape kcov_diag_emit_block uses (see stats/kcov_diag.c):
		 * iterate arch 0/1, label do32?"32":"64", skip zero rows.
		 * cold_count / kcov_syscall_is_cold stay per-nr -- the cold
		 * classification does not split by arch. */
		for (arch = 0; arch < 2; arch++) {
			bool do32 = (arch == 1);

			for (i = 0; i < nr_syscalls_to_scan; i++) {
				struct syscallentry *entry;
				unsigned long slot_edges;

				if (!kcov_syscall_is_cold(i))
					continue;

				slot_edges = __atomic_load_n(
					&kcov_shm->per_syscall.per_syscall_edges[i][arch],
					__ATOMIC_RELAXED);
				if (slot_edges == 0)
					continue;

				entry = table[i].entry;
				output(0, "  %-24s [arch=%s] (edges:%lu, last new @ call %lu)\n",
					entry ? entry->name : "???",
					do32 ? "32" : "64",
					slot_edges,
					kcov_shm->per_syscall.last_edge_at[i]);
			}
		}
	}
}

