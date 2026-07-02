/*
 * corrupt_ptr attribution + reject dumps.
 *
 * Carved verbatim out of stats.c.  Contains the render helpers for
 * the wild-write attribution surface: the per-syscall
 * range_overlaps_shared() top-offenders table
 * (dump_range_overlaps_shared_top_offenders), the burst detector
 * (corrupt_ptr_spike_check), the per-handler + per-callsite
 * attribution rings for post_handler_corrupt_ptr
 * (corrupt_ptr_attr_dump) plus its supporting comparators and shard
 * mergers, and the per-callsite deferred-free reject dump
 * (deferred_free_reject_pc_dump) with its own merger.
 *
 * dump_range_overlaps_shared_top_offenders, corrupt_ptr_attr_dump and
 * deferred_free_reject_pc_dump are called from the stats.c core /
 * periodic dump respectively so they are non-static + externed via
 * stats-internal.h; the qsort comparators, shard mergers, and the
 * corrupt_ptr_pc_dump_for row emitter stay static -- their only
 * callers are the three top-level dumps in this same TU.
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
#include "child.h"
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

/*
 * Walk the per-syscall range_overlaps_shared() reject buckets and emit the
 * top 10 worst offenders.  Names the syscalls whose arg generators are most
 * often producing pointers into trinity's own shared regions, so they can
 * be retrofitted with avoid_shared_buffer() (or similar) sanitisation.
 */
#define ROS_TOPN 10

void dump_range_overlaps_shared_top_offenders(void)
{
	struct {
		unsigned int nr;
		bool do32bit;
		unsigned long count;
	} top[ROS_TOPN];
	unsigned int top_count = 0;
	unsigned int i, j;

	memset(top, 0, sizeof(top));

	for (i = 0; i < MAX_NR_SYSCALL; i++) {
		unsigned long c64 = parent_stats.range_overlaps_shared_rejects_per_syscall_64[i];
		unsigned long c32 = parent_stats.range_overlaps_shared_rejects_per_syscall_32[i];
		unsigned int pass;
		unsigned long c;
		bool is32;

		for (pass = 0; pass < 2; pass++) {
			c = pass ? c32 : c64;
			is32 = pass ? true : false;

			if (c == 0)
				continue;

			for (j = top_count; j > 0 && c > top[j - 1].count; j--) {
				if (j < ROS_TOPN)
					top[j] = top[j - 1];
			}
			if (j < ROS_TOPN) {
				top[j].nr = i;
				top[j].do32bit = is32;
				top[j].count = c;
				if (top_count < ROS_TOPN)
					top_count++;
			}
		}
	}

	if (top_count == 0)
		return;

	output(0, "Top range_overlaps_shared() offenders by syscall:\n");
	for (j = 0; j < top_count; j++) {
		const char *sname = print_syscall_name(top[j].nr, top[j].do32bit);

		output(0, "  %-24s %s %lu\n",
			sname, top[j].do32bit ? "(32)" : "(64)", top[j].count);
	}
}

/*
 * Spike detector for parent_stats.post_handler_corrupt_ptr.  Called once
 * per main_loop tick from the parent.  Emits a single-line WARNING when
 * the counter advances by at least CORRUPT_PTR_SPIKE_THRESHOLD over a
 * CORRUPT_PTR_SPIKE_WINDOW_SEC window.
 *
 * The counter ticks whenever a post-handler caught a pid-shaped or
 * canonical-out-of-range pointer in rec->aN -- i.e. the snapshot
 * pattern intercepted a wild write.  A slow trickle is normal noise; a
 * sudden burst is the signal that scribbles are landing in rec-> memory
 * often enough to matter.  Per-window throttling keeps the log quiet
 * during a steady drip and re-arms after each report so a sustained
 * spike emits one line per minute, not a flood.
 *
 * Scoped to genuine .post-handler pointer rejections only.  The
 * dispatcher-level RZS rettype-contract check has its own counter
 * (rzs_blanket_reject) and does not feed this detector; previously the
 * two signals shared post_handler_corrupt_ptr and the RZS background
 * (~2/s steady-state across the fleet) drowned the burst-detection
 * window in ~85-90% noise.
 */
#define CORRUPT_PTR_SPIKE_THRESHOLD	100UL
#define CORRUPT_PTR_SPIKE_WINDOW_SEC	60

void corrupt_ptr_spike_check(void)
{
	static unsigned long window_baseline;
	static struct timespec window_start;
	struct timespec now;
	unsigned long current, delta;

	clock_gettime(CLOCK_MONOTONIC, &now);

	/* First call: arm the window from the live counter so any
	 * pre-existing count carried over from earlier in the run is
	 * not mis-attributed to this window.  Reads from parent_stats
	 * since the counter now lives in the parent aggregate (no
	 * atomic needed -- parent is the sole writer via the ring
	 * drain and the sole reader here). */
	if (window_start.tv_sec == 0) {
		window_start = now;
		window_baseline = parent_stats.post_handler_corrupt_ptr;
		return;
	}

	if ((now.tv_sec - window_start.tv_sec) < CORRUPT_PTR_SPIKE_WINDOW_SEC)
		return;

	current = parent_stats.post_handler_corrupt_ptr;
	delta = current - window_baseline;

	if (delta >= CORRUPT_PTR_SPIKE_THRESHOLD)
		output(0, "WARNING: post_handler_corrupt_ptr spiked +%lu in %us (total %lu) -- snapshot guards are catching scribbles\n",
		       delta, CORRUPT_PTR_SPIKE_WINDOW_SEC, current);

	window_start = now;
	window_baseline = current;
}

/*
 * Render the per-handler attribution ring for post_handler_corrupt_ptr.
 * Snapshots the ring under the same lock the recorder uses so a
 * concurrent insertion cannot reorder entries underneath the sort.  The
 * snapshot is then sorted descending by count and emitted; suppressed
 * entirely when the ring is empty so quiet windows stay terse.
 */
static int corrupt_ptr_attr_cmp(const void *a, const void *b)
{
	const struct corrupt_ptr_attr_entry *ea = a;
	const struct corrupt_ptr_attr_entry *eb = b;

	if (eb->count > ea->count)
		return 1;
	if (eb->count < ea->count)
		return -1;
	return 0;
}

/*
 * Comparator for the per-callsite sub-attribution ring.  Same
 * descending-by-count order as the per-handler ring so the dump leads
 * with the loudest call site within each handler row.
 */
static int corrupt_ptr_pc_cmp(const void *a, const void *b)
{
	const struct corrupt_ptr_pc_entry *ea = a;
	const struct corrupt_ptr_pc_entry *eb = b;

	if (eb->count > ea->count)
		return 1;
	if (eb->count < ea->count)
		return -1;
	return 0;
}

/*
 * Render PC sub-attribution entries that match (nr, do32bit) as
 * indented sub-rows beneath the matching per-handler row.  Caller
 * passes a snapshot already sorted descending by count so all rows
 * share one snap+sort across the dump pass; @n_entries is the number
 * of populated slots in @snap (everything from index @n_entries onward
 * is guaranteed zero-count and skipped).  Silent when no entry matches
 * -- pre-sub-attribution runs and quiet handlers stay terse.
 *
 * Each row is annotated with a best-effort "file.c:NNN" from addr2line
 * because pc_to_string() alone renders a PIE-relative offset that gets
 * resolved by addr2line / external tooling DOWN to the nearest
 * preceding global symbol -- a captured PC living inside an
 * LTO-inlined static helper body therefore appears under whichever
 * unrelated non-static symbol happens to precede it in the binary.
 * Source coordinates disambiguate; falls back to the bare offset when
 * addr2line is unavailable or the address can't be resolved.
 */
static void corrupt_ptr_pc_dump_for(const struct corrupt_ptr_pc_entry *snap,
				    unsigned int n_entries,
				    unsigned int nr, bool do32bit)
{
	unsigned int i;

	for (i = 0; i < n_entries; i++) {
		char pcbuf[128];
		char srcbuf[256];
		const char *src;

		if (snap[i].count == 0)
			break;
		if (snap[i].nr != nr || snap[i].do32bit != do32bit)
			continue;
		/*
		 * The pc slots in this ring are themselves a write target
		 * of the wild-write storm being measured -- entries get
		 * stomped between sample-time and dump-time.  Skip rows
		 * whose pc no longer points into our own .text so the
		 * sub-attribution output stays trustworthy for triage.
		 */
		if (snap[i].pc == NULL || !pc_in_text(snap[i].pc))
			continue;
		src = pc_to_source_line(snap[i].pc, srcbuf, sizeof(srcbuf));
		/* The site tag field lives in the same shared stompable ring
		 * as pc, so a wild write can leave site dangling while pc
		 * still passes pc_in_text.  Unlike pc, there is no cheap
		 * in-text/rodata-range helper to validate site before handing
		 * it to vsnprintf, so the [%s] column is omitted entirely:
		 * the pc and (src) columns already identify the rejection
		 * site for triage. */
		if (src != NULL)
			stats_log_write("    %-32s (%s) %lu\n",
					pc_to_string(snap[i].pc, pcbuf, sizeof(pcbuf)),
					src, snap[i].count);
		else
			stats_log_write("    %-32s %lu\n",
					pc_to_string(snap[i].pc, pcbuf, sizeof(pcbuf)),
					snap[i].count);
	}
}

/*
 * Walk every child's local_corrupt_ptr_attr shard and merge into @out
 * by summing counts on (nr, do32bit) key matches.  Returns the number
 * of populated entries written to @out (bounded by @out_cap).  Reads
 * the per-child shards without a lock -- the owning child is the sole
 * writer, so a torn read at most shaves a count by one on a single
 * shard slot, which is in the noise once all shards are summed.
 */
static unsigned int merge_corrupt_ptr_attr_shards(struct corrupt_ptr_attr_entry *out,
						  unsigned int out_cap)
{
	unsigned int i, j, k, n_merged = 0;

	for_each_child(i) {
		struct childdata *child;
		const struct corrupt_ptr_attr_entry *shard;

		child = __atomic_load_n(&children[i], __ATOMIC_ACQUIRE);
		if (child == NULL)
			continue;
		shard = child->local_corrupt_ptr_attr;

		for (j = 0; j < CORRUPT_PTR_ATTR_SLOTS; j++) {
			if (shard[j].count == 0)
				continue;
			for (k = 0; k < n_merged; k++) {
				if (out[k].nr == shard[j].nr &&
				    out[k].do32bit == shard[j].do32bit) {
					out[k].count += shard[j].count;
					break;
				}
			}
			if (k == n_merged && n_merged < out_cap) {
				out[n_merged] = shard[j];
				n_merged++;
			}
		}
	}
	return n_merged;
}

/*
 * Walk every child's local_corrupt_ptr_pc shard and merge into @out
 * by summing counts on (nr, do32bit, pc) key matches.  The first
 * non-NULL site tag wins -- later shards may carry NULL for the same
 * PC if they only saw it through the legacy tagless caller path.
 */
static unsigned int merge_corrupt_ptr_pc_shards(struct corrupt_ptr_pc_entry *out,
						unsigned int out_cap)
{
	unsigned int i, j, k, n_merged = 0;

	for_each_child(i) {
		struct childdata *child;
		const struct corrupt_ptr_pc_entry *shard;

		child = __atomic_load_n(&children[i], __ATOMIC_ACQUIRE);
		if (child == NULL)
			continue;
		shard = child->local_corrupt_ptr_pc;

		for (j = 0; j < CORRUPT_PTR_PC_SLOTS; j++) {
			if (shard[j].count == 0)
				continue;
			for (k = 0; k < n_merged; k++) {
				if (out[k].nr == shard[j].nr &&
				    out[k].do32bit == shard[j].do32bit &&
				    out[k].pc == shard[j].pc) {
					out[k].count += shard[j].count;
					if (out[k].site == NULL &&
					    shard[j].site != NULL)
						out[k].site = shard[j].site;
					break;
				}
			}
			if (k == n_merged && n_merged < out_cap) {
				out[n_merged] = shard[j];
				n_merged++;
			}
		}
	}
	return n_merged;
}

void corrupt_ptr_attr_dump(void)
{
	struct corrupt_ptr_attr_entry *snap;
	struct corrupt_ptr_pc_entry *pc_snap;
	unsigned int snap_cap, pc_cap, n, n_pc, i;

	/*
	 * Sized for the worst case where every child's shard is full of
	 * unique keys.  In practice the hot keys collide across children
	 * (post-handler attribution is dominated by a handful of syscalls)
	 * and n_merged stays near CORRUPT_PTR_*_SLOTS; the upper bound is
	 * just to avoid truncating when the long tail is unusually wide.
	 * Both allocations are bounded by max_children * SLOTS so a fleet
	 * with a few hundred children stays well under a MiB.
	 */
	snap_cap = max_children * CORRUPT_PTR_ATTR_SLOTS;
	pc_cap = max_children * CORRUPT_PTR_PC_SLOTS;
	snap = calloc(snap_cap, sizeof(*snap));
	pc_snap = calloc(pc_cap, sizeof(*pc_snap));
	if (snap == NULL || pc_snap == NULL) {
		free(snap);
		free(pc_snap);
		return;
	}

	n = merge_corrupt_ptr_attr_shards(snap, snap_cap);
	if (n == 0) {
		free(snap);
		free(pc_snap);
		return;
	}
	n_pc = merge_corrupt_ptr_pc_shards(pc_snap, pc_cap);

	qsort(snap, n, sizeof(snap[0]), corrupt_ptr_attr_cmp);
	if (n_pc > 0)
		qsort(pc_snap, n_pc, sizeof(pc_snap[0]), corrupt_ptr_pc_cmp);

	stats_log_write("post_handler_corrupt_ptr attribution (top %u handlers):\n", n);
	for (i = 0; i < n; i++) {
		const char *name;
		const char *width;

		if (snap[i].nr == CORRUPT_PTR_ATTR_NR_NONE) {
			name = "<deferred-free / non-syscall>";
			width = "(all)";
		} else {
			name = print_syscall_name(snap[i].nr, snap[i].do32bit);
			width = snap[i].do32bit ? "(32)" : "(64)";
		}
		stats_log_write("  %-32s %s %lu\n", name, width, snap[i].count);
		corrupt_ptr_pc_dump_for(pc_snap, n_pc, snap[i].nr, snap[i].do32bit);
	}

	free(snap);
	free(pc_snap);
}

/*
 * Render the per-callsite attribution ring for deferred_free_reject.
 * Mirrors corrupt_ptr_attr_dump() but with no per-handler dimension --
 * every entry is keyed by deferred_free_enqueue's caller PC alone, since
 * all bumps originate from the rec==NULL deferred-free path.  Emits a
 * top-N PC list sorted descending by count and is suppressed entirely
 * on a quiet ring so windows with no rejects stay terse.
 */
static int deferred_free_reject_pc_cmp(const void *a, const void *b)
{
	const struct deferred_free_reject_pc_entry *ea = a;
	const struct deferred_free_reject_pc_entry *eb = b;

	if (eb->count > ea->count)
		return 1;
	if (eb->count < ea->count)
		return -1;
	return 0;
}

/*
 * Walk every child's local_deferred_free_reject_pc shard and merge into
 * @out by summing counts on pc matches.  Same locking model as
 * merge_corrupt_ptr_attr_shards -- single writer per shard, torn reads
 * are tolerable noise on the 600-second dump cadence.
 */
static unsigned int merge_deferred_free_reject_pc_shards(struct deferred_free_reject_pc_entry *out,
							 unsigned int out_cap)
{
	unsigned int i, j, k, n_merged = 0;

	for_each_child(i) {
		struct childdata *child;
		const struct deferred_free_reject_pc_entry *shard;

		child = __atomic_load_n(&children[i], __ATOMIC_ACQUIRE);
		if (child == NULL)
			continue;
		shard = child->local_deferred_free_reject_pc;

		for (j = 0; j < CORRUPT_PTR_PC_SLOTS; j++) {
			if (shard[j].count == 0)
				continue;
			for (k = 0; k < n_merged; k++) {
				if (out[k].pc == shard[j].pc) {
					out[k].count += shard[j].count;
					break;
				}
			}
			if (k == n_merged && n_merged < out_cap) {
				out[n_merged] = shard[j];
				n_merged++;
			}
		}
	}
	return n_merged;
}

void deferred_free_reject_pc_dump(void)
{
	struct deferred_free_reject_pc_entry *snap;
	unsigned int snap_cap, n, i;

	snap_cap = max_children * CORRUPT_PTR_PC_SLOTS;
	snap = calloc(snap_cap, sizeof(*snap));
	if (snap == NULL)
		return;

	n = merge_deferred_free_reject_pc_shards(snap, snap_cap);
	if (n == 0) {
		free(snap);
		return;
	}

	qsort(snap, n, sizeof(snap[0]), deferred_free_reject_pc_cmp);

	stats_log_write("deferred_free_reject attribution (top %u callers):\n", n);
	for (i = 0; i < n; i++) {
		char pcbuf[128];
		char srcbuf[256];
		const char *src;

		if (snap[i].count == 0)
			break;
		/*
		 * Same in-flight-stomp risk as corrupt_ptr_pc_dump_for: skip
		 * rows whose pc no longer points into our own .text so the
		 * sub-attribution output stays trustworthy for triage.
		 */
		if (snap[i].pc == NULL || !pc_in_text(snap[i].pc))
			continue;
		/*
		 * Annotate with addr2line file:line for the same reason as
		 * corrupt_ptr_pc_dump_for: load-relative offsets resolved by
		 * external tooling round DOWN to the nearest preceding
		 * global symbol, mis-attributing PCs inside LTO-inlined
		 * static helpers (deferred_free_enqueue itself is exactly
		 * that shape via the looks_like_corrupted_ptr_pc and
		 * post_handler_corrupt_ptr_bump inlines).  Falls back to
		 * the bare offset on resolution miss.
		 */
		src = pc_to_source_line(snap[i].pc, srcbuf, sizeof(srcbuf));
		if (src != NULL)
			stats_log_write("  %-32s (%s) %lu\n",
					pc_to_string(snap[i].pc, pcbuf, sizeof(pcbuf)),
					src, snap[i].count);
		else
			stats_log_write("  %-32s %lu\n",
					pc_to_string(snap[i].pc, pcbuf, sizeof(pcbuf)),
					snap[i].count);
	}

	free(snap);
}
