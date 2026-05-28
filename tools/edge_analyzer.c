/*
 * edge_analyzer - offline analysis of trinity edge-pair coverage data.
 *
 * Reads a binary dump produced by trinity (edgepair.dump) and reports:
 *   1. Hash table utilization stats
 *   2. Collision rates (linear-probe displacement histogram)
 *   3. Top N most-productive edge pairs
 *   4. Coverage growth rate over time
 *   5. Top K outgoing pairs per productive predecessor syscall
 *   6. Dead-end productive predecessors (reached productively but with
 *      no productive outgoing pairs of their own)
 *   7. Cold-but-high-total productive pairs (saturated sequences)
 *
 * Optionally emits a DOT-language graph of the pair table via -d for
 * visualisation in graphviz.  The DOT export is orthogonal to the
 * stdout reports -- both run when -d is given.
 *
 * Usage: edge_analyzer [options] [dump_file]
 *   -n N         show top N pairs (default 20)
 *   -k N         per-predecessor top-K width (default 5)
 *   -b N         time buckets for growth chart (default 20)
 *   -d FILE      emit DOT graph to FILE ('-' for stdout)
 *   dump_file defaults to "edgepair.dump"
 */

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "edgepair.h"		/* table sizing, struct edgepair_entry,
				 * edgepair_pair_hash, dump header */

/* Tool-local view of the on-disk dump payload: the canonical table
 * followed by the three top-level counters.  Header rides in front of
 * this struct in the file and is consumed separately. */
struct edgepair_shared {
	struct edgepair_entry table[EDGEPAIR_TABLE_SIZE];
	unsigned long total_pair_calls;
	unsigned long pairs_tracked;
	unsigned long pairs_dropped;
};

/* Replica of edgepair_entry_is_cold_parent() from edgepair.c.  The
 * analyzer reads a dump file offline and does not link against the
 * fuzzer runtime, so the cooldown-timer math lives here too.  Keep
 * the predicate identical: productive pair whose last_new_at is more
 * than EDGEPAIR_COLD_THRESHOLD pair-calls behind the global counter,
 * with a guard for the racing-publisher case where last >= total. */
static int entry_is_cold(const struct edgepair_entry *e,
			 unsigned long total_pair_calls)
{
	if (e->new_edge_count == 0)
		return 0;
	if (e->last_new_at >= total_pair_calls)
		return 0;
	return (total_pair_calls - e->last_new_at) > EDGEPAIR_COLD_THRESHOLD;
}

/* DOT penwidth scaled to log(new_edges + 1), clipped to [1.0, 6.0].
 * Computed via integer bit position + linear interpolation so the
 * tool stays libm-free (the Makefile rule does not link -lm). */
static double pair_penwidth(unsigned long new_edges)
{
	unsigned long v = new_edges + 1;
	int top_bit;
	double base, frac, l2, ln;

	if (v <= 1)
		return 1.0;

	top_bit = 63 - __builtin_clzll(v);
	base = (double)(1ULL << top_bit);
	frac = ((double)v - base) / base;
	l2 = (double)top_bit + frac;
	ln = l2 * 0.6931471805599453;	/* log2(x) * ln(2) = ln(x) */

	if (ln < 1.0)
		ln = 1.0;
	if (ln > 6.0)
		ln = 6.0;
	return ln;
}

static void print_bar(unsigned long value, unsigned long max, int width)
{
	int filled = 0;
	int i;

	if (max > 0)
		filled = (int)((unsigned long)width * value / max);

	for (i = 0; i < width; i++)
		putchar(i < filled ? '#' : ' ');
}

static void analyze_identity(const struct edgepair_dump_header *hdr)
{
	printf("identity:\n");
	printf("  magic           : 0x%08x\n", hdr->magic);
	printf("  version         : %u\n", hdr->version);
	printf("  table_size      : %u\n", hdr->table_size);
	printf("  payload_crc32   : 0x%08x\n", hdr->payload_crc32);
	printf("  total_pair_calls: %" PRIu64 "\n", hdr->total_pair_calls);
	printf("  pairs_tracked   : %" PRIu64 "\n", hdr->pairs_tracked);
	printf("  pairs_dropped   : %" PRIu64 "\n", hdr->pairs_dropped);
	printf("  max_nr_syscall  : %u\n", hdr->max_nr_syscall);
	printf("  biarch_mode     : %u\n", hdr->biarch_mode);
	printf("  kallsyms_sha256 : ");
	for (size_t i = 0; i < sizeof(hdr->kallsyms_sha256); i++)
		printf("%02x", hdr->kallsyms_sha256[i]);
	printf("\n");
	printf("  syscall_digest  : ");
	for (size_t i = 0; i < sizeof(hdr->syscall_table_digest); i++)
		printf("%02x", hdr->syscall_table_digest[i]);
	printf("\n\n");
}

static void analyze_utilization(const struct edgepair_shared *shm)
{
	unsigned int occupied = 0;
	unsigned int productive = 0;
	unsigned long total_exec = 0;
	unsigned long total_new = 0;
	unsigned int i;

	for (i = 0; i < EDGEPAIR_TABLE_SIZE; i++) {
		const struct edgepair_entry *e = &shm->table[i];

		if (e->prev_nr == EDGEPAIR_EMPTY)
			continue;
		occupied++;
		total_exec += e->total_count;
		total_new  += e->new_edge_count;
		if (e->new_edge_count > 0)
			productive++;
	}

	printf("=== Hash Table Utilization ===\n");
	printf("  Table size:    %u slots\n", EDGEPAIR_TABLE_SIZE);
	printf("  Max probes:    %u\n", EDGEPAIR_MAX_PROBE);
	printf("  Occupied:      %u  (%.1f%%)\n",
		occupied, 100.0 * occupied / EDGEPAIR_TABLE_SIZE);
	printf("  Empty:         %u  (%.1f%%)\n",
		EDGEPAIR_TABLE_SIZE - occupied,
		100.0 * (EDGEPAIR_TABLE_SIZE - occupied) / EDGEPAIR_TABLE_SIZE);
	printf("  Productive:    %u  (%.1f%% of occupied)\n",
		productive,
		occupied ? 100.0 * productive / occupied : 0.0);
	printf("  pairs_tracked: %lu\n", shm->pairs_tracked);
	printf("  pairs_dropped: %lu  (inserts that overflowed the probe window)\n",
		shm->pairs_dropped);
	printf("  total_calls:   %lu\n", shm->total_pair_calls);
	printf("  total_exec:    %lu  (pair executions counted)\n", total_exec);
	printf("  total_new:     %lu  (new-edge events counted)\n", total_new);
	if (total_exec > 0)
		printf("  yield rate:    %.4f%%  (new-edge events per pair execution)\n",
			100.0 * total_new / total_exec);
	printf("\n");
}

static void analyze_collisions(const struct edgepair_shared *shm)
{
	unsigned long disp_hist[EDGEPAIR_MAX_PROBE + 1];
	unsigned long max_disp_count = 0;
	unsigned long no_collision;
	unsigned int occupied = 0;
	unsigned int i;

	memset(disp_hist, 0, sizeof(disp_hist));

	for (i = 0; i < EDGEPAIR_TABLE_SIZE; i++) {
		const struct edgepair_entry *e = &shm->table[i];
		unsigned int ideal;
		unsigned int disp;

		if (e->prev_nr == EDGEPAIR_EMPTY)
			continue;

		occupied++;
		ideal = edgepair_pair_hash(e->prev_nr, e->curr_nr);
		disp = (i + EDGEPAIR_TABLE_SIZE - ideal) & EDGEPAIR_TABLE_MASK;

		if (disp > EDGEPAIR_MAX_PROBE)
			disp = EDGEPAIR_MAX_PROBE;	/* clamp to overflow bucket */
		disp_hist[disp]++;
	}

	if (occupied == 0) {
		printf("=== Collision Rates ===\n  (no data)\n\n");
		return;
	}

	for (i = 0; i <= EDGEPAIR_MAX_PROBE; i++) {
		if (disp_hist[i] > max_disp_count)
			max_disp_count = disp_hist[i];
	}

	no_collision = disp_hist[0];

	printf("=== Collision Rates ===\n");
	printf("  Displacement 0 (no collision): %lu  (%.1f%%)\n",
		no_collision, 100.0 * no_collision / occupied);
	printf("  Collision rate: %.1f%%\n",
		100.0 * (occupied - no_collision) / occupied);
	printf("\n  Displacement histogram (entries requiring N probes to insert):\n");

	for (i = 0; i <= EDGEPAIR_MAX_PROBE; i++) {
		if (i < EDGEPAIR_MAX_PROBE)
			printf("  %2u:  %6lu  |", i, disp_hist[i]);
		else
			printf("  >%u: %6lu  |", EDGEPAIR_MAX_PROBE - 1,
				disp_hist[i]);
		print_bar(disp_hist[i], max_disp_count, 40);
		printf("|\n");
	}
	printf("\n");
}

static int cmp_by_new_edges(const void *a, const void *b)
{
	const struct edgepair_entry *ea = (const struct edgepair_entry *)a;
	const struct edgepair_entry *eb = (const struct edgepair_entry *)b;

	if (eb->new_edge_count > ea->new_edge_count)
		return 1;
	if (eb->new_edge_count < ea->new_edge_count)
		return -1;
	return 0;
}

static void analyze_top_pairs(const struct edgepair_shared *shm, int top_n)
{
	struct edgepair_entry *sorted;
	unsigned long max_new;
	unsigned int occupied = 0;
	unsigned int limit;
	unsigned int j = 0;
	unsigned int i;

	for (i = 0; i < EDGEPAIR_TABLE_SIZE; i++) {
		if (shm->table[i].prev_nr != EDGEPAIR_EMPTY)
			occupied++;
	}

	if (occupied == 0) {
		printf("=== Top %d Most-Productive Pairs ===\n  (no data)\n\n",
			top_n);
		return;
	}

	sorted = malloc(occupied * sizeof(*sorted));
	if (sorted == NULL) {
		fprintf(stderr, "out of memory\n");
		return;
	}

	for (i = 0; i < EDGEPAIR_TABLE_SIZE; i++) {
		if (shm->table[i].prev_nr != EDGEPAIR_EMPTY)
			sorted[j++] = shm->table[i];
	}

	qsort(sorted, occupied, sizeof(*sorted), cmp_by_new_edges);

	limit = (unsigned int)top_n < occupied ? (unsigned int)top_n : occupied;
	max_new = sorted[0].new_edge_count;

	printf("=== Top %u Most-Productive Pairs ===\n", limit);
	printf("  %-8s  %-8s  %-12s  %-12s  %s\n",
		"prev_nr", "curr_nr", "new_edges", "total_exec", "hit_rate");

	for (i = 0; i < limit; i++) {
		const struct edgepair_entry *e = &sorted[i];
		double hit_rate;

		hit_rate = e->total_count > 0
			? 100.0 * e->new_edge_count / e->total_count : 0.0;

		printf("  %-8u  %-8u  %-12lu  %-12lu  %.2f%%  |",
			e->prev_nr, e->curr_nr,
			e->new_edge_count, e->total_count, hit_rate);
		print_bar(e->new_edge_count, max_new, 20);
		printf("|\n");
	}
	printf("\n");
	free(sorted);
}

static int cmp_by_last_new(const void *a, const void *b)
{
	const struct edgepair_entry *ea = (const struct edgepair_entry *)a;
	const struct edgepair_entry *eb = (const struct edgepair_entry *)b;

	if (ea->last_new_at < eb->last_new_at)
		return -1;
	if (ea->last_new_at > eb->last_new_at)
		return 1;
	return 0;
}

static void analyze_growth(const struct edgepair_shared *shm, int buckets)
{
	struct edgepair_entry *productive;
	unsigned long *bucket_pairs;
	unsigned long *bucket_edges;
	unsigned long max_pairs = 0;
	unsigned long total_pair_calls = shm->total_pair_calls;
	unsigned int productive_count = 0;
	unsigned int i;

	if (total_pair_calls == 0) {
		printf("=== Coverage Growth Rate ===\n  (no data)\n\n");
		return;
	}

	productive = malloc(EDGEPAIR_TABLE_SIZE * sizeof(*productive));
	bucket_pairs = calloc((size_t)buckets, sizeof(*bucket_pairs));
	bucket_edges = calloc((size_t)buckets, sizeof(*bucket_edges));

	if (productive == NULL || bucket_pairs == NULL || bucket_edges == NULL) {
		fprintf(stderr, "out of memory\n");
		free(productive);
		free(bucket_pairs);
		free(bucket_edges);
		return;
	}

	for (i = 0; i < EDGEPAIR_TABLE_SIZE; i++) {
		const struct edgepair_entry *e = &shm->table[i];

		if (e->prev_nr == EDGEPAIR_EMPTY)
			continue;
		if (e->new_edge_count == 0)
			continue;
		productive[productive_count++] = *e;
	}

	if (productive_count == 0) {
		printf("=== Coverage Growth Rate ===\n  (no productive pairs)\n\n");
		goto out;
	}

	qsort(productive, productive_count, sizeof(*productive), cmp_by_last_new);

	/*
	 * Bucket productive pairs by last_new_at.  Each bucket covers an equal
	 * slice of the total_pair_calls timeline.  A pair falls into the bucket
	 * where it was last seen finding new edges.
	 *
	 * Interpretation: front-loaded -> coverage saturated early.
	 * Uniform or trailing -> coverage still growing at end of run.
	 */
	for (i = 0; i < productive_count; i++) {
		unsigned long t = productive[i].last_new_at;
		int b;

		if (t >= total_pair_calls)
			t = total_pair_calls - 1;

		b = (int)((unsigned long)buckets * t / total_pair_calls);
		if (b >= buckets)
			b = buckets - 1;

		bucket_pairs[b]++;
		bucket_edges[b] += productive[i].new_edge_count;
	}

	for (i = 0; i < (unsigned int)buckets; i++) {
		if (bucket_pairs[i] > max_pairs)
			max_pairs = bucket_pairs[i];
	}

	printf("=== Coverage Growth Rate ===\n");
	printf("  total_pair_calls: %lu    productive_pairs: %u\n\n",
		total_pair_calls, productive_count);
	printf("  Each row = %.1f%% of run.  '#' = pairs last-active in window.\n",
		100.0 / buckets);
	printf("  %-14s  %-8s  %-10s  %s\n",
		"time_window", "pairs", "new_edges", "activity (by pairs)");

	for (i = 0; i < (unsigned int)buckets; i++) {
		unsigned long t_start = total_pair_calls * i
			/ (unsigned long)buckets;
		unsigned long t_end = total_pair_calls * (i + 1)
			/ (unsigned long)buckets;

		printf("  %7lu-%-7lu  %-8lu  %-10lu  |",
			t_start, t_end, bucket_pairs[i], bucket_edges[i]);
		print_bar(bucket_pairs[i], max_pairs, 40);
		printf("|\n");
	}
	printf("\n");

out:
	free(productive);
	free(bucket_pairs);
	free(bucket_edges);
}

/*
 * Top-K outgoing pairs per productive predecessor.  For each syscall
 * that appears as prev in at least one productive pair, list its top
 * K outgoing destinations by new_edge_count.  The list of predecessors
 * itself is ranked by summed new_edge_count and capped to keep the
 * report readable on saturated dumps.
 */
struct outgoing_group {
	unsigned int prev_nr;
	unsigned int start;		/* index into sorted[] */
	unsigned int count;		/* number of productive pairs */
	unsigned long sum_new;		/* sum of new_edge_count */
};

static int cmp_by_prev_then_new(const void *a, const void *b)
{
	const struct edgepair_entry *ea = (const struct edgepair_entry *)a;
	const struct edgepair_entry *eb = (const struct edgepair_entry *)b;

	if (ea->prev_nr < eb->prev_nr)
		return -1;
	if (ea->prev_nr > eb->prev_nr)
		return 1;
	if (eb->new_edge_count > ea->new_edge_count)
		return 1;
	if (eb->new_edge_count < ea->new_edge_count)
		return -1;
	return 0;
}

static int cmp_group_by_sum(const void *a, const void *b)
{
	const struct outgoing_group *ga = (const struct outgoing_group *)a;
	const struct outgoing_group *gb = (const struct outgoing_group *)b;

	if (gb->sum_new > ga->sum_new)
		return 1;
	if (gb->sum_new < ga->sum_new)
		return -1;
	return 0;
}

static void analyze_top_outgoing(const struct edgepair_shared *shm, int top_k)
{
	struct edgepair_entry *sorted;
	struct outgoing_group *groups;
	unsigned int productive_count = 0;
	unsigned int group_count = 0;
	unsigned int pred_cap = 30;
	unsigned int shown;
	unsigned int i;
	unsigned int g;

	for (i = 0; i < EDGEPAIR_TABLE_SIZE; i++) {
		const struct edgepair_entry *e = &shm->table[i];

		if (e->prev_nr == EDGEPAIR_EMPTY)
			continue;
		if (e->new_edge_count == 0)
			continue;
		productive_count++;
	}

	printf("=== Top %d outgoing per syscall (productive predecessors) ===\n",
		top_k);

	if (productive_count == 0) {
		printf("  (no productive pairs)\n\n");
		return;
	}

	sorted = malloc(productive_count * sizeof(*sorted));
	groups = malloc(productive_count * sizeof(*groups));

	if (sorted == NULL || groups == NULL) {
		fprintf(stderr, "out of memory\n");
		free(sorted);
		free(groups);
		return;
	}

	{
		unsigned int j = 0;

		for (i = 0; i < EDGEPAIR_TABLE_SIZE; i++) {
			const struct edgepair_entry *e = &shm->table[i];

			if (e->prev_nr == EDGEPAIR_EMPTY)
				continue;
			if (e->new_edge_count == 0)
				continue;
			sorted[j++] = *e;
		}
	}

	qsort(sorted, productive_count, sizeof(*sorted), cmp_by_prev_then_new);

	/* Build per-prev groups over the now-contiguous runs. */
	for (i = 0; i < productive_count; ) {
		unsigned int prev_nr = sorted[i].prev_nr;
		unsigned int start = i;
		unsigned long sum = 0;

		while (i < productive_count && sorted[i].prev_nr == prev_nr) {
			sum += sorted[i].new_edge_count;
			i++;
		}

		groups[group_count].prev_nr = prev_nr;
		groups[group_count].start = start;
		groups[group_count].count = i - start;
		groups[group_count].sum_new = sum;
		group_count++;
	}

	qsort(groups, group_count, sizeof(*groups), cmp_group_by_sum);

	shown = group_count < pred_cap ? group_count : pred_cap;

	printf("  (showing top %u predecessors of %u total, K=%d per row)\n\n",
		shown, group_count, top_k);

	for (g = 0; g < shown; g++) {
		const struct outgoing_group *gr = &groups[g];
		unsigned int k_limit = gr->count < (unsigned int)top_k
			? gr->count : (unsigned int)top_k;
		unsigned int ki;

		printf("  syscall_%u (total outgoing: %u productive pairs, "
			"sum new_edges: %lu)\n",
			gr->prev_nr, gr->count, gr->sum_new);

		for (ki = 0; ki < k_limit; ki++) {
			const struct edgepair_entry *e = &sorted[gr->start + ki];
			double yield;

			yield = e->total_count > 0
				? 100.0 * e->new_edge_count / e->total_count
				: 0.0;

			printf("    -> syscall_%-4u  %6lu/%-8lu  (%.2f%% yield)\n",
				e->curr_nr, e->new_edge_count, e->total_count,
				yield);
		}
	}
	printf("\n");

	free(sorted);
	free(groups);
}

/*
 * Dead-end productive predecessors: syscalls reached productively
 * (appear as curr in some productive pair) but whose own outgoing
 * pairs never produce new edges.  Candidates for misclassified
 * terminators, sanitiser tuning, or true exploration-boundary calls.
 */
struct dead_end {
	unsigned int nr;
	unsigned int inbound_productive;
	unsigned long outbound_total;
};

static int cmp_dead_end_by_inbound(const void *a, const void *b)
{
	const struct dead_end *da = (const struct dead_end *)a;
	const struct dead_end *db = (const struct dead_end *)b;

	if (db->inbound_productive > da->inbound_productive)
		return 1;
	if (db->inbound_productive < da->inbound_productive)
		return -1;
	return 0;
}

static void analyze_dead_ends(const struct edgepair_shared *shm)
{
	unsigned int *inbound_productive;
	unsigned int *outbound_productive;
	unsigned long *outbound_total_exec;
	struct dead_end *dead;
	unsigned int max_nr = 0;
	unsigned int dim;
	unsigned int dead_count = 0;
	unsigned int dead_cap = 50;
	unsigned int shown;
	unsigned int i;

	for (i = 0; i < EDGEPAIR_TABLE_SIZE; i++) {
		const struct edgepair_entry *e = &shm->table[i];

		if (e->prev_nr == EDGEPAIR_EMPTY)
			continue;
		if (e->prev_nr > max_nr)
			max_nr = e->prev_nr;
		if (e->curr_nr > max_nr)
			max_nr = e->curr_nr;
	}

	printf("=== Dead-end productive predecessors ===\n");

	dim = max_nr + 1;
	inbound_productive = calloc(dim, sizeof(*inbound_productive));
	outbound_productive = calloc(dim, sizeof(*outbound_productive));
	outbound_total_exec = calloc(dim, sizeof(*outbound_total_exec));
	dead = malloc(dim * sizeof(*dead));

	if (inbound_productive == NULL || outbound_productive == NULL
	    || outbound_total_exec == NULL || dead == NULL) {
		fprintf(stderr, "out of memory\n");
		free(inbound_productive);
		free(outbound_productive);
		free(outbound_total_exec);
		free(dead);
		return;
	}

	for (i = 0; i < EDGEPAIR_TABLE_SIZE; i++) {
		const struct edgepair_entry *e = &shm->table[i];

		if (e->prev_nr == EDGEPAIR_EMPTY)
			continue;
		outbound_total_exec[e->prev_nr] += e->total_count;
		if (e->new_edge_count > 0) {
			inbound_productive[e->curr_nr]++;
			outbound_productive[e->prev_nr]++;
		}
	}

	for (i = 0; i < dim; i++) {
		if (inbound_productive[i] == 0)
			continue;
		if (outbound_productive[i] != 0)
			continue;
		dead[dead_count].nr = i;
		dead[dead_count].inbound_productive = inbound_productive[i];
		dead[dead_count].outbound_total = outbound_total_exec[i];
		dead_count++;
	}

	if (dead_count == 0) {
		printf("  (none -- every productively-reached syscall has at "
			"least one productive outgoing pair)\n\n");
		goto out;
	}

	qsort(dead, dead_count, sizeof(*dead), cmp_dead_end_by_inbound);

	shown = dead_count < dead_cap ? dead_count : dead_cap;
	printf("  (showing top %u of %u dead-end syscalls)\n\n",
		shown, dead_count);

	for (i = 0; i < shown; i++)
		printf("  syscall_%-4u  (inbound productive: %u, "
			"outbound total executed: %lu)\n",
			dead[i].nr, dead[i].inbound_productive,
			dead[i].outbound_total);
	printf("\n");

out:
	free(inbound_productive);
	free(outbound_productive);
	free(outbound_total_exec);
	free(dead);
}

/*
 * Cold-but-high-total productive pairs: pairs that historically were
 * productive (new_edge_count > 0), executed at least the median number
 * of times for productive pairs, and have since gone cold by the
 * cooldown-timer predicate.  These are likely-saturated sequences.
 */
static int cmp_by_total_desc(const void *a, const void *b)
{
	const struct edgepair_entry *ea = (const struct edgepair_entry *)a;
	const struct edgepair_entry *eb = (const struct edgepair_entry *)b;

	if (eb->total_count > ea->total_count)
		return 1;
	if (eb->total_count < ea->total_count)
		return -1;
	return 0;
}

static int cmp_ul_asc(const void *a, const void *b)
{
	unsigned long va = *(const unsigned long *)a;
	unsigned long vb = *(const unsigned long *)b;

	if (va < vb)
		return -1;
	if (va > vb)
		return 1;
	return 0;
}

static void analyze_cold_high_total(const struct edgepair_shared *shm, int top_n)
{
	struct edgepair_entry *productive;
	struct edgepair_entry *cand;
	unsigned long *totals;
	unsigned long median;
	unsigned long total_pair_calls = shm->total_pair_calls;
	unsigned int productive_count = 0;
	unsigned int cand_count = 0;
	unsigned int limit;
	unsigned int i;

	printf("=== Cold-but-high-total productive pairs ===\n");

	for (i = 0; i < EDGEPAIR_TABLE_SIZE; i++) {
		const struct edgepair_entry *e = &shm->table[i];

		if (e->prev_nr == EDGEPAIR_EMPTY)
			continue;
		if (e->new_edge_count == 0)
			continue;
		productive_count++;
	}

	if (productive_count == 0) {
		printf("  (no productive pairs)\n\n");
		return;
	}

	productive = malloc(productive_count * sizeof(*productive));
	cand = malloc(productive_count * sizeof(*cand));
	totals = malloc(productive_count * sizeof(*totals));

	if (productive == NULL || cand == NULL || totals == NULL) {
		fprintf(stderr, "out of memory\n");
		free(productive);
		free(cand);
		free(totals);
		return;
	}

	{
		unsigned int j = 0;

		for (i = 0; i < EDGEPAIR_TABLE_SIZE; i++) {
			const struct edgepair_entry *e = &shm->table[i];

			if (e->prev_nr == EDGEPAIR_EMPTY)
				continue;
			if (e->new_edge_count == 0)
				continue;
			productive[j] = *e;
			totals[j] = e->total_count;
			j++;
		}
	}

	qsort(totals, productive_count, sizeof(*totals), cmp_ul_asc);
	median = totals[productive_count / 2];

	for (i = 0; i < productive_count; i++) {
		const struct edgepair_entry *e = &productive[i];

		if (e->total_count < median)
			continue;
		if (!entry_is_cold(e, total_pair_calls))
			continue;
		cand[cand_count++] = *e;
	}

	if (cand_count == 0) {
		printf("  threshold (median total over productive pairs): %lu\n",
			median);
		printf("  (no productive pairs at or above the median total "
			"are cold)\n\n");
		goto out;
	}

	qsort(cand, cand_count, sizeof(*cand), cmp_by_total_desc);

	limit = (unsigned int)top_n < cand_count
		? (unsigned int)top_n : cand_count;

	printf("  threshold (median total over productive pairs): %lu\n",
		median);
	printf("  cold_threshold (pair-calls since last new edge): %u\n",
		EDGEPAIR_COLD_THRESHOLD);
	printf("  (showing top %u of %u cold high-total pairs)\n\n",
		limit, cand_count);
	printf("  %-8s  %-8s  %-12s  %-12s  %-14s  %s\n",
		"prev_nr", "curr_nr", "new_edges", "total_exec",
		"last_new_at", "yield");

	for (i = 0; i < limit; i++) {
		const struct edgepair_entry *e = &cand[i];
		double yield;

		yield = e->total_count > 0
			? 100.0 * e->new_edge_count / e->total_count : 0.0;

		printf("  %-8u  %-8u  %-12lu  %-12lu  %-14lu  %.2f%%\n",
			e->prev_nr, e->curr_nr,
			e->new_edge_count, e->total_count,
			e->last_new_at, yield);
	}
	printf("\n");

out:
	free(productive);
	free(cand);
	free(totals);
}

/*
 * DOT-language export of the pair graph for visualisation in graphviz.
 * Nodes are syscall numbers that appear as prev or curr in any non-empty
 * entry.  Edges are one per non-empty pair, coloured by state:
 *   productive-fresh  -> darkgreen, penwidth = log(new_edges+1) [1..6]
 *   productive-cold   -> orange,    penwidth = log(new_edges+1) [1..6]
 *   seen-unproductive -> gray70, penwidth=0.5, dashed
 * Edge label is "<new_edges>/<total>" for productive pairs only.
 */
static int emit_dot(const struct edgepair_shared *shm, const char *path)
{
	unsigned char *node_seen;
	unsigned long total_pair_calls = shm->total_pair_calls;
	unsigned int max_nr = 0;
	unsigned int dim;
	unsigned int i;
	FILE *out;
	int close_out = 0;

	for (i = 0; i < EDGEPAIR_TABLE_SIZE; i++) {
		const struct edgepair_entry *e = &shm->table[i];

		if (e->prev_nr == EDGEPAIR_EMPTY)
			continue;
		if (e->prev_nr > max_nr)
			max_nr = e->prev_nr;
		if (e->curr_nr > max_nr)
			max_nr = e->curr_nr;
	}

	dim = max_nr + 1;
	node_seen = calloc(dim, sizeof(*node_seen));
	if (node_seen == NULL) {
		fprintf(stderr, "error: out of memory for DOT export\n");
		return -1;
	}

	for (i = 0; i < EDGEPAIR_TABLE_SIZE; i++) {
		const struct edgepair_entry *e = &shm->table[i];

		if (e->prev_nr == EDGEPAIR_EMPTY)
			continue;
		node_seen[e->prev_nr] = 1;
		node_seen[e->curr_nr] = 1;
	}

	if (strcmp(path, "-") == 0) {
		out = stdout;
	} else {
		out = fopen(path, "w");
		if (out == NULL) {
			fprintf(stderr, "error: cannot open '%s' for DOT: ",
				path);
			perror(NULL);
			free(node_seen);
			return -1;
		}
		close_out = 1;
	}

	fprintf(out, "digraph edgepair {\n");
	fprintf(out, "\trankdir=LR;\n");
	fprintf(out, "\tnode [shape=ellipse, fontsize=10];\n");

	for (i = 0; i < dim; i++) {
		if (!node_seen[i])
			continue;
		fprintf(out, "\tsyscall_%u [label=\"syscall_%u\"];\n", i, i);
	}

	for (i = 0; i < EDGEPAIR_TABLE_SIZE; i++) {
		const struct edgepair_entry *e = &shm->table[i];

		if (e->prev_nr == EDGEPAIR_EMPTY)
			continue;

		if (e->new_edge_count == 0) {
			fprintf(out,
				"\tsyscall_%u -> syscall_%u "
				"[color=gray70, penwidth=0.5, style=dashed];\n",
				e->prev_nr, e->curr_nr);
			continue;
		}

		{
			int cold = entry_is_cold(e, total_pair_calls);
			const char *color = cold ? "orange" : "darkgreen";
			double pw = pair_penwidth(e->new_edge_count);

			fprintf(out,
				"\tsyscall_%u -> syscall_%u "
				"[color=%s, penwidth=%.2f, "
				"label=\"%lu/%lu\"];\n",
				e->prev_nr, e->curr_nr, color, pw,
				e->new_edge_count, e->total_count);
		}
	}

	fprintf(out, "}\n");

	if (close_out)
		fclose(out);
	free(node_seen);
	return 0;
}

int main(int argc, char *argv[])
{
	const char *dump_file = "edgepair.dump";
	const char *dot_path = NULL;
	struct edgepair_dump_header hdr;
	struct edgepair_shared *shm;
	FILE *f;
	int top_n = 20;
	int top_k = 5;
	int buckets = 20;
	int opt;

	while ((opt = getopt(argc, argv, "n:k:b:d:")) != -1) {
		switch (opt) {
		case 'n':
			top_n = atoi(optarg);
			if (top_n <= 0)
				top_n = 20;
			break;
		case 'k':
			top_k = atoi(optarg);
			if (top_k <= 0)
				top_k = 5;
			break;
		case 'b':
			buckets = atoi(optarg);
			if (buckets <= 0 || buckets > 100)
				buckets = 20;
			break;
		case 'd':
			dot_path = optarg;
			break;
		default:
			fprintf(stderr,
				"Usage: %s [-n top_n] [-k top_k] [-b buckets] "
				"[-d dotfile] [dump_file]\n",
				argv[0]);
			return EXIT_FAILURE;
		}
	}

	if (optind < argc)
		dump_file = argv[optind];

	f = fopen(dump_file, "rb");
	if (f == NULL) {
		fprintf(stderr, "error: cannot open '%s': ", dump_file);
		perror(NULL);
		return EXIT_FAILURE;
	}

	if (fread(&hdr, sizeof(hdr), 1, f) != 1) {
		fprintf(stderr, "error: cannot read header from '%s'\n", dump_file);
		fclose(f);
		return EXIT_FAILURE;
	}

	if (hdr.magic != EDGEPAIR_DUMP_MAGIC) {
		fprintf(stderr, "error: bad magic 0x%08x (expected 0x%08x)\n",
			hdr.magic, EDGEPAIR_DUMP_MAGIC);
		fclose(f);
		return EXIT_FAILURE;
	}
	if (hdr.version != EDGEPAIR_DUMP_VERSION) {
		fprintf(stderr, "error: unsupported version %u (expected %u)\n",
			hdr.version, EDGEPAIR_DUMP_VERSION);
		fclose(f);
		return EXIT_FAILURE;
	}
	if (hdr.table_size != EDGEPAIR_TABLE_SIZE) {
		fprintf(stderr, "error: table_size %u (expected %u)\n",
			hdr.table_size, EDGEPAIR_TABLE_SIZE);
		fclose(f);
		return EXIT_FAILURE;
	}

	shm = malloc(sizeof(*shm));
	if (shm == NULL) {
		fprintf(stderr, "error: out of memory\n");
		fclose(f);
		return EXIT_FAILURE;
	}

	if (fread(shm->table, sizeof(shm->table), 1, f) != 1) {
		fprintf(stderr, "error: truncated dump file '%s'\n", dump_file);
		free(shm);
		fclose(f);
		return EXIT_FAILURE;
	}
	shm->total_pair_calls = (unsigned long)hdr.total_pair_calls;
	shm->pairs_tracked    = (unsigned long)hdr.pairs_tracked;
	shm->pairs_dropped    = (unsigned long)hdr.pairs_dropped;

	fclose(f);

	printf("edge_analyzer: %s\n\n", dump_file);
	analyze_identity(&hdr);
	analyze_utilization(shm);
	analyze_collisions(shm);
	analyze_top_pairs(shm, top_n);
	analyze_growth(shm, buckets);
	analyze_top_outgoing(shm, top_k);
	analyze_dead_ends(shm);
	analyze_cold_high_total(shm, top_n);

	if (dot_path != NULL)
		emit_dot(shm, dot_path);

	free(shm);
	return EXIT_SUCCESS;
}
