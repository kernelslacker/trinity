/*
 * edge_analyzer - offline analysis of trinity edge-pair coverage data.
 *
 * Reads a binary dump produced by trinity (edgepair.dump) and reports:
 *   1. Hash table utilization stats
 *   2. Collision rates (linear-probe displacement histogram)
 *   3. Top N most-productive edge pairs
 *   4. Coverage growth rate over time
 *
 * Usage: edge_analyzer [options] [dump_file]
 *   -n N   show top N pairs (default 20)
 *   -b N   time buckets for growth chart (default 20)
 *   dump_file defaults to "edgepair.dump"
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * These must match include/edgepair.h and edgepair.c exactly.
 * If edgepair.h changes its struct layout or hash function, update here
 * and bump EDGEPAIR_DUMP_MAGIC so old dumps fail loudly.
 */
#define EDGEPAIR_TABLE_SIZE	65536
#define EDGEPAIR_TABLE_MASK	(EDGEPAIR_TABLE_SIZE - 1)
#define EDGEPAIR_EMPTY		0xFFFFFFFFU
#define EDGEPAIR_MAX_PROBE	32
#define EDGEPAIR_DUMP_MAGIC	0xEDDA7A01U

struct edgepair_entry {
	unsigned int  prev_nr;
	unsigned int  curr_nr;
	unsigned long new_edge_count;
	unsigned long total_count;
	unsigned long last_new_at;
};

struct edgepair_shared {
	struct edgepair_entry table[EDGEPAIR_TABLE_SIZE];
	unsigned long total_pair_calls;
	unsigned long pairs_tracked;
	unsigned long pairs_dropped;
};

/* Must match pair_hash() in edgepair.c. */
static unsigned int pair_hash(unsigned int prev, unsigned int curr)
{
	unsigned int h = prev * 31 + curr;

	h ^= h >> 16;
	h *= 0x45d9f3bU;
	h ^= h >> 16;
	return h & EDGEPAIR_TABLE_MASK;
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
		ideal = pair_hash(e->prev_nr, e->curr_nr);
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

int main(int argc, char *argv[])
{
	const char *dump_file = "edgepair.dump";
	struct edgepair_shared *shm;
	uint32_t magic;
	FILE *f;
	int top_n = 20;
	int buckets = 20;
	int opt;

	while ((opt = getopt(argc, argv, "n:b:")) != -1) {
		switch (opt) {
		case 'n':
			top_n = atoi(optarg);
			if (top_n <= 0)
				top_n = 20;
			break;
		case 'b':
			buckets = atoi(optarg);
			if (buckets <= 0 || buckets > 100)
				buckets = 20;
			break;
		default:
			fprintf(stderr,
				"Usage: %s [-n top_n] [-b buckets] [dump_file]\n",
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

	if (fread(&magic, sizeof(magic), 1, f) != 1) {
		fprintf(stderr, "error: cannot read magic from '%s'\n", dump_file);
		fclose(f);
		return EXIT_FAILURE;
	}

	if (magic != EDGEPAIR_DUMP_MAGIC) {
		fprintf(stderr, "error: bad magic 0x%08x (expected 0x%08x)\n",
			magic, EDGEPAIR_DUMP_MAGIC);
		fclose(f);
		return EXIT_FAILURE;
	}

	shm = malloc(sizeof(*shm));
	if (shm == NULL) {
		fprintf(stderr, "error: out of memory\n");
		fclose(f);
		return EXIT_FAILURE;
	}

	if (fread(shm, sizeof(*shm), 1, f) != 1) {
		fprintf(stderr, "error: truncated dump file '%s'\n", dump_file);
		free(shm);
		fclose(f);
		return EXIT_FAILURE;
	}

	fclose(f);

	printf("edge_analyzer: %s\n\n", dump_file);
	analyze_utilization(shm);
	analyze_collisions(shm);
	analyze_top_pairs(shm, top_n);
	analyze_growth(shm, buckets);

	free(shm);
	return EXIT_SUCCESS;
}
