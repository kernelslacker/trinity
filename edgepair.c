/*
 * Edge-pair tracking: (prev_syscall, curr_syscall) -> coverage data.
 *
 * Open-addressed hash table.  Post-retrofit the canonical lives in
 * parent-private struct edgepair_aggregate (parent_edgepair in
 * edgepair-ring.c), fed by per-child SPSC observation rings drained
 * each main_loop iteration.  Children publish their (prev, curr,
 * new_edges) observations into their own edgepair_ring; the parent
 * applies them serially under single-writer discipline, no CAS, no
 * packed-key layout pin.
 *
 * The one child-side reader (edgepair_is_cold on the syscall-selection
 * biasing path) consults the parent-published mirror page
 * (edgepair_published), refreshed in full at every drain.  Parent-side
 * consumers (edgepair_get_stats, dump, stats display) read the
 * canonical aggregate directly.
 */

#include <stdbool.h>
#include <stdio.h>

#include "child.h"
#include "edgepair.h"
#include "edgepair_ring.h"
#include "trinity.h"

static bool edgepair_enabled;

bool edgepair_is_enabled(void)
{
	return edgepair_enabled;
}

void edgepair_init_global(void)
{
	edgepair_enabled = true;

	output(0, "KCOV: edge-pair tracking enabled (%lu KB canonical, %u slots)\n",
		sizeof(parent_edgepair.table) / 1024,
		EDGEPAIR_TABLE_SIZE);
}

static unsigned int pair_hash(unsigned int prev, unsigned int curr)
{
	/* Simple but effective: mix both syscall numbers. */
	unsigned int h = prev * 31 + curr;
	h ^= h >> 16;
	h *= 0x45d9f3b;
	h ^= h >> 16;
	return h & EDGEPAIR_TABLE_MASK;
}

void edgepair_record(struct childdata *child,
		     unsigned int prev_nr, unsigned int curr_nr,
		     bool found_new)
{
	if (!edgepair_enabled)
		return;

	if (child == NULL || child->edgepair_ring == NULL)
		return;

	if (prev_nr >= MAX_NR_SYSCALL || curr_nr >= MAX_NR_SYSCALL)
		return;

	/* Drop on ring overflow: parent_edgepair.ring_overflow_total
	 * already conveys "we lost samples".  Blocking a child on an
	 * observer enqueue is the wrong tradeoff for a syscall-prior
	 * bias; at worst the cold-pair detector takes one more drain to
	 * notice a productive pair just went cold. */
	(void)edgepair_ring_enqueue(child->edgepair_ring,
				    prev_nr, curr_nr, found_new);
}

bool edgepair_is_cold(unsigned int prev_nr, unsigned int curr_nr)
{
	unsigned int idx;
	unsigned int probe;

	if (edgepair_published == NULL)
		return false;

	idx = pair_hash(prev_nr, curr_nr);
	for (probe = 0; probe < EDGEPAIR_MAX_PROBE; probe++) {
		const struct edgepair_published_slot *e =
			&edgepair_published->slots[idx];

		if (e->prev_nr == EDGEPAIR_EMPTY)
			return false;
		if (e->prev_nr == prev_nr && e->curr_nr == curr_nr) {
			unsigned long total, last;

			/* Never found new edges -- not cold, just unproductive. */
			if (e->new_edge_count == 0)
				return false;

			total = edgepair_published->total_pair_calls;
			last = e->last_new_at;
			return (total - last) > EDGEPAIR_COLD_THRESHOLD;
		}
		idx = (idx + 1) & EDGEPAIR_TABLE_MASK;
	}

	return false;
}

struct edgepair_stats edgepair_get_stats(unsigned int prev_nr,
					 unsigned int curr_nr)
{
	struct edgepair_stats s = { 0, 0 };
	unsigned int idx;
	unsigned int probe;

	if (!edgepair_enabled)
		return s;

	if (prev_nr >= MAX_NR_SYSCALL || curr_nr >= MAX_NR_SYSCALL)
		return s;

	idx = pair_hash(prev_nr, curr_nr);
	for (probe = 0; probe < EDGEPAIR_MAX_PROBE; probe++) {
		const struct edgepair_entry *e = &parent_edgepair.table[idx];

		if (e->prev_nr == EDGEPAIR_EMPTY)
			return s;
		if (e->prev_nr == prev_nr && e->curr_nr == curr_nr) {
			s.new_edges = e->new_edge_count;
			s.total     = e->total_count;
			return s;
		}
		idx = (idx + 1) & EDGEPAIR_TABLE_MASK;
	}

	return s;
}

void edgepair_dump_to_file(const char *path)
{
	FILE *f;
	uint32_t magic = EDGEPAIR_DUMP_MAGIC;

	if (!edgepair_enabled)
		return;

	f = fopen(path, "wb");
	if (f == NULL) {
		perror("edgepair: failed to open dump file");
		return;
	}

	/* On-disk layout: 4-byte magic, then the canonical table followed
	 * by the three top-level counters.  The magic bump from
	 * 0xEDDA7A01U to 0xEDDA7A02U lets edge_analyzer reject pre-retrofit
	 * dumps cleanly; the byte layout below the magic matches the
	 * pre-retrofit prefix so the analyzer's table walk needs only the
	 * magic constant updated. */
	if (fwrite(&magic, sizeof(magic), 1, f) != 1 ||
	    fwrite(parent_edgepair.table,
		   sizeof(parent_edgepair.table), 1, f) != 1 ||
	    fwrite(&parent_edgepair.total_pair_calls,
		   sizeof(parent_edgepair.total_pair_calls), 1, f) != 1 ||
	    fwrite(&parent_edgepair.pairs_tracked,
		   sizeof(parent_edgepair.pairs_tracked), 1, f) != 1 ||
	    fwrite(&parent_edgepair.pairs_dropped,
		   sizeof(parent_edgepair.pairs_dropped), 1, f) != 1) {
		perror("edgepair: failed to write dump file");
		fclose(f);
		return;
	}

	fclose(f);
	output(0, "KCOV: edge-pair data dumped to %s\n", path);
}
