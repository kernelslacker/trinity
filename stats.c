#include <errno.h>
#include <string.h>
#include "arch.h"
#include "cmp_hints.h"
#include "edgepair.h"
#include "kcov.h"
#include "shm.h"
#include "stats.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"

static void dump_entry(const struct syscalltable *table, unsigned int i)
{
	struct syscallentry *entry;
	unsigned int j;

	entry = table[i].entry;
	if (entry == NULL)
		return;

	if (entry->attempted == 0)
		return;

	output(0, "%s: (attempted:%u. success:%u. failures:%u.\n", entry->name, entry->attempted, entry->successes, entry->failures);

	for (j = 0; j < NR_ERRNOS; j++) {
		if (entry->errnos[j] != 0) {
			output(0, "    %s: %d\n", strerror(j), entry->errnos[j]);
		}
	}
}

void dump_stats(void)
{
	unsigned int i;

	if (biarch == true) {
		output(0, "32bit:\n");
		for_each_32bit_syscall(i) {
			dump_entry(syscalls_32bit, i);
		}
		output(0, "64bit:\n");
		for_each_64bit_syscall(i) {
			dump_entry(syscalls_64bit, i);
		}
	} else {
		for_each_syscall(i) {
			dump_entry(syscalls, i);
		}
	}

	if (shm->stats.fd_stale_detected || shm->stats.fd_closed_tracked ||
	    shm->stats.fd_regenerated || shm->stats.fd_stale_by_generation ||
	    shm->stats.fd_duped || shm->stats.fd_events_processed) {
		output(0, "\nfd lifecycle: stale:%lu (generation:%lu) closed:%lu regenerated:%lu duped:%lu\n",
			shm->stats.fd_stale_detected,
			shm->stats.fd_stale_by_generation,
			shm->stats.fd_closed_tracked,
			shm->stats.fd_regenerated,
			shm->stats.fd_duped);
		output(0, "fd events: processed:%lu dropped:%lu\n",
			shm->stats.fd_events_processed,
			shm->stats.fd_events_dropped);
	}

	if (kcov_shm != NULL) {
		unsigned int top_nr[10];
		unsigned long top_edges[10];
		unsigned int top_count = 0;
		unsigned int cold_count = 0;
		unsigned int j;

		output(0, "\nKCOV coverage: %lu unique edges, %lu total PCs, %lu calls\n",
			kcov_shm->edges_found, kcov_shm->total_pcs,
			kcov_shm->total_calls);

		/* Find top 10 edge-producing syscalls via insertion sort. */
		unsigned int nr_syscalls_to_scan = biarch ? max_nr_64bit_syscalls : max_nr_syscalls;
		const struct syscalltable *table = biarch ? syscalls_64bit : syscalls;

		memset(top_edges, 0, sizeof(top_edges));
		for (i = 0; i < nr_syscalls_to_scan; i++) {
			unsigned long edges = kcov_shm->per_syscall_edges[i];

			if (edges == 0)
				continue;

			if (kcov_syscall_is_cold(i))
				cold_count++;

			/* Find insertion point. */
			for (j = top_count; j > 0 && edges > top_edges[j - 1]; j--) {
				if (j < 10) {
					top_edges[j] = top_edges[j - 1];
					top_nr[j] = top_nr[j - 1];
				}
			}
			if (j < 10) {
				top_edges[j] = edges;
				top_nr[j] = i;
				if (top_count < 10)
					top_count++;
			}
		}

		if (top_count > 0) {
			output(0, "Top edge-producing syscalls:\n");
			for (j = 0; j < top_count; j++) {
				struct syscallentry *entry = table[top_nr[j]].entry;
				const char *name = entry ? entry->name : "???";

				output(0, "  %-24s %lu\n", name, top_edges[j]);
			}
		}

		if (cold_count > 0) {
			output(0, "Cold syscalls (need better sanitise): %u\n", cold_count);
			for (i = 0; i < nr_syscalls_to_scan; i++) {
				struct syscallentry *entry;

				if (kcov_shm->per_syscall_edges[i] == 0)
					continue;
				if (!kcov_syscall_is_cold(i))
					continue;

				entry = table[i].entry;
				output(0, "  %-24s (edges:%lu, last new @ call %lu)\n",
					entry ? entry->name : "???",
					kcov_shm->per_syscall_edges[i],
					kcov_shm->last_edge_at[i]);
			}
		}
	}

	if (cmp_hints_shm != NULL) {
		unsigned int total_hints = 0, syscalls_with_hints = 0;

		for (i = 0; i < MAX_NR_SYSCALL; i++) {
			if (cmp_hints_shm->pools[i].count > 0) {
				total_hints += cmp_hints_shm->pools[i].count;
				syscalls_with_hints++;
			}
		}
		output(0, "CMP hints: %u values across %u syscalls\n",
			total_hints, syscalls_with_hints);
	}

	if (edgepair_shm != NULL) {
		unsigned int top_count = 0;
		unsigned int cold_pairs = 0;
		struct {
			unsigned int prev_nr;
			unsigned int curr_nr;
			unsigned long new_edges;
		} top[10];
		unsigned int j;

		memset(top, 0, sizeof(top));

		output(0, "\nEdge-pair coverage: %lu unique pairs, %lu total pair-calls\n",
			edgepair_shm->pairs_tracked,
			edgepair_shm->total_pair_calls);

		for (i = 0; i < EDGEPAIR_TABLE_SIZE; i++) {
			struct edgepair_entry *e = &edgepair_shm->table[i];
			unsigned long edges;

			if (e->prev_nr == EDGEPAIR_EMPTY)
				continue;

			edges = e->new_edge_count;
			if (edges == 0)
				continue;

			if (edgepair_is_cold(e->prev_nr, e->curr_nr))
				cold_pairs++;

			for (j = top_count; j > 0 && edges > top[j - 1].new_edges; j--) {
				if (j < 10)
					top[j] = top[j - 1];
			}
			if (j < 10) {
				top[j].prev_nr = e->prev_nr;
				top[j].curr_nr = e->curr_nr;
				top[j].new_edges = edges;
				if (top_count < 10)
					top_count++;
			}
		}

		if (top_count > 0) {
			const struct syscalltable *table = biarch ? syscalls_64bit : syscalls;
			unsigned int nr_max = biarch ? max_nr_64bit_syscalls : max_nr_syscalls;

			output(0, "Top edge-producing syscall pairs:\n");
			for (j = 0; j < top_count; j++) {
				const char *prev_name = "???";
				const char *curr_name = "???";

				if (top[j].prev_nr < nr_max && table[top[j].prev_nr].entry)
					prev_name = table[top[j].prev_nr].entry->name;
				if (top[j].curr_nr < nr_max && table[top[j].curr_nr].entry)
					curr_name = table[top[j].curr_nr].entry->name;

				output(0, "  %-20s -> %-20s %lu\n",
					prev_name, curr_name, top[j].new_edges);
			}
		}

		if (cold_pairs > 0)
			output(0, "Cold pairs (saturated sequences): %u\n", cold_pairs);
	}
}
