#include <errno.h>
#include <string.h>
#include "arch.h"
#include "cmp_hints.h"
#include "kcov.h"
#include "shm.h"
#include "stats.h"
#include "syscall.h"
#include "tables.h"

static void dump_entry(const struct syscalltable *table, unsigned int i)
{
	struct syscallentry *entry;
	unsigned int j;

	entry = table[i].entry;
	if (entry == NULL)
		return;

	if (entry->attempted == 0)
		return;

	printf("%s: (attempted:%u. success:%u. failures:%u.\n", entry->name, entry->attempted, entry->successes, entry->failures);

	for (j = 0; j < NR_ERRNOS; j++) {
		if (entry->errnos[j] != 0) {
			printf("    %s: %d\n", strerror(j), entry->errnos[j]);
		}
	}
}

void dump_stats(void)
{
	unsigned int i;

	if (biarch == true) {
		printf("32bit:\n");
		for_each_32bit_syscall(i) {
			dump_entry(syscalls_32bit, i);
		}
		printf("64bit:\n");
		for_each_64bit_syscall(i) {
			dump_entry(syscalls_64bit, i);
		}
	} else {
		for_each_syscall(i) {
			dump_entry(syscalls, i);
		}
	}

	if (shm->stats.fd_stale_detected || shm->stats.fd_closed_tracked ||
	    shm->stats.fd_regenerated) {
		printf("\nfd lifecycle: stale:%lu closed:%lu regenerated:%lu\n",
			shm->stats.fd_stale_detected,
			shm->stats.fd_closed_tracked,
			shm->stats.fd_regenerated);
	}

	if (kcov_shm != NULL) {
		unsigned int top_nr[10];
		unsigned long top_edges[10];
		unsigned int top_count = 0;
		unsigned int cold_count = 0;
		unsigned int j;

		printf("\nKCOV coverage: %lu unique edges, %lu total PCs, %lu calls\n",
			kcov_shm->edges_found, kcov_shm->total_pcs,
			kcov_shm->total_calls);

		/* Find top 10 edge-producing syscalls via insertion sort. */
		memset(top_edges, 0, sizeof(top_edges));
		for (i = 0; i < max_nr_syscalls; i++) {
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
			printf("Top edge-producing syscalls:\n");
			for (j = 0; j < top_count; j++) {
				struct syscallentry *entry = syscalls[top_nr[j]].entry;
				const char *name = entry ? entry->name : "???";

				printf("  %-24s %lu\n", name, top_edges[j]);
			}
		}

		if (cold_count > 0)
			printf("Cold syscalls (deprioritized): %u\n", cold_count);
	}

	if (cmp_hints_shm != NULL) {
		unsigned int total_hints = 0, syscalls_with_hints = 0;

		for (i = 0; i < MAX_NR_SYSCALL; i++) {
			if (cmp_hints_shm->pools[i].count > 0) {
				total_hints += cmp_hints_shm->pools[i].count;
				syscalls_with_hints++;
			}
		}
		printf("CMP hints: %u values across %u syscalls\n",
			total_hints, syscalls_with_hints);
	}
}
