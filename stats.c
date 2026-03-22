#include <errno.h>
#include "arch.h"
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

	if (biarch == TRUE) {
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
		printf("\nKCOV coverage: %lu unique edges, %lu total PCs collected\n",
			kcov_shm->edges_found, kcov_shm->total_pcs);
	}
}
