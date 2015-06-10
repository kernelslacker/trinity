/*
 * Shared mapping creation.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include "arch.h"
#include "child.h"
#include "log.h"
#include "params.h"
#include "pids.h"
#include "random.h"
#include "shm.h"
#include "utils.h"

struct shm_s *shm;

#define SHM_PROT_PAGES 30

unsigned int shm_size;

void create_shm(void)
{
	unsigned int nr_shm_pages;

	/* round up shm to nearest page size */
	shm_size = (sizeof(struct shm_s) + page_size - 1) & PAGE_MASK;
	nr_shm_pages = shm_size / page_size;

	/* Waste some address space to set up some "protection" near the SHM location. */
	shm = alloc_shared(shm_size);

	/* clear the whole shm. */
	memset(shm, 0, shm_size);
	printf("shm:%p-%p (%d pages)\n", shm, shm + shm_size - 1, nr_shm_pages);
}

void shm_ro(void)
{
	mprotect(shm, shm_size, PROT_READ);
}

void shm_rw(void)
{
	mprotect(shm, shm_size, PROT_READ|PROT_WRITE);
}

void init_shm(void)
{
	unsigned int i;

	output(2, "shm is at %p\n", shm);

	if (set_debug == TRUE)
		shm->debug = TRUE;

	shm->stats.total_syscalls_done = 1;

	if (user_set_seed == TRUE)
		shm->seed = init_seed(seed);
	else
		shm->seed = new_seed();
	/* Set seed in parent thread */
	set_seed(NULL);

	shm->children = zmalloc(max_children * sizeof(struct childdata *));

	for_each_child(i) {
		struct childdata *child;

		child = alloc_shared(sizeof(struct childdata));
		shm->children[i] = child;

		memset(&child->syscall, 0, sizeof(struct syscallrecord));
		memset(&child->previous, 0, sizeof(struct syscallrecord));

		child->pid = EMPTY_PIDSLOT;

		child->logfile = NULL;
	}
}
