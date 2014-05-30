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

void create_shm(void)
{
	void *p;
	unsigned int shm_pages;

	/* round up shm to nearest page size */
	shm_pages = ((sizeof(struct shm_s) + page_size - 1) & PAGE_MASK) / page_size;

	/* Waste some address space to set up some "protection" near the SHM location. */
	p = alloc_shared((SHM_PROT_PAGES + shm_pages + SHM_PROT_PAGES) * page_size);

	/* clear whole mapping, including the redzones. */
	memset(p, 0, shm_pages * page_size);

	/* set the redzones to PROT_NONE */
	mprotect(p, SHM_PROT_PAGES * page_size, PROT_NONE);
	mprotect(p + (SHM_PROT_PAGES + shm_pages) * page_size,
			SHM_PROT_PAGES * page_size, PROT_NONE);

	shm = p + SHM_PROT_PAGES * page_size;
}

void create_shm_arrays(void)
{
	shm->child_op_count = alloc_shared(max_children * sizeof(unsigned long));

	shm->pids = alloc_shared(max_children * sizeof(pid_t));

	shm->tv = alloc_shared(max_children * sizeof(struct timeval));

	shm->syscall = alloc_shared(max_children * sizeof(struct syscallrecord));
	shm->previous = alloc_shared(max_children * sizeof(struct syscallrecord));

	shm->mappings = alloc_shared(max_children * sizeof(struct map *));
	shm->num_mappings = alloc_shared(max_children * sizeof(unsigned int));

	shm->seeds = alloc_shared(max_children * sizeof(int));
	shm->kill_count = alloc_shared(max_children * sizeof(unsigned char));
	shm->logfiles = alloc_shared(max_children * sizeof(FILE *));
	shm->logdirty = alloc_shared(max_children * sizeof(bool));
	shm->scratch = alloc_shared(max_children * sizeof(unsigned long));
}

void init_shm(void)
{
	unsigned int i;

	output(2, "shm is at %p\n", shm);

	shm->total_syscalls_done = 1;

	if (user_set_seed == TRUE)
		shm->seed = init_seed(seed);
	else
		shm->seed = new_seed();
	/* Set seed in parent thread */
	set_seed(0);

	for_each_child(i) {
		shm->pids[i] = EMPTY_PIDSLOT;

		shm->previous[i].nr = shm->syscall[i].nr = -1;

		shm->previous[i].a1 = shm->syscall[i].a1 = -1;
		shm->previous[i].a2 = shm->syscall[i].a2 = -1;
		shm->previous[i].a3 = shm->syscall[i].a3 = -1;
		shm->previous[i].a4 = shm->syscall[i].a4 = -1;
		shm->previous[i].a5 = shm->syscall[i].a5 = -1;
		shm->previous[i].a6 = shm->syscall[i].a6 = -1;
	}
}
