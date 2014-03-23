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
	shm_pages = ((sizeof(struct shm_s) + page_size - 1) & ~(page_size - 1)) / page_size;

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
	shm->child_syscall_count = alloc_shared(max_children * sizeof(unsigned long));

	shm->pids = alloc_shared(max_children * sizeof(pid_t));

	shm->tv = alloc_shared(max_children * sizeof(struct timeval));

	shm->previous_nr = alloc_shared(max_children * sizeof(unsigned int));

	shm->previous_a1 = alloc_shared(max_children * sizeof(unsigned long));
	shm->previous_a2 = alloc_shared(max_children * sizeof(unsigned long));
	shm->previous_a3 = alloc_shared(max_children * sizeof(unsigned long));
	shm->previous_a4 = alloc_shared(max_children * sizeof(unsigned long));
	shm->previous_a5 = alloc_shared(max_children * sizeof(unsigned long));
	shm->previous_a6 = alloc_shared(max_children * sizeof(unsigned long));

	shm->syscall = alloc_shared(max_children * sizeof(struct syscallrecord));

	shm->mappings = alloc_shared(max_children * sizeof(struct map *));
	shm->num_mappings = alloc_shared(max_children * sizeof(unsigned int));

	shm->seeds = alloc_shared(max_children * sizeof(int));
	shm->child_type = alloc_shared(max_children * sizeof(unsigned char));
	shm->kill_count = alloc_shared(max_children * sizeof(unsigned char));
	shm->logfiles = alloc_shared(max_children * sizeof(FILE *));
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

	for (i = 0; i < max_children; i++) {

		shm->pids[i] = EMPTY_PIDSLOT;

		shm->previous_nr[i] = -1;

		shm->syscall[i].nr = -1;

		shm->previous_a1[i] = shm->syscall[i].a1 = -1;
		shm->previous_a2[i] = shm->syscall[i].a2 = -1;
		shm->previous_a3[i] = shm->syscall[i].a3 = -1;
		shm->previous_a4[i] = shm->syscall[i].a4 = -1;
		shm->previous_a5[i] = shm->syscall[i].a5 = -1;
		shm->previous_a6[i] = shm->syscall[i].a6 = -1;
	}
}
