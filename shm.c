/*
 * Shared mapping creation.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/time.h>
#include "arch.h"
#include "log.h"
#include "params.h"
#include "pids.h"
#include "random.h"
#include "shm.h"
#include "utils.h"

struct shm_s *shm;

void * alloc_shared(unsigned int size)
{
	void *ret;

	ret = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, -1, 0);
	if (ret == MAP_FAILED)
		return NULL;

	return ret;
}

static void shm_init(void)
{
	unsigned int i;

	shm->total_syscalls_done = 1;

	if (user_set_seed == TRUE)
		shm->seed = init_seed(seed);
	else
		shm->seed = new_seed();
	/* Set seed in parent thread */
	set_seed(0);

	for (i = 0; i < MAX_NR_CHILDREN; i++) {

		shm->pids[i] = EMPTY_PIDSLOT;

		shm->previous_syscallno[i] = -1;
		shm->syscallno[i] = -1;

		shm->previous_a1[i] = shm->a1[i] = -1;
		shm->previous_a2[i] = shm->a2[i] = -1;
		shm->previous_a3[i] = shm->a3[i] = -1;
		shm->previous_a4[i] = shm->a4[i] = -1;
		shm->previous_a5[i] = shm->a5[i] = -1;
		shm->previous_a6[i] = shm->a6[i] = -1;
	}
}

#define SHM_PROT_PAGES 30

void create_shm(void)
{
	void *p;
	unsigned int shm_pages;

	/* round up shm to nearest page size */
	shm_pages = ((sizeof(struct shm_s) + page_size - 1) & ~(page_size - 1)) / page_size;

	/* Waste some address space to set up some "protection" near the SHM location. */
	p = alloc_shared((SHM_PROT_PAGES + shm_pages + SHM_PROT_PAGES) * page_size);
	if (p == NULL)
		exit(EXIT_FAILURE);

	/* clear whole mapping, including the redzones. */
	memset(p, 0, shm_pages * page_size);

	/* set the redzones to PROT_NONE */
	mprotect(p, SHM_PROT_PAGES * page_size, PROT_NONE);
	mprotect(p + (SHM_PROT_PAGES + shm_pages) * page_size,
			SHM_PROT_PAGES * page_size, PROT_NONE);

	shm = p + SHM_PROT_PAGES * page_size;
	output(2, "shm is at %p\n", shm);

	shm->child_syscall_count = zmalloc(MAX_NR_CHILDREN * sizeof(unsigned long));

	shm->pids = alloc_shared(MAX_NR_CHILDREN * sizeof(pid_t));
	if (shm->pids == NULL)
		exit(EXIT_FAILURE);

	shm->tv = zmalloc(MAX_NR_CHILDREN * sizeof(struct timeval));

	shm->previous_syscallno = zmalloc(MAX_NR_CHILDREN * sizeof(unsigned int));
	shm->syscallno = zmalloc(MAX_NR_CHILDREN * sizeof(unsigned int));

	//FIXME: Maybe a 'struct regs' ?
	shm->previous_a1 = zmalloc(MAX_NR_CHILDREN * sizeof(unsigned long));
	shm->previous_a2 = zmalloc(MAX_NR_CHILDREN * sizeof(unsigned long));
	shm->previous_a3 = zmalloc(MAX_NR_CHILDREN * sizeof(unsigned long));
	shm->previous_a4 = zmalloc(MAX_NR_CHILDREN * sizeof(unsigned long));
	shm->previous_a5 = zmalloc(MAX_NR_CHILDREN * sizeof(unsigned long));
	shm->previous_a6 = zmalloc(MAX_NR_CHILDREN * sizeof(unsigned long));

	shm->a1 = zmalloc(MAX_NR_CHILDREN * sizeof(unsigned long));
	shm->a2 = zmalloc(MAX_NR_CHILDREN * sizeof(unsigned long));
	shm->a3 = zmalloc(MAX_NR_CHILDREN * sizeof(unsigned long));
	shm->a4 = zmalloc(MAX_NR_CHILDREN * sizeof(unsigned long));
	shm->a5 = zmalloc(MAX_NR_CHILDREN * sizeof(unsigned long));
	shm->a6 = zmalloc(MAX_NR_CHILDREN * sizeof(unsigned long));

	shm->mappings = zmalloc(MAX_NR_CHILDREN * sizeof(struct map *));
	shm->num_mappings = zmalloc(MAX_NR_CHILDREN * sizeof(unsigned int));

	shm->seeds = zmalloc(MAX_NR_CHILDREN * sizeof(int));
	shm->child_type = zmalloc(MAX_NR_CHILDREN * sizeof(unsigned char));
	shm->kill_count = zmalloc(MAX_NR_CHILDREN * sizeof(unsigned char));
	shm->logfiles = zmalloc(MAX_NR_CHILDREN * sizeof(FILE *));
	shm->retval = zmalloc(MAX_NR_CHILDREN * sizeof(unsigned long));
	shm->scratch = zmalloc(MAX_NR_CHILDREN * sizeof(unsigned long));
	shm->do32bit = zmalloc(MAX_NR_CHILDREN * sizeof(bool));

	shm_init();
}
