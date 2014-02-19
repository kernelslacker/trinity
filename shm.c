/*
 * Shared mapping creation.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include "arch.h"
#include "log.h"
#include "params.h"
#include "pids.h"
#include "random.h"
#include "shm.h"

struct shm_s *shm;

void * alloc_shared(unsigned int size)
{
	void *ret;

	ret = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, -1, 0);
	if (ret == MAP_FAILED)
		return NULL;

	return ret;
}

static int shm_init(void)
{
	shm->total_syscalls_done = 1;

	memset(shm->pids, EMPTY_PIDSLOT, sizeof(shm->pids));

	memset(shm->active_syscalls, 0, sizeof(shm->active_syscalls));
	memset(shm->active_syscalls32, 0, sizeof(shm->active_syscalls32));
	memset(shm->active_syscalls64, 0, sizeof(shm->active_syscalls64));

	/* Overwritten later in setup_shm_postargs if user passed -s */
	shm->seed = new_seed();

	/* Set seed in parent thread */
	set_seed(0);
	return 0;
}

#define SHM_PROT_PAGES 30

int create_shm(void)
{
	void *p;
	unsigned int shm_pages;
	int ret;

	/* round up shm to nearest page size */
	shm_pages = ((sizeof(struct shm_s) + page_size - 1) & ~(page_size - 1)) / page_size;

	/* Waste some address space to set up some "protection" near the SHM location. */
	p = alloc_shared((SHM_PROT_PAGES + shm_pages + SHM_PROT_PAGES) * page_size);
	if (p == NULL) {
		perror("mmap");
		return -1;
	}

	/* clear whole mapping, including the redzones. */
	memset(p, 0, shm_pages * page_size);

	/* set the redzones to PROT_NONE */
	mprotect(p, SHM_PROT_PAGES * page_size, PROT_NONE);
	mprotect(p + (SHM_PROT_PAGES + shm_pages) * page_size,
			SHM_PROT_PAGES * page_size, PROT_NONE);

	shm = p + SHM_PROT_PAGES * page_size;
	output(2, "shm is at %p\n", shm);

	ret = shm_init();
	return ret;
}

void setup_shm_postargs(void)
{
	if (user_set_seed == TRUE) {
		shm->seed = init_seed(seed);
		/* Set seed in parent thread */
		set_seed(0);
	}
}
