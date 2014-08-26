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
	void *redbefore, *redafter;
	unsigned int shm_pages;
	unsigned int wholesize;

	/* round up shm to nearest page size */
	shm_pages = ((sizeof(struct shm_s) + page_size - 1) & PAGE_MASK) / page_size;
	wholesize = (SHM_PROT_PAGES + shm_pages + SHM_PROT_PAGES) * page_size;

	/* Waste some address space to set up some "protection" near the SHM location. */
	p = alloc_shared(wholesize);

	redbefore = p;
	redafter = p + (SHM_PROT_PAGES + shm_pages) * page_size;

	/* set the redzones. */
	memset(redbefore, 0x77, SHM_PROT_PAGES * page_size);
	memset(redafter, 0x88, SHM_PROT_PAGES * page_size);

	/* set the redzones to PROT_NONE */
	mprotect(redbefore, SHM_PROT_PAGES * page_size, PROT_NONE);
	mprotect(redafter, SHM_PROT_PAGES * page_size, PROT_NONE);

	/* clear the whole shm. */
	shm = p + (SHM_PROT_PAGES * page_size);
	memset(shm, 0, shm_pages * page_size);
	printf("shm: redzone:%p. shmdata:%p. redzone:%p end:%p.\n",
		redbefore, shm, redafter, p + wholesize);
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
