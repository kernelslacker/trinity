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

void create_child_structs(void)
{
	unsigned int i;

	shm->children = alloc_shared(max_children * sizeof(struct childdata *));

	for_each_child(i)
		shm->children[i] = (struct childdata *) alloc_shared(sizeof(struct childdata));
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
		struct childdata *child = shm->children[i];
		struct syscallrecord *syscall, *previous;

		syscall = &child->syscall;
		previous = &child->previous;

		child->pid = EMPTY_PIDSLOT;

		previous->nr = syscall->nr = -1;

		previous->a1 = syscall->a1 = -1;
		previous->a2 = syscall->a2 = -1;
		previous->a3 = syscall->a3 = -1;
		previous->a4 = syscall->a4 = -1;
		previous->a5 = syscall->a5 = -1;
		previous->a6 = syscall->a6 = -1;
	}
}
