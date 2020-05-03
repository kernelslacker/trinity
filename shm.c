/*
 * Shared mapping creation.
 */

#include <malloc.h>
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
	printf("shm:%p-%p (%u pages)\n", shm, shm + shm_size - 1, nr_shm_pages);
}

void init_shm(void)
{
	unsigned int i;
	unsigned int childptrslen;

	output(2, "shm is at %p\n", shm);

	if (set_debug == TRUE)
		shm->debug = TRUE;

	shm->stats.op_count = 0;
	shm->stats.previous_op_count = 0;

	shm->seed = init_seed(seed);

	childptrslen = max_children * sizeof(struct childdata *);
	/* round up to page size */
	childptrslen += page_size - 1;
	childptrslen &= PAGE_MASK;

	shm->children = memalign(page_size, childptrslen);
	if (shm->children == NULL) {
		printf("Failed to allocate child structures.\n");
		exit(EXIT_FAILURE);
	}

	memset(shm->children, 0, childptrslen);

	/* We allocate the childdata structs as shared mappings, because
	 * the forking process needs to peek into each childs syscall records
	 * to make sure they are making progress.
	 */
	for_each_child(i) {
		struct childdata *child;

		child = alloc_shared(sizeof(struct childdata));
		shm->children[i] = child;

		memset(&child->syscall, 0, sizeof(struct syscallrecord));

		child->num = i;
		init_child_logging(child);
	}
	mprotect(shm->children, childptrslen, PROT_READ);
}
