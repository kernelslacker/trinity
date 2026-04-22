/*
 * Shared mapping creation.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include "arch.h"
#include "child.h"
#include "cmp_hints.h"
#include "debug.h"
#include "struct_catalog.h"
#include "fd-event.h"
#include "kcov.h"
#include "minicorpus.h"
#include "params.h"
#include "pids.h"
#include "random.h"
#include "sequence.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

struct shm_s *shm;

struct childdata **children;

struct fd_event_ring **expected_fd_event_rings;

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
	output(1, "shm:%p-%p (%u pages)\n", shm, (char *)shm + shm_size - 1, nr_shm_pages);
}

void init_shm(void)
{
	unsigned int i;
	unsigned int childptrslen;

	output(2, "shm is at %p\n", shm);

	if (set_debug == true)
		shm->debug = true;

	shm->stats.op_count = 0;
	shm->stats.previous_op_count = 0;

	__atomic_store_n(&shm->seed, init_seed(seed), __ATOMIC_RELAXED);

	childptrslen = max_children * sizeof(struct childdata *);
	/* round up to page size */
	childptrslen += page_size - 1;
	childptrslen &= PAGE_MASK;

	children = alloc_shared(childptrslen);

	/*
	 * Allocate the canary array as a global object so freeze_global_objects()
	 * will mprotect it PROT_READ before the first child forks.  Any write
	 * to it after that point will SIGSEGV at the source.  We store one
	 * pointer per child slot and compare in fd_event_drain_all().
	 */
	expected_fd_event_rings = alloc_shared_global(
		max_children * sizeof(struct fd_event_ring *));

	/* We allocate the childdata structs as shared mappings, because
	 * the forking process needs to peek into each childs syscall records
	 * to make sure they are making progress.
	 */
	for_each_child(i) {
		struct childdata *child;

		child = alloc_shared(sizeof(struct childdata));
		children[i] = child;

		memset(&child->syscall, 0, sizeof(struct syscallrecord));

		child->num = i;

		/* Allocate per-child fd event ring in shared memory.
		 * The ring is used by the child (producer) and parent
		 * (consumer) for lock-free fd state change reporting. */
		child->fd_event_ring = alloc_shared(sizeof(struct fd_event_ring));
		fd_event_ring_init(child->fd_event_ring);

		/* Record the ring address in the canary array.  The array
		 * is mprotected PROT_READ by freeze_global_objects() before
		 * any child runs, so any post-init write to it will fault. */
		expected_fd_event_rings[i] = child->fd_event_ring;
	}
	mprotect(children, childptrslen, PROT_READ);

	kcov_init_global();
	minicorpus_init();
	chain_corpus_init();
	cmp_hints_init();
	struct_catalog_init();
}
