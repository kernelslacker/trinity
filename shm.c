/*
 * Shared mapping creation.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/mman.h>
#include "arch.h"
#include "child.h"
#include "cmp_hints.h"
#include "debug.h"
#include "deferred-free.h"
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

	/* Waste some address space to set up some "protection" near the SHM location.
	 *
	 * Stays alloc_shared() rather than alloc_shared_global().  The shm
	 * struct itself is the most pervasive shared region in trinity:
	 * children write to shm->stats counters on every syscall, to
	 * shm->shared_obj_freelist / shm->shared_str_freelist on every
	 * shared-heap free, to shm->shared_obj_heap_used / shm->shared_str_
	 * heap_used on every alloc, to shm->fd_regen_pending[] on every fd
	 * regen request, to shm->fd_hash[] generation counters indirectly
	 * via the parent's fd-event drain, and to shm->seed via reseed().
	 * The parent writes shm->global_objects[*].array entries through
	 * the bracketed add_object / __destroy_object paths but the array
	 * pointers themselves point into already-frozen alloc_shared_global
	 * regions (shm.c init_shm + objects.c init_object_lists), so the
	 * structurally important freeze coverage already exists at the
	 * sub-region level.  Promoting struct shm_s itself to is_global_obj
	 * would require thaw / refreeze brackets around effectively every
	 * counter increment in the codebase — net negative.
	 *
	 * Wild-write risk this leaves open: a child wild-write into shm
	 * could corrupt any of the above scalar / counter fields.  The
	 * per-bucket freelist heads in particular are sensitive — a wrong
	 * value there would hand a bogus pointer to alloc_shared_obj's
	 * freelist_pop and crash the next allocator.  This is the same
	 * residual risk the obj heap freeze (fbce60744dfb) was designed
	 * to MITIGATE rather than eliminate; the heap freeze ensures the
	 * pointer freelist_pop returns lands in a frozen page so the
	 * caller's first write to it faults at the source — but the head
	 * pointer itself is in shm and stays writable.
	 */
	shm = alloc_shared(shm_size);

	/* clear the whole shm. */
	memset(shm, 0, shm_size);
	output(1, "shm:%p-%p (%u pages)\n", shm, (char *)shm + shm_size - 1, nr_shm_pages);
}

void init_shm(void)
{
	unsigned int i;
	size_t childptrslen;
	size_t fd_event_ring_arr_bytes;

	output(2, "shm is at %p\n", shm);

	if (set_debug == true)
		shm->debug = true;

	shm->stats.op_count = 0;
	shm->stats.previous_op_count = 0;

	/* Seed the per-childop adaptive-budget multipliers at unity (1.0x in
	 * Q8.8) so a fresh run starts with every opt-in childop running its
	 * hardcoded MAX_ITERATIONS / BUDGET_NS unchanged.  adapt_budget()
	 * ratchets these up or down post-invocation based on the kcov edge
	 * delta.  The zero_streak counters intentionally stay at 0 — that's
	 * the correct starting state for the hysteresis. */
	for (i = 0; i < NR_CHILD_OP_TYPES; i++)
		shm->stats.childop_budget_mult[i] = ADAPT_BUDGET_UNITY;

	shm->start_time = time(NULL);

	/* Multi-strategy rotation starts on the heuristic.  The window
	 * boundary is op_count - syscalls_at_last_switch, so seeding both
	 * the strategy and the switch-tick at zero gives the first window
	 * a full STRATEGY_WINDOW ops on the heuristic before the first
	 * rotation fires. */
	__atomic_store_n(&shm->current_strategy, STRATEGY_HEURISTIC, __ATOMIC_RELAXED);
	__atomic_store_n(&shm->syscalls_at_last_switch, 0UL, __ATOMIC_RELAXED);
	shm->edges_at_window_start = 0;

	__atomic_store_n(&shm->seed, init_seed(seed), __ATOMIC_RELAXED);

	if (!shared_size_mul(max_children, sizeof(struct childdata *),
			     &childptrslen)) {
		outputerr("init_shm: max_children=%u * sizeof(struct childdata *) overflows size_t\n",
			  max_children);
		exit(EXIT_FAILURE);
	}
	/* round up to page size */
	childptrslen += page_size - 1;
	childptrslen &= PAGE_MASK;

	/*
	 * children[] (the array of childdata pointers) stays alloc_shared()
	 * rather than alloc_shared_global() because it pre-dates the freeze
	 * pattern and is already protected by the explicit mprotect() at
	 * the bottom of init_shm — children only ever read these slots, and
	 * the parent writes them once during init then never again.  The
	 * existing mprotect is functionally equivalent to is_global_obj for
	 * a region that has no post-init parent writes; converting would
	 * just churn the call site without changing behaviour.
	 */
	children = alloc_shared(childptrslen);

	/*
	 * Allocate the canary array as a global object so freeze_global_objects()
	 * will mprotect it PROT_READ before the first child forks.  Any write
	 * to it after that point will SIGSEGV at the source.  We store one
	 * pointer per child slot and compare in fd_event_drain_all().
	 */
	if (!shared_size_mul(max_children, sizeof(struct fd_event_ring *),
			     &fd_event_ring_arr_bytes)) {
		outputerr("init_shm: max_children=%u * sizeof(struct fd_event_ring *) overflows size_t\n",
			  max_children);
		exit(EXIT_FAILURE);
	}
	expected_fd_event_rings = alloc_shared_global(fd_event_ring_arr_bytes);

	/* We allocate the childdata structs as shared mappings, because
	 * the forking process needs to peek into each childs syscall records
	 * to make sure they are making progress.
	 */
	for_each_child(i) {
		struct childdata *child;

		/*
		 * Per-child childdata stays alloc_shared() rather than
		 * alloc_shared_global() because each child writes its own slot
		 * extensively: child->syscall (rec->nr / args / retval before
		 * each syscall), child->kcov (per-call remote_mode
		 * flag), child->objects[] (OBJ_LOCAL pools the child mutates
		 * without parent involvement), child->last_syscall_nr,
		 * child->fd_lifetime / current_fd, etc.  Freeze would EFAULT
		 * the child's syscall dispatch loop on the first write to its
		 * own record.
		 *
		 * The wild-write risk is bounded: a child can only realistically
		 * corrupt its OWN childdata via its own syscall args, and the
		 * parent's reads (handle_children's progress check, dump_child
		 * data on crash) tolerate inconsistency by design.  Cross-child
		 * corruption would require a child syscall arg pointing into
		 * another child's slot — possible but exceedingly unlikely
		 * given the address-space layout, and the parent's overwatch
		 * (pidmap sanity, fd_event_ring canary) catches the structural
		 * fallout when it does happen.
		 */
		child = alloc_shared(sizeof(struct childdata));
		children[i] = child;

		memset(&child->syscall, 0, sizeof(struct syscallrecord));

		child->num = i;

		/* Allocate per-child fd event ring in shared memory.
		 * The ring is used by the child (producer) and parent
		 * (consumer) for lock-free fd state change reporting.
		 *
		 * Stays alloc_shared() rather than alloc_shared_global()
		 * because the child IS the producer: fd_event_enqueue writes
		 * ring->events[head] / ring->head / ring->overflow from child
		 * context on every fd close / dup2 / new-socket event.
		 * mprotect PROT_READ would EFAULT the enqueue store and
		 * disable the parent's fd lifecycle tracking entirely.  The
		 * canary array (expected_fd_event_rings) handles the related
		 * concern of detecting wild-write damage to the per-child
		 * ring POINTER itself — the canary is alloc_shared_global
		 * and frozen, so a stray write that swaps ring pointers gets
		 * caught at the next drain.  The ring CONTENTS necessarily
		 * stay child-writable.
		 */
		child->fd_event_ring = alloc_shared(sizeof(struct fd_event_ring));
		fd_event_ring_init(child->fd_event_ring);

		/* Record the ring address in the canary array.  The array
		 * is mprotected PROT_READ by freeze_global_objects() before
		 * any child runs, so any post-init write to it will fault. */
		expected_fd_event_rings[i] = child->fd_event_ring;
	}
	if (mprotect(children, childptrslen, PROT_READ) != 0)
		log_mprotect_failure(children, (size_t) childptrslen, PROT_READ,
				     __builtin_return_address(0), errno);

	kcov_init_global();
	minicorpus_init();
	chain_corpus_init();
	cmp_hints_init();
	struct_catalog_init();

	/*
	 * Allocate the deferred-free ring in the parent before any child
	 * forks so its address range is registered with shared_regions[]
	 * once and inherited (MAP_PRIVATE / COW) by every forked child.
	 * See deferred-free.c for the rationale on MAP_PRIVATE vs MAP_SHARED.
	 */
	deferred_free_init();
}
