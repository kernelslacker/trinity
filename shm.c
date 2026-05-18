/*
 * Shared mapping creation.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
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
#include "strategy.h"
#include "edgepair_ring.h"
#include "healer_ring.h"
#include "stats_ring.h"
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
	 * Wild-write risk: a child wild-write into shm could corrupt any
	 * scalar / counter field — children write to shm->stats counters on
	 * every syscall, to shm->shared_obj_freelist / shm->shared_str_
	 * freelist on every shared-heap free, to shm->shared_obj_heap_used /
	 * shm->shared_str_heap_used on every alloc, to shm->fd_regen_pending[]
	 * on every fd regen request, and to shm->seed via reseed().  The
	 * per-bucket freelist heads in particular are sensitive — a wrong
	 * value there would hand a bogus pointer to alloc_shared_obj's
	 * freelist_pop and crash the next allocator.
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

	/* Seed the per-childop adaptive-budget multipliers at unity (1.0x in
	 * Q8.8) so a fresh run starts with every opt-in childop running its
	 * hardcoded MAX_ITERATIONS / BUDGET_NS unchanged.  adapt_budget()
	 * ratchets these up or down post-invocation based on the kcov edge
	 * delta.  The zero_streak counters intentionally stay at 0 — that's
	 * the correct starting state for the hysteresis. */
	for (i = 0; i < NR_CHILD_OP_TYPES; i++)
		shm->stats.childop_budget_mult[i] = ADAPT_BUDGET_UNITY;

	shm->start_time = time(NULL);

	/*
	 * Snapshot trinity's own (dev, ino) so the execve sanitiser can
	 * fstatat() the resolved target and refuse to fire when the
	 * fuzz path resolves back to this binary.  Done in the parent
	 * before any child forks, so the populated cache is inherited
	 * via the shared mapping without per-child rework.  A stat
	 * failure here is unexpected (would mean /proc/self/exe is
	 * unreadable) but non-fatal -- valid=false short-circuits the
	 * guard to the pre-protection baseline.
	 */
	{
		struct stat st;

		if (stat("/proc/self/exe", &st) == 0) {
			shm->trinity_self_exe.dev = st.st_dev;
			shm->trinity_self_exe.ino = st.st_ino;
			shm->trinity_self_exe.valid = true;
		} else {
			outputerr("init_shm: stat(/proc/self/exe) failed: %s -- "
				  "execve self-exec guard disabled\n",
				  strerror(errno));
			shm->trinity_self_exe.valid = false;
		}
	}

	/* Multi-strategy rotation starts on the heuristic.  The window
	 * boundary is op_count - syscalls_at_last_switch, so seeding both
	 * the strategy and the switch-tick at zero gives the first window
	 * a full STRATEGY_WINDOW ops on the heuristic before the first
	 * rotation fires. */
	__atomic_store_n(&shm->current_strategy, STRATEGY_HEURISTIC, __ATOMIC_RELAXED);
	/* SR_COLD_START matches the cold-start convention in the picker:
	 * the very first window is the initial seed, no policy or
	 * intervention has scored it.  Keeps the rotation site's
	 * "was the prev window forced?" check unambiguous on the first
	 * close. */
	__atomic_store_n(&shm->current_selection_reason,
			 (int)SR_COLD_START, __ATOMIC_RELAXED);
	__atomic_store_n(&shm->syscalls_at_last_switch, 0UL, __ATOMIC_RELAXED);
	shm->pc_edge_calls_at_window_start = 0;
	shm->pc_edge_count_at_window_start = 0;

	/* Optimistic seed for the biarch picker's per-table validity cache.
	 * The authoritative pass through validate_syscall_table_{32,64}() at
	 * the end of munge_tables() will rewrite both before any child runs;
	 * deactivate_syscall{32,64}() then keep them in sync at runtime. */
	shm->valid_syscall_table_32 = true;
	shm->valid_syscall_table_64 = true;

	/* Frontier-picker bias-mass cache starts at 0 so the first pick
	 * before any new-edge bumps degenerates to uniform.  Explicit init
	 * (the surrounding shm memset already zeroes it) keeps the cache
	 * lifecycle visible alongside the other strategy-rotation fields. */
	__atomic_store_n(&shm->frontier_max_weight_cached, 0U, __ATOMIC_RELAXED);

	/* Picker mode (round-robin vs UCB1 bandit) was selected by
	 * parse_args via --strategy.  Stash it in shm so the CAS-winning
	 * child at each rotation reads a consistent value.  bandit_pulls/
	 * bandit_reward_calls/bandit_reward_pc_edge_count and the parallel
	 * discounted recent_pulls_x1000/recent_reward_x1000/
	 * last_selected_window series are zeroed by the shm_zero default
	 * and only touched by the bandit picker, so no further init is
	 * needed. */
	__atomic_store_n(&shm->picker_mode, picker_mode_arg, __ATOMIC_RELAXED);

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
	 * children[] (the array of childdata pointers) is protected by the
	 * explicit mprotect(PROT_READ) at the bottom of init_shm — children
	 * only ever read these slots, and the parent writes them once during
	 * init then never again.
	 */
	children = alloc_shared(childptrslen);

	/*
	 * Allocate the canary array.  We store one pointer per child slot
	 * and compare in fd_event_drain_all().
	 */
	if (!shared_size_mul(max_children, sizeof(struct fd_event_ring *),
			     &fd_event_ring_arr_bytes)) {
		outputerr("init_shm: max_children=%u * sizeof(struct fd_event_ring *) overflows size_t\n",
			  max_children);
		exit(EXIT_FAILURE);
	}
	expected_fd_event_rings = alloc_shared(fd_event_ring_arr_bytes);

	/* We allocate the childdata structs as shared mappings, because
	 * the forking process needs to peek into each childs syscall records
	 * to make sure they are making progress.
	 */
	for_each_child(i) {
		struct childdata *child;

		/*
		 * Wild-write risk on per-child childdata is bounded: a child
		 * can only realistically corrupt its OWN childdata via its
		 * own syscall args, and the parent's reads (handle_children's
		 * progress check, dump_childdata on crash) tolerate
		 * inconsistency by design.  Cross-child corruption would
		 * require a child syscall arg pointing into another child's
		 * slot — possible but exceedingly unlikely given the address-
		 * space layout, and the parent's overwatch (pidmap sanity,
		 * fd_event_ring canary) catches the structural fallout when
		 * it does happen.
		 */
		child = alloc_shared(sizeof(struct childdata));
		children[i] = child;

		memset(&child->syscall, 0, sizeof(struct syscallrecord));

		child->num = i;

		/* Allocate per-child fd event ring in shared memory.
		 * The ring is used by the child (producer) and parent
		 * (consumer) for lock-free fd state change reporting.
		 * Wild-write damage to the per-child ring POINTER itself is
		 * caught at the next drain via the canary array
		 * (expected_fd_event_rings); the ring CONTENTS are necessarily
		 * child-writable.
		 */
		child->fd_event_ring = alloc_shared(sizeof(struct fd_event_ring));
		fd_event_ring_init(child->fd_event_ring);

		/* Record the ring address in the canary array. */
		expected_fd_event_rings[i] = child->fd_event_ring;

		/* Per-child stats ring.  The child IS the producer (every
		 * syscall enqueues at least one slot), so the ring contents
		 * stay child-writable.  The ring POINTER is in struct
		 * childdata which sits in shared memory; a wild write that
		 * swapped it would surface in the same overflow / payload
		 * validation paths the drain already runs.  No dedicated
		 * canary array yet -- the structural improvement here is
		 * moving the COUNTER VALUES out of shm; the ring storage
		 * being shared is inherent to the SPSC contract. */
		child->stats_ring = alloc_shared(sizeof(struct stats_ring));
		stats_ring_init(child->stats_ring);

		/* Per-child HEALER observation ring.  The child IS the
		 * producer (every observer-hook fire on the new-edge path
		 * enqueues both a TRIPLE and a PAIR slot), so the ring
		 * contents stay child-writable.  Dark-launched in this commit
		 * -- no call site enqueues yet -- so the drain runs empty and
		 * the canonical aggregate stays at zero. */
		child->healer_ring = alloc_shared(sizeof(struct healer_ring));
		healer_ring_init(child->healer_ring);

		/* Per-child edgepair observation ring.  The child IS the
		 * producer (every non-cmp dispatched syscall enqueues one
		 * slot once the per-child sentinel is past), so the ring
		 * contents stay child-writable.  Dark-launched in this commit
		 * -- no call site enqueues yet -- so the drain runs empty and
		 * the canonical aggregate stays at zero. */
		child->edgepair_ring = alloc_shared(sizeof(struct edgepair_ring));
		edgepair_ring_init(child->edgepair_ring);
	}

	/* Allocate the parent-write / child-read mirror page.
	 * Children read shm_published->fleet_op_count off the cold path
	 * (rotation clock, syscalls_todo termination); the parent re-publishes
	 * inside stats_ring_drain_all(). */
	stats_published_init();

	/* HEALER mirror pages: parent-write / child-read.  Picker reads
	 * the relation table and pair table through these pages, refreshed
	 * once per drain. */
	healer_published_init();

	/* Edgepair mirror page: parent-write / child-read.  edgepair_is_cold
	 * reads its three fields off this page on the syscall-selection
	 * biasing path, refreshed once per drain. */
	edgepair_published_init();
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
