/*
 * Shared mapping creation.
 */

#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "arch.h"
#include "blob_corpus.h"
#include "blob_mutator.h"
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
#include "sanitise.h"		// alloc_iovec_init
#include "sequence.h"
#include "shm.h"
#include "strategy.h"
#include "stats_ring.h"
#include "trinity.h"
#include "utils.h"

struct shm_s *shm;

struct childdata **children;

struct fd_event_ring **expected_fd_event_rings;

struct stats_ring **expected_stats_rings;

unsigned int shm_size;

/*
 * Set by init_shm_per_child_rings() to sizeof(struct childdata) rounded
 * up to a page multiple.  freeze_sibling_childdata() reads it to pass
 * the same span its mprotect() covers; alloc_shared_page_aligned()
 * fills it via its out-param on the first per-child alloc.
 */
size_t childdata_mapping_len;

void create_shm(void)
{
	unsigned int nr_shm_pages;

	/* round up shm to nearest page size */
	shm_size = (sizeof(struct shm_s) + page_size - 1) & PAGE_MASK;
	nr_shm_pages = shm_size / page_size;

	/* Wild-write risk: a child wild-write into shm could corrupt any
	 * scalar / counter field — children write to shm->stats counters on
	 * every syscall, to shm->shared_str_freelist on every shared-string
	 * free, to shm->shared_str_heap_used on every shared-string alloc,
	 * to shm->fd_regen_pending[] on every fd regen request, and to
	 * shm->seed via reseed().  The shared-string freelist heads in
	 * particular are sensitive — a wrong value there would hand a bogus
	 * pointer to the next shared-string allocation and crash it.
	 */
	shm = alloc_shared(shm_size);

	/* clear the whole shm. */
	memset(shm, 0, shm_size);

	/* memset leaves shm->isolation.netns_fd at 0, which is a valid fd
	 * (stdin) and would silently sneak past the "not published"
	 * sentinel check in any childop that reads the field before
	 * setup_startup_isolation() has run.  Stamp -1 here so the
	 * sentinel is honest from the moment shm exists, independent of
	 * whether the parent later opens /proc/self/ns/net. */
	shm->isolation.netns_fd = -1;

	/* Same reasoning for the scratch_block pool: loop_num == 0 maps
	 * to /dev/loop0 (a live block device on most hosts) and loop_fd
	 * == 0 is stdin -- a consumer that reads either before the pool
	 * has been populated would treat the zero sentinel as a vetted
	 * entry.  Stamp -1 across every slot so a pre-init read trips
	 * the "not a real entry" check on both fields. */
	{
		unsigned int i;

		for (i = 0; i < SCRATCH_BLOCK_MAX; i++) {
			shm->isolation.scratch_block[i].loop_num = -1;
			shm->isolation.scratch_block[i].loop_fd = -1;
		}
	}

	output(1, "shm:%p-%p (%u pages)\n", shm, (char *)shm + shm_size - 1, nr_shm_pages);
}

/*
 * Wall-clock + adaptive-budget seed phase.  Three steps, all about
 * stamping the initial values the rest of init_shm and the live
 * fuzz loop reads as starting state: the debug flag mirror so
 * children observe --debug, the per-childop adaptive-budget
 * multipliers at unity so adapt_budget() has a sane baseline to
 * ratchet from, and the run's start_time tick that downstream
 * elapsed-time accounting (rate-limited logs, plateau windows)
 * subtracts from.  Bundled first because every subsequent phase
 * assumes these scalars are populated.
 */
static void init_shm_debug_start(void)
{
	unsigned int i;

	if (set_debug == true)
		shm->debug = true;

	/* Seed the per-childop adaptive-budget multipliers at unity (1.0x in
	 * Q8.8) so a fresh run starts with every opt-in childop running its
	 * hardcoded MAX_ITERATIONS / BUDGET_NS unchanged.  adapt_budget()
	 * ratchets these up or down post-invocation based on the kcov edge
	 * delta.  The zero_streak counters intentionally stay at 0 — that's
	 * the correct starting state for the hysteresis. */
	for (i = 0; i < NR_CHILD_OP_TYPES; i++)
		shm->stats.childop.budget_mult[i] = ADAPT_BUDGET_UNITY;

	shm->start_time = time(NULL);
	shm->start_mono_ns = mono_ns();
}

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
static void init_shm_self_exe_snapshot(void)
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

/*
 * Stashed by init_shm_alloc_children() so the post-publish
 * mprotect(children, ..., PROT_READ) at the tail of init_shm() can
 * pass the exact byte length the children[] allocation rounded up
 * to.  File-scope static (init-only, parent-only) instead of a
 * threaded out-param to keep the orchestrator at one bare call
 * per phase.
 */
static size_t init_shm_childptrslen;

/*
 * Strategy-rotation / picker-mode / plateau intervention state
 * init.  All __atomic_store_n stamps so the values the
 * picker/orchestrator/plateau code reads (often from a child that
 * raced into its first window before the parent reached this
 * point) land with release semantics.  The surrounding shm memset
 * has already zeroed every field; these explicit stamps document
 * which fields are load-bearing for the rotation state machine
 * and pin the cold-start sentinels (SR_COLD_START,
 * RRC_NR_CLASSES, PLATEAU_HYPOTHESIS_NONE) that diverge from zero.
 * Closes with the run's seed so init_seed() runs after every
 * other strategy-state field is in place.
 */
static void init_shm_strategy_state(void)
{
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
	__atomic_store_n(&shm->pc_edge_calls_at_window_start, 0UL,
			 __ATOMIC_RELAXED);
	__atomic_store_n(&shm->pc_edge_count_at_window_start, 0UL,
			 __ATOMIC_RELAXED);

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
	 * discounted recent_pulls_x1000/recent_reward_x1000 series are
	 * zeroed by the shm_zero default and only touched by the bandit
	 * picker, so no further init is needed. */
	__atomic_store_n(&shm->picker_mode, picker_mode_arg, __ATOMIC_RELAXED);

	/* Random-rescue amplification has no "zero is none" representation
	 * (RRC_COLD_SKIP = 0), so the orchestrator's "no class amplified"
	 * sentinel is RRC_NR_CLASSES.  Explicit init so a fresh run starts
	 * in the unamplified state even though the surrounding shm memset
	 * already zeroed the field. */
	__atomic_store_n(&shm->plateau_rescue_amplified_class,
			 (int)RRC_NR_CLASSES, __ATOMIC_RELAXED);

	/* Plateau intervention mode starts on PIM_UNIFORM_RANDOM (the
	 * zero-init value) so any pre-plateau read sees the
	 * unmodified-RANDOM shape; the orchestrator's rotation latches a
	 * fresh mode at every plateau-window boundary.  Baseline calls
	 * starts at zero so plateau_anti_prior_accept() short-circuits to
	 * "pass" until the first PIM_ANTI_PRIOR rotation populates it. */
	__atomic_store_n(&shm->plateau_intervention_mode_current,
			 (int)PIM_UNIFORM_RANDOM, __ATOMIC_RELAXED);
	__atomic_store_n(&shm->plateau_anti_prior_baseline_calls, 0UL,
			 __ATOMIC_RELAXED);

	/* Phase 2 plateau intervention: hypothesis mirror starts at NONE
	 * so any pre-plateau rotation in select_next_strategy sees the
	 * no-pin sentinel and falls through to the round-robin path. */
	__atomic_store_n(&shm->plateau_current_hypothesis,
			 (int)PLATEAU_HYPOTHESIS_NONE, __ATOMIC_RELAXED);

	__atomic_store_n(&shm->seed, init_seed(seed), __ATOMIC_RELAXED);
}

/*
 * Allocate the parent's three child-indexed pointer arrays:
 * children[] (the per-slot childdata pointer array),
 * expected_fd_event_rings[] (the fd_event_ring canary), and
 * expected_stats_rings[] (the stats_ring canary).  All are sized
 * max_children * sizeof(pointer), checked with shared_size_mul --
 * overflow at this scale is structurally unrecoverable so the
 * helper exits on overflow rather than threading a failure back to
 * the caller.  childptrslen is rounded up to page_size before the
 * children[] alloc (the parent-only mprotect(PROT_READ) at the
 * tail of init_shm runs on this exact length) and stashed in
 * init_shm_childptrslen so that mprotect can find it without a
 * third pass through shared_size_mul.  The for_each_child
 * population pass that fills all three arrays is the next phase;
 * this helper only carves the address space.
 */
static void init_shm_alloc_children(void)
{
	size_t childptrslen;
	size_t fd_event_ring_arr_bytes;

	if (!shared_size_mul(max_children, sizeof(struct childdata *),
			     &childptrslen)) {
		outputerr("init_shm: max_children=%u * sizeof(struct childdata *) overflows size_t\n",
			  max_children);
		exit(EXIT_FAILURE);
	}
	/* round up to page size */
	childptrslen += page_size - 1;
	childptrslen &= PAGE_MASK;
	init_shm_childptrslen = childptrslen;

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
	expected_fd_event_rings = alloc_shared_pool(fd_event_ring_arr_bytes);

	/*
	 * Same shape for the stats_ring canary -- one pointer per child slot,
	 * compared in stats_ring_drain_all().
	 */
	{
		size_t stats_ring_arr_bytes;

		if (!shared_size_mul(max_children, sizeof(struct stats_ring *),
				     &stats_ring_arr_bytes)) {
			outputerr("init_shm: max_children=%u * sizeof(struct stats_ring *) overflows size_t\n",
				  max_children);
			exit(EXIT_FAILURE);
		}
		expected_stats_rings = alloc_shared_pool(stats_ring_arr_bytes);
	}
}

/*
 * Per-child childdata + ring allocation pass.  For each
 * for_each_child slot, alloc the shared childdata struct,
 * publish its pointer into children[], zero the embedded
 * syscallrecord, stamp child->num from the loop counter, then
 * carve out the two per-child shared rings (fd_event_ring,
 * stats_ring) and run each ring's init.  The fd_event_ring
 * address is also mirrored into the expected_fd_event_rings[]
 * canary so fd_event_drain_all() can spot a wild-write swap of
 * the in-childdata pointer.
 *
 * Runs after init_shm_alloc_children() (which carves children[]
 * and expected_fd_event_rings[]) and before the published-mirror
 * + mprotect tail phase that locks children[] PROT_READ.  Pulled
 * into its own helper so the orchestrator reads as a phase list;
 * no shared state with adjacent phases, signature collapses to
 * (void).
 */
static void init_shm_per_child_rings(void)
{
	unsigned int i;

	/* We allocate the childdata structs as shared mappings, because
	 * the forking process needs to peek into each childs syscall records
	 * to make sure they are making progress.
	 */
	for_each_child(i) {
		struct childdata *child;
		size_t mapping_len = 0;

		/*
		 * Dedicated page-aligned mapping per childdata.  Cross-child
		 * corruption via a fuzzed syscall arg pointing into another
		 * child's slot IS the failure mode this per-child freeze
		 * exists to defend against: freeze_sibling_childdata()
		 * mprotect()s every sibling's childdata PROT_READ from each
		 * child's address space, so a stray kernel-side write
		 * traps at -EFAULT instead of scribbling the sibling.
		 *
		 * Routing through alloc_shared_page_aligned() (rather than
		 * alloc_shared_pool()) pins a page-aligned base so the
		 * freeze's mprotect() precondition holds unconditionally.
		 * The prior alloc_shared_pool() path handed out an end-
		 * aligned pointer under --guard-shared=pools, silently
		 * EINVAL'ing every sibling's mprotect() and leaving the
		 * freeze off -- which was the mechanism behind the
		 * self-SIGSEGV cluster in add_object / kcov_collect /
		 * addr_in_local_runtime_map traced to sibling scribbles of
		 * childdata->objects / OBJ_LOCAL.
		 */
		child = alloc_shared_page_aligned(sizeof(struct childdata),
						  &mapping_len);
		if (childdata_mapping_len == 0)
			childdata_mapping_len = mapping_len;
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
		child->fd_event_ring = alloc_shared_pool(sizeof(struct fd_event_ring));
		fd_event_ring_init(child->fd_event_ring);

		/* Record the ring address in the canary array. */
		expected_fd_event_rings[i] = child->fd_event_ring;

		/* Per-child stats ring.  The child IS the producer (every
		 * syscall enqueues at least one slot), so the ring contents
		 * stay child-writable.  The ring POINTER lives in struct
		 * childdata in shared memory and would SIGSEGV the parent's
		 * drain if a wild write or recycled-zombie store swapped it;
		 * record the address in the canary array so
		 * stats_ring_drain_all() can spot the swap before deref. */
		child->stats_ring = alloc_shared_pool(sizeof(struct stats_ring));
		stats_ring_init(child->stats_ring);

		/* Record the ring address in the canary array. */
		expected_stats_rings[i] = child->stats_ring;
	}
}

/*
 * Final init_shm phase: publish the parent-write / child-read
 * mirror page (stats_published_init), lock down the children[]
 * pointer array PROT_READ via mprotect
 * using the length stashed by init_shm_alloc_children(), then
 * stand up the cross-subsystem singletons that need shared
 * memory in place before any child forks -- kcov_init_global,
 * minicorpus_init, chain_corpus_init, cmp_hints_init,
 * struct_catalog_init, deferred_free_init.
 *
 * Ordering is load-bearing: the mprotect MUST run after the
 * published_init helper (which publishes initial values that the
 * children read off the mirror page as soon as they start) and
 * BEFORE the kcov / corpus / catalog / deferred-free init bundle
 * (those allocate further shared regions and must not be
 * gratuitously interleaved with the read-only flip on children
 * []).  Bundled last because every prior phase assumes a
 * still-writable children[] and the subsystem singletons depend
 * on the per-child rings already being in place.  No shared
 * state with the orchestrator, signature collapses to (void) --
 * the mprotect length comes from init_shm_childptrslen.
 */
static void init_shm_publish_and_subsystems(void)
{
	/* Allocate the parent-write / child-read mirror page.
	 * Children read shm_published->fleet_op_count off the cold path
	 * (rotation clock, syscalls_todo termination); the parent re-publishes
	 * inside stats_ring_drain_all(). */
	stats_published_init();

	if (mprotect(children, init_shm_childptrslen, PROT_READ) != 0)
		log_mprotect_failure(children, init_shm_childptrslen, PROT_READ,
				     __builtin_return_address(0), errno);

	kcov_init_global();
	minicorpus_init();
	chain_corpus_init();
	cmp_hints_init();
	struct_catalog_init();
	blob_corpus_init();
	struct_field_mutate_self_check();
	blob_mutator_self_check();
	blob_corpus_self_check();

	/*
	 * Allocate the deferred-free ring in the parent before any child
	 * forks so its address range is registered with shared_regions[]
	 * once and inherited (MAP_PRIVATE / COW) by every forked child.
	 * See deferred-free.c for the rationale on MAP_PRIVATE vs MAP_SHARED.
	 */
	deferred_free_init();

	/*
	 * Same pre-fork-allocate / register-once / inherit-via-COW pattern
	 * for alloc_iovec()'s dedicated iov[] backing buffer.  Keeps the
	 * iov array off the writable pool so a fuzzed
	 * madvise(MADV_REMOVE) cannot SIGBUS the next iov fill, and the
	 * shared-region registration steers the mm-syscall sanitisers off
	 * its VMA so PROT_WRITE cannot be stripped either.  See alloc_
	 * iovec_init() in rand/random-address.c for the full rationale.
	 */
	alloc_iovec_init();

	/*
	 * Same pre-fork-allocate / register-once / inherit-via-COW pattern
	 * for the writable-address pool that backs get_writable_address().
	 * Replaces the OBJ_MMAP/SysV-shm pool-picking machinery whose slots
	 * lived in shared backings and could be hole-punched, prot-stripped,
	 * or otherwise mutated by sibling children.  Keeping the pool in a
	 * MAP_PRIVATE|MAP_ANON region kills the dual SIGBUS(BUS_ADRERR) and
	 * SEGV(ACCERR) classes at the same time.
	 */
	writable_pool_init();
}

void init_shm(void)
{
	output(2, "shm is at %p\n", shm);

	init_shm_debug_start();

	init_shm_self_exe_snapshot();

	init_shm_strategy_state();

	init_shm_alloc_children();

	init_shm_per_child_rings();

	init_shm_publish_and_subsystems();
}
