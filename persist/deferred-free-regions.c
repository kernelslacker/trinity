/*
 * Deferred-free protected regions: the mmap'd alloc_track, ring_control, ring
 * and generation-arena pages, the mprotect brackets (with their cost
 * accounting) that open one for a mutation, the kernel-entry seal barrier,
 * and deferred_free_init().  Steady state is PROT_READ (PROT_NONE for the
 * ring), so a stray write faults at the store instead of reaching free().
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>

#ifndef NDEBUG
#include <assert.h>
#endif

#include "deferred-free.h"
#include "params.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#include "deferred-free-internal.h"

/*
 * alloc_track[] and alloc_track_hash[] share a single mmap'd backing
 * region so one mprotect bracket covers both arrays' pages, halving
 * the syscall cost on the deferred_alloc_track hot path (which writes
 * both in one operation).  The base, size, and array pointers below
 * are set up in deferred_free_init().  Steady state is PROT_READ so
 * the lookup hot path (alloc_track_lookup, called from every
 * cleanup_release_post_state and the deferred-free enqueue gate)
 * reads directly without an mprotect syscall; only the writer entry
 * points (deferred_alloc_track, alloc_track_consume) flip RW for the
 * duration of the mutation.
 */
static void *alloc_track_base;
static size_t alloc_track_bytes;

/*
 * Untraced cost accounting for the per-region mprotect
 * brackets (alloc_track, ring+ring_control).  Each unlock
 * records CLOCK_MONOTONIC before its mprotect and stashes it in the
 * per-region timestamp; the matching lock re-samples after its
 * mprotect and accumulates the elapsed nanoseconds into shm->stats.
 * deferred_free.*_rw_ns_total.  The paired call counters (*_rw_calls
 * / *_ro_calls) let an operator compute mean-ns-per-bracket from the
 * cumulative totals without additional plumbing.  Statics are per-
 * child by COW-at-fork and single-writer per bracket, so no locking
 * is required.  A zero timestamp (tv_sec == 0 && tv_nsec == 0) means
 * "no open unlock window" -- lock() skips the counter bumps and
 * df_cost_elapsed_ns returns 0 in that case, so the four unpaired
 * lock-downs at init tail (and any future unpaired lock) record
 * nothing rather than charging the machine-uptime delta between the
 * zero-init timestamp and CLOCK_MONOTONIC into *_rw_ns_total.
 */
static struct timespec alloc_track_rw_open_at;
static struct timespec rc_rw_open_at;
static struct timespec ring_rw_open_at;

/*
 * Per-region open flags for the batched mode.  With batching off
 * these stay false and the X_unlock/X_lock helpers behave exactly as
 * before (real mprotect flip per mutation).  With batching ON the
 * first X_unlock() of a phase mprotects the region RW and sets its
 * flag; subsequent X_unlock() calls on the same region within the same
 * phase short-circuit; the paired X_lock() calls become no-ops (the
 * deferred close is issued by deferred_free_seal_all() at the next
 * kernel-entry chokepoint).  Only real mprotect flips bump the
 * *_rw_calls / *_ro_calls / *_rw_ns_total accounting, so the t372-a
 * counters measure the actual syscall reduction.  Statics are per-
 * child by COW-at-fork and single-writer per region, so no locking.
 */
static bool alloc_track_rw_open;
static bool rc_rw_open;
static bool ring_rw_open;

static inline bool df_ts_is_zero(const struct timespec *ts)
{
	return ts->tv_sec == 0 && ts->tv_nsec == 0;
}

static inline unsigned long df_cost_elapsed_ns(const struct timespec *begin)
{
	struct timespec now;
	long ns;

	if (df_ts_is_zero(begin))
		return 0;

	clock_gettime(CLOCK_MONOTONIC, &now);
	ns = (now.tv_sec - begin->tv_sec) * 1000000000L
	     + (now.tv_nsec - begin->tv_nsec);
	if (ns < 0)
		return 0;
	return (unsigned long)ns;
}

/*
 * Flip the alloc_track / alloc_track_hash backing to PROT_READ|WRITE
 * for a single mutation, then back to PROT_READ.  Lookups read
 * directly against the PROT_READ steady state -- no bracket on the
 * hot path.  An unlock failure leaves the page PROT_READ and the
 * caller skips its write; the side-set ends up with a missing entry
 * (subsequent deferred_free_enqueue of that ptr rejects it as
 * untracked and the ptr is leaked) or a stale entry (subsequent
 * alloc_track_lookup answers false-positive, the lookup result
 * still flows through the deferred-free shape/heap/shared-region
 * gates), both safer than silently flipping a membership bit.
 */
int alloc_track_unlock(void)
{
	struct timespec begin;

	if (deferred_free_batch && alloc_track_rw_open)
		return 0;

	clock_gettime(CLOCK_MONOTONIC, &begin);
	if (mprotect(alloc_track_base, alloc_track_bytes,
		     PROT_READ | PROT_WRITE) != 0) {
		outputerr("deferred_free: alloc_track unlock failed: "
			  "errno=%d\n", errno);
		return -1;
	}
	alloc_track_rw_open_at = begin;
	alloc_track_rw_open = true;
	__atomic_add_fetch(&shm->stats.deferred_free.alloc_track_rw_calls,
			   1, __ATOMIC_RELAXED);
	return 0;
}

void alloc_track_lock(void)
{
	unsigned long ns;

	if (deferred_free_batch)
		return;

	if (mprotect(alloc_track_base, alloc_track_bytes, PROT_READ) != 0)
		outputerr("deferred_free: alloc_track lock failed: "
			  "errno=%d\n", errno);
	alloc_track_rw_open = false;
	if (df_ts_is_zero(&alloc_track_rw_open_at))
		return;
	ns = df_cost_elapsed_ns(&alloc_track_rw_open_at);
	alloc_track_rw_open_at = (struct timespec){0};
	__atomic_add_fetch(&shm->stats.deferred_free.alloc_track_ro_calls,
			   1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.deferred_free.alloc_track_rw_ns_total,
			   ns, __ATOMIC_RELAXED);
}

struct ring_control *rc;
static size_t rc_bytes;

int rc_unlock(void)
{
	struct timespec begin;

	if (deferred_free_batch && rc_rw_open)
		return 0;

	clock_gettime(CLOCK_MONOTONIC, &begin);
	if (mprotect(rc, rc_bytes, PROT_READ | PROT_WRITE) != 0) {
		outputerr("deferred_free: ring_control unlock failed: "
			  "errno=%d\n", errno);
		return -1;
	}
	rc_rw_open_at = begin;
	rc_rw_open = true;
	__atomic_add_fetch(&shm->stats.deferred_free.ring_rw_calls,
			   1, __ATOMIC_RELAXED);
	return 0;
}

void rc_lock(void)
{
	unsigned long ns;

	if (deferred_free_batch)
		return;

	if (mprotect(rc, rc_bytes, PROT_READ) != 0)
		outputerr("deferred_free: ring_control lock failed: "
			  "errno=%d\n", errno);
	rc_rw_open = false;
	if (df_ts_is_zero(&rc_rw_open_at))
		return;
	ns = df_cost_elapsed_ns(&rc_rw_open_at);
	rc_rw_open_at = (struct timespec){0};
	__atomic_add_fetch(&shm->stats.deferred_free.ring_ro_calls,
			   1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.deferred_free.ring_rw_ns_total,
			   ns, __ATOMIC_RELAXED);
}

enum ring_unlock_result ring_unlock(void)
{
	struct timespec begin;

	if (deferred_free_batch && ring_rw_open)
		return RING_UNLOCK_OK;

	clock_gettime(CLOCK_MONOTONIC, &begin);
	if (mprotect(rc->ring, rc->ring_bytes, PROT_READ | PROT_WRITE) != 0) {
		int e = errno;
		static unsigned long rw_fail_n;

		if ((++rw_fail_n % 1000) == 1)
			outputerr("deferred_free: mprotect RW failed: errno=%d\n", e);
		return (e == ENOMEM) ? RING_UNLOCK_ENOMEM : RING_UNLOCK_FAIL;
	}
	ring_rw_open_at = begin;
	ring_rw_open = true;
	__atomic_add_fetch(&shm->stats.deferred_free.ring_rw_calls,
			   1, __ATOMIC_RELAXED);
	return RING_UNLOCK_OK;
}

void ring_lock(void)
{
	unsigned long ns;

	if (deferred_free_batch)
		return;

	if (mprotect(rc->ring, rc->ring_bytes, PROT_NONE) != 0) {
		static unsigned long none_fail_n;

		if ((++none_fail_n % 1000) == 1)
			outputerr("deferred_free: mprotect NONE failed: errno=%d\n", errno);
	}
	ring_rw_open = false;
	if (df_ts_is_zero(&ring_rw_open_at))
		return;
	ns = df_cost_elapsed_ns(&ring_rw_open_at);
	ring_rw_open_at = (struct timespec){0};
	__atomic_add_fetch(&shm->stats.deferred_free.ring_ro_calls,
			   1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.deferred_free.ring_rw_ns_total,
			   ns, __ATOMIC_RELAXED);
}

struct gen_arena_region *gen;
static size_t gen_bytes;
static struct timespec gen_rw_open_at;
static bool gen_rw_open;

int gen_unlock(void)
{
	struct timespec begin;

	if (deferred_free_batch && gen_rw_open)
		return 0;

	clock_gettime(CLOCK_MONOTONIC, &begin);
	if (mprotect(gen, gen_bytes, PROT_READ | PROT_WRITE) != 0) {
		outputerr("deferred_free: gen_arena unlock failed: errno=%d\n",
			  errno);
		return -1;
	}
	gen_rw_open_at = begin;
	gen_rw_open = true;
	__atomic_add_fetch(&shm->stats.deferred_free.gen_arena_rw_calls,
			   1, __ATOMIC_RELAXED);
	return 0;
}

void gen_lock(void)
{
	unsigned long ns;

	if (deferred_free_batch)
		return;

	if (mprotect(gen, gen_bytes, PROT_READ) != 0)
		outputerr("deferred_free: gen_arena lock failed: errno=%d\n",
			  errno);
	gen_rw_open = false;
	if (df_ts_is_zero(&gen_rw_open_at))
		return;
	ns = df_cost_elapsed_ns(&gen_rw_open_at);
	gen_rw_open_at = (struct timespec){0};
	__atomic_add_fetch(&shm->stats.deferred_free.gen_arena_ro_calls,
			   1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.deferred_free.gen_arena_rw_ns_total,
			   ns, __ATOMIC_RELAXED);
}

/*
 * Tear down the ring after ring_unlock() ENOMEM: munmap releases the
 * VMA (dropping the PROT_NONE SEGV_ACCERR bait) at the cost of leaking
 * still-queued ptrs until child exit.  Untrack the shared region BEFORE
 * munmap (check-static pairing rule).  Idempotent (ring==NULL bail);
 * after dispose the deferred-free machinery is functionally off in this
 * child for the rest of its life.  See Documentation/deferred-free.md
 * "ring_dispose_after_enomem" for the tradeoff analysis.
 */
void ring_dispose_after_enomem(void)
{
	if (rc->ring == NULL)
		return;

	untrack_shared_region((unsigned long)rc->ring, rc->ring_bytes);
	if (munmap(rc->ring, rc->ring_bytes) != 0)
		outputerr("deferred_free: munmap ring after ENOMEM failed: errno=%d\n",
			  errno);

	/*
	 * The ring page is gone.  Under batching a leftover
	 * ring_rw_open=true would drive the next seal barrier into an
	 * mprotect against a stale VA (EFAULT, flag stays set, debug assert
	 * trips at the next chokepoint).  Clear it now: no page to reprotect
	 * anyway.  Byte-neutral under batch OFF (flag was never set).
	 */
	ring_rw_open = false;

	if (rc_unlock() == 0) {
		rc->ring = NULL;
		rc->ring_count = 0;
		rc->occupied_mask = 0;
		rc_lock();
	}
}

/*
 * Kernel-entry seal barrier for the batched mode.  Walk each of
 * the protection regions; for any left rw_open by an earlier
 * lazy-open, mprotect it back to its steady state (READ for
 * alloc_track / rc, NONE for ring) and clear the
 * flag.  Real close, so it bumps the *_ro_calls / *_rw_ns_total
 * counters the same way the pre-batch X_lock() would have -- the
 * A/B delta measured against the t372-a *_rw_calls totals stays
 * accurate.  With batching OFF this is unreachable via the flag
 * check on every X_lock (which flips the region back immediately),
 * so the barrier body never runs and the seal is a no-op.
 *
 * Fail-closed: an mprotect that returns non-zero leaves the flag
 * SET so a subsequent barrier re-attempts the close.  The caller
 * (do_syscall prologue / op_fn dispatch prologue) checks the bool
 * return and, on false, does NOT proceed to the target syscall or
 * childop — it aborts or recycles the child before any kernel
 * entry.  The outputerr line preserves the breadcrumb.  Ring
 * skipped when ring_dispose_after_enomem() has already torn it
 * down (ring == NULL); the disposed state re-arms via rw_open
 * being clear once the dispose path runs.
 */
bool deferred_free_seal_all(void)
{
	bool sealed = true;

	if (!deferred_free_batch)
		return true;

	if (alloc_track_rw_open) {
		unsigned long ns;

		if (mprotect(alloc_track_base, alloc_track_bytes,
			     PROT_READ) != 0) {
			outputerr("deferred_free: seal alloc_track failed: "
				  "errno=%d\n", errno);
			sealed = false;
		} else {
			ns = df_cost_elapsed_ns(&alloc_track_rw_open_at);
			alloc_track_rw_open = false;
			__atomic_add_fetch(&shm->stats.deferred_free.alloc_track_ro_calls,
					   1, __ATOMIC_RELAXED);
			__atomic_add_fetch(&shm->stats.deferred_free.alloc_track_rw_ns_total,
					   ns, __ATOMIC_RELAXED);
		}
	}

	if (rc_rw_open) {
		unsigned long ns;

		if (mprotect(rc, rc_bytes, PROT_READ) != 0) {
			outputerr("deferred_free: seal ring_control failed: "
				  "errno=%d\n", errno);
			sealed = false;
		} else {
			ns = df_cost_elapsed_ns(&rc_rw_open_at);
			rc_rw_open = false;
			__atomic_add_fetch(&shm->stats.deferred_free.ring_ro_calls,
					   1, __ATOMIC_RELAXED);
			__atomic_add_fetch(&shm->stats.deferred_free.ring_rw_ns_total,
					   ns, __ATOMIC_RELAXED);
		}
	}

	if (ring_rw_open && rc->ring != NULL) {
		unsigned long ns;

		if (mprotect(rc->ring, rc->ring_bytes, PROT_NONE) != 0) {
			outputerr("deferred_free: seal ring failed: "
				  "errno=%d\n", errno);
			sealed = false;
		} else {
			ns = df_cost_elapsed_ns(&ring_rw_open_at);
			ring_rw_open = false;
			__atomic_add_fetch(&shm->stats.deferred_free.ring_ro_calls,
					   1, __ATOMIC_RELAXED);
			__atomic_add_fetch(&shm->stats.deferred_free.ring_rw_ns_total,
					   ns, __ATOMIC_RELAXED);
		}
	} else if (rc->ring == NULL) {
		/* Ring was disposed after ENOMEM inside this phase; the
		 * page is gone, so drop the flag with no mprotect.  A
		 * PROT_NONE call against a stale VA would fail EFAULT
		 * and leave the flag set, arming the assert. */
		ring_rw_open = false;
	}

	if (gen_rw_open && gen != NULL) {
		unsigned long ns;

		if (mprotect(gen, gen_bytes, PROT_READ) != 0) {
			outputerr("deferred_free: seal gen_arena failed: "
				  "errno=%d\n", errno);
			sealed = false;
		} else {
			ns = df_cost_elapsed_ns(&gen_rw_open_at);
			gen_rw_open = false;
			__atomic_add_fetch(&shm->stats.deferred_free.gen_arena_ro_calls,
					   1, __ATOMIC_RELAXED);
			__atomic_add_fetch(&shm->stats.deferred_free.gen_arena_rw_ns_total,
					   ns, __ATOMIC_RELAXED);
		}
	}

	return sealed;
}

#ifndef NDEBUG
void deferred_free_debug_assert_sealed(void)
{
	if (!deferred_free_batch)
		return;
	assert(!alloc_track_rw_open);
	assert(!rc_rw_open);
	assert(!ring_rw_open);
	assert(!gen_rw_open);
}
#endif

void deferred_free_init(void)
{
	const size_t raw = sizeof(struct deferred_entry) * DEFERRED_RING_SIZE;
	const size_t at_raw = sizeof(void *) *
		(ALLOC_TRACK_SIZE + ALLOC_TRACK_HASH_SIZE) +
		sizeof(size_t) * ALLOC_TRACK_SIZE;
	const size_t rc_raw = sizeof(struct ring_control);

	/*
	 * Ring control armor page first -- writes to ring/ring_bytes/
	 * ring_count below all go through rc->* fields, so the page must
	 * be live and writable for the duration of init.  Locked to
	 * PROT_READ at the tail of init alongside the data ring.
	 */
	rc_bytes = ((rc_raw + page_size - 1) / page_size) * page_size;
	rc = mmap(NULL, rc_bytes, PROT_READ | PROT_WRITE,
		  MAP_PRIVATE | MAP_ANON, -1, 0);
	if (rc == MAP_FAILED) {
		outputerr("deferred_free_init: ring_control mmap %zu failed\n",
			  rc_bytes);
		exit(EXIT_FAILURE);
	}
	memset(rc, 0, rc_bytes);
	track_shared_region((unsigned long)rc, rc_bytes);

	rc->ring_bytes = ((raw + page_size - 1) / page_size) * page_size;

	rc->ring = mmap(NULL, rc->ring_bytes, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANON, -1, 0);
	if (rc->ring == MAP_FAILED) {
		outputerr("deferred_free_init: mmap %zu failed\n",
			  rc->ring_bytes);
		exit(EXIT_FAILURE);
	}
	memset(rc->ring, 0, rc->ring_bytes);
	track_shared_region((unsigned long)rc->ring, rc->ring_bytes);
	rc->ring_count = 0;
	rc->occupied_mask = 0;
	ring_lock();
	rc_lock();

	/*
	 * alloc_track[] and alloc_track_hash[] share one mmap'd region so a
	 * single mprotect bracket covers both for deferred_alloc_track's
	 * combined slot+hash write.  PROT_READ steady state keeps the lookup
	 * hot path (alloc_track_lookup, called from every deferred-free
	 * enqueue ownership gate and from every cleanup_release_post_state)
	 * free of mprotect syscalls -- only the writer paths flip RW.
	 */
	alloc_track_bytes = ((at_raw + page_size - 1) / page_size) * page_size;
	alloc_track_base = mmap(NULL, alloc_track_bytes,
				PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANON, -1, 0);
	if (alloc_track_base == MAP_FAILED) {
		outputerr("deferred_free_init: alloc_track mmap %zu failed\n",
			  alloc_track_bytes);
		exit(EXIT_FAILURE);
	}
	memset(alloc_track_base, 0, alloc_track_bytes);
	alloc_track = (void **)alloc_track_base;
	alloc_track_hash = alloc_track + ALLOC_TRACK_SIZE;
	alloc_track_sizes = (size_t *)(alloc_track_hash + ALLOC_TRACK_HASH_SIZE);
	track_shared_region((unsigned long)alloc_track_base, alloc_track_bytes);
	alloc_track_lock();

	/*
	 * Generation-arena armor page.  One region shared across all
	 * GEN_ARENA_SLOTS generations plus the active_idx and tick_counter
	 * bookkeeping fields (see struct gen_arena_region above).  Steady
	 * state PROT_READ so gen_arena_tick's per-generation state reads
	 * (mostly the "sealed?  aged enough?" checks) run without an
	 * mprotect syscall; only push/retire flip RW via
	 * gen_unlock()/gen_lock().  Tracked with track_shared_region so the
	 * mm-syscall sanitisers refuse fuzzed pointers/lengths aliasing the
	 * arena's page.
	 */
	{
		const size_t gen_raw = sizeof(struct gen_arena_region);

		gen_bytes = ((gen_raw + page_size - 1) / page_size) * page_size;
		gen = mmap(NULL, gen_bytes, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANON, -1, 0);
		if (gen == MAP_FAILED) {
			outputerr("deferred_free_init: gen_arena mmap %zu failed\n",
				  gen_bytes);
			exit(EXIT_FAILURE);
		}
		memset(gen, 0, gen_bytes);
		track_shared_region((unsigned long)gen, gen_bytes);
		gen_lock();
	}

	/*
	 * Read vm.max_map_count once in the parent so every child
	 * inherits the same cached value via COW BSS.  Failure to read
	 * is non-fatal: the default DEFERRED_DEFAULT_MAX_VMAS leaves
	 * the soft cap at half the upstream default, which is
	 * conservative without being trigger-happy.
	 */
	deferred_free_read_max_map_count();

	/*
	 * Cache the brk-arena extent and labeled non-brk allocator
	 * regions now, before any child forks.  Every child inherits
	 * the bounds via COW BSS as a baseline, then re-parses
	 * /proc/self/maps once at end-of-init_child() to capture the
	 * mmap arenas glibc spawned post-fork.  Caching at init time
	 * (here and at child startup, not per call) keeps the hot
	 * is_in_glibc_heap / range_overlaps_libc_heap path a small
	 * array walk -- a syscall fuzzer parsing /proc on every
	 * deferred_free_enqueue would dwarf the work it's gating.
	 */
	heap_bounds_init();
}
