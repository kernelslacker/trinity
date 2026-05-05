/*
 * KCOV comparison operand collection and hint pool management.
 *
 * Parses KCOV_TRACE_CMP trace buffers to extract constants that the
 * kernel compared syscall-derived values against. These constants
 * are stored in per-syscall hint pools and used during argument
 * generation to produce values more likely to pass kernel validation.
 *
 * Buffer format (each record is 4 x u64):
 *   [0] type  - KCOV_CMP_CONST | KCOV_CMP_SIZE(n)
 *   [1] arg1  - first comparison operand
 *   [2] arg2  - second comparison operand
 *   [3] ip    - instruction pointer (unused here)
 */

#include <errno.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include "cmp_hints.h"
#include "kcov.h"
#include "random.h"
#include "syscall.h"
#include "trinity.h"
#include "utils.h"

/* From uapi/linux/kcov.h */
#define KCOV_CMP_CONST  (1U << 0)

/* Words per comparison record in the trace buffer. */
#define WORDS_PER_CMP 4

struct cmp_hints_shared *cmp_hints_shm = NULL;

void cmp_hints_init(void)
{
	if (kcov_shm == NULL)
		return;

	/*
	 * Stays alloc_shared() rather than alloc_shared_global().
	 * Children are the producers for the per-syscall pools — every
	 * syscall calls cmp_hints_collect() (via kcov_collect_cmp) in child
	 * context, which acquires pool->lock and mutates pool->values[] /
	 * pool->count via pool_add_locked.  An mprotect PROT_READ on this
	 * region would EFAULT
	 * the lock-acquire write itself (the lock byte lives inside the
	 * region) and disable the CMP-guided arg generation entirely.
	 *
	 * Wild-write risk this leaves open: a child syscall whose user-buffer
	 * arg aliases into a pool could let the kernel scribble into
	 * pool->values[] (corrupt sorted invariant; pool_add_locked tolerates
	 * out-of-order entries via the binary-search dedup, so worst case is
	 * a duplicate insertion or a missed dedup — not a crash) or into the
	 * lock byte (a stuck lock would deadlock subsequent cmp_hints_collect
	 * callers in that one syscall slot).  Diagnostic-grade only.
	 */
	cmp_hints_shm = alloc_shared(sizeof(struct cmp_hints_shared));
	memset(cmp_hints_shm, 0, sizeof(struct cmp_hints_shared));
	output(0, "KCOV: CMP hint pool allocated (%lu KB)\n",
		(unsigned long) sizeof(struct cmp_hints_shared) / 1024);
}

/*
 * Filter out uninteresting comparison values.
 * Skip 0, 1, -1, and very small values that are likely to be
 * boolean/flag checks rather than meaningful constants.
 */
static bool interesting_value(unsigned long val)
{
	if (val == 0 || val == 1)
		return false;
	if (val == (unsigned long) -1)
		return false;
	if (val < 4)
		return false;
	return true;
}

static void pool_lock(struct cmp_hint_pool *pool)
{
	lock(&pool->lock);
}

static void pool_unlock(struct cmp_hint_pool *pool)
{
	unlock(&pool->lock);
}

/*
 * Insert val into the sorted values[] array. Dedups via binary search.
 * When the pool is full, evicts a random slot. Caller must hold pool->lock.
 */
static void pool_add_locked(struct cmp_hint_pool *pool, unsigned long val)
{
	unsigned int lo = 0, hi = pool->count, mid;

	while (lo < hi) {
		mid = (lo + hi) / 2;
		if (pool->values[mid] == val)
			return;
		if (pool->values[mid] < val)
			lo = mid + 1;
		else
			hi = mid;
	}

	if (pool->count < CMP_HINTS_PER_SYSCALL) {
		memmove(&pool->values[lo + 1], &pool->values[lo],
			(pool->count - lo) * sizeof(unsigned long));
		pool->values[lo] = val;
		/*
		 * RELEASE-store count so a lockless reader in cmp_hints_get
		 * that observes the new count is guaranteed to also see the
		 * values[] store above.
		 */
		__atomic_store_n(&pool->count, pool->count + 1, __ATOMIC_RELEASE);
	} else {
		unsigned int victim = rand() % CMP_HINTS_PER_SYSCALL;
		unsigned int pos = (victim < lo) ? lo - 1 : lo;

		if (victim < pos) {
			memmove(&pool->values[victim], &pool->values[victim + 1],
				(pos - victim) * sizeof(unsigned long));
		} else if (victim > pos) {
			memmove(&pool->values[pos + 1], &pool->values[pos],
				(victim - pos) * sizeof(unsigned long));
		}
		pool->values[pos] = val;
	}
}

void cmp_hints_collect(unsigned long *trace_buf, unsigned int nr)
{
	unsigned long count;
	unsigned long i;
	struct cmp_hint_pool *pool;

	if (cmp_hints_shm == NULL || trace_buf == NULL)
		return;

	if (nr >= MAX_NR_SYSCALL)
		return;

	pool = &cmp_hints_shm->pools[nr];

	count = __atomic_load_n(&trace_buf[0], __ATOMIC_RELAXED);

	/* Buffer is the per-child KCOV_TRACE_CMP mmap, sized off
	 * KCOV_CMP_BUFFER_SIZE u64 entries.  Truncation accounting lives
	 * in kcov_collect_cmp(); here we just clamp to be defensive. */
	if (count > KCOV_CMP_RECORDS_MAX)
		count = KCOV_CMP_RECORDS_MAX;

	if (count == 0)
		return;

	pool_lock(pool);
	for (i = 0; i < count; i++) {
		unsigned long type = trace_buf[1 + i * WORDS_PER_CMP];
		unsigned long arg1 = trace_buf[1 + i * WORDS_PER_CMP + 1];
		unsigned long arg2 = trace_buf[1 + i * WORDS_PER_CMP + 2];

		/* We only care about comparisons where one side is a
		 * compile-time constant — those reveal what the kernel
		 * actually checks for. */
		if (!(type & KCOV_CMP_CONST))
			continue;

		if (interesting_value(arg1))
			pool_add_locked(pool, arg1);
		if (interesting_value(arg2))
			pool_add_locked(pool, arg2);
	}
	pool_unlock(pool);
}

unsigned long cmp_hints_get(unsigned int nr)
{
	struct cmp_hint_pool *pool;
	unsigned int count;

	if (cmp_hints_shm == NULL || nr >= MAX_NR_SYSCALL)
		return 0;

	pool = &cmp_hints_shm->pools[nr];

	/*
	 * Lockless read.  Multiple children fuzzing the same syscall would
	 * otherwise serialize on pool->lock just to grab one hint.
	 *
	 * Tolerated races:
	 *   - Stale count: we may pick an idx within an older snapshot, which
	 *     still indexes a populated slot (count is monotonic up to the
	 *     CMP_HINTS_PER_SYSCALL cap; once full, count stops moving).
	 *   - Concurrent insert/eviction shifting values[] under us: each slot
	 *     is a naturally-aligned unsigned long, so the read is atomic at
	 *     the hardware level — we get either the pre- or post-shift value.
	 *     Both are valid hints that lived in the pool, possibly a duplicate
	 *     of a neighbouring entry.
	 *
	 * For fuzzer hints these are all benign — values[] entries are direct
	 * unsigned longs substituted as syscall args, never dereferenced, and a
	 * stale or duplicated hint is no worse than picking a different one.
	 */
	count = __atomic_load_n(&pool->count, __ATOMIC_ACQUIRE);
	if (count == 0)
		return 0;

	return pool->values[rand() % count];
}

bool cmp_hints_available(unsigned int nr)
{
	if (cmp_hints_shm == NULL || nr >= MAX_NR_SYSCALL)
		return false;

	return __atomic_load_n(&cmp_hints_shm->pools[nr].count,
			       __ATOMIC_RELAXED) > 0;
}
