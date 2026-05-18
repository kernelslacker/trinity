/*
 * KCOV comparison operand collection and hint pool management.
 *
 * Parses KCOV_TRACE_CMP trace buffers to extract constants that the
 * kernel compared syscall-derived values against. These constants
 * are stored in per-syscall in-memory pools and used during argument
 * generation to produce values more likely to pass kernel validation.
 *
 * Buffer format (each record is 4 x u64):
 *   [0] type  - KCOV_CMP_CONST | KCOV_CMP_SIZE(n)
 *   [1] arg1  - first comparison operand
 *   [2] arg2  - second comparison operand
 *   [3] ip    - instruction pointer of the comparison
 *
 * Pool entries are keyed by (cmp_ip, value, size).  Distinguishing on
 * cmp_ip means the same constant compared at two different kernel
 * sites occupies two slots rather than colliding -- the precision
 * matters once a downstream consumer wants to attribute which site a
 * hint came from.  When a pool fills, the entry with the lowest
 * last_used generation is evicted (least-recently-inserted), so a
 * fresh constant displaces stale long-tail noise instead of stomping
 * a slot at random.
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

/* From uapi/linux/kcov.h.  KCOV_CMP_SIZE(n) packs the operand-width
 * index n in {0,1,2,3} into bits 1..2 of the type word; the actual
 * operand width in bytes is (1U << n). */
#define KCOV_CMP_CONST		(1U << 0)
#define KCOV_CMP_SIZE_SHIFT	1
#define KCOV_CMP_SIZE_MASK	3U

/* Words per comparison record in the trace buffer. */
#define WORDS_PER_CMP 4

struct cmp_hints_shared *cmp_hints_shm = NULL;

void cmp_hints_init(void)
{
	if (kcov_shm == NULL)
		return;

	/*
	 * Wild-write risk: a child syscall whose user-buffer arg aliases
	 * into a pool could let the kernel scribble into pool->entries[]
	 * (worst case: a duplicate slips past the linear-scan dedup, or a
	 * stale value is handed back as a hint -- not a crash) or into the
	 * lock byte (a stuck lock would deadlock subsequent
	 * cmp_hints_collect callers in that one syscall slot).
	 * Diagnostic-grade only.
	 */
	cmp_hints_shm = alloc_shared(sizeof(struct cmp_hints_shared));
	memset(cmp_hints_shm, 0, sizeof(struct cmp_hints_shared));
	output(0, "KCOV: CMP hint pool allocated (%lu KB)\n",
		(unsigned long) sizeof(struct cmp_hints_shared) / 1024);
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
 * Insert (cmp_ip, val, size) into the entries[] array.  Dedups via linear
 * scan on the full (cmp_ip, value, size) key.  When the pool is full,
 * evicts the entry with the smallest last_used (least-recently-inserted)
 * to make room.  Duplicate hits refresh last_used so an actively-observed
 * constant doesn't get evicted by transient long-tail noise.  Caller must
 * hold pool->lock.
 */
static void pool_add_locked(struct cmp_hint_pool *pool,
			    unsigned long cmp_ip,
			    unsigned long val,
			    unsigned int size)
{
	unsigned int i, count = pool->count;
	unsigned int stamp = ++pool->generation;
	unsigned int victim;
	unsigned int oldest;

	for (i = 0; i < count; i++) {
		struct cmp_hint_entry *e = &pool->entries[i];

		if (e->value == val && e->cmp_ip == cmp_ip && e->size == size) {
			e->last_used = stamp;
			return;
		}
	}

	if (count < CMP_HINTS_PER_SYSCALL) {
		struct cmp_hint_entry *e = &pool->entries[count];

		e->value = val;
		e->cmp_ip = cmp_ip;
		e->size = size;
		e->last_used = stamp;
		/*
		 * RELEASE-store count so a lockless reader in cmp_hints_try_get
		 * that observes the new count is guaranteed to also see the
		 * entries[] store above.
		 */
		__atomic_store_n(&pool->count, count + 1, __ATOMIC_RELEASE);
		return;
	}

	victim = 0;
	oldest = pool->entries[0].last_used;
	for (i = 1; i < CMP_HINTS_PER_SYSCALL; i++) {
		if (pool->entries[i].last_used < oldest) {
			oldest = pool->entries[i].last_used;
			victim = i;
		}
	}
	pool->entries[victim].value = val;
	pool->entries[victim].cmp_ip = cmp_ip;
	pool->entries[victim].size = size;
	pool->entries[victim].last_used = stamp;
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
		unsigned long *rec = &trace_buf[1 + i * WORDS_PER_CMP];
		unsigned long type = rec[0];
		unsigned long arg1 = rec[1];
		unsigned long arg2 = rec[2];
		unsigned long ip   = rec[3];
		unsigned int size  = 1U << ((type >> KCOV_CMP_SIZE_SHIFT)
					    & KCOV_CMP_SIZE_MASK);

		/* We only care about comparisons where one side is a
		 * compile-time constant — those reveal what the kernel
		 * actually checks for. */
		if (!(type & KCOV_CMP_CONST))
			continue;

		/*
		 * Filter out uninteresting comparison operands inline so the
		 * compiler can fold the per-record check to a couple of
		 * branches: skip 0/1/2/3 (caught by the ~3UL mask going to 0)
		 * and the all-ones sentinel.
		 */
		if (((arg1 & ~3UL) != 0) && (arg1 != (unsigned long) -1))
			pool_add_locked(pool, ip, arg1, size);
		if (((arg2 & ~3UL) != 0) && (arg2 != (unsigned long) -1))
			pool_add_locked(pool, ip, arg2, size);
	}
	pool_unlock(pool);
}

bool cmp_hints_try_get(unsigned int nr, unsigned long *out)
{
	struct cmp_hint_pool *pool;
	unsigned int count;

	if (cmp_hints_shm == NULL || nr >= MAX_NR_SYSCALL)
		return false;

	pool = &cmp_hints_shm->pools[nr];

	/*
	 * Lockless read.  Multiple children fuzzing the same syscall would
	 * otherwise serialize on pool->lock just to grab one hint.
	 *
	 * Tolerated race: a stale count snapshot still indexes a populated
	 * slot — count is monotonic up to the CMP_HINTS_PER_SYSCALL cap, and
	 * once full it stops moving (full-pool eviction overwrites in place).
	 * The per-entry .value field is a naturally-aligned unsigned long, so
	 * a concurrent eviction yields either the pre- or post-overwrite
	 * value at the hardware level; both are valid hints that lived in
	 * the pool.
	 *
	 * For fuzzer hints this is benign — values are direct unsigned longs
	 * substituted as syscall args, never dereferenced.  We do not refresh
	 * the entry's last_used field on lookup: the LRU stamp tracks
	 * insertion freshness from cmp_hints_collect(), which is what the
	 * dedup-vs-eviction policy is built around.
	 */
	count = __atomic_load_n(&pool->count, __ATOMIC_ACQUIRE);
	if (count == 0)
		return false;

	*out = pool->entries[rand() % count].value;
	return true;
}
