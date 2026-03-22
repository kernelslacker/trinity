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

#include <string.h>

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
		return FALSE;
	if (val == (unsigned long) -1)
		return FALSE;
	if (val < 4)
		return FALSE;
	return TRUE;
}

/*
 * Add a value to the hint pool for a given syscall number.
 * Deduplicates and overwrites a random slot when full.
 */
static void pool_add(struct cmp_hint_pool *pool, unsigned long val)
{
	unsigned int i;

	for (i = 0; i < pool->count && i < CMP_HINTS_PER_SYSCALL; i++) {
		if (pool->values[i] == val)
			return;
	}

	if (pool->count < CMP_HINTS_PER_SYSCALL) {
		pool->values[pool->count] = val;
		pool->count++;
	} else {
		pool->values[rand() % CMP_HINTS_PER_SYSCALL] = val;
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

	if (count > (KCOV_TRACE_SIZE - 1) / WORDS_PER_CMP)
		count = (KCOV_TRACE_SIZE - 1) / WORDS_PER_CMP;

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
			pool_add(pool, arg1);
		if (interesting_value(arg2))
			pool_add(pool, arg2);
	}
}

unsigned long cmp_hints_get(unsigned int nr)
{
	struct cmp_hint_pool *pool;

	if (cmp_hints_shm == NULL || nr >= MAX_NR_SYSCALL)
		return 0;

	pool = &cmp_hints_shm->pools[nr];

	if (pool->count == 0)
		return 0;

	return pool->values[rand() % pool->count];
}

bool cmp_hints_available(unsigned int nr)
{
	if (cmp_hints_shm == NULL || nr >= MAX_NR_SYSCALL)
		return FALSE;

	return cmp_hints_shm->pools[nr].count > 0;
}
