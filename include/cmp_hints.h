#pragma once

#include <sys/types.h>

#include "locks.h"
#include "types.h"

/*
 * KCOV comparison operand hint pool.
 *
 * When running in KCOV_TRACE_CMP mode, the kernel records every
 * comparison instruction with its operands. We extract constants
 * the kernel compares against and store them per-syscall-number.
 * During argument generation, we sometimes substitute a learned
 * constant instead of a random value, dramatically improving the
 * fuzzer's ability to pass kernel validation checks.
 *
 * Entries are keyed by (cmp_ip, value, size) -- a single comparison
 * site that exercises both small and large operand widths is two
 * distinct hints, and the same constant compared at two different
 * kernel PCs is two distinct hints.  Precision over robustness: a
 * kernel rebuild that shuffles addresses invalidates the IP keys,
 * but the kallsyms fingerprint on the persisted file catches that
 * and forces a cold start.
 */

/* Max unique hints stored per syscall number. */
#define CMP_HINTS_PER_SYSCALL 32

struct cmp_hint_entry {
	unsigned long value;
	unsigned long cmp_ip;
	uint32_t size;		/* operand width in bytes: 1, 2, 4, or 8 */
	uint32_t last_used;	/* pool->generation snapshot at insertion */
};

struct cmp_hint_pool {
	lock_t lock;
	unsigned int count;
	/* Monotonic counter bumped under pool->lock on every insertion /
	 * duplicate-refresh.  The current value stamps the entry's
	 * last_used field; the entry with the lowest last_used is the LRU
	 * eviction victim when count == CMP_HINTS_PER_SYSCALL. */
	unsigned int generation;
	struct cmp_hint_entry entries[CMP_HINTS_PER_SYSCALL];
};

struct cmp_hints_shared {
	struct cmp_hint_pool pools[1024]; /* indexed by syscall number */
};

extern struct cmp_hints_shared *cmp_hints_shm;

/* Called once from init_shm() to allocate shared hint storage. */
void cmp_hints_init(void);

/* Extract comparison operands from a CMP-mode trace buffer and
 * add interesting constants to the hint pool for syscall nr. */
void cmp_hints_collect(unsigned long *trace_buf, unsigned int nr);

/* Try to extract a random hint value for the given syscall.
 * Returns true with the hint written to *out, or false if none available. */
bool cmp_hints_try_get(unsigned int nr, unsigned long *out);
