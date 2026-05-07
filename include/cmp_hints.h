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
 */

/* Max unique hints stored per syscall number. */
#define CMP_HINTS_PER_SYSCALL 32

struct cmp_hint_pool {
	lock_t lock;
	unsigned int count;
	unsigned long values[CMP_HINTS_PER_SYSCALL];
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
