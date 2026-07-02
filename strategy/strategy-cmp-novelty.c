/*
 * Per-syscall comparison-constant novelty bloom.  Split from
 * strategy.c so the CMP-novelty surface compiles independently of
 * the bandit / picker / plateau / frontier translation units.
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "kcov.h"		/* KCOV_CMP_RECORDS_MAX, kcov_shm */
#include "shm.h"
#include "strategy.h"
#include "syscall.h"		/* MAX_NR_SYSCALL */

/* Same KCOV_CMP_CONST bit cmp_hints.c uses; from uapi/linux/kcov.h. */
#define KCOV_CMP_CONST  (1U << 0)
#define WORDS_PER_CMP   4

/*
 * Per-syscall comparison-constant novelty bloom.
 *
 * Two complementary 64-bit hashes derive ten-bit indices into a
 * 1024-bit (128-byte) bloom filter per syscall.  The multipliers are
 * splitmix64-style high-entropy odd constants; XOR-folding the upper
 * half into the index defeats the multiplier's tendency to leave low
 * bits weakly mixed when val itself has small magnitude (true for
 * many comparison constants the kernel checks against -- length
 * limits, error codes, magic numbers in the first few KiB of address
 * space).  Two hashes is the textbook efficient point for k below
 * ~3% FPR at the loads expected here (a few hundred distinct
 * constants per syscall over the K-window decay).
 */
static inline uint32_t cmp_bloom_h1(unsigned long val)
{
	uint64_t x = (uint64_t)val * 0x9e3779b97f4a7c15ULL;
	x ^= x >> 32;
	return (uint32_t)(x & 0x3FF);
}

static inline uint32_t cmp_bloom_h2(unsigned long val)
{
	uint64_t x = (uint64_t)val * 0xbf58476d1ce4e5b9ULL;
	x ^= x >> 32;
	x ^= x >> 16;
	return (uint32_t)(x & 0x3FF);
}

/*
 * Same "boring constant" filter cmp_hints.c uses (interesting_value).
 * Kept private here so the two filters can drift independently if it
 * turns out the novelty signal benefits from a different threshold
 * than the hint-substitution pool.
 */
static bool cmp_novelty_interesting(unsigned long val)
{
	if (val == 0 || val == 1)
		return false;
	if (val == (unsigned long) -1)
		return false;
	if (val < 4)
		return false;
	return true;
}

/*
 * Lazy bloom decay.  If the entry's window_tag is more than
 * CMP_NOVELTY_DECAY_WINDOWS rotations behind the current rotation
 * counter, zero the bloom and republish the tag.  CAS protects against
 * multiple children racing to clear the same entry — the loser sees
 * the new tag on the second load and skips the clear.  Children that
 * race the clear and observe a half-zeroed bloom may miss-credit a
 * constant as novel; that is benign for a noisy diagnostic counter
 * and self-correcting on the next observation.
 */
static void cmp_bloom_maybe_decay(struct cmp_novelty_entry *e,
				  uint32_t now)
{
	uint32_t tag = __atomic_load_n(&e->window_tag, __ATOMIC_RELAXED);

	if (now - tag <= CMP_NOVELTY_DECAY_WINDOWS)
		return;

	if (!__atomic_compare_exchange_n(&e->window_tag, &tag, now,
					 false,
					 __ATOMIC_RELAXED, __ATOMIC_RELAXED))
		return;

	memset((void *)e->bloom, 0, sizeof(e->bloom));
}

/*
 * Test-and-set one bloom bit.  Returns true if the bit was previously
 * clear (the constant is novel along this hash).  Bits are atomic at
 * byte granularity; the caller treats "either hash bit was clear" as
 * "constant is novel".
 */
static bool cmp_bloom_set(uint8_t *bloom, uint32_t bit)
{
	uint8_t mask = (uint8_t)(1U << (bit & 7));
	uint8_t prev = __atomic_fetch_or(&bloom[bit >> 3], mask,
					 __ATOMIC_RELAXED);

	return (prev & mask) == 0;
}

unsigned long bandit_cmp_observe(unsigned long *trace_buf, unsigned int nr,
				bool do32, bool is_explorer,
				int strategy_at_pick)
{
	struct cmp_novelty_entry *e;
	unsigned long count, i;
	unsigned long novel = 0;
	uint32_t now;

	if (trace_buf == NULL || nr >= MAX_NR_SYSCALL)
		return 0;

	count = __atomic_load_n(&trace_buf[0], __ATOMIC_RELAXED);
	if (count == 0)
		return 0;
	if (count > KCOV_CMP_RECORDS_MAX)
		count = KCOV_CMP_RECORDS_MAX;

	e = &shm->cmp_novelty[nr][do32 ? 1 : 0];
	now = (uint32_t)__atomic_load_n(&shm->bandit_window_count,
					__ATOMIC_RELAXED);
	cmp_bloom_maybe_decay(e, now);

	for (i = 0; i < count; i++) {
		unsigned long type = trace_buf[1 + i * WORDS_PER_CMP];
		unsigned long arg1 = trace_buf[1 + i * WORDS_PER_CMP + 1];
		bool novel_here;

		if (!(type & KCOV_CMP_CONST))
			continue;

		/* arg1 is the compile-time constant under KCOV_CMP_CONST
		 * (clang/gcc's __sanitizer_cov_trace_const_cmpN convention);
		 * arg2 is the runtime value the kernel compared it against
		 * and would just credit the bandit for novelty in the
		 * fuzzer's own input distribution. */
		if (!cmp_novelty_interesting(arg1))
			continue;

		novel_here = cmp_bloom_set(e->bloom, cmp_bloom_h1(arg1));
		novel_here = cmp_bloom_set(e->bloom, cmp_bloom_h2(arg1)) ||
			     novel_here;
		if (novel_here)
			novel++;
	}

	if (novel == 0)
		return 0;

	/* Per-arm bandit attribution is gated separately from the return
	 * value: explorer-pool children run a different strategy than
	 * whatever the bandit picked, so crediting their CMP novelty into
	 * bandit_cmp_new_constants[] would misattribute their work and bias
	 * the bandit's reward calculation.  Out-of-range strategy_at_pick
	 * (including the -1 sentinel for pre-first-pick) likewise skips
	 * attribution.  The bloom updates above and the `novel` return
	 * still propagate so the global novelty horizon stays consistent
	 * across the fleet and so callers can use CMP novelty from
	 * explorers as a corpus-save signal.
	 *
	 * Attribute to the arm that PICKED the syscall, snapshotted in
	 * set_syscall_nr().  Re-reading shm->current_strategy here would
	 * misattribute any call whose syscall started under one arm and
	 * completed under another (rotation lands mid-syscall) -- frequent
	 * for long or blocking syscalls. */
	if (!is_explorer &&
	    strategy_at_pick >= 0 && strategy_at_pick < NR_STRATEGIES) {
		__atomic_fetch_add(
			&shm->bandit_cmp_new_constants[strategy_at_pick],
			novel, __ATOMIC_RELAXED);
	}

	return novel;
}
