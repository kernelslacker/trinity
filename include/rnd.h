#pragma once

#include <stdint.h>

/*
 * Inline per-process PRNG used on the syscall-generation hot path
 * in place of libc rand().
 *
 * Why: glibc's rand() is an out-of-line call into an LFSR-based state
 * machine that shows up consistently in the top of perf-top profiles
 * during fuzz runs (~3-4% of runtime).  The helpers below are
 * static-inline splitmix64 calls and compile down to a handful of
 * register-only multiplies and xor-shifts, taking rand() out of the
 * profile while preserving the existing seed-reproducibility story.
 *
 * State is a plain process-global so that fork() naturally gives
 * each child its own copy.  Children re-seed inside set_seed() via
 * rnd_seed(), mirroring the existing srand() seeding path -- the
 * same shm seed + childno combiner that drives srand() also drives
 * rnd_seed(), so a run reproduced via `-s` reuses the same per-child
 * stream.  The parent seeds at startup from init_seed().
 *
 * Note: rand()-using sites are being migrated incrementally; the
 * existing srand() calls in rand/seed.c stay in place until every
 * caller has been converted.
 */

extern uint64_t rnd_state;

void rnd_seed(uint64_t seed);

/*
 * splitmix64.  Public-domain mixer by Sebastiano Vigna (see
 * https://prng.di.unimi.it/splitmix64.c).  Picked over xoshiro256**
 * because the state is a single u64 -- no array, no alignment
 * concerns, no all-zero-state escape requirement -- and the output
 * quality is more than enough for fuzz argument generation.
 */
static inline uint64_t rnd_u64(void)
{
	uint64_t z = (rnd_state += 0x9e3779b97f4a7c15ULL);

	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
	z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
	return z ^ (z >> 31);
}

static inline uint32_t rnd_u32(void)
{
	return (uint32_t) rnd_u64();
}

/*
 * Lemire's debiased fast bounded random: returns a uniform value in
 * [0, n).  Uses a single 64-bit multiply and only takes the rejection
 * path on the rare residue band, avoiding the slow 32-bit divide
 * implied by `rnd_u32() % n`.
 * See https://lemire.me/blog/2016/06/30/fast-random-shuffling/.
 *
 * Matches the `rand() % 0` UB by returning 0 instead of trapping --
 * no existing caller passes 0, but the guard keeps a future caller
 * from triggering `-n % n` UB on n==0.
 */
static inline uint32_t rnd_modulo_u32(uint32_t n)
{
	uint64_t m;
	uint32_t l, t;

	if (n == 0)
		return 0;

	m = (uint64_t) rnd_u32() * (uint64_t) n;
	l = (uint32_t) m;
	if (l < n) {
		t = (uint32_t) (-n) % n;
		while (l < t) {
			m = (uint64_t) rnd_u32() * (uint64_t) n;
			l = (uint32_t) m;
		}
	}
	return (uint32_t) (m >> 32);
}
