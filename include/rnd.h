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
 * libc rand() / random() / *rand48() are banned on this path: new
 * callsites are rejected at build by check-static, with a link-time
 * --wrap tripwire (rand/rand-warn.c) catching any that arrive via
 * macro expansion.  srand() in rand/seed.c is the one deliberate
 * exception, driving seed reproduction.
 */

extern uint64_t rnd_state;

void rnd_seed(uint64_t seed);

/*
 * Secondary splitmix64 stream reserved for --blob-ab-mode's within-run
 * A/B harness.  Kept process-local (fork() gives each child its own
 * copy) and seeded in set_seed() from the same combined (shm seed,
 * childno) value that drives rnd_state, XORed with a fixed offset
 * constant so the two streams do not overlap.  All blob-mutator RNG
 * draws (the HAVOC-vs-CMPDICT coin-flip, havoc arm ops, cmpdict pulls,
 * and the nested generate_rand_bytes / cmp_hints_try_get calls) route
 * through this stream during --blob-ab-mode fills via a swap of
 * rnd_state around blob_fill(), keeping the main syscall-selection
 * stream identical regardless of which blob mode fired -- without
 * this the modes desync the main stream and the per-fill new-edges
 * comparison leaks.  Only touched under --blob-ab-mode; when the flag
 * is absent this stream is untouched and the blob path stays
 * byte-identical to today. */
extern uint64_t rnd_blob_state;

void rnd_blob_seed(uint64_t seed);

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

/*
 * 64-bit sibling of rnd_modulo_u32: uniform value in [0, n) via the
 * same Lemire debiased shape, but with a 128-bit product so the high
 * half is the bounded result.  __uint128_t is supported by both gcc
 * and clang on the 64-bit targets trinity is built for; if/when a
 * 32-bit-only build comes back this needs an alternative.
 *
 * As with the u32 variant, n==0 returns 0 rather than trapping -- no
 * existing caller passes 0 but the guard keeps a future caller from
 * tripping `-n % n` UB.
 */
static inline uint64_t rnd_modulo_u64(uint64_t n)
{
	__uint128_t m;
	uint64_t l, t;

	if (n == 0)
		return 0;

	m = (__uint128_t) rnd_u64() * (__uint128_t) n;
	l = (uint64_t) m;
	if (l < n) {
		t = ((uint64_t) -n) % n;
		while (l < t) {
			m = (__uint128_t) rnd_u64() * (__uint128_t) n;
			l = (uint64_t) m;
		}
	}
	return (uint64_t) (m >> 64);
}
