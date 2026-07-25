/*
 * Test-binary RNG provider.
 *
 * Satisfies the rnd.h contract (rnd_state, rnd_seed, rnd_blob_state,
 * rnd_blob_seed) for PURE modules linked into the test binary without
 * pulling in rand/seed.c's dependency chain (shm->seed, childdata,
 * urandom, syslog, params).  The seed init path is identical to the
 * production path -- same splitmix64 seed mix -- so a test running
 * under a fixed seed produces the same rnd_u32() / rnd_modulo_u32()
 * stream production would at the equivalent (shm seed, childno) pair.
 *
 * Deterministic-by-default: the parent test main() calls test_rng_seed()
 * with a caller-chosen constant so a repro is a single `-s <seed>`
 * flag flip in the harness, not "walk the /dev/urandom draw".
 */

#include <stdint.h>

#include "rnd.h"

uint64_t rnd_state;
uint64_t rnd_blob_state;

void rnd_seed(uint64_t s)
{
	rnd_state = s ^ 0x9e3779b97f4a7c15ULL;
}

void rnd_blob_seed(uint64_t s)
{
	rnd_blob_state = s ^ 0xd1b54a32d192ed03ULL;
}
