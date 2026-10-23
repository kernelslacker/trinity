/*
 * Test-binary RNG provider: rnd_state, rnd_seed(), rnd_blob_state and
 * rnd_blob_seed() without rand/seed.c's dependency chain (shm->seed,
 * childdata, urandom, syslog, params).  The seed mix is the production one,
 * so rnd_seed(s) gives the stream production draws from the same s;
 * test_main.c seeds it from a fixed constant or -s <seed>.
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
