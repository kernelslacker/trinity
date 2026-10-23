/*
 * Seeding for the per-process PRNG streams.  init_seed() takes the -s value
 * or draws one from /dev/urandom in the parent; set_seed() mixes the shm seed
 * with a child's number so every child gets its own reproducible stream;
 * reseed() bumps the shm seed so children converge on a new generation.
 */
#include <syslog.h>
#include <unistd.h>
#include <sys/time.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <stdlib.h>
#include "child.h"
#include "shm.h"
#include "params.h"	// 'user_set_seed'
#include "pids.h"
#include "random.h"
#include "rnd.h"
#include "trinity.h"
#include "utils.h"

/*
 * Process-global state for the inline PRNG in rnd.h.  fork()
 * gives each child its own copy; set_seed() reseeds the child
 * copy via rnd_seed() from the combined (shm seed, childno)
 * value, so reproducing a run with `-s` reuses the same per-child
 * stream.
 */
uint64_t rnd_state;

void rnd_seed(uint64_t s)
{
	/* splitmix64 tolerates a zero state, but mix anyway so that
	 * trivially small seeds don't produce a trivially small first
	 * batch of outputs. */
	rnd_state = s ^ 0x9e3779b97f4a7c15ULL;
}

/*
 * Secondary splitmix64 stream for --blob-ab-mode.  Process-local like
 * rnd_state, seeded in set_seed() from the same combined (shm seed,
 * childno) value XORed with a fixed offset so the streams do not
 * overlap.  When --blob-ab-mode is absent this variable is never read
 * and never written past this seeding, so the flag-off arm stays
 * byte-identical.
 */
uint64_t rnd_blob_state;

void rnd_blob_seed(uint64_t s)
{
	rnd_blob_state = s ^ 0xd1b54a32d192ed03ULL;
}

/* The actual seed lives in the shm. This variable is used
 * to store what gets passed in from the command line -s argument */
unsigned int seed = 0;

/*
 * If we passed in a seed with -s, use that. Otherwise make one up from time of day.
 */
unsigned int init_seed(unsigned int seedparam)
{
	if (user_set_seed == true)
		output(0, "Using user passed random seed: %u.\n", seedparam);
	else {
		int urandomfd;
		unsigned int r = getpid() ^ (unsigned int)time(NULL);

		urandomfd = open("/dev/urandom", O_RDONLY);
		if (urandomfd == -1) {
			outputerr("urandom: %s, using fallback seed\n", strerror(errno));
		} else {
			if (read(urandomfd, &r, sizeof(r)) != sizeof(r))
				outputerr("urandom: %s\n", strerror(errno));
			close(urandomfd);
		}

		seedparam = r;
		output(0, "Initial random seed: %u\n", seedparam);
	}

	/* Always seed the parent RNG, including the -s path. */
	rnd_seed(seedparam);
	rnd_blob_seed((uint64_t) seedparam);

	if (do_syslog == true) {
		openlog("trinity", LOG_CONS|LOG_PERROR, LOG_USER);
		syslog(LOG_CRIT, "Initial random seed: %u\n", seedparam);
		closelog();
	}

	return seedparam;
}

/*
 * Splitmix32-style mixer. Combines two 32-bit values with good
 * avalanche so that nearby (seed, childno) pairs land far apart.
 * Plain addition (seed + childno + 1) collides easily: e.g.
 * (100, 0) and (99, 1) both produce 101.
 */
static unsigned int seed_combine(unsigned int seedval, unsigned int childno)
{
	unsigned int x = seedval ^ ((childno + 1) * 0x9e3779b1U);

	x = (x ^ (x >> 16)) * 0x85ebca6bU;
	x = (x ^ (x >> 13)) * 0xc2b2ae35U;
	x = x ^ (x >> 16);
	return x;
}

/* Mix in the childno so that all children get different randomness.
 * we can't use the actual pid or anything else 'random' because otherwise reproducing
 * seeds with -s would be much harder to replicate.
 */
void set_seed(struct childdata *child)
{
	unsigned int seedval = __atomic_load_n(&shm->seed, __ATOMIC_RELAXED);
	unsigned int mixed = seed_combine(seedval, child->num);

	rnd_seed(mixed);
	/* --blob-ab-mode secondary stream: same combined value, distinct
	 * offset inside rnd_blob_seed().  Seeded unconditionally so a
	 * later runtime flip of blob_ab_mode picks up a valid stream
	 * without re-plumbing; the stream is not read when the flag is
	 * absent, so this write is inert on the flag-off arm. */
	rnd_blob_seed((uint64_t) mixed);
	child->seed = seedval;
}

/*
 * Set a new seed in the parent.
 * Called when a new child starts, so we don't repeat runs across different pids.
 * We only reseed in the main pid; all the children are expected to
 * periodically check if the seed changed, and reseed accordingly, since two
 * 'main' seeds in play at once would make an oops hard to reproduce.
 */
void reseed(void)
{
	if (getpid() != mainpid) {
		outputerr("Reseeding should only happen from parent!\n");
		trinity_exit(EXIT_FAILURE);
	}

	/* We are reseeding. */
	__atomic_fetch_add(&shm->seed, max_children, __ATOMIC_RELAXED);
}
