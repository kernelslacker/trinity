/*
 * Routines to get/set seeds.
 *
 * On startup, the main process either generates a seed via rand()
 * or gets one passed in by the -s parameter.
 *
 * Example: we have four children, and our initial seed is 10000.
 * When we fork children, each child uses this seed + its child number
 * as its own personal seed. So the child seeds are 10001, 10002, 10003, 10004.
 * If a child segfaults, we need to get a new seed, or we'll end up just
 * redoing the same system calls. If our new seed is 20000, we now have children
 * with seeds 10001, 20002, 10003, 10004.  This out-of-sync situation is
 * a problem if we should happen to cause an oops, because we have two separate
 * 'main' seeds in play.  So when we segfault, and main regenerates a new seed,
 * we make sure the other children take notice and have them reseed to the
 * new seed. We then end up with 20001, 20002, 20003, 20004.
 *
 * The net result is we end up reseeding quite a lot (and the chance of a child
 * segfaulting increases as the child count goes up. Such is life when we
 * deal with multi-threaded rand consumers.
 */
#include <syslog.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include "shm.h"
#include "params.h"	// 'user_set_seed'
#include "pids.h"
#include "random.h"
#include "trinity.h"
#include "utils.h"

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

	/* Always seed the parent RNG, including the -s path.  Previously
	 * srand() was only called for the auto-generated seed branch,
	 * leaving the parent at the default state when -s was used. */
	srand(seedparam);

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
	srand(seed_combine(__atomic_load_n(&shm->seed, __ATOMIC_RELAXED), child->num));
	child->seed = __atomic_load_n(&shm->seed, __ATOMIC_RELAXED);
}

/*
 * Set a new seed in the parent.
 * Called when a new child starts, so we don't repeat runs across different pids.
 * We only reseed in the main pid, all the children are expected to periodically
 * check if the seed changed, and reseed accordingly.
 */
void reseed(void)
{
	if (getpid() != mainpid) {
		outputerr("Reseeding should only happen from parent!\n");
		exit(EXIT_FAILURE);
	}

	/* We are reseeding. */
	__atomic_fetch_add(&shm->seed, max_children, __ATOMIC_RELAXED);
}
