/*
 * Routines to get/set seeds.
 *
 * On startup, the main process either generates a seed via new_seed()
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
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include "shm.h"
#include "params.h"	// 'user_set_seed'
#include "pids.h"
#include "log.h"
#include "random.h"
#include "utils.h"

static int urandomfd;

/* The actual seed lives in the shm. This variable is used
 * to store what gets passed in from the command line -s argument */
unsigned int seed = 0;

static int fallbackseed(void)
{
	struct timeval t;
	unsigned int r;

	//printf("Fell back to gtod seed! errno:%s\n", strerror(errno));
	r = rand();
	if (!(RAND_BOOL())) {
		gettimeofday(&t, NULL);
		r |= t.tv_usec;
	}
	return r;
}

unsigned int new_seed(void)
{
	unsigned int r, bits;

	if (urandomfd == -1)
		return fallbackseed();

	if (read(urandomfd, &r, sizeof(r)) != sizeof(r))
		return fallbackseed();

	if (read(urandomfd, &bits, sizeof(bits)) != sizeof(bits))
		return fallbackseed();

	bits %= 31;
	bits = max(bits, 8U);
	r &= ((1 << bits) -1);

	//printf("new seed:%u\n", r);
	return r;
}

bool init_random(void)
{
	urandomfd = open("/dev/urandom", O_RDONLY);
	if (urandomfd == -1) {
		printf("urandom: %s\n", strerror(errno));
		return FALSE;
	}
	return TRUE;
}

/*
 * If we passed in a seed with -s, use that. Otherwise make one up from time of day.
 */
unsigned int init_seed(unsigned int seedparam)
{
	if (user_set_seed == TRUE)
		output(0, "Using user passed random seed: %u\n", seedparam);
	else {
		seedparam = new_seed();

		output(0, "Initial random seed: %u\n", seedparam);
	}

	if (do_syslog == TRUE) {
		openlog("trinity", LOG_CONS|LOG_PERROR, LOG_USER);
		syslog(LOG_CRIT, "Initial random seed: %u\n", seedparam);
		closelog();
	}

	return seedparam;
}

/* Mix in the childno so that all children get different randomness.
 * we can't use the actual pid or anything else 'random' because otherwise reproducing
 * seeds with -s would be much harder to replicate.
 */
void set_seed(struct childdata *child)
{
	/* if no shm yet, we must be the init process. */
	if (shm == NULL) {
		srand(new_seed());
		return;
	}

	/* if not in child context, we must be main. */
	if (child == NULL) {
//		printf("Setting shm seed:%u\n", shm->seed);
		srand(shm->seed);
		return;
	}
	srand(shm->seed + (child->num + 1));
	child->seed = shm->seed;
}

/*
 * Set a new seed in the parent.
 * Called when a new child starts, so we don't repeat runs across different pids.
 * We only reseed in the main pid, all the children are expected to periodically
 * check if the seed changed, and reseed accordingly.
 *
 * Caveat: Not used if we passed in our own seed with -s
 */
void reseed(void)
{
	if (getpid() != shm->mainpid) {
		outputerr("Reseeding should only happen from parent!\n");
		exit(EXIT_FAILURE);
	}

	/* don't change the seed if we passed -s */
	if (user_set_seed == TRUE)
		return;

	/* We are reseeding. */
	shm->seed = new_seed();
}
