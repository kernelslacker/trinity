#include <syslog.h>
#include <unistd.h>
#include <stdlib.h>
#include "trinity.h"
#include "shm.h"

/* The actual seed lives in the shm. This variable is used
 * to store what gets passed in from the command line -s argument */
unsigned int seed = 0;

static void syslog_seed(int seedparam)
{
	fprintf(stderr, "Randomness reseeded to %u\n", seedparam);
	openlog("trinity", LOG_CONS|LOG_PERROR, LOG_USER);
	syslog(LOG_CRIT, "Randomness reseeded to %u\n", seedparam);
	closelog();
}

static unsigned int new_seed(void)
{
	struct timeval t;
	unsigned int r;

	gettimeofday(&t, 0);
	r = rand() ^ (t.tv_sec * getpid()) ^ t.tv_usec;
	return r;
}

/*
 * If we passed in a seed with -s, use that. Otherwise make one up from time of day.
 */
unsigned int init_seed(unsigned int seedparam)
{
	if (user_set_seed == TRUE)
		printf("[%d] Using user passed random seed: %u\n", getpid(), seedparam);
	else {
		seedparam = new_seed();

		printf("Initial random seed from time of day: %u\n", seedparam);
	}

	if (do_syslog == TRUE)
		syslog_seed(seedparam);

	return seedparam;
}


/* Mix in the pidslot so that all children get different randomness.
 * we can't use the actual pid or anything else 'random' because otherwise reproducing
 * seeds with -s would be much harder to replicate.
 */
void set_seed(unsigned int pidslot)
{
	srand(shm->seed + (pidslot + 1));
	srandom(shm->seed + (pidslot + 1));
	shm->seeds[pidslot] = shm->seed;
}

/*
 * Periodically reseed.
 *
 * We do this so we can log a new seed every now and again, so we can cut down on the
 * amount of time necessary to reproduce a bug.
 * Caveat: Not used if we passed in our own seed with -s
 */
void reseed(void)
{
	shm->need_reseed = FALSE;
	shm->reseed_counter = 0;

	if (getpid() != shm->parentpid) {
		output(0, "Reseeding should only happen from parent!\n");
		exit(EXIT_FAILURE);
	}

	/* don't change the seed if we passed -s */
	if (user_set_seed == TRUE)
		return;

	/* We are reseeding. */
	shm->seed = new_seed();

	output(0, "[%d] Random reseed: %u\n", getpid(), shm->seed);

	if (do_syslog == TRUE)
		syslog_seed(shm->seed);
}
