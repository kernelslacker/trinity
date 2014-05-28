/*
 * Routines to get/set seeds.
 */
#include <syslog.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include "shm.h"
#include "params.h"	// 'user_set_seed'
#include "pids.h"
#include "log.h"
#include "random.h"

/* The actual seed lives in the shm. This variable is used
 * to store what gets passed in from the command line -s argument */
unsigned int seed = 0;

unsigned int new_seed(void)
{
	int fd;
	struct timeval t;
	unsigned int r;

	if ((fd = open("/dev/urandom", O_RDONLY)) < 0 ||
	    read(fd, &r, sizeof(r)) != sizeof(r)) {
		r = rand();
		if (!(rand_bool())) {
			gettimeofday(&t, NULL);
			r |= t.tv_usec;
		}
	}
	if (fd >= 0)
		close(fd);
	return r;
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
void set_seed(unsigned int childno)
{
	srand(shm->seed + (childno + 1));
	shm->seeds[childno] = shm->seed;
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
