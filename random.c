/*
 * Routines to get randomness/set seeds.
 */
#include <syslog.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include "shm.h"
#include "params.h"	// 'user_set_seed'
#include "log.h"
#include "random.h"
#include "sanitise.h"
#include "types.h"

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

unsigned int new_seed(void)
{
	int fd;
	struct timeval t;
	unsigned int r;

	if ((fd = open("/dev/urandom", O_RDONLY)) < 0 ||
	    read(fd, &r, sizeof(r)) != sizeof(r)) {
		r = rand();
		if (!(rand() % 2)) {
			gettimeofday(&t, 0);
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
		printf("[%d] Using user passed random seed: %u\n", getpid(), seedparam);
	else {
		seedparam = new_seed();

		printf("Initial random seed: %u\n", seedparam);
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

unsigned int rand_bool(void)
{
	return rand() % 2;
}

static unsigned int rand_single_bit(unsigned char size)
{
	return (1L << (rand() % size));
}

static unsigned long randbits(int limit)
{
	unsigned int num = rand() % limit / 2;
	unsigned int i;
	unsigned long r = 0;

	for (i = 0; i < num; i++)
		r |= (1 << (rand() % (limit - 1)));

	return r;
}

/*
 * Based on very similar routine stolen from iknowthis. Thanks Tavis.
 */
static unsigned long taviso(void)
{
	unsigned long r = 0;

	switch (rand() % 3) {
	case 0:	r = rand() & rand();
#if __WORDSIZE == 64
		r <<= 32;
		r |= rand() & rand();
#endif
		break;

	case 1:	r = rand() | rand();
#if __WORDSIZE == 64
		r <<= 32;
		r |= rand() | rand();
#endif
		break;

	case 2:	r = rand();
#if __WORDSIZE == 64
		r <<= 32;
		r |= rand();
#endif
		break;

	default:
		break;
	}

	return r;
}

static unsigned long rand8x8(void)
{
	unsigned long r = 0UL;
	unsigned int i;

	for (i = (rand() % 7) + 1; i > 0; --i)
		r = (r << 8) | rand() % 256;

	return r;
}

static unsigned long rept8(unsigned int num)
{
	unsigned long r = 0UL;
	unsigned int i;
	unsigned char c;

	c = rand() % 256;
	for (i = rand() % (num - 1) ; i > 0; --i)
		r = (r << 8) | c;

	return r;
}

static unsigned int __rand32(void)
{
	unsigned long r = 0;

	switch (rand() % 7) {
	case 0: r = rand_single_bit(32);
		break;
	case 1:	r = randbits(32);
		break;
	case 2: r = rand();
		break;
	case 3:	r = taviso();
		break;
	case 4:	r = rand8x8();
		break;
	case 5:	r = rept8(4);
		break;
	case 6:	return get_interesting_32bit_value();
	default:
		break;
	}

	return r;
}

unsigned int rand32(void)
{
	unsigned long r = 0;

	r = __rand32();

	if (rand_bool()) {
		unsigned int i;
		unsigned int rounds;

		/* mangle it. */
		rounds = rand() % 3;
		for (i = 0; i < rounds; i++) {
			switch (rand() % 2) {
			case 0: r |= __rand32();
				break;
			case 1: r ^= __rand32();
				break;
			default:
				break;
			}
		}
	}

	if (rand_bool())
		r = INT_MAX - r;

	if (rand_bool())
		r |= (1L << 31);

	/* limit the size */
	switch (rand() % 4) {
	case 0: r &= 0xff;
		break;
	case 1: r &= 0xffff;
		break;
	case 2: r &= 0xffffff;
		break;
	default:
		break;
	}

	return r;
}

u64 rand64(void)
{
	unsigned long r = 0;

	if (rand_bool()) {
		/* 32-bit ranges. */
		r = rand32();

	} else {
		/* 33:64-bit ranges. */
		switch (rand() % 7) {
		case 0:	r = rand_single_bit(64);
			break;
		case 1:	r = randbits(64);
			break;
		case 2:	r = rand32() | rand32() << 31;
			break;
		case 3:	r = taviso();
			break;
		case 4:	r = rand8x8();
			break;
		case 5:	r = rept8(8);
			break;
		/* Sometimes pick a not-so-random number. */
		case 6:	return get_interesting_value();
		default:
			break;
		}

		/* limit the size */
		switch (rand() % 4) {
		case 0: r &= 0x000000ffffffffffULL;
			break;
		case 1: r &= 0x0000ffffffffffffULL;
			break;
		case 2: r &= 0x00ffffffffffffffULL;
			break;
		default:
			break;
		}

	}

	if (rand_bool())
		r ^= r;

	/* increase distribution in MSB */
	if ((rand() % 10)) {
		unsigned int i;
		unsigned int rounds;

		rounds = rand() % 4;
		for (i = 0; i < rounds; i++)
			r |= (1L << (__WORDSIZE - (rand() % 256)));
	}

	/* randomly flip sign bit. */
	if (rand_bool())
		r |= (1L << (__WORDSIZE - 1));

	return r;
}
