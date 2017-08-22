/*
 * Routines to get randomness.
 */
#include <syslog.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <limits.h>
#include "arch.h"
#include "pids.h"
#include "random.h"
#include "sanitise.h"	// interesting_numbers
#include "types.h"
#include "utils.h"

int rnd(void)
{
	return rand();
}

/*
 * OR a random number of bits into a mask.
 * Used by ARG_LIST generation, and get_o_flags()
 */
unsigned long set_rand_bitmask(unsigned int num, const unsigned long *values)
{
	unsigned long i;
	unsigned long mask = 0;
	unsigned int bits;

	bits = RAND_RANGE(0, num);      /* num of bits to OR */
	if (bits == 0)
		return mask;

	for (i = 0; i < bits; i++)
		mask |= values[rnd() % num];

	return mask;
}

/*
 * Pick a random power of two between 2^0 and 2^(WORD_BIT-1)
 */
unsigned long rand_single_bit(unsigned char size)
{
	if (size > WORD_BIT)
		size = WORD_BIT;

	return (1UL << (rnd() % size));
}

/*
 * set N bits, where N= rand(0 - WORDSIZE/2)
 */
static unsigned long randbits(int limit)
{
	unsigned int num = rnd() % (limit / 2);
	unsigned int i;
	unsigned long r = 0;

	for (i = 0; i < num; i++)
		r |= (1UL << (rnd() % (limit - 1)));

	return r;
}

/*
 * Pick 1 random byte, and repeat it through a long.
 */
static unsigned long rept_byte(void)
{
	unsigned long r = RAND_BYTE();

	r = (r << 8) | r;
	r = (r << 16) | r;
#if WORD_BIT == 64
	r = (r << 32) | r;
#endif
	return r;
}

/*
 * Generate, and munge a 16bit number.
 */
unsigned short rand16(void)
{
	unsigned short r = 0, r2;

	switch (rnd() % 6) {
	case 0:	r = RAND_BYTE();
		break;

	case 1: r = rand_single_bit(16);
		break;
	case 2:	r = randbits(16);
		break;
	case 3: r = rnd();
		break;
	case 4:	r2 = rnd() & 0xff;
		r = r2 | r2 << 8;
		break;
	case 5: return 0 - ((rnd() % 10) + 1);
	}

	/* Sometimes flip sign */
	if (ONE_IN(25))
		r = ~r + 1;

	if (ONE_IN(25)) {
		int _div = 1 << RAND_RANGE(1, 4);	/* 2,4,8 or 16 */
		r /= _div;
	}

	if (RAND_BOOL()) {
		/* limit the size */
		switch (rnd() % 3) {
		case 0: r &= 0xff;
			break;
		case 1: r &= 0xfff;
			break;
		case 2: r &= PAGE_MASK;
			break;
		}
	}
	return r;
}

/*
 * Generate, and munge a 32bit number.
 */
unsigned int rand32(void)
{
	unsigned long r = 0;

	switch (rnd() % 8) {
	case 0:	r = RAND_BYTE();
		break;
	case 1:	r = rand16();
		break;
	case 2: r = rand_single_bit(32);
		break;
	case 3:	r = randbits(32);
		break;
	case 4: r = rnd();
		break;
	case 5:	r = rept_byte();
		break;

	case 6:	return get_interesting_value();

	case 7: return 0 - ((rnd() % 10) + 1);
	}

	/* Sometimes deduct it from INT_MAX */
	if (ONE_IN(25))
		r = INT_MAX - r;

	/* Sometimes flip sign */
	if (ONE_IN(25))
		r = ~r + 1;

	/* we might get lucky if something is counting ints/longs etc. */
	if (ONE_IN(25)) {
		int _div = 1 << RAND_RANGE(1, 4);	/* 2,4,8 or 16 */
		r /= _div;
	}

	if (RAND_BOOL()) {
		/* limit the size */
		switch (rnd() % 4) {
		case 0: r &= 0xff;
			break;
		case 1: r &= 0xffff;
			break;
		case 2: r &= PAGE_MASK;
			break;
		case 3: r &= 0xffffff;
			break;
		}
	}

	return r;
}

/*
 * Generate and munge a 64bit number.
 */
u64 rand64(void)
{
	u64 r = 0;

	switch (rnd() % 9) {

	/* 8-bit ranges */
	case 0:	r = RAND_BYTE();
		break;

	/* 16-bit ranges */
	case 1:	r = rand16();
		break;

	/* 32-bit ranges. */
	case 2:	r = rand32();
		break;

	/* 33:64-bit ranges. */
	case 3:	r = rand_single_bit(64);
		break;
	case 4:	r = randbits(64);
		break;
	case 5:	r = (u64) rnd() << 32 | rnd();
		break;
	case 6:	r = rept_byte();
		break;

	/* Sometimes pick a not-so-random number. */
	case 7:	return get_interesting_value();

	// small 64bit negative number.
	case 8: return 0 - ((rnd() % 10) + 1);
	}

	/* limit the size */
	switch (rnd() % 4) {
	case 0: r &= 0x000000ffffffffffULL;
		break;
	case 1: r &= 0x0000ffffffffffffULL;
		break;
	case 2: r &= 0x00ffffffffffffffULL;
		break;
	default: /* no limiting. */
		break;
	}

	/* Sometimes invert the generated number. */
	if (ONE_IN(25))
		r = ~r;

	/* increase distribution in MSB */
	if (ONE_IN(10)) {
		unsigned int i;
		unsigned int rounds;

		rounds = rnd() % 4;
		for (i = 0; i < rounds; i++)
			r |= (1UL << ((WORD_BIT - 1) - (rnd() % 8)));
	}

	/* Sometimes flip sign */
	if (ONE_IN(25))
		r = ~r + 1;

	return r;
}
