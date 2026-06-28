/*
 * Routines to get randomness.
 */
#include <limits.h>
#include "arch.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"	// interesting_numbers
#include "types.h"

/*
 * OR a random number of bits into a mask.
 * Used by ARG_LIST generation, and get_o_flags()
 */
unsigned long set_rand_bitmask(unsigned int num, const unsigned long *values)
{
	unsigned long i;
	unsigned long mask = 0;
	unsigned int bits;

	if (num == 0)
		return 0;

	bits = rnd_modulo_u32(num + 1);
	/* Always set at least one bit. Returning a zero mask means
	 * many flag-style ioctls (e.g. UFFDIO_REGISTER) get rejected
	 * with EINVAL, wasting a syscall. */
	if (bits == 0)
		bits = 1;

	for (i = 0; i < bits; i++)
		mask |= values[rnd_modulo_u32(num)];

	return mask;
}

/*
 * Pick a random power of two between 2^0 and 2^(WORD_BIT-1)
 */
unsigned long rand_single_bit(unsigned char size)
{
	if (size > WORD_BIT)
		size = WORD_BIT;

	return (1UL << rnd_modulo_u32(size));
}

/*
 * set N bits, where N is in the range [0, limit/2].
 */
static unsigned long randbits(int limit)
{
	unsigned int num = rnd_modulo_u32(limit / 2 + 1);
	unsigned int i;
	unsigned long r = 0;

	for (i = 0; i < num; i++)
		r |= (1UL << rnd_modulo_u32(limit));

	return r;
}

/*
 * u64-strict sibling of rand_single_bit().  Shifts a 1ULL so the
 * result distributes across all 64 bits regardless of host word
 * size; rand_single_bit() clamps to WORD_BIT and on a 32-bit host
 * can never set a bit above position 31.
 */
static u64 rand_single_bit64(unsigned char size)
{
	if (size > 64)
		size = 64;

	return (1ULL << rnd_modulo_u32(size));
}

/*
 * u64-strict sibling of randbits().  Uses a 64-bit accumulator and
 * 1ULL shifts so that `limit` values up to 64 are well-defined on
 * 32-bit hosts; randbits(64) would shift an unsigned long by 32..63,
 * which is undefined behaviour when unsigned long is 32 bits wide.
 */
static u64 randbits64(int limit)
{
	unsigned int num = rnd_modulo_u32(limit / 2 + 1);
	unsigned int i;
	u64 r = 0;

	for (i = 0; i < num; i++)
		r |= (1ULL << rnd_modulo_u32(limit));

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

	switch (rnd_modulo_u32(6)) {
	case 0:	r = RAND_BYTE();
		break;

	case 1: r = rand_single_bit(16);
		break;
	case 2:	r = randbits(16);
		break;
	case 3: r = rnd_u32();
		break;
	case 4:	r2 = rnd_u32() & 0xff;
		r = r2 | r2 << 8;
		break;
	case 5: return 0 - (rnd_modulo_u32(10) + 1);
	}

	/*
	 * Two independent post-mix 1/25 gates folded onto a single
	 * rnd_u32() draw, tested against disjoint 8-bit slices.  Each
	 * slice gives 11/256 (~4.30%) outcomes vs the exact 1/25 = 4%
	 * the bounded helper would produce -- ~0.3pp absolute bias,
	 * acceptable for a fuzz-flavour gate.
	 */
	unsigned int munge_roll = rnd_u32();

	/* Sometimes flip sign */
	if ((munge_roll & 0xff) % 25 == 0)
		r = ~r + 1;

	if (((munge_roll >> 8) & 0xff) % 25 == 0) {
		int divisor = 1 << RAND_RANGE(1, 4);	/* 2,4,8 or 16 */
		r /= divisor;
	}

	if (RAND_BOOL()) {
		/* limit the size */
		switch (rnd_modulo_u32(3)) {
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
	unsigned int r = 0;

	switch (rnd_modulo_u32(8)) {
	case 0:	r = RAND_BYTE();
		break;
	case 1:	r = rand16();
		break;
	case 2: r = rand_single_bit(32);
		break;
	case 3:	r = randbits(32);
		break;
	case 4: r = rnd_u32();
		break;
	case 5:	r = rept_byte();
		break;

	case 6:	return get_interesting_32bit_value();

	case 7: return 0 - (rnd_modulo_u32(10) + 1);
	}

	/*
	 * Three independent post-mix 1/25 gates folded onto a single
	 * rnd_u32() draw, tested against disjoint 8-bit slices.  Each
	 * slice gives 11/256 (~4.30%) outcomes vs the exact 1/25 = 4%
	 * the bounded helper would produce -- ~0.3pp absolute bias,
	 * acceptable for a fuzz-flavour gate.
	 */
	unsigned int munge_roll = rnd_u32();

	/* Sometimes deduct it from INT_MAX */
	if ((munge_roll & 0xff) % 25 == 0)
		r = INT_MAX - r;

	/* Sometimes flip sign */
	if (((munge_roll >> 8) & 0xff) % 25 == 0)
		r = ~r + 1;

	/* we might get lucky if something is counting ints/longs etc. */
	if (((munge_roll >> 16) & 0xff) % 25 == 0) {
		int divisor = 1 << RAND_RANGE(1, 4);	/* 2,4,8 or 16 */
		r /= divisor;
	}

	if (RAND_BOOL()) {
		/* limit the size */
		switch (rnd_modulo_u32(4)) {
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

	switch (rnd_modulo_u32(9)) {

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
	case 3:	r = rand_single_bit64(64);
		break;
	case 4:	r = randbits64(64);
		break;
	case 5:	/* Combine three draws with shifts and XOR to cover
		 * all 64 bits.  Originally compensated for libc rand()
		 * only giving 31 bits; kept as three draws after the
		 * mechanical conversion to rnd_u32() so the bit-mix
		 * structure is preserved. */
		r = ((u64) rnd_u32() << 33) ^ ((u64) rnd_u32() << 16) ^ (u64) rnd_u32();
		break;
	case 6:	r = rept_byte();
		break;

	/* Sometimes pick a not-so-random number. */
	case 7:	return get_interesting_value();

	// small 64bit negative number.
	case 8: return 0 - (rnd_modulo_u32(10) + 1);
	}

	/* limit the size */
	switch (rnd_modulo_u32(4)) {
	case 0: r &= 0x000000ffffffffffULL;
		break;
	case 1: r &= 0x0000ffffffffffffULL;
		break;
	case 2: r &= 0x00ffffffffffffffULL;
		break;
	default: /* no limiting. */
		break;
	}

	/*
	 * Two independent post-mix 1/25 gates folded onto a single
	 * rnd_u32() draw, tested against disjoint 8-bit slices.  Each
	 * slice gives 11/256 (~4.30%) outcomes vs the exact 1/25 = 4%
	 * the bounded helper would produce -- ~0.3pp absolute bias,
	 * acceptable for a fuzz-flavour gate.  The ONE_IN(10)
	 * MSB-distribution gate between the two stays on its own draw
	 * (different probability, different intent).
	 */
	unsigned int munge_roll = rnd_u32();

	/* Sometimes invert the generated number. */
	if ((munge_roll & 0xff) % 25 == 0)
		r = ~r;

	/* increase distribution in MSB */
	if (ONE_IN(10)) {
		unsigned int i;
		unsigned int rounds;

		rounds = rnd_modulo_u32(4);
		for (i = 0; i < rounds; i++)
			r |= (1ULL << (63 - rnd_modulo_u32(8)));
	}

	/* Sometimes flip sign */
	if (((munge_roll >> 8) & 0xff) % 25 == 0)
		r = ~r + 1;

	return r;
}
