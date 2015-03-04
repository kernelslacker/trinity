#include <stdio.h>
#include <stdlib.h>
#include "arch.h"
#include "random.h"
#include "sanitise.h"

static unsigned int plus_minus_two(unsigned int num)
{
	/* Now munge it for off-by-ones. */
	switch (rand() % 4) {
	case 0:	num -= 2;
		break;
	case 1:	num -= 1;
		break;
	case 2:	num += 1;
		break;
	case 3:	num += 2;
		break;
	}
	return num;
}

static unsigned char get_interesting_8bit_value(void)
{
	switch (rand() % 5) {
	case 0: return 1;					// one
	case 1: return 0xff;				// max
	case 2: return 1UL << (rand() & 7);	// 2^n (1 -> 128)
	case 3: return rand() & 0xff;		// 0 -> 0xff
	default: return 0;					// zero
	}
}

static int get_interesting_16bit_value(void)
{
	int num = 0;

	switch (rand() % 8) {
	case 0:	num = 0;
		break;
	case 1:	num = get_interesting_8bit_value();
		break;
	case 2:	num = -32768;
		break;
	case 3:	num = -129;
		break;
	case 4:	num = 255;
		break;
	case 5:	num = 32767;
		break;
	case 6:	num = 1UL << (rand() % 15);
		break;
	case 7:	num = rand() % 0xffff;
		break;
	}

	return num;
}

unsigned int get_interesting_32bit_value(void)
{
	unsigned int num = 0;

	switch (rand() % 11) {
	case 0:	num = 0;
		break;

	case 1:	num = get_interesting_8bit_value();
		break;

	case 2:	num = get_interesting_16bit_value();
		break;

	case 3:	num = 1UL << (rand() % 32);	// set a single bit.
		break;
	case 4:	num = 0x8fffffff;
		break;
	case 5:	num = 0xff;
		num = num << (rand() % 31);
		break;
	case 6: num = 0xffff0000;
		break;
	case 7: num = 0xffffe000;
		break;
	case 8: num = 0xffffff00 | (rand() % 256);
		break;
	case 9: num = 0xffffffff - page_size;
		break;
	case 10: num = 0xffffffff;
		break;
	}

	num = rand() & 0xf ? num : plus_minus_two(num);	// 1 in 16 call plus_minus_two

	return num;
}

#if __WORDSIZE != 32
static unsigned long per_arch_interesting_addr(unsigned long low)
{
	int i = 0;

#if defined(__x86_64__)
	i = rand() % 4;

	switch (i) {
	case 0: return 0x00007fffffffffffUL;			// x86-64 canonical addr end.
	case 1: return 0x0000800000000000UL;			// First x86-64 non-canonical addr
	case 2: return 0xffff800000000000UL | (low << 4);		// x86-64 canonical addr range 2 begin
	case 3: return VDSO_ADDR | (low & 0x0fffff);
	}
#endif

	// FIXME: Add more arch specific addresses here.

	return i | low;
}
#endif	/* __WORDSIZE */

unsigned long get_interesting_value(void)
{
#if __WORDSIZE == 32
	return get_interesting_32bit_value();
#else
	unsigned long low = 0;

	if (rand_bool())
		low = get_interesting_32bit_value();

	switch (rand() % 13) {
	case 0: return 0;
	case 1: return low;
	case 2: return 0x0000000100000000UL | low;
	case 3: return 0x7fffffff00000000UL | low;
	case 4: return 0x8000000000000000UL | low;
	case 5: return 0xffffffff00000000UL | low;
	case 6: return 0xffffffffffffff00UL | (rand() % 256);
	case 7: return 0xffffffffffffffffUL - page_size;
	case 8: return PAGE_OFFSET | (low << 4);
	case 9: return KERNEL_ADDR | (low & 0xffffff);
	case 10: return MODULE_ADDR | (low & 0xffffff);
	case 11: return per_arch_interesting_addr(low);
	case 12: return (low << 32);
	}

	return low;	// unreachable, but gcc is dumb.
#endif	/* __WORDSIZE */
}
