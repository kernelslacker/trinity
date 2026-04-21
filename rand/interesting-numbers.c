#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <stdint.h>
#include "arch.h"
#include "random.h"
#include "sanitise.h"

/*
 * Boundary values that tend to trigger off-by-one errors, integer overflows,
 * and sign-extension bugs in kernel code.  These values find a
 * disproportionate number of bugs compared to purely random input.
 */
static const unsigned long boundary_values[] = {
	0,
	1,
	2,
	4,
	8,
	16,
	32,
	64,
	100,				/* round decimal (buffer/loop count) */
	128,
	256,
	512,
	1000,				/* round decimal (buffer/loop count) */
	1024,
	4095,				/* page_size - 1 */
	4096,				/* common page_size */
	4097,				/* page_size + 1 */
	32768,				/* INT16_MAX + 1: wrong sign as i16 */
	65535,				/* USHRT_MAX */
	65536,				/* USHRT_MAX + 1 */
	0x7ffffffe,			/* INT_MAX - 1 */
	0x7fffffff,			/* INT_MAX */
	0x80000000,			/* INT_MIN (as unsigned) */
	0x80000001,			/* INT_MIN + 1 */
	0xfffffffe,			/* UINT_MAX - 1 */
	0x200000,			/* 2MB hugepage size */
	0x40000000,			/* 1GB hugepage size */
	0xffffffff,			/* UINT_MAX */
#if WORD_BIT == 64
	0x100000000UL,			/* UINT_MAX + 1 */
	0x7ffffffffffffffeUL,		/* LONG_MAX - 1 */
	0x7fffffffffffffffUL,		/* LONG_MAX */
	0x8000000000000000UL,		/* LONG_MIN (as unsigned) */
	0x8000000000000001UL,		/* LONG_MIN + 1 */
	0xfffffffffffffffeUL,		/* ULONG_MAX - 1 */
	(unsigned long) -32769,		/* INT16_MIN - 1: overflows i16 */
	(unsigned long) -129,		/* INT8_MIN - 1: overflows i8 */
	0xffffffffffffffffUL,		/* ULONG_MAX */
#endif
};

#define NR_BOUNDARY_VALUES (sizeof(boundary_values) / sizeof(boundary_values[0]))

unsigned long get_boundary_value(void)
{
	return boundary_values[rand() % NR_BOUNDARY_VALUES];
}

/*
 * Boundary values divided by common struct sizes, targeting integer
 * overflow in kernel allocation-size calculations (count * sizeof).
 * The kernel frequently does: kmalloc(count * sizeof(struct foo))
 * and if count is close to SIZE_MAX/sizeof, the multiplication wraps.
 */
static const unsigned int common_struct_sizes[] = {
	4, 8, 12, 16, 20, 24, 32, 48, 64, 128, 256, 512, 1024, 4096,
};

#define NR_STRUCT_SIZES (sizeof(common_struct_sizes) / sizeof(common_struct_sizes[0]))

unsigned long get_sizeof_boundary_value(void)
{
	static const unsigned long overflow_bases[] = {
		0x7fffffff,				/* INT_MAX */
		0x80000000,				/* INT_MIN (unsigned) */
		0xffffffff,				/* UINT_MAX */
#if WORD_BIT == 64
		0x7fffffffffffffffUL,			/* LONG_MAX */
		0x8000000000000000UL,			/* LONG_MIN (unsigned) */
		0xffffffffffffffffUL,			/* ULONG_MAX */
#endif
	};
	#define NR_OVERFLOW_BASES (sizeof(overflow_bases) / sizeof(overflow_bases[0]))

	unsigned long base = overflow_bases[rand() % NR_OVERFLOW_BASES];
	unsigned int sz = common_struct_sizes[rand() % NR_STRUCT_SIZES];
	unsigned long val = base / sz;

	/* Occasionally add +/-1 to probe the exact overflow boundary */
	switch (rand() % 3) {
	case 0: break;
	case 1: val++; break;
	case 2: val--; break;
	}

	return val;
}

#define ARITH_MAX 128

static unsigned int plus_minus_arith(unsigned int num)
{
	/* Arithmetic delta: +/- 1..ARITH_MAX. */
	unsigned int delta = (rand() % ARITH_MAX) + 1;

	if (RAND_BOOL())
		num += delta;
	else
		num -= delta;
	return num;
}

static unsigned char get_interesting_8bit_value(void)
{
	switch (rand() % 5) {
	case 0: return 1;					// one
	case 1: return 0xff;				// max
	case 2: return 1UL << (rand() & 7);	// 2^n (1 -> 128)
	case 3: return RAND_BYTE();			// 0 -> 0xff
	default: return 0;					// zero
	}
}

static unsigned short get_interesting_16bit_value(void)
{
	switch (rand() % 4) {
	case 0: return 0x8000 >> (rand() & 7);		// 2^n (0x100 -> 0x8000)
	case 1: return rand() & 0xffff;				// 0 -> 0xffff
	case 2: return 0xff00 | RAND_BYTE();		// 0xff00 -> 0xffff
	default: return 0xffff;						// max
	}
}

unsigned int get_interesting_32bit_value(void)
{
	switch (rand() % 13) {
	case 0: return 0x80000000 >> (rand() & 0x1f);	// 2^n (1 -> 0x80000000)
	case 1: return rand32();						// 0 -> 0xffffffff
	case 2: return (unsigned int) 0xff << (4 * (rand() % 7));
	case 3: return 0xffff0000;
	case 4: return 0xffffe000;
	case 5: return 0xffffff00 | RAND_BYTE();
	case 6: return 0xffffffff - page_size;
	case 7: return page_size;
	case 8: return page_size * ((rand() % (0xffffffff/page_size)) + 1);
	case 9: return page_size - 1;					// PAGE_SIZE - 1: last byte before boundary
	case 10: return page_size + 1;					// PAGE_SIZE + 1: one past boundary
	case 11: return page_size * 2 - 1;				// PAGE_SIZE*2 - 1: straddles two pages
	default: return 0xffffffff;						// max
	}
}

#if WORD_BIT != 32
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
#elif defined(__aarch64__)
	i = rand() % 4;

	switch (i) {
	case 0: return MODULE_ADDR | (low & 0x03ffffff);		// module region
	case 1: return 0xffffffbfc0000000UL | (low & 0x3fffffff);	// vmalloc region
	case 2: return KERNEL_ADDR | (low & 0x0fffff);			// kernel text
	case 3: return 0xffffff8000000000UL | (low & 0x3fffffff);	// KASAN shadow region
	}
#elif defined(__powerpc64__)
	i = rand() % 4;

	switch (i) {
	case 0: return MODULE_ADDR | (low & 0x0fffffff);		// module region
	case 1: return 0xd000100000000000UL | (low & 0x0fffffffffff);	// vmalloc region
	case 2: return KERNEL_ADDR | (low & 0x0fffff);			// kernel text
	case 3: return 0xc00000003fff0000UL | (low & 0xffff);		// SLB/bolted region end
	}
#elif defined(__s390x__)
	i = rand() % 3;

	switch (i) {
	case 0: return MODULE_ADDR | (low & 0x7fffffff);		// module region
	case 1: return 0x0000000000100000UL | (low & 0x0fffff);	// kernel text
	case 2: return 0x0000020000000000UL | (low & 0x3fffffff);	// vmemmap region
	}
#endif

	return i | low;
}
#endif	/* WORD_BIT */

unsigned long get_interesting_value(void)
{
	unsigned long low = 0;

	switch (rand() % 3) {
	case 0:	low = get_interesting_8bit_value();
		break;
	case 1:	low = get_interesting_16bit_value();
		break;
	case 2: low = get_interesting_32bit_value();
		break;
	}

	low = (rand() & 0xf) ? low : plus_minus_arith(low);	// 1 in 16 call plus_minus_arith
#if WORD_BIT != 32

	if (ONE_IN(4)) {
		switch (rand() % 14) {
		case 0: return 0x0000000100000000UL | low;
		case 1: return 0x7fffffff00000000UL | low;
		case 2: return 0x8000000000000000UL | low;
		case 3: return 0xffffffff00000000UL | low;
		case 4: return 0xffffffffffffff00UL | RAND_BYTE();
		case 5: return 0xffffffffffffffffUL - page_size;
		case 6: return PAGE_OFFSET | (low << 4);
		case 7: return KERNEL_ADDR | (low & 0xffffff);
		case 8: return MODULE_ADDR | (low & 0xffffff);
		case 9: return per_arch_interesting_addr(low);
		case 10: return (low << 32);
		case 11: return SIZE_MAX - page_size + 1;	/* last allocation that crosses no page boundary */
		case 12: return SIZE_MAX & ~((unsigned long)page_size - 1);	/* page-aligned near SIZE_MAX */
		case 13: return (unsigned long)page_size * 2 - 1;		/* straddles two pages as size_t */
		}
	}

#endif	/* WORD_BIT */
	return low;
}
