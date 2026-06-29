#pragma once

#include "child.h"
#include "rnd.h"
#include "types.h"

#define ONE_IN(x)		((x) > 0 && rnd_modulo_u32(x) == 0)

#define RAND_BOOL()		(rnd_u32() & 1)
#define RAND_BYTE()		(rnd_u32() & 0xff)
/* Span is computed in 32 bits; use RAND_RANGE64 when (max - min) > UINT32_MAX. */
#define RAND_RANGE(min, max)	((min) <= (max) \
	? (min) + (typeof(min))rnd_modulo_u32((max) - (min) + 1) \
	: (max) + (typeof(max))rnd_modulo_u32((min) - (max) + 1))

/*
 * 64-bit-span variant of RAND_RANGE: use when (max - min) can exceed
 * UINT32_MAX.  RAND_RANGE computes its span with rnd_modulo_u32 and
 * would truncate a 64-bit span to 32 bits.
 */
#define RAND_RANGE64(min, max)	((min) <= (max) \
	? (min) + (typeof(min))rnd_modulo_u64((max) - (min) + 1) \
	: (max) + (typeof(max))rnd_modulo_u64((min) - (max) + 1))

/*
 * Edge-value injection.  A childop that picks a numeric arg from random
 * can wrap it in RAND_NEGATIVE_OR(...) to get its computed default value
 * most of the time, but with probability 1/RAND_NEGATIVE_RATIO substitute
 * one curated boundary value (0, -1, INT_MAX, LONG_MIN, page_size +/- 1,
 * etc.) instead.  Use only for args whose value is passed to the kernel
 * where bounds-checking matters; do not use for in-process indices into
 * trinity-owned arrays where a negative would just walk our own memory.
 *
 * The 1-in-50 default is deliberately low: higher rates produce noise
 * without finding new bugs once a kernel path's bounds-check has been
 * exercised once.
 */
#define RAND_NEGATIVE_RATIO	50

long get_negative_edge_value(void);

#define RAND_NEGATIVE_OR(default_val) \
	(rnd_modulo_u32(RAND_NEGATIVE_RATIO) == 0 \
	 ? get_negative_edge_value() \
	 : (long)(default_val))

extern unsigned int seed;
unsigned int init_seed(unsigned int seed);
void set_seed(struct childdata *child);
void reseed(void);

void generate_rand_bytes(unsigned char *ptr, unsigned int len);
void generate_random_page(char *page);
unsigned short rand16(void);
unsigned int rand32(void);
u64 rand64(void);
unsigned long rand_single_bit(unsigned char size);
unsigned long set_rand_bitmask(unsigned int num, const unsigned long *values);
