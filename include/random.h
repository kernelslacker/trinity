#pragma once

#include <stdlib.h>
#include "child.h"
#include "types.h"

#define ONE_IN(x)		((x) > 0 && (rand() % (x)) == 0)

#define RAND_BOOL()		(rand() & 1)
#define RAND_BYTE()		(rand() & 0xff)
#define RAND_RANGE(min, max)	((min) <= (max) \
	? (min) + rand() / (RAND_MAX / ((max) - (min) + 1) + 1) \
	: (max) + rand() / (RAND_MAX / ((min) - (max) + 1) + 1))

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
	((rand() % RAND_NEGATIVE_RATIO == 0) \
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
