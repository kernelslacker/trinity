#pragma once

#include <stdlib.h>
#include "child.h"
#include "types.h"

int rnd(void);

#define ONE_IN(x)				((rnd() % x) == 0)	// limit of RAND_MAX-1

#if RAND_MAX == 0x7FFFFFFF
#define RAND_32()				rnd()
#define RAND_64()				(((0ULL | rnd()) << 33) | ((0ULL | rnd()) << 2) | (rnd() & 0x3))
#else
#error "Unexpected RAND_MAX value. Please add support."
#endif

#define RAND_BOOL()				(rnd() & 1)
#define RAND_BYTE()				(rnd() & 0xff)
#define RAND_RANGE(min, max)	(min + rnd() / (RAND_MAX / (max - min + 1) + 1))

extern unsigned int seed;
unsigned int init_seed(unsigned int seed);
void set_seed(struct childdata *child);
void reseed(void);
unsigned int new_seed(void);

bool init_random(void);
void generate_rand_bytes(unsigned char *ptr, unsigned int len);
unsigned int rand32(void);
u64 rand64(void);
unsigned long rand_single_bit(unsigned char size);
unsigned long set_rand_bitmask(unsigned int num, const unsigned long *values);
