#pragma once

#include <stdlib.h>
#include "child.h"
#include "types.h"

#define ONE_IN(x)				((rand() % x) == 0)	// limit of RAND_MAX-1

#if RAND_MAX == 0x7FFFFFFF
#define RAND_32()				((rand() << 1) | (rand() & 1))
#define RAND_64()				(((0ULL | rand()) << 33) | ((0ULL | rand()) << 2) | (rand() & 0x3))
#else
#error "Unexpected RAND_MAX value. Please add support."
#endif

#define RAND_BOOL()				(rand() & 1)
#define RAND_BYTE()				(rand() & 0xff)

extern unsigned int seed;
unsigned int init_seed(unsigned int seed);
void set_seed(struct childdata *child);
void reseed(void);
unsigned int new_seed(void);

void generate_rand_bytes(unsigned char *ptr, unsigned int len);
unsigned int rand32(void);
u64 rand64(void);
unsigned int rand_range(unsigned int min, unsigned int max);
unsigned long rand_single_bit(unsigned char size);
unsigned long set_rand_bitmask(unsigned int num, const unsigned long *values);
