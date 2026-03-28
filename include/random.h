#pragma once

#include <stdlib.h>
#include "child.h"
#include "types.h"

#define ONE_IN(x)		((x) > 0 && (rand() % (x)) == 0)

#define RAND_BOOL()		(rand() & 1)
#define RAND_BYTE()		(rand() & 0xff)
#define RAND_RANGE(min, max)	((min) + rand() / (RAND_MAX / ((max) - (min) + 1) + 1))

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
