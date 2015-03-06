#pragma once

#include "child.h"
#include "types.h"

#define ONE_IN(x)				((rand() % x) == 0)	// limit of RAND_MAX-1

extern unsigned int seed;
unsigned int init_seed(unsigned int seed);
void set_seed(struct childdata *child);
void reseed(void);
unsigned int new_seed(void);

void generate_rand_bytes(unsigned char *ptr, unsigned int len);
unsigned int rand_bool(void);
unsigned int rand32(void);
u64 rand64(void);
unsigned int rand_range(unsigned int min, unsigned int max);
unsigned long set_rand_bitmask(unsigned int num, const unsigned long *values);
