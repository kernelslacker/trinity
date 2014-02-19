#pragma once

#include <types.h>

#define MB (1024 * 1024UL)
#define GB (1024 * MB)

void * alloc_shared(unsigned int size);
void * zmalloc(size_t size);

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define max(x, y) ((x) >= (y) ? (x) : (y))
#define min(x, y) ((x) <= (y) ? (x) : (y))

#ifndef offsetof
# define offsetof(type, member)	((size_t) &((type *) 0)->member)
#endif

#define MAX_ERRNO 4095
#define IS_ERR_VALUE(x) ((x) >= (unsigned long)-MAX_ERRNO)
static inline long IS_ERR(unsigned long x)
{
	return IS_ERR_VALUE(x);
}

void sizeunit(unsigned long size, char *buf);
