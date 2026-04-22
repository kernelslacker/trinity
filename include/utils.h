#pragma once

#include <sys/types.h>
#include <sys/mman.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define MB(_x) ((_x) * 1024UL * 1024UL)
#define GB(_x) ((_x) * 1024UL * MB(1))

void * alloc_shared(unsigned int size);
void * alloc_shared_global(unsigned int size);
void * alloc_shared_obj(size_t size);
void free_shared_obj(void *p, size_t size);
void * alloc_shared_str(size_t size);
char * alloc_shared_strdup(const char *src);
void free_shared_str(void *p, size_t size);
void freeze_global_objects(void);
void thaw_global_objects(void);
bool globals_are_protected(void);
bool range_overlaps_shared(unsigned long addr, unsigned long len);
void dump_obj_heap_stats(void);

void * __zmalloc(size_t size, const char *func);
#define zmalloc(size)	__zmalloc(size, __func__)

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define min(x, y) ({				\
	typeof(x) _min1 = (x);			\
	typeof(y) _min2 = (y);			\
	(void) (&_min1 == &_min2);		\
	_min1 < _min2 ? _min1 : _min2; })

#define max(x, y) ({				\
	typeof(x) _max1 = (x);			\
	typeof(y) _max2 = (y);			\
	(void) (&_max1 == &_max2);		\
	_max1 > _max2 ? _max1 : _max2; })

#ifndef offsetof
# define offsetof(type, member)	((size_t) &((type *) 0)->member)
#endif

#define container_of(ptr, type, member) ({                      \
	const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
	(type *)( (char *)__mptr - offsetof(type,member) );})

/*
 * swap - swap value of @a and @b
 */
#define swap(a, b) \
	do { typeof(a) __tmp = (a); (a) = (b); (b) = __tmp; } while (0)

#define MAX_ERRNO 4095
#define IS_ERR_VALUE(x) ((x) >= (unsigned long)-MAX_ERRNO)
static inline long IS_ERR(unsigned long x)
{
	return IS_ERR_VALUE(x);
}

void sizeunit(unsigned long size, char *buf, size_t buflen);

void kill_pid(pid_t pid);

void freeptr(unsigned long *p);

int get_num_fds(void);

#define __stringify_1(x...)     #x
#define __stringify(x...)       __stringify_1(x)

#define unreachable() __builtin_unreachable()

#define RAND_ELEMENT(_array, _element) \
	_array[rand() % ARRAY_SIZE(_array)]._element

#define RAND_ARRAY(_array) _array[rand() % ARRAY_SIZE(_array)]

#define IS_ALIGNED(x, a)	(((x) & ((typeof(x))(a) - 1)) == 0)
