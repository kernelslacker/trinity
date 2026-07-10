#pragma once

#include <stddef.h>

#include "compiler.h"
#include "rnd.h"

#define MB(_x) ((_x) * 1024UL * 1024UL)
#define GB(_x) ((_x) * 1024UL * MB(1))

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

#define __stringify_1(x...)     #x
#define __stringify(x...)       __stringify_1(x)

#define unreachable() __builtin_unreachable()

#define likely(x)	__builtin_expect(!!(x), 1)
#define unlikely(x)	__builtin_expect(!!(x), 0)

#define RAND_ELEMENT(_array, _element) \
	_array[rnd_modulo_u32(ARRAY_SIZE(_array))]._element

#define RAND_ARRAY(_array) _array[rnd_modulo_u32(ARRAY_SIZE(_array))]

#define IS_ALIGNED(x, a)	(((x) & ((typeof(x))(a) - 1)) == 0)
