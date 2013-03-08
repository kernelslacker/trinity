#ifndef _TRINITY_H
#define _TRINITY_H 1

#include "types.h"

#define UNLOCKED 0
#define LOCKED 1

#define __unused__ __attribute((unused))

extern char *progname;

void * alloc_shared(unsigned int size);

void do_main_loop(void);

extern unsigned int page_size;

extern bool biarch;

extern bool ignore_tainted;
int check_tainted(void);

void init_watchdog(void);

extern unsigned int user_specified_children;

#define UNUSED(x) (void)(x)

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define max(x, y) ((x) >= (y) ? (x) : (y))
#define min(x, y) ((x) <= (y) ? (x) : (y))

#endif	/* _TRINITY_H */
