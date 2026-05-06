#pragma once

#include <sys/types.h>
#include <stdint.h>
#include "types.h"

struct __lock {
	uint32_t futex;
	pid_t owner_pid;
};

void create_futexes(void);
void init_child_futexes(void);
u32 * get_futex(void);
struct __lock * get_random_lock(void);

/*
 * Pick a random futex word from the shared cross-child pool
 * (OBJ_GLOBAL / OBJ_FUTEX_SHARED).  The returned pointer addresses a
 * 32-bit slot in the shared obj heap, so concurrent waiters from
 * different children operate on the SAME virtual address and exercise
 * the kernel's cross-task futex hash lookup paths.  Returns NULL when
 * the pool is empty or the lockless reader's retry budget is exhausted
 * by concurrent destroys; callers must handle that.
 */
uint32_t * get_shared_futex_word(void);
