#pragma once

#include <sys/types.h>
#include <stdint.h>
#include "compiler.h"
#include "types.h"

struct __lock {
	uint32_t futex;
	pid_t owner_pid;
};

void create_futexes(void);
void init_child_futexes(void);
struct __lock * get_random_lock(void) __must_check;

/*
 * Pick a random futex word from the shared cross-child pool
 * (OBJ_GLOBAL / OBJ_FUTEX_SHARED).  The obj wrappers live in private
 * heap; the returned pointer addresses a 32-bit slot in a separate
 * alloc_shared() mapping, so concurrent waiters from different children
 * operate on the SAME virtual address and exercise the kernel's
 * cross-task futex hash lookup paths.  Returns NULL when the pool is
 * empty or the lockless reader's retry budget is exhausted by
 * concurrent destroys; callers must handle that.
 */
uint32_t * get_shared_futex_word(void);
