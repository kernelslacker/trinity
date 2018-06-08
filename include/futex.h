#pragma once

#include <sys/types.h>
#include <stdint.h>
#include "types.h"

struct __lock {
	uint32_t futex;
	pid_t owner_pid;
};

void create_futexes(void);
u32 * get_futex(void);
struct __lock * get_random_lock(void);
