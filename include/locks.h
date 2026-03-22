#pragma once

#include <sys/types.h>
#include "types.h"

struct lock_struct {
	unsigned char lock;
	pid_t owner;
};

typedef struct lock_struct lock_t;

#define UNLOCKED 0
#define LOCKED 1

bool trylock(lock_t *lk);
void lock(lock_t *lk);
void unlock(lock_t *lk);

bool check_all_locks(void);

void bust_lock(lock_t *lk);
