#pragma once

#include <sys/types.h>
#include "types.h"

struct lock_struct {
	volatile unsigned char lock;
	pid_t owner;
};

typedef struct lock_struct lock_t;

#define UNLOCKED 0
#define LOCKING 1
#define LOCKED 2

bool trylock(lock_t *_lock);
void lock(lock_t *_lock);
void unlock(lock_t *_lock);

bool check_all_locks(void);

void bust_lock(lock_t *_lock);
