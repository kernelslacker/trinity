#pragma once

#include <sys/types.h>

struct lock_struct {
	volatile unsigned char lock;
	pid_t owner;
	unsigned long contention;
};

typedef struct lock_struct lock_t;

#define UNLOCKED 0
#define LOCKED 1

void lock(lock_t *_lock);
void unlock(lock_t *_lock);

void check_all_locks(void);

void bust_lock(lock_t *_lock);
