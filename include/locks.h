#pragma once

struct lock_struct {
	volatile unsigned char lock;
	pid_t owner;
};

typedef struct lock_struct lock_t;

#define UNLOCKED 0
#define LOCKED 1

void lock(lock_t *_lock);
void unlock(lock_t *_lock);
