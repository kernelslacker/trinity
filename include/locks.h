#pragma once

typedef volatile unsigned char lock_t;

#define UNLOCKED 0
#define LOCKED 1

void acquire(lock_t *lock);
void release(lock_t *lock);
