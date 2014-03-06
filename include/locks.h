#pragma once

typedef volatile unsigned char lock_t;

#define UNLOCKED 0
#define LOCKED 1

void lock(lock_t *lock);
void unlock(lock_t *lock);
