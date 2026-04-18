#pragma once

#include <sys/types.h>
#include "types.h"

/*
 * Combined lock state and owner pid in a single 64-bit word so that
 * the lock can be acquired/released atomically. A torn unlock (e.g.
 * SIGABRT firing between two stores) used to leave lock=LOCKED with
 * owner=0, deadlocking every waiter. Packing eliminates that.
 *
 * Bit layout:
 *   bit 0:      lock state (0 = UNLOCKED, 1 = LOCKED)
 *   bits 1-31:  reserved (zero)
 *   bits 32-63: owner pid
 */
struct lock_struct {
	unsigned long state;
};

typedef struct lock_struct lock_t;

#define UNLOCKED 0
#define LOCKED 1

#define LOCK_STATE(s)	((unsigned char) ((s) & 1))
#define LOCK_OWNER(s)	((pid_t) ((s) >> 32))
#define MAKE_LOCK(owner, state)	(((unsigned long)(owner) << 32) | ((state) & 1))

bool trylock(lock_t *lk);
void lock(lock_t *lk);
void unlock(lock_t *lk);

bool check_all_locks(void);

void bust_lock(lock_t *lk);
