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
	/* Set once per lock by the load-path scribble diagnostic so a
	 * persistently-corrupted word does not flood the log on every
	 * acquire.  Cleared by check_lock() after force_bust_lock()
	 * recovers the word, so a fresh scribble after recovery can log
	 * again. */
	bool dirty_logged;
};

typedef struct lock_struct lock_t;

#define UNLOCKED 0
#define LOCKED 1

#define LOCK_STATE(s)	((unsigned char) ((s) & 1))
#define LOCK_OWNER(s)	((pid_t) ((s) >> 32))
#define MAKE_LOCK(owner, state)	(((unsigned long)(owner) << 32) | ((state) & 1))

/* Reserved-bit payload (bits 1..31 of the lock word).  Non-zero means a
 * stray write -- typically a fuzzed syscall scribbling through aliased
 * shared memory -- has corrupted the lock word.  bit 0 (state) and bits
 * 32..63 (owner) carry no information once these bits are dirty: the
 * write that landed them likely smeared the whole 64-bit word. */
#define LOCK_RESERVED_DIRTY(s)	((((unsigned long)(s)) >> 1) & 0x7FFFFFFFUL)

bool trylock(lock_t *lk);
void lock(lock_t *lk);
void unlock(lock_t *lk);

bool check_all_locks(void);

void bust_lock(lock_t *lk);
void force_bust_lock(lock_t *lk);
