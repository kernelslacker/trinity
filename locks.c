#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#include "locks.h"

void lock(lock_t *_lock)
{
	while (_lock->lock == LOCKED) {
		_lock->contention++;
		usleep(1);
	}

	_lock->contention = 0;
	_lock->owner = getpid();
	_lock->lock = LOCKED;
}

void unlock(lock_t *_lock)
{
	asm volatile("" ::: "memory");
	_lock->contention = 0;
	_lock->owner = 0;
	_lock->lock = UNLOCKED;
}
