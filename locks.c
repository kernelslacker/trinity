#include <unistd.h>
#include "locks.h"

void lock(lock_t *_lock)
{
	while (_lock->lock == LOCKED)
		usleep(1);

	_lock->lock = LOCKED;
	_lock->owner = getpid();
}

void unlock(lock_t *_lock)
{
	_lock->lock = UNLOCKED;
	_lock->owner = 0;
}
