#include <unistd.h>
#include "locks.h"

void lock(lock_t *_lock)
{
	while (*_lock == LOCKED)
		usleep(1);

	*_lock = LOCKED;
}

void unlock(lock_t *_lock)
{
	*_lock = UNLOCKED;
}
