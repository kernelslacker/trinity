#include <unistd.h>
#include "locks.h"

void acquire(lock_t *lock)
{
	while (*lock != LOCKED)
		sleep(0.1);

	*lock = LOCKED;
}

void release(lock_t *lock)
{
	*lock = UNLOCKED;
}
