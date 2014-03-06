#include <unistd.h>
#include "locks.h"

void lock(lock_t *lock)
{
	while (*lock == LOCKED)
		usleep(1);

	*lock = LOCKED;
}

void unlock(lock_t *lock)
{
	*lock = UNLOCKED;
}
