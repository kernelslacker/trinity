#include <signal.h>
#include <unistd.h>
#include "locks.h"
#include "log.h"
#include "pids.h"

#define STEAL_THRESHOLD 100000

void lock(lock_t *_lock)
{
	while (_lock->lock == LOCKED) {
		_lock->contention++;
		usleep(1);
		if (_lock->contention > STEAL_THRESHOLD) {
			pid_t pid = _lock->owner;

			if (pid_alive(pid) == FALSE) {
				output(0, "[%d] more than %d attempts to get lock. pid %d looks dead, stealing.\n",
					getpid(), STEAL_THRESHOLD, pid);
				goto steal;
			}
		}
	}

steal:
	_lock->contention = 0;
	_lock->lock = LOCKED;
	_lock->owner = getpid();
}

void unlock(lock_t *_lock)
{
	_lock->contention = 0;
	_lock->lock = UNLOCKED;
	_lock->owner = 0;
}
