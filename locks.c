#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#include "debug.h"
#include "exit.h"
#include "locks.h"
#include "pids.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/*
 * Check that the processes holding locks are still alive.
 */
static bool check_lock(lock_t *lk)
{
	pid_t pid;

	if (lk == NULL)
		return false;

	/* We don't care about unlocked locks */
	if (__atomic_load_n(&lk->lock, __ATOMIC_RELAXED) != LOCKED)
		return false;

	/* First the easy case. If it's held by a dead pid, release it. */
	pid = __atomic_load_n(&lk->owner, __ATOMIC_ACQUIRE);

	/* unlock() clears owner before clearing lock. A child killed
	 * between those two stores leaves lock=LOCKED, owner=0 forever.
	 * Force-unlock it — if a live process really were mid-unlock,
	 * the window is nanoseconds and we only check from main's loop.
	 */
	if (pid == 0) {
		debugf("Found orphaned lock (owner=0). Freeing.\n");
		unlock(lk);
		return true;
	}

	if (pid_alive(pid) == false) {
		if (errno != ESRCH)
			return true;

		debugf("Found a lock held by dead pid %d. Freeing.\n", pid);
		unlock(lk);
		return true;
	}
	return false;
}

/* returns true if something is awry */
bool check_all_locks(void)
{
	unsigned int i;
	bool ret = false;

	check_lock(&shm->syscalltable_lock);

	if (children == NULL)
		return false;

	for_each_child(i)
		ret |= check_lock(&children[i]->syscall.lock);

	return ret;
}

static void __lock(lock_t *lk)
{
	__atomic_store_n(&lk->owner, getpid(), __ATOMIC_RELEASE);
}

bool trylock(lock_t *lk)
{
	unsigned char expected = UNLOCKED;

	if (__atomic_compare_exchange_n(&lk->lock, &expected, LOCKED,
					0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
		__lock(lk);
		return true;
	}
	return false;
}

void lock(lock_t *lk)
{
	pid_t pid = getpid();

	while (!trylock(lk)) {
		if (__atomic_load_n(&lk->owner, __ATOMIC_ACQUIRE) == pid) {
			debugf("lol, already have lock!\n");
			show_backtrace();
			panic(EXIT_LOCKING_CATASTROPHE);
			_exit(EXIT_LOCKING_CATASTROPHE);
		}

		/* This is pretty horrible. But if we call lock()
		 * from stuck_syscall_info(), and a child is hogging a lock
		 * (or worse, a dead child), we'll deadlock, because main won't
		 *  ever get back, and subsequently check_lock().
		 * So we add an extra explicit check here.
		 */
		if (pid == mainpid) {
			check_lock(lk);
		} else {
			/* Ok, we're a child pid. If we reached the limit, just exit */
			if (__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED) == EXIT_REACHED_COUNT)
				_exit(EXIT_SUCCESS);

			/* if something bad happened, like main crashed,
			 * we don't want to spin forever, so just get out.
			 */
			if (__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED) != STILL_RUNNING)
				_exit(__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED));

		}

		sched_yield();
	}
}

void unlock(lock_t *lk)
{
	__atomic_store_n(&lk->owner, 0, __ATOMIC_RELEASE);
	__atomic_store_n(&lk->lock, UNLOCKED, __ATOMIC_RELEASE);
}

/*
 * Release a lock we already hold.
 *
 * This function should be used sparingly. It's pretty much never something
 * that you'll need, just for rare occasions like when we return from a
 * signal handler with a lock held.
 */
void bust_lock(lock_t *lk)
{
	if (__atomic_load_n(&lk->lock, __ATOMIC_RELAXED) == UNLOCKED)
		return;
	if (getpid() != __atomic_load_n(&lk->owner, __ATOMIC_RELAXED))
		return;
	unlock(lk);
}
