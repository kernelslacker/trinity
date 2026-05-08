#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#include "cmp_hints.h"
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
	unsigned long s;
	pid_t pid;

	if (lk == NULL)
		return false;

	s = __atomic_load_n(&lk->state, __ATOMIC_ACQUIRE);

	/* We don't care about unlocked locks */
	if (LOCK_STATE(s) != LOCKED)
		return false;

	pid = LOCK_OWNER(s);

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

	/* Per-syscall cmp_hints pools each have their own lock_t.  These
	 * are acquired by children from generate-args.c during cmp-mode
	 * argument generation, so a SIGSEGV/SIGABRT mid-pool-update leaves
	 * the lock held by a dead child.  Without this scan, that lock has
	 * no reaper at all — child-side try_release_dead_holder is the only
	 * fallback, and it only fires after a million-spin starvation. */
	if (cmp_hints_shm != NULL) {
		for (i = 0; i < ARRAY_SIZE(cmp_hints_shm->pools); i++)
			ret |= check_lock(&cmp_hints_shm->pools[i].lock);
	}

	return ret;
}

bool trylock(lock_t *lk)
{
	unsigned long expected = 0;
	unsigned long desired = MAKE_LOCK(cached_pid, LOCKED);

	/* Single CAS sets both lock state AND owner atomically.
	 * No torn state possible — if we die after this, the lock
	 * appears fully held by us, and the next check_lock pass
	 * will recognize the dead pid and release it. */
	return __atomic_compare_exchange_n(&lk->state, &expected, desired,
					   0, __ATOMIC_ACQUIRE,
					   __ATOMIC_RELAXED);
}

/*
 * If a child held this lock and got killed (SIGABRT, SIGSEGV, etc.),
 * the lock is permanently held by a dead pid. Detect that case and
 * release. We need ABA protection: between sampling owner=A and
 * checking liveness, the lock could have been released and re-acquired
 * by a recycled pid. Compare the entire state word — if it's unchanged,
 * nothing happened in between, so it's safe to CAS the lock to 0.
 *
 * Use pid_alive() rather than a raw kill(pid, 0): a zombie holder still
 * has a task struct (kill returns 0) but cannot release the lock, so a
 * naive kill-only check leaves us spinning forever waiting for a corpse
 * that hasn't been reaped yet.
 */
static void try_release_dead_holder(lock_t *lk)
{
	unsigned long sampled = __atomic_load_n(&lk->state, __ATOMIC_ACQUIRE);
	pid_t owner = LOCK_OWNER(sampled);

	if (LOCK_STATE(sampled) != LOCKED || owner == 0)
		return;
	if (pid_alive(owner))
		return;

	/* Owner is dead. Try to release ONLY if nothing changed since
	 * we sampled — a CAS to 0 with the sampled state as expected. */
	__atomic_compare_exchange_n(&lk->state, &sampled, 0,
				    0, __ATOMIC_RELEASE, __ATOMIC_RELAXED);
}

void lock(lock_t *lk)
{
	pid_t pid = cached_pid;
	unsigned int spins = 0;

	while (!trylock(lk)) {
		unsigned long s = __atomic_load_n(&lk->state, __ATOMIC_ACQUIRE);

		if (LOCK_OWNER(s) == pid) {
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

			/* After spinning a long time, check if the holder
			 * died. Children can't rely on parent's check_lock()
			 * because the parent might be busy or stuck itself. */
			if (++spins > 1000000) {
				try_release_dead_holder(lk);
				spins = 0;
			}
		}

		sched_yield();
	}
}

void unlock(lock_t *lk)
{
	/* Single store clears both lock state and owner atomically.
	 * No torn unlock state possible. */
	__atomic_store_n(&lk->state, 0, __ATOMIC_RELEASE);
}

/*
 * Release a lock we already hold.
 *
 * This function should be used sparingly. It's pretty much never something
 * that you'll need, just for rare occasions like when we return from a
 * signal handler with a lock held.  The owner check below means cross-pid
 * recovery (parent freeing a dead child's lock) must use force_bust_lock().
 */
void bust_lock(lock_t *lk)
{
	unsigned long s = __atomic_load_n(&lk->state, __ATOMIC_RELAXED);

	if (LOCK_STATE(s) != LOCKED)
		return;
	if (LOCK_OWNER(s) != cached_pid)
		return;
	unlock(lk);
}

/*
 * Cross-pid orphan release. Parent calls this on a lock held by a dead
 * child after check_all_locks() has already exhausted its 10-iteration
 * reap loop. bust_lock() above can't do this — its LOCK_OWNER == cached_pid
 * gate rejects every parent-side release of a child-held lock, leaving the
 * post-cap fallback inert and the orphan sitting until check_lock()'s
 * pid_alive scan eventually self-heals it on the next pass.
 *
 * Confirm the holder is truly dead before clearing.  Releasing a lock owned
 * by a live process would let two waiters enter the critical section and is
 * a UAF source, so on a live owner we log once and bail — that's a real
 * lock-acquisition bug, not something to paper over here.  ABA-CAS on the
 * sampled state mirrors try_release_dead_holder() so a sibling child
 * grabbing shm->syscalltable_lock during the bust window isn't clobbered.
 */
void force_bust_lock(lock_t *lk)
{
	unsigned long s = __atomic_load_n(&lk->state, __ATOMIC_ACQUIRE);
	pid_t owner;

	if (LOCK_STATE(s) != LOCKED)
		return;

	owner = LOCK_OWNER(s);
	if (pid_alive(owner)) {
		static bool warned;
		if (!warned) {
			warned = true;
			outputerr("force_bust_lock: refusing to release lock held by live pid %d\n",
				  owner);
		}
		return;
	}

	__atomic_compare_exchange_n(&lk->state, &s, 0,
				    0, __ATOMIC_RELEASE, __ATOMIC_RELAXED);
}
