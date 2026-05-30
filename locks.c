#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#include "cmp_hints.h"
#include "debug.h"
#include "exit.h"
#include "locks.h"
#include "minicorpus.h"
#include "pids.h"
#include "sequence.h"
#include "shm.h"
#include "stats_ring.h"
#include "trinity.h"
#include "utils.h"

/*
 * Periodic sanity walker.  Recovers the lock word in two failure
 * modes: a scribbled word whose reserved bits got smeared by a
 * stray fuzz write (force_bust_lock + bump shm-wide counter), and a
 * cleanly-encoded lock held by a dead pid (released via unlock()).
 */
static bool check_lock(lock_t *lk)
{
	unsigned long s;
	pid_t pid;

	if (lk == NULL)
		return false;

	s = __atomic_load_n(&lk->state, __ATOMIC_ACQUIRE);

	/* Reserved bits dirty -- the lock word has been scribbled by a
	 * fuzzed syscall.  State and owner are both untrustworthy now;
	 * recover by clearing the whole word and surface the event on a
	 * dedicated counter so an operator can tell scribble activity
	 * apart from the regular dead-pid reaper signal.  Reset the
	 * load-path dirty_logged latch so a fresh scribble after this
	 * recovery can log again. */
	if (LOCK_RESERVED_DIRTY(s)) {
		force_bust_lock(lk);
		parent_stats.lock_word_scribbled++;
		__atomic_store_n(&lk->dirty_logged, false, __ATOMIC_RELAXED);
		return true;
	}

	/* We don't care about unlocked locks */
	if (LOCK_STATE(s) != LOCKED)
		return false;

	pid = LOCK_OWNER(s);

	if (pid_alive(pid) == false) {
		unsigned long stored_start;
		unsigned long long current_start;

		if (errno != ESRCH)
			return true;

		/* Recycle race: between pid_alive returning ESRCH and our CAS
		 * below, the pid could be reissued to a new process that re-
		 * acquires this lock.  The state word might still match `s` if
		 * the new owner happens to encode identically, so gate the CAS
		 * on the owner_start_time fingerprint: only release if the live
		 * owner's start_time differs from the sampled one (or is 0 =
		 * truly dead).  Mirrors try_release_dead_holder at locks.c:201-204
		 * and force_bust_lock's same check. */
		stored_start = __atomic_load_n(&lk->owner_start_time, __ATOMIC_ACQUIRE);
		current_start = pid_start_time(pid);
		if (current_start != 0 && current_start == stored_start)
			return true;

		debugf("Found a lock held by dead pid %d. Freeing.\n", pid);
		__atomic_compare_exchange_n(&lk->state, &s, 0, 0,
					    __ATOMIC_RELEASE, __ATOMIC_RELAXED);
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

	/* check_parent_pid (child.c) is the only taker; held briefly on the
	 * EXIT_REPARENT_PROBLEM fatal path.  A second child entering reparent
	 * recovery while the first died mid-update would otherwise spin until
	 * the in-primitive pid_alive recovery fires.  Same shm struct as
	 * syscalltable_lock above — no NULL gate needed. */
	check_lock(&shm->buglock);

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
		unsigned int a;

		for (i = 0; i < ARRAY_SIZE(cmp_hints_shm->pools); i++)
			for (a = 0; a < 2; a++)
				ret |= check_lock(&cmp_hints_shm->pools[i][a].lock);
	}

	/* Per-syscall minicorpus rings.  Writers are children on the hot
	 * save/replay path; the parent also takes every ring lock at
	 * shutdown via minicorpus_save_file, so a leaked ring lock wedges
	 * the shutdown save and burns the accumulated corpus.  Same
	 * per-array idiom as the cmp_hints walk above. */
	if (minicorpus_shm != NULL) {
		for (i = 0; i < ARRAY_SIZE(minicorpus_shm->rings); i++)
			ret |= check_lock(&minicorpus_shm->rings[i].lock);
	}

	/* Global chain-corpus ring lock.  Written by children only
	 * (chain_corpus_save); readers are lockless.  No parent-side
	 * caller today, but the lock has no other reaper — without this
	 * scan a SIGSEGV inside chain_corpus_save leaves the ring wedged
	 * for every subsequent child saver until the million-spin
	 * try_release_dead_holder eventually fires. */
	if (chain_corpus_shm != NULL)
		ret |= check_lock(&chain_corpus_shm->lock);

	return ret;
}

bool trylock(lock_t *lk)
{
	unsigned long current = __atomic_load_n(&lk->state, __ATOMIC_RELAXED);
	unsigned long desired = MAKE_LOCK(cached_pid, LOCKED);
	bool won;

	/* Scribbled reserved bits on the live word.  One-shot diagnostic
	 * per lock instance: the exchange returns the previous value of
	 * the latch, so only the first caller to see dirty bits logs --
	 * subsequent acquires on the same persistently-corrupted word stay
	 * quiet until check_lock() recovers and clears the latch.
	 * Acquire still proceeds on the sampled word below; the diagnostic
	 * here is for visibility, not correctness. */
	if (LOCK_RESERVED_DIRTY(current)) {
		if (!__atomic_exchange_n(&lk->dirty_logged, true, __ATOMIC_RELAXED))
			outputerr("trylock: lock word scribbled (state=0x%lx) -- reserved bits 0x%lx\n",
				  current, LOCK_RESERVED_DIRTY(current));
	}

	/* Acquire on any word with the state bit clear, even if the
	 * reserved or owner bits are dirty.  A corrupted-but-unlocked
	 * word (e.g. a stray write from a fuzzed syscall scribbling
	 * through an aliased iov_base into shared lock memory) is
	 * logically unlocked -- treating it as held would spin trylock
	 * forever waiting for an unlock that never comes because
	 * nobody actually owns it.  The CAS uses the sampled current
	 * value, so a concurrent acquirer that flips the state bit
	 * between our load and our CAS just makes the CAS fail; the
	 * caller loops, same as before.
	 *
	 * Single CAS still sets state and owner together, so a death
	 * after this point leaves the lock cleanly held by us, and the
	 * next check_lock pid_alive scan will release it. */
	if (LOCK_STATE(current) != UNLOCKED)
		return false;

	/* Pre-stamp our start_time so a force_bust_lock() running
	 * immediately after our CAS sees a value that matches the new
	 * owner pid in the state word.  Two-store protocol: a racing
	 * loser writes here too and may stomp us, so we re-stamp after
	 * winning the CAS below to clobber any racing loser's value.
	 * See the comment on owner_start_time in include/locks.h for the
	 * residual race window. */
	__atomic_store_n(&lk->owner_start_time, cached_start_time,
			 __ATOMIC_RELAXED);

	won = __atomic_compare_exchange_n(&lk->state, &current, desired,
					  0, __ATOMIC_ACQUIRE,
					  __ATOMIC_RELAXED);
	if (won)
		__atomic_store_n(&lk->owner_start_time, cached_start_time,
				 __ATOMIC_RELEASE);
	return won;
}

/*
 * If a child held this lock and got killed (SIGABRT, SIGSEGV, etc.),
 * the lock is permanently held by a dead pid. Detect that case and
 * release. We need ABA protection: between sampling owner=A and
 * checking liveness, the lock could have been released and re-acquired
 * by a recycled pid that reuses A's numeric pid value -- the state
 * word looks identical to ours but is a different acquisition.  The
 * (pid, start_time) fingerprint catches that: a recycled pid will have
 * a different /proc/<pid>/stat field 22 even if the numeric pid
 * matches.  We compare against the stored owner_start_time and treat
 * mismatch as "the original holder is gone".
 *
 * Use pid_alive() rather than a raw kill(pid, 0): a zombie holder still
 * has a task struct (kill returns 0) but cannot release the lock, so a
 * naive kill-only check leaves us spinning forever waiting for a corpse
 * that hasn't been reaped yet.
 */
static void try_release_dead_holder(lock_t *lk)
{
	unsigned long sampled = __atomic_load_n(&lk->state, __ATOMIC_ACQUIRE);
	unsigned long stored_start;
	unsigned long long current_start;
	pid_t owner = LOCK_OWNER(sampled);

	if (LOCK_STATE(sampled) != LOCKED || owner == 0)
		return;

	stored_start = __atomic_load_n(&lk->owner_start_time, __ATOMIC_ACQUIRE);
	current_start = pid_start_time(owner);
	if (current_start != 0 && current_start == stored_start)
		return;

	/* Either the pid is gone (current_start == 0) or it was recycled
	 * (mismatch).  Try to release ONLY if the state word hasn't
	 * changed since we sampled -- a CAS to 0 with the sampled state
	 * as expected, so a fresh acquirer who CAS'd in between (and
	 * therefore wrote a new owner_start_time) doesn't get clobbered. */
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
	/* Re-check reserved-bit scribble at release.  trylock() catches a
	 * scribble that landed before acquire; this catches scribbles that
	 * landed DURING the hold-time window (a fuzzed syscall scribbling
	 * through aliased shared memory while we held the lock).  Bump a
	 * shm-wide counter that surfaces in dump_stats -- one increment is
	 * enough evidence; we still release rather than refuse, because
	 * refusing on the release path would deadlock every subsequent
	 * waiter on a lock that legitimately needs to be freed. */
	unsigned long s = __atomic_load_n(&lk->state, __ATOMIC_RELAXED);
	if (LOCK_RESERVED_DIRTY(s))
		__atomic_fetch_add(&shm->stats.lock_held_scribble, 1,
				   __ATOMIC_RELAXED);

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
 * Confirm the holder is truly dead before clearing.  Releasing a lock
 * owned by a live process would let two waiters enter the critical
 * section and is a UAF source, so on a live owner we log once and
 * bail -- that's a real lock-acquisition bug, not something to paper
 * over here.  pid_alive() alone is insufficient: a long fuzz run
 * recycles PIDs, and a recycled pid matching the dead lock-owner's
 * numeric value would keep the bust refused forever.  Compare the
 * stored owner_start_time against the live /proc/<pid>/stat field 22
 * -- mismatch means the original owner is gone (process exited and a
 * different process now holds that pid).  Match means the original
 * lock-acquiring process is still alive; log once and bail.  ABA-CAS
 * on the sampled state mirrors try_release_dead_holder() so a sibling
 * child grabbing shm->syscalltable_lock during the bust window isn't
 * clobbered.
 */
void force_bust_lock(lock_t *lk)
{
	unsigned long s = __atomic_load_n(&lk->state, __ATOMIC_ACQUIRE);
	unsigned long stored_start;
	unsigned long long current_start;
	pid_t owner;

	/* Scribbled reserved bits: the encoded state and owner are both
	 * untrustworthy, so the pid_alive gate below cannot help.  Clear
	 * the whole word back to a known-good zero unconditionally; ABA
	 * via a fresh acquirer racing us just gets clobbered (acceptable
	 * -- the alternative is leaving the scribble in place for the
	 * next acquirer to inherit). */
	if (LOCK_RESERVED_DIRTY(s)) {
		__atomic_store_n(&lk->state, 0, __ATOMIC_RELEASE);
		return;
	}

	if (LOCK_STATE(s) != LOCKED)
		return;

	owner = LOCK_OWNER(s);
	stored_start = __atomic_load_n(&lk->owner_start_time, __ATOMIC_ACQUIRE);
	current_start = pid_start_time(owner);
	if (current_start != 0 && current_start == stored_start) {
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
