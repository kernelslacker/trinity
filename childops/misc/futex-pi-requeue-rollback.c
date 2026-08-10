/*
 * futex_pi_requeue_rollback: structured PI-chain + requeue-PI + priority
 * race exerciser.
 *
 * The generic futex-storm childop drives random mass contention against
 * the plain FUTEX_WAIT / FUTEX_WAKE / FUTEX_REQUEUE / FUTEX_CMP_REQUEUE
 * mix.  It cannot by chance assemble a three-thread PI chain, arm a
 * timed FUTEX_WAIT_REQUEUE_PI on top of it, and race a priority-boost
 * against a concurrent FUTEX_CMP_REQUEUE_PI -- the exact set of
 * preconditions the rt_mutex proxy-lock start -> rollback ->
 * remove_waiter path needs to become reachable.  This childop hand-
 * builds the recipe.
 *
 * Recipe (three workers cloned via fork() under a per-invocation transient
 * scope):
 *
 *   owner    : publishes tid, FUTEX_LOCK_PI(target_pi) -> holds target.
 *              Then FUTEX_LOCK_PI(chain_pi) -> blocks, so target_pi's
 *              owner is itself a waiter on chain_pi.  That is the PI-
 *              chain link the requeue path has to walk when the waiter
 *              is later transferred onto target_pi's rt_mutex.
 *
 *   waiter   : publishes tid, FUTEX_LOCK_PI(chain_pi) -> holds chain
 *              (owner is now blocked behind waiter).  Then arms a timed
 *              FUTEX_WAIT_REQUEUE_PI(wait_word -> target_pi); the short
 *              timeout is the race window against the parent's requeue
 *              call.
 *
 *   consumer : sched_setattr(waiter_tid, ...) mid-flight to change the
 *              waiter's priority once WAIT_REQUEUE_PI has parked.  That
 *              forces rt_mutex_adjust_prio_chain to re-walk the chain
 *              while the requeue is in flight, exercising the concurrent
 *              PI-adjust-vs-requeue path that random priority churn on
 *              unrelated tasks cannot reach.
 *
 *   parent   : after handshakes, fires FUTEX_CMP_REQUEUE_PI(wait_word ->
 *              target_pi) so the transition races the WAIT_REQUEUE_PI
 *              timeout expiry.  The waiter is either transferred onto
 *              target_pi's rt_mutex (proxy-lock start), or the wait
 *              times out first (rollback).  Either landing pass is
 *              interesting; the mid-flight priority churn changes what
 *              rt_mutex_start_proxy_lock / rt_mutex_cleanup_proxy_lock
 *              sees on the way through.
 *
 * Churn axes per invocation: WAIT_REQUEUE_PI timeout value, nice /
 * priority the consumer flips to, requeue nr / nr_requeue counts,
 * private vs shared futex flag.  Held small on purpose so per-invocation
 * wall time stays bounded.
 *
 * Bounded teardown is load-bearing: an owner blocked on FUTEX_LOCK_PI or
 * a waiter parked in FUTEX_WAIT_REQUEUE_PI can wedge the child if we let
 * a plain waitpid() sit on them.  Teardown FUTEX_UNLOCK_PIs anything the
 * parent might still hold (nothing normally, but the target_pi may have
 * been requeued onto the parent), SIGKILLs all three workers, then
 * per-worker WNOHANG-polls with a small grace window before falling back
 * to a blocking waitpid_eintr().  A stuck worker still gets a SIGKILL +
 * bounded wait; a zombie left behind counts against the escape counter
 * rather than pinning the whole invocation past the parent's stall
 * detector.
 *
 * Default-off; only for a targeted debugging run behind the canary queue.
 */

#include <errno.h>
#include <linux/futex.h>
#include <linux/sched.h>
#include <linux/sched/types.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "child.h"
#include "childop-outcome.h"
#include "syscall-gate.h"
#include "childops-util.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "signals.h"
#include "trinity.h"

/*
 * ---------------------------------------------------------------------------
 * CLONE_VM pivot-race sub-arm
 *
 * Two CLONE_VM siblings race prctl(PR_FUTEX_HASH_SET_SLOTS, slot_count) in
 * the same mm.  A third CLONE_VM sibling parks in FUTEX_WAIT|
 * FUTEX_PRIVATE_FLAG so futex_ref_is_dead(fph_old) stays false for the
 * losing racer, forcing it into wait_var_event (the WARNING path in
 * futex_hash_allocate / futex_pivot_pending).
 *
 * Prerequisite sequence:
 *   1. Orchestrator calls prctl(SET_SLOTS, N>0) to establish a non-zero
 *      per-mm private hash (fph_old) before any CLONE_VM siblings run.
 *   2. Holder sibling parks in FUTEX_WAIT | FUTEX_PRIVATE_FLAG on
 *      ps->futex_hold.  This grabs a reference to fph_old so
 *      futex_ref_is_dead(fph_old) returns false while the holder is parked.
 *   3. Racer siblings both call prctl(SET_SLOTS, slot_count).  The first
 *      one to enter futex_hash_allocate sets a pending state.  The second
 *      sees it, checks futex_ref_is_dead(fph_old) -- false because the
 *      holder is still parked -- and blocks in wait_var_event.
 *
 * One-way-door accounting: slot_count==0 permanently pivots a mm to the
 * global hash; further SET_SLOTS calls on that mm return -EBUSY.  Because
 * fpr_run_pivot_race() now forks an orchestrator, step 1 always runs on a
 * freshly created mm so -EBUSY cannot occur there.  The racers may still
 * see -EBUSY from each other (one wins, the other is then -EBUSY on the
 * same child mm); those are counted in slots_ebusy for visibility.
 * fpr_pick_slot_count() still draws 0 with ~1/8 probability to exercise
 * the global-hash pivot path inside the throwaway mm.
 *
 * Structural note: this arm is self-contained and mutually exclusive with
 * the fork()-based PI/foreign-TID arm.  The PI arm requires distinct mms;
 * this arm requires a shared mm.  fpr_pick_axes() sets use_privhash to
 * select which arm runs.
 * ---------------------------------------------------------------------------
 */

#define FPR_PIVOT_STACK_SZ  (64U * 1024U)

struct fpr_pivot_shared {
	/* Private futex the holder parks on.  Initialised to 0. */
	int		futex_hold;
	/*
	 * Set to 1 just before the holder enters FUTEX_WAIT.  Racers spin on
	 * this and then sleep 1 ms to let the holder fully enter the kernel.
	 */
	uint32_t	holder_parked;
	/*
	 * Release latch: set to 1 after both racers are spawned so they
	 * fire as simultaneously as possible.
	 */
	uint32_t	racers_go;
	/* slot count the racers pass to SET_SLOTS (copied from s->slot_count) */
	unsigned int	race_slots;
	/* syscall accumulator; drained into s->direct_syscalls at teardown */
	unsigned long	direct_syscalls;
};

/*
 * Holder body.  Parks in FUTEX_WAIT | FUTEX_PRIVATE_FLAG to hold a live
 * reference to the per-mm private hash so futex_ref_is_dead(fph_old)
 * returns false while the racers are running.
 */
static int fpr_pivot_holder_fn(void *arg)
{
	struct fpr_pivot_shared *ps = arg;
	struct timespec ts = { .tv_sec = 0, .tv_nsec = 120L * 1000000L };

	CHILDOP_GRANDCHILD_ENTER();
	(void)prctl(PR_SET_PDEATHSIG, SIGKILL);
	if (getppid() == 1)
		_exit(0);

	/*
	 * Publish parked BEFORE calling FUTEX_WAIT.  There is a tiny window
	 * between this store and the syscall; racers absorb it with a 1 ms
	 * sleep after they observe holder_parked == 1.
	 */
	__atomic_store_n(&ps->holder_parked, 1U, __ATOMIC_RELEASE);
	__atomic_add_fetch(&ps->direct_syscalls, 1, __ATOMIC_RELAXED);
	(void)syscall(__NR_futex, &ps->futex_hold,
		      FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 0, &ts, NULL, 0);
	_exit(0);
}

/*
 * Racer body.  Waits for holder_parked then fires prctl(SET_SLOTS, race_slots)
 * in a tight race with its sibling.
 */
static int fpr_pivot_racer_fn(void *arg)
{
	struct fpr_pivot_shared *ps = arg;
	struct timespec nap = { .tv_sec = 0, .tv_nsec = 1000000L }; /* 1 ms */
	unsigned int spins;

	CHILDOP_GRANDCHILD_ENTER();
	(void)prctl(PR_SET_PDEATHSIG, SIGKILL);
	if (getppid() == 1)
		_exit(0);

	/* Spin until holder signals it is about to park. */
	for (spins = 0; spins < 40; spins++) {
		if (__atomic_load_n(&ps->holder_parked, __ATOMIC_ACQUIRE))
			break;
		(void)nanosleep(&nap, NULL);
	}
	/* 1 ms grace so holder is likely blocking in the kernel. */
	(void)nanosleep(&nap, NULL);

	/* Spin until orchestrator releases the go latch. */
	for (spins = 0; spins < 40; spins++) {
		if (__atomic_load_n(&ps->racers_go, __ATOMIC_ACQUIRE))
			break;
		(void)nanosleep(&nap, NULL);
	}

	__atomic_add_fetch(&ps->direct_syscalls, 1, __ATOMIC_RELAXED);
	if (prctl(PR_FUTEX_HASH, PR_FUTEX_HASH_SET_SLOTS,
		  (int)ps->race_slots) < 0 && errno == EBUSY)
		__atomic_add_fetch(
			&shm->stats.futex_pi_requeue_rollback.slots_ebusy,
			1, __ATOMIC_RELAXED);
	_exit(0);
}

static void fpr_pivot_free_stack(void *stack)
{
	if (stack && stack != MAP_FAILED)
		(void)munmap(stack, FPR_PIVOT_STACK_SZ);
}

static void fpr_pivot_reap(pid_t pid)
{
	struct timespec grace = { .tv_sec = 0, .tv_nsec = 20L * 1000000L };
	int status;
	int spin;

	if (pid <= 0)
		return;
	(void)kill(pid, SIGKILL);
	for (spin = 0; spin < 5; spin++) {
		if (waitpid_eintr(pid, &status, WNOHANG) == pid)
			return;
		(void)nanosleep(&grace, NULL);
	}
	(void)waitpid_eintr(pid, &status, 0);
}


/*
 * Handshake sequence numbers stored in the shared page.  Ordering matters:
 * waiter must not arm WAIT_REQUEUE_PI before owner has published its LOCK_PI
 * on target_pi, otherwise there is no proxy-lock chain to walk.
 */
#define FPR_STATE_START		0U
#define FPR_STATE_OWNER_READY	1U	/* owner holds target_pi */
#define FPR_STATE_WAITER_READY	2U	/* waiter holds chain_pi and armed WAIT_REQUEUE_PI */

#define FPR_HANDSHAKE_WAIT_NS	(20L * 1000L * 1000L)	/* 20ms bound per handshake step */
#define FPR_WORKER_REAP_GRACE_MS	100
#define FPR_WORKER_REAP_SPINS	10

struct fpr_shared {
	int futex_target_pi;	/* PI futex the waiter is requeued onto */
	int futex_chain_pi;	/* PI futex that pins owner -> waiter */
	int futex_wait;		/* WAIT_REQUEUE_PI source word */
	uint32_t state;		/* handshake sequence (see FPR_STATE_*) */
	pid_t waiter_tid;
	unsigned int use_private;	/* 0 -> shared futex, 1 -> FUTEX_PRIVATE_FLAG */
	long wait_timeout_ns;	/* WAIT_REQUEUE_PI timeout in ns */
	int consumer_policy;	/* SCHED_FIFO / SCHED_RR / SCHED_OTHER */
	int consumer_priority;	/* RT priority when policy is FIFO/RR */
	int consumer_nice;	/* nice value when policy is OTHER */
	int requeue_nr_wake;	/* val (nr_wake) for CMP_REQUEUE_PI */
	int requeue_nr;		/* val2 (nr_requeue) for CMP_REQUEUE_PI */
	pid_t foreign_tid;	/* waiter's tid stored as lock-word owner in privhash arm */
	unsigned int use_privhash;	/* 1 -> prctl per-mm hash + foreign-tid lock word */
	unsigned int slot_count;	/* PR_FUTEX_HASH_SET_SLOTS argument drawn by fpr_pick_axes */
	/* Direct-syscall accumulator: every raw_futex() bumps this
	 * before entering the kernel, plus the consumer's sched_setattr
	 * trinity_raw_syscall and the waiter's syscall(__NR_gettid).
	 * Workers and parent all live in the same MAP_SHARED region so
	 * the RELAXED atomic add serialises cross-process without
	 * dragging the futex hot path onto a heavier ordering.  Drained
	 * once by the orchestrator at reap-time and published via
	 * childop_direct_syscalls_add(). */
	unsigned long direct_syscalls;
};

static long raw_futex(struct fpr_shared *s, int *uaddr, int op,
		      unsigned int flag_or, int val,
		      const struct timespec *ts, int *uaddr2, int val3)
{
	__atomic_add_fetch(&s->direct_syscalls, 1, __ATOMIC_RELAXED);
	return trinity_raw_syscall(__NR_futex, uaddr, op | (int)flag_or, val,
				   ts, uaddr2, val3);
}

/*
 * Bounded wait for the shared handshake state to advance past `at_least`.
 * Bounded via a per-poll FUTEX_WAIT timeout so a worker that died mid-
 * handshake cannot pin the parent for longer than a handful of these
 * slices.  Returns true if the state advanced, false on timeout.
 */
static bool wait_for_state(struct fpr_shared *s, uint32_t at_least)
{
	struct timespec ts;
	unsigned int spins;
	uint32_t cur;

	for (spins = 0; spins < 8; spins++) {
		cur = __atomic_load_n(&s->state, __ATOMIC_ACQUIRE);
		if (cur >= at_least)
			return true;
		ts.tv_sec  = 0;
		ts.tv_nsec = FPR_HANDSHAKE_WAIT_NS;
		(void)raw_futex(s, (int *)&s->state, FUTEX_WAIT, 0U, (int)cur,
				&ts, NULL, 0);
	}
	return __atomic_load_n(&s->state, __ATOMIC_ACQUIRE) >= at_least;
}

static void publish_state(struct fpr_shared *s, uint32_t val)
{
	__atomic_store_n(&s->state, val, __ATOMIC_RELEASE);
	(void)raw_futex(s, (int *)&s->state, FUTEX_WAKE, 0U, INT_MAX, NULL, NULL, 0);
}

/*
 * owner worker body.  Runs in a fork()'d child; must never return.
 * PDEATHSIG + getppid()==1 recheck cover the parent-died-before-arming
 * window so a wedged run cannot leak this thread to PID 1 blocking on
 * a PI futex.
 */
static void fpr_owner_main(struct fpr_shared *s)
{
	unsigned int flag = s->use_private ? FUTEX_PRIVATE_FLAG : 0U;

	(void)prctl(PR_SET_PDEATHSIG, SIGKILL);
	if (getppid() == 1)
		_exit(0);

	if (raw_futex(s, &s->futex_target_pi, FUTEX_LOCK_PI, flag, 0, NULL, NULL, 0) < 0)
		_exit(0);
	publish_state(s, FPR_STATE_OWNER_READY);

	/*
	 * Block on chain_pi so target_pi's owner is itself a PI waiter --
	 * the exact chain shape rt_mutex_adjust_prio_chain has to walk when
	 * the parent later requeues the waiter onto target_pi's rt_mutex.
	 */
	(void)raw_futex(s, &s->futex_chain_pi, FUTEX_LOCK_PI, flag, 0, NULL, NULL, 0);
	_exit(0);
}

static void fpr_waiter_main(struct fpr_shared *s)
{
	unsigned int flag = s->use_private ? FUTEX_PRIVATE_FLAG : 0U;
	struct timespec ts;
	int val;

	(void)prctl(PR_SET_PDEATHSIG, SIGKILL);
	if (getppid() == 1)
		_exit(0);

	__atomic_add_fetch(&s->direct_syscalls, 1, __ATOMIC_RELAXED);
	__atomic_store_n(&s->waiter_tid, (pid_t)syscall(__NR_gettid),
			 __ATOMIC_RELEASE);

	if (raw_futex(s, &s->futex_chain_pi, FUTEX_LOCK_PI, flag, 0, NULL, NULL, 0) < 0)
		_exit(0);
	if (!wait_for_state(s, FPR_STATE_OWNER_READY))
		_exit(0);

	/*
	 * Arm the timed FUTEX_WAIT_REQUEUE_PI.  val = current wait_word so
	 * the kernel's cmp-and-enqueue succeeds only if the parent has not
	 * bumped the word between now and the syscall entry.  A short
	 * timeout is the race window against the parent's CMP_REQUEUE_PI.
	 */
	val = __atomic_load_n(&s->futex_wait, __ATOMIC_RELAXED);
	publish_state(s, FPR_STATE_WAITER_READY);

	ts.tv_sec  = 0;
	ts.tv_nsec = s->wait_timeout_ns;
	(void)raw_futex(s, &s->futex_wait, FUTEX_WAIT_REQUEUE_PI, flag, val,
			&ts, &s->futex_target_pi, 0);
	_exit(0);
}

static void fpr_consumer_main(struct fpr_shared *s)
{
	struct sched_attr attr;
	pid_t waiter_tid;

	(void)prctl(PR_SET_PDEATHSIG, SIGKILL);
	if (getppid() == 1)
		_exit(0);

	if (!wait_for_state(s, FPR_STATE_WAITER_READY))
		_exit(0);

	waiter_tid = __atomic_load_n(&s->waiter_tid, __ATOMIC_ACQUIRE);
	if (waiter_tid <= 0)
		_exit(0);

	memset(&attr, 0, sizeof(attr));
	attr.size = sizeof(attr);
	attr.sched_policy = (unsigned int)s->consumer_policy;
	if (s->consumer_policy == SCHED_FIFO || s->consumer_policy == SCHED_RR)
		attr.sched_priority = (unsigned int)s->consumer_priority;
	else
		attr.sched_nice = s->consumer_nice;

	/*
	 * The setattr races the parent's CMP_REQUEUE_PI landing on
	 * target_pi.  Success flips the waiter's PI-effective priority
	 * mid-transfer, forcing rt_mutex_adjust_prio_chain to re-walk the
	 * chain concurrently with the transfer.  EPERM on RT classes is
	 * expected on unprivileged runs; the plain-nice fallback still
	 * exercises SCHED_NORMAL's dynamic prio path.
	 */
	__atomic_add_fetch(&s->direct_syscalls, 1, __ATOMIC_RELAXED);
	(void)trinity_raw_syscall(__NR_sched_setattr, waiter_tid, &attr, 0U);
	_exit(0);
}

/*
 * fpr_run_pivot_race - orchestrate the CLONE_VM private-hash pivot race.
 *
 * Called from futex_pi_requeue_rollback() when s->use_privhash is set.
 *
 * We fork an orchestrator child so the step-1 prctl(SET_SLOTS) and all
 * CLONE_VM siblings execute in the *forked child's* mm, not the trinity
 * child's mm.  This matters because prctl(SET_SLOTS, 0) is a one-way door:
 * once a mm is pivoted to the global hash, every subsequent SET_SLOTS
 * returns -EBUSY, meaning the sub-arm can fire at most once per child
 * lifetime if it runs in the caller's own mm.  By running inside a
 * disposable fork the door closes only in the throwaway mm; the kernel
 * zeroes mm->futex.phash in futex_hash_init_mm() at fork time, so each
 * call to fpr_run_pivot_race() gets a virgin private hash regardless of
 * what the previous invocation drew.  The CLONE_VM requirement is still
 * satisfied within the fork; only the scope of the door changes.
 */
static void fpr_run_pivot_race(struct fpr_shared *s)
{
	pid_t orch_pid;
	int status;

	orch_pid = fork();
	if (orch_pid < 0)
		return;

	if (orch_pid == 0) {
		/* ---- orchestrator child: throwaway mm ---- */
		static const unsigned int init_slots[] = {
			2, 4, 8, 16, 32, 64, 128, 256
		};
		struct fpr_pivot_shared *ps;
		void *hstack = NULL, *rastack = NULL, *rbstack = NULL;
		pid_t holder_pid = -1, racer_a_pid = -1, racer_b_pid = -1;
		struct timespec nap = { .tv_sec = 0, .tv_nsec = 500000L };
		unsigned int spins;

		CHILDOP_GRANDCHILD_ENTER();
		(void)prctl(PR_SET_PDEATHSIG, SIGKILL);
		if (getppid() == 1)
			_exit(0);

		ps = mmap(NULL, sizeof(*ps), PROT_READ | PROT_WRITE,
			  MAP_ANONYMOUS | MAP_SHARED, -1, 0);
		if (ps == MAP_FAILED)
			_exit(0);
		memset(ps, 0, sizeof(*ps));
		ps->race_slots = s->slot_count;

		/*
		 * Step 1: Establish a non-zero private hash in this mm so the
		 * holder's FUTEX_WAIT | FUTEX_PRIVATE_FLAG attaches to fph_old
		 * rather than the global hash.  EBUSY cannot occur here because
		 * this is a freshly forked mm; any other error means the kernel
		 * lacks per-mm hash support.
		 */
		__atomic_add_fetch(&s->direct_syscalls, 1, __ATOMIC_RELAXED);
		if (prctl(PR_FUTEX_HASH, PR_FUTEX_HASH_SET_SLOTS,
			  (int)init_slots[rnd_modulo_u32(ARRAY_SIZE(init_slots))]) < 0)
			goto child_out;

		hstack  = mmap(NULL, FPR_PIVOT_STACK_SZ, PROT_READ | PROT_WRITE,
			       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		rastack = mmap(NULL, FPR_PIVOT_STACK_SZ, PROT_READ | PROT_WRITE,
			       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		rbstack = mmap(NULL, FPR_PIVOT_STACK_SZ, PROT_READ | PROT_WRITE,
			       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (hstack == MAP_FAILED || rastack == MAP_FAILED ||
		    rbstack == MAP_FAILED)
			goto child_out;

		/*
		 * Step 2: Spawn holder (CLONE_VM -- shares this child's mm and
		 * its private hash).
		 */
		holder_pid = clone(fpr_pivot_holder_fn,
				   (char *)hstack + FPR_PIVOT_STACK_SZ,
				   CLONE_VM | SIGCHLD, ps);
		if (holder_pid < 0)
			goto child_out;

		for (spins = 0; spins < 40; spins++) {
			if (__atomic_load_n(&ps->holder_parked, __ATOMIC_ACQUIRE))
				break;
			(void)nanosleep(&nap, NULL);
		}
		if (!__atomic_load_n(&ps->holder_parked, __ATOMIC_ACQUIRE))
			goto child_out;

		/*
		 * Step 3: Spawn both racers.  Set the go latch after both are
		 * spawned so they fire as simultaneously as possible.
		 */
		racer_a_pid = clone(fpr_pivot_racer_fn,
				    (char *)rastack + FPR_PIVOT_STACK_SZ,
				    CLONE_VM | SIGCHLD, ps);
		racer_b_pid = clone(fpr_pivot_racer_fn,
				    (char *)rbstack + FPR_PIVOT_STACK_SZ,
				    CLONE_VM | SIGCHLD, ps);
		__atomic_store_n(&ps->racers_go, 1U, __ATOMIC_RELEASE);

child_out:
		fpr_pivot_reap(racer_a_pid);
		fpr_pivot_reap(racer_b_pid);
		fpr_pivot_reap(holder_pid);

		/* Drain the pivot arm's syscall tally into the main counter. */
		__atomic_add_fetch(&s->direct_syscalls,
				   __atomic_load_n(&ps->direct_syscalls,
						   __ATOMIC_RELAXED),
				   __ATOMIC_RELAXED);

		(void)munmap(ps, sizeof(*ps));
		fpr_pivot_free_stack(hstack);
		fpr_pivot_free_stack(rastack);
		fpr_pivot_free_stack(rbstack);
		_exit(0);
	}

	/* ---- trinity child waits for the throwaway orchestrator ---- */
	(void)waitpid_eintr(orch_pid, &status, 0);
}

/*
 * Draw PR_FUTEX_HASH_SET_SLOTS argument.
 *
 * Value space: {0} ∪ {2, 4, 8, 16, 32, 64, 128, 256} (valid values) plus 1
 * as a rare deliberate -EINVAL probe.
 *
 * Using a 16-outcome draw:
 *   r == 15        -> 1   (EINVAL probe, ~1/16 of calls)
 *   r == 13 or 14 -> 0   (global-hash-to-private pivot, ~1/8 of valid draws)
 *   r in [0,12]   -> valid_slots[r % 8]
 *
 * The 0 one-way door: once a mm calls SET_SLOTS(0) it is permanently pinned
 * to the global hash and every subsequent SET_SLOTS returns -EBUSY.  Because
 * fpr_run_pivot_race() now forks a throwaway orchestrator, the door closes
 * only in the disposable mm so subsequent invocations start with a virgin
 * mm->futex.phash.  Drawing 0 with ~1/8 probability still exercises the
 * global-hash pivot path; -EBUSY from racer siblings racing on the same
 * child mm is counted in slots_ebusy for visibility.
 */
static unsigned int fpr_pick_slot_count(void)
{
	static const unsigned int valid_slots[] = {
		2, 4, 8, 16, 32, 64, 128, 256
	};
	unsigned int r = rnd_modulo_u32(16);

	if (r == 15)
		return 1;   /* deliberate -EINVAL probe */
	if (r >= 13)
		return 0;   /* global-hash-to-private pivot */
	return valid_slots[r % ARRAY_SIZE(valid_slots)];
}

/*
 * Pick per-invocation churn parameters.  Kept in one place so the axes
 * documented at the top of the file all mutate together and the reader
 * can eyeball the value range on a single screen.
 */
static void fpr_pick_axes(struct fpr_shared *s)
{
	static const int policies[] = { SCHED_FIFO, SCHED_RR, SCHED_OTHER };

	s->use_private     = rnd_u32() & 1U;
	s->use_privhash    = s->use_private && (rnd_u32() & 1U) ? 1U : 0U;
	/*
	 * slot_count is the prctl argument the CLONE_VM racers use.  Drawn via
	 * fpr_pick_slot_count() which returns 0 (~1/8 probability) for the
	 * global-hash pivot path and a valid power-of-two otherwise.  Only
	 * meaningful when use_privhash is set.
	 */
	s->slot_count      = s->use_privhash ? fpr_pick_slot_count() : 0U;
	s->wait_timeout_ns = (long)(100000 + rnd_modulo_u32(900000));	/* 100us..1ms */
	s->consumer_policy = policies[rnd_modulo_u32(ARRAY_SIZE(policies))];
	s->consumer_priority = 1 + (int)rnd_modulo_u32(20);
	s->consumer_nice   = -5 + (int)rnd_modulo_u32(15);	/* -5..9 */
	s->requeue_nr_wake = 1;	/* CMP_REQUEUE_PI requires exactly 1 wake */
	s->requeue_nr      = (int)rnd_modulo_u32(4);	/* 0..3 requeues */
}

static struct fpr_shared *fpr_shared_alloc(void)
{
	struct fpr_shared *s;

	s = mmap(NULL, sizeof(*s), PROT_READ | PROT_WRITE,
		 MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	if (s == MAP_FAILED)
		return NULL;
	memset(s, 0, sizeof(*s));
	return s;
}

typedef void (*fpr_worker_entry)(struct fpr_shared *);

static pid_t fpr_spawn_worker(struct fpr_shared *s, fpr_worker_entry entry)
{
	pid_t pid = fork();

	if (pid == 0) {
		CHILDOP_GRANDCHILD_ENTER();
		entry(s);
		_exit(0);
	}
	return pid;
}

/*
 * Bounded teardown.  A PI-blocked worker cannot return to userspace on
 * its own once we tear down the shared mapping; SIGKILL is unblockable,
 * so a small per-worker grace loop plus a final blocking waitpid_eintr()
 * caps the wall-clock we spend here even if one worker is genuinely
 * wedged in the kernel.
 */
static void fpr_reap_worker(pid_t pid)
{
	struct timespec grace;
	int status;
	int spin;

	if (pid <= 0)
		return;

	(void)kill(pid, SIGKILL);
	for (spin = 0; spin < FPR_WORKER_REAP_SPINS; spin++) {
		pid_t r = waitpid_eintr(pid, &status, WNOHANG);

		if (r == pid || r < 0)
			return;
		grace.tv_sec  = 0;
		grace.tv_nsec = (long)FPR_WORKER_REAP_GRACE_MS * 1000000L
				/ (long)FPR_WORKER_REAP_SPINS;
		(void)nanosleep(&grace, NULL);
	}
	(void)waitpid_eintr(pid, &status, 0);
}

bool futex_pi_requeue_rollback(struct childdata *child)
{
	struct fpr_shared *s;
	pid_t owner_pid = -1;
	pid_t waiter_pid = -1;
	pid_t consumer_pid = -1;
	unsigned int flag;
	int wait_val;
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	__atomic_add_fetch(&shm->stats.futex_pi_requeue_rollback.runs,
			   1, __ATOMIC_RELAXED);

	s = fpr_shared_alloc();
	if (s == NULL)
		return true;
	fpr_pick_axes(s);
	flag = s->use_private ? FUTEX_PRIVATE_FLAG : 0U;

	if (s->use_privhash) {
		/*
		 * CLONE_VM sub-arm: races two mm-sharing siblings on
		 * prctl(PR_FUTEX_HASH_SET_SLOTS, slot_count) to reach the
		 * futex_hash_allocate / futex_pivot_pending / wait_var_event
		 * WARNING path.  Self-contained; does not use fork() workers.
		 */
		if (valid_op) {
			__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
					   1, __ATOMIC_RELAXED);
			__atomic_add_fetch(&shm->stats.childop.data_path[op],
					   1, __ATOMIC_RELAXED);
		}
		fpr_run_pivot_race(s);
		goto out;
	}

	/*
	 * fork()-based PI/foreign-TID arm (distinct mms required).
	 * Kept intact; do not add use_privhash logic here.
	 */
	owner_pid = fpr_spawn_worker(s, fpr_owner_main);
	if (owner_pid < 0)
		goto out;

	if (!wait_for_state(s, FPR_STATE_OWNER_READY)) {
		__atomic_add_fetch(&shm->stats.futex_pi_requeue_rollback.setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}

	waiter_pid = fpr_spawn_worker(s, fpr_waiter_main);
	if (waiter_pid < 0)
		goto out;
	consumer_pid = fpr_spawn_worker(s, fpr_consumer_main);
	if (consumer_pid < 0)
		goto out;

	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	}

	if (!wait_for_state(s, FPR_STATE_WAITER_READY)) {
		__atomic_add_fetch(&shm->stats.futex_pi_requeue_rollback.setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}

	/*
	 * Fire the requeue.  val3 must equal *uaddr1 at kernel entry or the
	 * kernel returns -EAGAIN before touching the rt_mutex.  Sample here
	 * so the racy load is deliberate: a concurrent bump between sample
	 * and syscall exercises the cmp-vs-enqueue rollback path.
	 */
	wait_val = __atomic_load_n(&s->futex_wait, __ATOMIC_RELAXED);
	if (raw_futex(s, &s->futex_wait, FUTEX_CMP_REQUEUE_PI, flag,
		      s->requeue_nr_wake, NULL, &s->futex_target_pi, wait_val) >= 0)
		__atomic_add_fetch(&shm->stats.futex_pi_requeue_rollback.requeue_ok,
				   1, __ATOMIC_RELAXED);
	else
		__atomic_add_fetch(&shm->stats.futex_pi_requeue_rollback.requeue_failed,
				   1, __ATOMIC_RELAXED);

	/*
	 * Best-effort UNLOCK on target_pi in case the requeue transferred
	 * the rt_mutex to the parent (kernel does that when the requeue
	 * lands with the waiter as new top waiter and no in-kernel owner).
	 * EPERM is the expected path when we never became the owner and is
	 * ignored.
	 */
	(void)raw_futex(s, &s->futex_target_pi, FUTEX_UNLOCK_PI, flag, 0, NULL, NULL, 0);

out:
	fpr_reap_worker(consumer_pid);
	fpr_reap_worker(waiter_pid);
	fpr_reap_worker(owner_pid);

	/* All workers are reaped here so their per-worker bumps against
	 * s->direct_syscalls have retired; the RELAXED add-fetches
	 * happened-before the waitpid_eintr() return that gave us this
	 * pid, so a plain load lifts the total safely.  Read before the
	 * munmap that follows.  Gated on valid_op to match the childop
	 * stats bumps above; the fpr_shared_alloc-failure early return
	 * skips this by virtue of returning before we ever touched s. */
	if (valid_op)
		childop_direct_syscalls_add(op,
			__atomic_load_n(&s->direct_syscalls, __ATOMIC_RELAXED));

	(void)munmap(s, sizeof(*s));
	return true;
}
