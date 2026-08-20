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
#include "kernel/prctl.h"
#include "childop-outcome.h"
#include "pids.h"
#include "syscall-gate.h"
#include "childops-util.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "signals.h"
#include "trinity.h"

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
	unsigned int use_vfork_race;	/* 1 -> nested-vfork phash.ref NULL-race arm */
	unsigned int slot_count;	/* PR_FUTEX_HASH_SET_SLOTS argument drawn by fpr_pick_axes */
	/* Parent pid captured before fork(); forked workers compare getppid()
	 * against this to detect reparenting in the fork()->prctl() window. */
	pid_t expected_ppid;
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
 * PDEATHSIG + saved-ppid recheck cover the parent-died-before-arming
 * window so a wedged run cannot leak this thread blocking on a PI futex.
 * Comparing getppid() against the pre-prctl snapshot is subreaper-safe
 * (getppid()==1 misses reparents to a PR_SET_CHILD_SUBREAPER ancestor).
 */
static void fpr_owner_main(struct fpr_shared *s)
{
	unsigned int flag = s->use_private ? FUTEX_PRIVATE_FLAG : 0U;

	(void)prctl(PR_SET_PDEATHSIG, SIGKILL);
	/* Catch reparenting in the fork()->prctl() window; prctl covers after. */
	if (getppid() != s->expected_ppid)
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
	/* Catch reparenting in the fork()->prctl() window; prctl covers after. */
	if (getppid() != s->expected_ppid)
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
	/* Catch reparenting in the fork()->prctl() window; prctl covers after. */
	if (getppid() != s->expected_ppid)
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
 * ---------------------------------------------------------------------------
 * Nested-vfork phash.ref NULL-race arm
 *
 * CLONE_VM|CLONE_VFORK skips futex_hash_allocate_default(): the kernel gate
 * in copy_process() is `need_futex_hash_allocate_default()` which returns
 * `(clone_flags & (CLONE_VM|CLONE_VFORK)) == CLONE_VM`.  Adding CLONE_VFORK
 * makes it return false, so phash.ref stays NULL after cloning.
 *
 * Sequence (all within a throwaway orchestrator fork so the SET_SLOTS
 * one-way door closes only in the disposable mm):
 *
 *   P  = orchestrator (throwaway fork, fresh mm)
 *   G1 = clone(CLONE_VM|CLONE_VFORK|SIGCHLD) of P  -> P suspends in vfork
 *   G2 = clone(CLONE_VM|CLONE_VFORK|SIGCHLD) of G1 -> G1 suspends in vfork
 *   G2 kills G1 via kill(getppid(), SIGKILL) -> G1 dies -> P is released
 *   P and G2 are now both runnable in one mm with phash.ref still NULL
 *   Both race prctl(PR_FUTEX_HASH_SET_SLOTS, n) on a rendezvous barrier
 *   P does a GET_SLOTS readback after both racers finish as oracle check
 *
 * Stack safety: G1 and G2 each get a separately mmap'd stack.  G1's stack
 * is allocated by P (stored in the shared page); G2's stack is allocated by
 * G1.  CLONE_VFORK siblings MUST NOT share a stack.
 *
 * this_child() note: G2 inherits the parent's childdata pointer.  op_type
 * and op_nr are safe reads; per-process fields must not be written from G2.
 * ---------------------------------------------------------------------------
 */

#define FPR_VFORK_STACK_SZ  (64U * 1024U)

struct fpr_vfork_shared {
	/* G2 publishes its PID here so P knows G2 is alive */
	pid_t		g2_pid;
	/* Slot count both racers will pass to SET_SLOTS */
	unsigned int	slot_count;
	/* Rendezvous: P sets p_ready=1 after G1 is reaped, before its SET_SLOTS */
	uint32_t	p_ready;
	/* G2 sets g2_done=1 after its SET_SLOTS returns */
	uint32_t	g2_done;
	/* G2's SET_SLOTS return value (for oracle) */
	long		g2_ret;
	/* Stack for G2, allocated by G1; pointer stored here so P can munmap */
	void		*g2_stack;
	/* Orchestrator pid captured before clone(G1); G1 compares getppid()
	 * against this to detect reparenting in the clone()->prctl() window. */
	pid_t		expected_ppid;
	/* Direct-syscall accumulator (RELAXED atomic, same as pivot arm) */
	unsigned long	direct_syscalls;
};

/*
 * G2 body.  Runs after G1 clones it via CLONE_VM|CLONE_VFORK|SIGCHLD.
 * Must NOT set PDEATHSIG -- we intentionally outlive G1 (which we kill).
 */
static int fpr_vfork_g2_fn(void *arg)
{
	struct fpr_vfork_shared *vs = arg;
	struct timespec nap = { .tv_sec = 0, .tv_nsec = 1000000L }; /* 1 ms */
	unsigned int spins;

	/*
	 * Do NOT set PDEATHSIG.  G2 must survive G1's death because G2 is the
	 * one that kills G1 and then races with P.  If P dies unexpectedly the
	 * spin below times out and G2 exits cleanly.
	 */

	/* Publish PID so P can see G2 is live. */
	__atomic_store_n(&vs->g2_pid, (pid_t)getpid(), __ATOMIC_RELEASE);

	/*
	 * Kill G1 (our vfork parent).  SIGKILL is unblockable and is delivered
	 * even to a process suspended in a vfork wait.  G1's death releases P
	 * from its own vfork wait on G1.
	 */
	(void)kill(getppid(), SIGKILL);

	/*
	 * Spin until P signals it is running and ready to race.  P sets
	 * p_ready immediately after reaping G1 and just before its own
	 * SET_SLOTS call, creating a symmetric concurrent window.
	 */
	for (spins = 0; spins < 200; spins++) {
		if (__atomic_load_n(&vs->p_ready, __ATOMIC_ACQUIRE))
			break;
		(void)nanosleep(&nap, NULL);
	}
	if (!__atomic_load_n(&vs->p_ready, __ATOMIC_ACQUIRE))
		_exit(0);

	/* Race: SET_SLOTS on the mm whose phash.ref is still NULL. */
	__atomic_add_fetch(&vs->direct_syscalls, 1, __ATOMIC_RELAXED);
	vs->g2_ret = prctl(PR_FUTEX_HASH, PR_FUTEX_HASH_SET_SLOTS,
			   (int)vs->slot_count, 0, 0);

	__atomic_store_n(&vs->g2_done, 1U, __ATOMIC_RELEASE);
	_exit(0);
}

/*
 * G1 body.  Clones G2 via CLONE_VM|CLONE_VFORK|SIGCHLD then suspends in the
 * kernel's vfork wait.  G2 will SIGKILL G1 to break the vfork chain and
 * release P.  After G2 calls _exit(), G1 is also released and exits.
 */
static int fpr_vfork_g1_fn(void *arg)
{
	struct fpr_vfork_shared *vs = arg;
	pid_t g2_pid;

	(void)prctl(PR_SET_PDEATHSIG, SIGKILL);
	/* Catch reparenting in the clone()->prctl() window; prctl covers after. */
	if (getppid() != vs->expected_ppid)
		_exit(0);

	/*
	 * Allocate G2's stack independently.  CLONE_VFORK with a shared stack
	 * is a classic corruption path: G2 writes its own frame over G1's
	 * locals while G1 is suspended.  Store the pointer in the shared page
	 * so P can munmap it at teardown after G2 has exited.
	 */
	__atomic_add_fetch(&vs->direct_syscalls, 1, __ATOMIC_RELAXED);
	vs->g2_stack = mmap(NULL, FPR_VFORK_STACK_SZ, PROT_READ | PROT_WRITE,
			    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (vs->g2_stack == MAP_FAILED) {
		vs->g2_stack = NULL;
		_exit(0);
	}

	/*
	 * Clone G2 with CLONE_VM|CLONE_VFORK|SIGCHLD.  G1 suspends here until
	 * G2 exits.  G2 will kill us to release P from its vfork wait, then
	 * G2 calls _exit() which releases G1 (already dead via SIGKILL, so
	 * this is a no-op from the kernel's perspective).
	 */
	g2_pid = clone(fpr_vfork_g2_fn,
		       (char *)vs->g2_stack + FPR_VFORK_STACK_SZ,
		       CLONE_VM | CLONE_VFORK | SIGCHLD, vs);
	if (g2_pid < 0) {
		(void)munmap(vs->g2_stack, FPR_VFORK_STACK_SZ);
		vs->g2_stack = NULL;
	}
	/* Released from vfork (by G2's _exit or SIGKILL); exit now. */
	_exit(0);
}

static void fpr_vfork_free_stack(void *stack)
{
	if (stack && stack != MAP_FAILED)
		(void)munmap(stack, FPR_VFORK_STACK_SZ);
}

/*
 * fpr_run_nested_vfork_race - orchestrate the nested-vfork phash.ref race.
 *
 * Forks a throwaway orchestrator so the one-way SET_SLOTS door closes only
 * in a disposable mm.  Inside it:
 *
 *   1. Allocate a MAP_SHARED coordination page.
 *   2. Clone G1 with CLONE_VM|CLONE_VFORK|SIGCHLD.  P suspends in vfork.
 *   3. G1 clones G2 with CLONE_VM|CLONE_VFORK|SIGCHLD.  G1 suspends.
 *   4. G2 kills G1.  G1 dies.  P is released from its vfork wait.
 *   5. P reaps G1, sets p_ready=1, then calls SET_SLOTS.
 *   6. G2 sees p_ready, calls SET_SLOTS concurrently in the same mm.
 *   7. P waits briefly for G2's g2_done flag, then does GET_SLOTS readback.
 *   8. A negative readback bumps vfork_slotmismatch as an oracle signal.
 */
static void fpr_run_nested_vfork_race(struct fpr_shared *s)
{
	pid_t orch_pid;
	int status;

	orch_pid = fork();
	if (orch_pid < 0)
		return;

	if (orch_pid == 0) {
		/* ---- throwaway orchestrator (P): fresh mm ---- */
		struct fpr_vfork_shared *vs;
		void *g1stack = NULL;
		pid_t g1_pid = -1;
		struct timespec nap = { .tv_sec = 0, .tv_nsec = 2000000L }; /* 2 ms */
		unsigned int spins;
		long readback;

		(void)prctl(PR_SET_PDEATHSIG, SIGKILL);
		/* Catch reparenting in the fork()->prctl() window; prctl covers after. */
		if (getppid() != s->expected_ppid)
			_exit(0);

		vs = mmap(NULL, sizeof(*vs), PROT_READ | PROT_WRITE,
			  MAP_ANONYMOUS | MAP_SHARED, -1, 0);
		if (vs == MAP_FAILED)
			_exit(0);
		memset(vs, 0, sizeof(*vs));
		/* G1's expected parent is the orchestrator: capture before clone. */
		vs->expected_ppid = getpid();
		/*
		 * Use a non-zero slot count for the vfork arm.  The one-way door
		 * fires on SET_SLOTS(0) too, but a non-zero count is the common
		 * case and avoids trivially bypassing the per-mm alloc path.
		 */
		vs->slot_count = s->slot_count ? s->slot_count : 4U;

		/* Allocate G1's stack (G1 separately allocates G2's). */
		g1stack = mmap(NULL, FPR_VFORK_STACK_SZ, PROT_READ | PROT_WRITE,
			       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (g1stack == MAP_FAILED)
			goto vfork_child_out;

		/*
		 * Clone G1 with CLONE_VM|CLONE_VFORK|SIGCHLD.  P suspends here.
		 * CLONE_VFORK is the key: need_futex_hash_allocate_default()
		 * returns false for (CLONE_VM|CLONE_VFORK), so copy_process()
		 * skips futex_hash_allocate_default() and phash.ref stays NULL.
		 */
		g1_pid = clone(fpr_vfork_g1_fn,
			       (char *)g1stack + FPR_VFORK_STACK_SZ,
			       CLONE_VM | CLONE_VFORK | SIGCHLD, vs);
		if (g1_pid < 0)
			goto vfork_child_out;

		/*
		 * P was released (G1 killed by G2).  Reap G1 before signalling G2
		 * so the waitpid doesn't race with our SET_SLOTS call.
		 */
		(void)waitpid_eintr(g1_pid, &status, 0);
		g1_pid = -1;

		/*
		 * Set p_ready then call SET_SLOTS immediately.  G2 is spinning on
		 * p_ready; the moment it observes 1 it fires its own SET_SLOTS.
		 * Both tasks are in the same mm with phash.ref == NULL, which is
		 * the exact condition that triggers the kernel defect.
		 */
		__atomic_store_n(&vs->p_ready, 1U, __ATOMIC_RELEASE);
		__atomic_add_fetch(&vs->direct_syscalls, 1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&s->direct_syscalls, 1, __ATOMIC_RELAXED);
		(void)prctl(PR_FUTEX_HASH, PR_FUTEX_HASH_SET_SLOTS,
			    (int)vs->slot_count, 0, 0);

		/* Wait briefly for G2 to finish its SET_SLOTS. */
		for (spins = 0; spins < 50; spins++) {
			if (__atomic_load_n(&vs->g2_done, __ATOMIC_ACQUIRE))
				break;
			(void)nanosleep(&nap, NULL);
		}

		/*
		 * GET_SLOTS readback as oracle.  After both racers, the mm's
		 * slot count must be readable.  A negative return means something
		 * went wrong (possible use-after-free or double-free triggered
		 * the KASAN trap in futex_q_lock()).
		 */
		__atomic_add_fetch(&vs->direct_syscalls, 1, __ATOMIC_RELAXED);
		readback = prctl(PR_FUTEX_HASH, PR_FUTEX_HASH_GET_SLOTS, 0, 0, 0);
		if (readback < 0)
			__atomic_add_fetch(
				&shm->stats.futex_pi_requeue_rollback.vfork_slotmismatch,
				1, __ATOMIC_RELAXED);

		__atomic_add_fetch(
			&shm->stats.futex_pi_requeue_rollback.vfork_runs,
			1, __ATOMIC_RELAXED);

vfork_child_out:
		/* Drain the vfork arm's direct_syscalls into the main counter. */
		__atomic_add_fetch(&s->direct_syscalls,
				   __atomic_load_n(&vs->direct_syscalls,
						   __ATOMIC_RELAXED),
				   __ATOMIC_RELAXED);

		fpr_vfork_free_stack(g1stack);
		if (vs->g2_stack)
			fpr_vfork_free_stack(vs->g2_stack);
		(void)munmap(vs, sizeof(*vs));
		_exit(0);
	}

	/* ---- trinity child waits for the throwaway orchestrator ---- */
	(void)waitpid_eintr(orch_pid, &status, 0);
}

/*
 * Draw PR_FUTEX_HASH_SET_SLOTS argument.
 *
 * Value space: {0} ∪ {2, 4, 8, 16, 32, 64, 128, 256}.
 *
 * Using a 9-outcome draw (r in [0,8]):
 *   r == 0       -> 0       (global-hash-to-private pivot, ~1/9 of calls)
 *   r in [1,8]   -> 1u<<r  (valid power-of-two: 2..256)
 *
 * The 0 one-way door: once a mm calls SET_SLOTS(0) it is permanently pinned
 * to the global hash and every subsequent SET_SLOTS returns -EBUSY.  Because
 * fpr_run_nested_vfork_race() forks a throwaway orchestrator, the door closes
 * only in the disposable mm so subsequent invocations start with a virgin
 * mm->futex.phash.
 */
static unsigned int fpr_pick_slot_count(void)
{
	unsigned int r = rnd_modulo_u32(9);

	if (r == 0)
		return 0U;  /* global-hash-to-private pivot */
	return 1U << r; /* valid power-of-two: {2, 4, 8, 16, 32, 64, 128, 256} */
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
	/*
	 * Two-way arm selection (uniform over {0, 1}):
	 *   0 -> PI/foreign-TID arm (distinct mms, fork())
	 *   1 -> nested-vfork phash.ref NULL-race arm (use_vfork_race)
	 *
	 * The former CLONE_VM pivot-race arm (arm 1 in the original three-way
	 * draw) has been dropped: both copy_process() calling
	 * futex_hash_allocate_default() and the orchestrator's step-1
	 * prctl(SET_SLOTS, N>0) guarantee phash.ref is non-NULL before any
	 * sibling executes, making the kernel/futex/core.c:1844 phash.ref race
	 * unreachable from that arm.
	 */
	{
		unsigned int arm = rnd_modulo_u32(2);

		s->use_vfork_race = (arm == 1) ? 1U : 0U;
	}
	/*
	 * slot_count is the prctl argument the nested-vfork racers use.  Drawn
	 * via fpr_pick_slot_count() which returns 0 (~1/9 probability) for the
	 * global-hash pivot path and a valid power-of-two otherwise.
	 */
	s->slot_count      = s->use_vfork_race ? fpr_pick_slot_count() : 0U;
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
	s->expected_ppid = getpid();
	flag = s->use_private ? FUTEX_PRIVATE_FLAG : 0U;

	if (s->use_vfork_race) {
		/*
		 * Nested-vfork arm: puts two mm-sharing tasks into the same mm
		 * with phash.ref == NULL, then races them on SET_SLOTS to reach
		 * the double-alloc defect at kernel/futex/core.c:1844.
		 * Oracle: KASAN in futex_q_lock() + GET_SLOTS readback.
		 */
		if (valid_op) {
			__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
					   1, __ATOMIC_RELAXED);
			__atomic_add_fetch(&shm->stats.childop.data_path[op],
					   1, __ATOMIC_RELAXED);
		}
		fpr_run_nested_vfork_race(s);
		goto out;
	}

	/*
	 * fork()-based PI/foreign-TID arm (distinct mms required).
	 * Kept intact; do not add use_vfork_race logic here.
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
