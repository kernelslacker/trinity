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
#include "syscall-gate.h"
#include "childops-util.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
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
};

static long raw_futex(int *uaddr, int op, unsigned int flag_or, int val,
		      const struct timespec *ts, int *uaddr2, int val3)
{
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
		(void)raw_futex((int *)&s->state, FUTEX_WAIT, 0U, (int)cur,
				&ts, NULL, 0);
	}
	return __atomic_load_n(&s->state, __ATOMIC_ACQUIRE) >= at_least;
}

static void publish_state(struct fpr_shared *s, uint32_t val)
{
	__atomic_store_n(&s->state, val, __ATOMIC_RELEASE);
	(void)raw_futex((int *)&s->state, FUTEX_WAKE, 0U, INT_MAX, NULL, NULL, 0);
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

	if (raw_futex(&s->futex_target_pi, FUTEX_LOCK_PI, flag, 0, NULL, NULL, 0) < 0)
		_exit(0);
	publish_state(s, FPR_STATE_OWNER_READY);

	/*
	 * Block on chain_pi so target_pi's owner is itself a PI waiter --
	 * the exact chain shape rt_mutex_adjust_prio_chain has to walk when
	 * the parent later requeues the waiter onto target_pi's rt_mutex.
	 */
	(void)raw_futex(&s->futex_chain_pi, FUTEX_LOCK_PI, flag, 0, NULL, NULL, 0);
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

	__atomic_store_n(&s->waiter_tid, (pid_t)syscall(__NR_gettid),
			 __ATOMIC_RELEASE);

	if (raw_futex(&s->futex_chain_pi, FUTEX_LOCK_PI, flag, 0, NULL, NULL, 0) < 0)
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
	(void)raw_futex(&s->futex_wait, FUTEX_WAIT_REQUEUE_PI, flag, val,
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
	(void)trinity_raw_syscall(__NR_sched_setattr, waiter_tid, &attr, 0U);
	_exit(0);
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
	flag = s->use_private ? FUTEX_PRIVATE_FLAG : 0U;

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
	if (raw_futex(&s->futex_wait, FUTEX_CMP_REQUEUE_PI, flag,
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
	(void)raw_futex(&s->futex_target_pi, FUTEX_UNLOCK_PI, flag, 0, NULL, NULL, 0);

out:
	fpr_reap_worker(consumer_pid);
	fpr_reap_worker(waiter_pid);
	fpr_reap_worker(owner_pid);
	(void)munmap(s, sizeof(*s));
	return true;
}
