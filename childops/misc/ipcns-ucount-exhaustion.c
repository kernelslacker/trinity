/*
 * ipcns_ucount_exhaustion - exercise the create_ipc_ns() retry block.
 *
 * ipc/namespace.c contains an 'again:' retry loop in create_ipc_ns():
 * when inc_ipc_namespaces() returns false (the user namespace quota is
 * full), the kernel calls flush_work(&free_ipc_work) then retries.  The
 * flushed work body runs synchronize_rcu(), creating an uninterruptible
 * wait from inside an unshare() syscall.  This path has never been
 * exercised by trinity because trinity never writes a small value to
 * /proc/sys/user/max_ipc_namespaces, so the limit is never reached.
 *
 * Three concurrent lanes run inside a fresh user namespace:
 *
 *   Lane A  (limiter):  writes IPCNS_LIMIT to
 *                        /proc/sys/user/max_ipc_namespaces inside the
 *                        new userns, making the quota reachable quickly.
 *
 *   Lane B  (hammers):  HAMMER_NR worker processes each loop
 *                        unshare(CLONE_NEWIPC), rapidly consuming and
 *                        releasing quota so inc_ipc_namespaces() sees
 *                        the limit under contention.
 *
 *   Lane C  (churn):    A sibling forks CHURN_FORKS grandchildren that
 *                        each call unshare(CLONE_NEWIPC) and exit,
 *                        flooding free_ipc_work with pending entries.
 *                        This maximises the window where the count is
 *                        at the limit and a free is simultaneously in
 *                        flight -- the exact condition needed to enter
 *                        the flush_work + retry path.
 *
 * Oracle: CONFIG_DETECT_HUNG_TASK=y on the target kernel.  Signature:
 * "INFO: task ... blocked for more than N seconds".
 * Honest caveat: the upstream RT hang requires CONFIG_PREEMPT_RT to make
 * the flush_work uninterruptible wait block the unshare(2) caller visibly.
 * On !PREEMPT_RT kernels this covers the never-executed retry path only;
 * the specific RT stall may not be visible without a realtime kernel.
 */

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include "child.h"
#include "childop-outcome.h"
#include "childops-util.h"
#include "shm.h"
#include "signals.h"
#include "trinity.h"

/* Quota to install in the userns.  Low enough to be reachable in a
 * handful of unshare() calls; high enough to let multiple workers run
 * concurrently without immediately and permanently blocking. */
#define IPCNS_LIMIT	8

/* Number of parallel hammer workers (Lane B). */
#define HAMMER_NR	4

/* Grandchildren forked by the churn worker (Lane C). */
#define CHURN_FORKS	16

/* Iterations per hammer worker before it exits. */
#define HAMMER_LOOPS	64

/*
 * Wall-clock budget for the outer waitpid() on the inner fork child.
 * If the inner child stalls in D-state (e.g. inside synchronize_rcu()
 * triggered by flush_work(&free_ipc_work)), we stop waiting after this
 * interval, emit the inner_timeout counter, and return.  A D-state
 * process cannot be killed, so we leave it alone and move on.
 * Note: the per-worker waitpid_eintr() calls inside inner_child_main()
 * are not yet bounded; that is left as a follow-up.
 */
#define IPCNS_OUTER_WAIT_NS	500000000L   /* 500 ms */

/*
 * Write one line to a file.  Returns true on success.
 */
static bool ipcns_write_str(const char *path, const char *val,
			    unsigned long *dc)
{
	ssize_t wlen;
	size_t len;
	int fd;

	(*dc)++;
	fd = open(path, O_WRONLY);
	if (fd < 0)
		return false;
	len = strlen(val);
	wlen = write(fd, val, len);
	close(fd);
	*dc += 2;
	return wlen == (ssize_t)len;
}

/*
 * Lane B worker: tight loop of unshare(CLONE_NEWIPC).  Each call
 * replaces the current IPC ns with a fresh one; the displaced ns is
 * scheduled for async release via free_ipc_work.
 */
static void hammer_worker(void)
{
	CHILDOP_GRANDCHILD_ENTER();
	int i;

	for (i = 0; i < HAMMER_LOOPS; i++)
		(void)unshare(CLONE_NEWIPC);
	_exit(0);
}

/*
 * Lane C worker: fork CHURN_FORKS grandchildren each of which calls
 * unshare(CLONE_NEWIPC) and exits.  The rapid fork/unshare/exit pattern
 * keeps free_ipc_work continuously populated while Lane B hammers the
 * limit, creating the inc_ipc_namespaces()-fails-while-work-pending
 * condition that triggers the flush_work + retry path in create_ipc_ns().
 */
static void churn_worker(void)
{
	CHILDOP_GRANDCHILD_ENTER();
	pid_t pids[CHURN_FORKS];
	int i, n = 0;

	for (i = 0; i < CHURN_FORKS; i++) {
		pid_t p = fork();

		if (p < 0)
			break;
		if (p == 0) {
			CHILDOP_GRANDCHILD_ENTER();
			(void)unshare(CLONE_NEWIPC);
			_exit(0);
		}
		pids[n++] = p;
	}
	for (i = 0; i < n; i++)
		waitpid_eintr(pids[i], NULL, 0);
	_exit(0);
}

/*
 * Executed inside the fresh user namespace: install uid/gid maps,
 * write the IPC ns limit (Lane A), then launch Lanes B and C.
 */
static void inner_child_main(unsigned long *dc)
{
	pid_t workers[HAMMER_NR + 1];
	int nworkers = 0;
	uid_t euid = geteuid();
	gid_t egid = getegid();
	char buf[64];
	int i;

	*dc += 2; /* geteuid + getegid */

	(*dc)++;
	if (unshare(CLONE_NEWUSER) != 0)
		_exit(1);

	snprintf(buf, sizeof(buf), "0 %u 1\n", (unsigned int)euid);
	if (!ipcns_write_str("/proc/self/uid_map", buf, dc))
		_exit(2);
	if (!ipcns_write_str("/proc/self/setgroups", "deny\n", dc))
		_exit(2);
	snprintf(buf, sizeof(buf), "0 %u 1\n", (unsigned int)egid);
	if (!ipcns_write_str("/proc/self/gid_map", buf, dc))
		_exit(2);

	/* Lane A: shrink the per-userns IPC namespace quota. */
	snprintf(buf, sizeof(buf), "%d\n", IPCNS_LIMIT);
	if (!ipcns_write_str("/proc/sys/user/max_ipc_namespaces", buf, dc)) {
		__atomic_add_fetch(
			&shm->stats.ipcns_ucount_exhaustion.limit_install_failed,
			1, __ATOMIC_RELAXED);
		_exit(3);
	}

	/* Lane B: hammer workers. */
	for (i = 0; i < HAMMER_NR; i++) {
		pid_t p;

		(*dc)++;
		p = fork();
		if (p < 0)
			break;
		if (p == 0)
			hammer_worker();
		workers[nworkers++] = p;
	}

	/* Lane C: churn worker. */
	(*dc)++;
	{
		pid_t p = fork();

		if (p == 0)
			churn_worker();
		if (p > 0)
			workers[nworkers++] = p;
	}

	for (i = 0; i < nworkers; i++)
		waitpid_eintr(workers[i], NULL, 0);

	__atomic_add_fetch(&shm->stats.ipcns_ucount_exhaustion.runs,
			   1, __ATOMIC_RELAXED);
	_exit(0);
}

bool ipcns_ucount_exhaustion(struct childdata *child)
{
	unsigned long direct_calls = 0;
	unsigned long *shared_dc;
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int)op >= 0 && op < NR_CHILD_OP_TYPES);
	int status;
	pid_t pid;

	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	}

	/*
	 * Map one shared word so inner_child_main() can relay its syscall
	 * tally back to the parent: the forked child has its own address
	 * space copy, so &direct_calls would be inaccessible to the parent
	 * after the fork.
	 */
	direct_calls++;
	shared_dc = mmap(NULL, sizeof(*shared_dc),
			 PROT_READ | PROT_WRITE,
			 MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (shared_dc == MAP_FAILED) {
		if (valid_op)
			childop_direct_syscalls_add(op, direct_calls);
		return true;
	}
	*shared_dc = 0;

	direct_calls++;
	pid = fork();
	if (pid < 0) {
		direct_calls++;
		munmap(shared_dc, sizeof(*shared_dc));
		if (valid_op)
			childop_direct_syscalls_add(op, direct_calls);
		return true;
	}

	if (pid == 0) {
		CHILDOP_GRANDCHILD_ENTER();
		inner_child_main(shared_dc);
		_exit(0); /* unreachable */
	}

	/*
	 * Poll with WNOHANG so a D-state inner child can't hold this
	 * child slot forever.  On timeout, emit inner_timeout and skip
	 * folding the shared tally (the child may still be running).
	 */
	direct_calls++;   /* outer wait, modeled as one logical syscall */
	{
		struct timespec t_start;
		bool inner_reaped = true;

		clock_gettime(CLOCK_MONOTONIC, &t_start);
		for (;;) {
			pid_t r = waitpid_eintr(pid, &status, WNOHANG);

			if (r == pid || r < 0)
				break;
			if (budget_elapsed_ns(&t_start, IPCNS_OUTER_WAIT_NS)) {
				__atomic_add_fetch(
					&shm->stats.ipcns_ucount_exhaustion.inner_timeout,
					1, __ATOMIC_RELAXED);
				(void)waitpid_eintr(pid, &status, WNOHANG);
				inner_reaped = false;
				break;
			}
			{
				struct timespec nap = { 0, 2000000L }; /* 2 ms */

				nanosleep(&nap, NULL);
			}
		}

		if (!inner_reaped) {
			direct_calls++; /* munmap */
			munmap(shared_dc, sizeof(*shared_dc));
			if (valid_op)
				childop_direct_syscalls_add(op, direct_calls);
			return true;
		}
	}

	direct_calls += *shared_dc;   /* fold inner-child syscall tally */
	direct_calls++;               /* munmap */
	munmap(shared_dc, sizeof(*shared_dc));

	if (WIFSIGNALED(status))
		__atomic_add_fetch(
			&shm->stats.ipcns_ucount_exhaustion.inner_crashed,
			1, __ATOMIC_RELAXED);

	if (valid_op)
		childop_direct_syscalls_add(op, direct_calls);
	return true;
}
