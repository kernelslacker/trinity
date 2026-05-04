/*
 * close_racer - thread A blocks in a syscall on fd X; thread B closes fd X
 * out from under it.  Targets the kernel fd lookup paths (fdget/fdput,
 * __fget, files_struct->fdt updates) that have to remain consistent under
 * close() racing concurrent fdtable readers.
 *
 * Trinity's normal multi-process fuzzing rarely lands on this race because
 * each child has its own fdtable: a sibling closing the same numeric fd in
 * its own process never races with our fdget.  barrier_racer covers some
 * of this surface for *fork-based* workers, but a fork copies the fdtable
 * — both children get their own struct file refcount and the close-vs-
 * lookup race is in two different fdtables.  Threads share the fdtable,
 * which is the bug class we want.
 *
 * Per invocation: 1..MAX_CYCLES cycles.  Each cycle:
 *
 *   1. socketpair(AF_UNIX, SOCK_STREAM) — fresh fd pair, owned end-to-end
 *      by this op so we never touch trinity's global object pool (kcov fd,
 *      /proc/self/maps, anything add_object'd).  Brief gates this op
 *      against closing OBJ_GLOBAL fds; using a fresh pair sidesteps the
 *      question entirely and avoids fighting the parent's regen loop.
 *      Occasionally pipe2() instead, for path coverage in the pipe ->
 *      file teardown.
 *
 *   2. pthread_create a racer joinable.  Racer issues one of a small
 *      menu of *bounded-timeout* syscalls on sv[0]: poll(POLLIN, ~100ms),
 *      epoll_wait(timeout=100ms), recv() (peer close gives EOF), or
 *      ioctl(FIONREAD) (non-blocking — races at fdget directly).  Bounded
 *      timeouts are the cleanup story: pthread_cancel against a thread
 *      stuck in an uninterruptible read on a regular file is unreliable
 *      and detached threads leak state, so we sidestep both by never
 *      issuing a syscall that could wedge longer than the timeout.  Plain
 *      pthread_join() on the way out then always returns.
 *
 *   3. usleep(0..100us) — variable race window.  Random jitter helps
 *      land different sub-windows of the close path (file_close_fd_locked
 *      vs filp_close vs final fput).
 *
 *   4. close(sv[0]) — the race itself.
 *
 *   5. close(sv[1]) — release valve.  recv() on sv[0] only unblocks once
 *      the peer is closed; the timeout-armed syscalls don't strictly need
 *      this but closing the peer keeps lifetime symmetric.
 *
 *   6. pthread_join(racer) — bounded ≤ ~100ms by construction.
 *
 * Self-bounding: inner cycle hard-capped at MAX_CYCLES.  If pthread_create
 * fails (EAGAIN under thread limits / nproc rlimit) THREAD_SPAWN_LATCH
 * times in a row we bail for the rest of the invocation — there's no
 * point hammering a resource limit that won't lift mid-op, and the
 * alarm(1) the parent arms before dispatch bounds wall-clock time anyway.
 * fork_storm and cgroup_churn can both push us into EAGAIN territory, so
 * the latch is reset only across invocations, not within one.
 */

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <poll.h>

#include "child.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"

/* Hard cap on close/race cycles per invocation.  Each cycle spawns and
 * joins a thread plus syscall round-trips, so 16 keeps a single op well
 * inside the parent's alarm(1) window even under sibling load. */
#define MAX_CYCLES		16

/* Bounded timeout for racer-side blocking syscalls.  Long enough that
 * the close() consistently lands while the racer is mid-syscall, short
 * enough that pthread_join() returns in well under one alarm tick. */
#define RACER_TIMEOUT_MS	100

/* Latch threshold: if pthread_create fails this many times back-to-back
 * inside a single invocation, stop trying for the rest of it. */
#define THREAD_SPAWN_LATCH	3

/* What syscall does the racer thread block on?  All entries here have a
 * kernel-side bounded timeout (or are non-blocking and race in fdget
 * itself), so plain pthread_join always returns within RACER_TIMEOUT_MS
 * regardless of whether close() fired before, during, or after the
 * lookup. */
enum racer_op {
	RACER_POLL,		/* poll(POLLIN, RACER_TIMEOUT_MS) */
	RACER_PPOLL,		/* ppoll(POLLIN, timespec) */
	RACER_EPOLL_WAIT,	/* epoll_wait(epfd, RACER_TIMEOUT_MS) */
	RACER_RECV,		/* recv() — unblocks on peer close (EOF) */
	RACER_IOCTL_FIONREAD,	/* ioctl FIONREAD — non-blocking, races at fdget */
	RACER_OP_NR,
};

struct racer_arg {
	int fd;			/* the fd we race close() against */
	enum racer_op op;
};

static void *racer_thread(void *arg)
{
	struct racer_arg *ra = arg;
	struct pollfd pfd;
	struct timespec ts;
	struct epoll_event ev;
	char buf[64];
	int epfd;
	int val;

	switch (ra->op) {
	case RACER_POLL:
		pfd.fd = ra->fd;
		pfd.events = POLLIN;
		pfd.revents = 0;
		(void)poll(&pfd, 1, RACER_TIMEOUT_MS);
		break;

	case RACER_PPOLL:
		pfd.fd = ra->fd;
		pfd.events = POLLIN;
		pfd.revents = 0;
		ts.tv_sec = 0;
		ts.tv_nsec = (long)RACER_TIMEOUT_MS * 1000000L;
		(void)ppoll(&pfd, 1, &ts, NULL);
		break;

	case RACER_EPOLL_WAIT:
		epfd = epoll_create1(EPOLL_CLOEXEC);
		if (epfd >= 0) {
			ev.events = EPOLLIN;
			ev.data.fd = ra->fd;
			/* EPOLL_CTL_ADD may race close() too — that's fine,
			 * EBADF/EINVAL is still a valid lookup outcome. */
			(void)epoll_ctl(epfd, EPOLL_CTL_ADD, ra->fd, &ev);
			(void)epoll_wait(epfd, &ev, 1, RACER_TIMEOUT_MS);
			close(epfd);
		}
		break;

	case RACER_RECV:
		/* MSG_DONTWAIT off: blocks until peer close (close(sv[1]) by
		 * the main thread) or until close(sv[0]) races us in fdget
		 * and the syscall returns EBADF. */
		(void)recv(ra->fd, buf, sizeof(buf), 0);
		break;

	case RACER_IOCTL_FIONREAD:
		(void)ioctl(ra->fd, FIONREAD, &val);
		break;

	case RACER_OP_NR:
		break;
	}
	return NULL;
}

/* Create a fresh fd pair the op fully owns.  socketpair() is the default
 * because it gives a bidirectional connected channel where closing the
 * peer always unblocks a blocked recv(); pipe2() picks up the pipe-side
 * teardown path occasionally. */
static bool make_fd_pair(int sv[2])
{
	if (RAND_BOOL()) {
		if (pipe2(sv, (int)RAND_NEGATIVE_OR(O_CLOEXEC)) == 0)
			return true;
		/* Fall through to socketpair on pipe2 failure. */
	}
	return socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0;
}

bool close_racer(struct childdata *child)
{
	unsigned int cycles;
	unsigned int i;
	unsigned int spawn_fail_streak = 0;

	(void)child;

	__atomic_add_fetch(&shm->stats.close_racer_runs, 1, __ATOMIC_RELAXED);

	cycles = 1 + ((unsigned int)rand() % MAX_CYCLES);

	for (i = 0; i < cycles; i++) {
		struct racer_arg ra;
		pthread_t tid;
		int sv[2];
		int rc;

		if (!make_fd_pair(sv)) {
			__atomic_add_fetch(&shm->stats.close_racer_failed,
					   1, __ATOMIC_RELAXED);
			continue;
		}

		ra.fd = sv[0];
		ra.op = (enum racer_op)(rand() % RACER_OP_NR);

		rc = pthread_create(&tid, NULL, racer_thread, &ra);
		if (rc != 0) {
			/* EAGAIN under nproc/thread limits is the common case.
			 * Bookkeep, latch the streak, close the fds we just
			 * opened and skip this cycle. */
			__atomic_add_fetch(&shm->stats.close_racer_thread_spawn_fail,
					   1, __ATOMIC_RELAXED);
			close(sv[0]);
			close(sv[1]);
			if (++spawn_fail_streak >= THREAD_SPAWN_LATCH)
				return true;
			continue;
		}
		spawn_fail_streak = 0;

		/* Variable race window — 0..100us picks a random sub-window
		 * of the racer's syscall to land the close in. */
		if ((rand() & 0xff) != 0)
			usleep((useconds_t)(1 + rand() % 100));

		(void)close(sv[0]);
		(void)close(sv[1]);

		(void)pthread_join(tid, NULL);

		__atomic_add_fetch(&shm->stats.close_racer_pairs,
				   1, __ATOMIC_RELAXED);
	}

	return true;
}
