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

/* Within-cycle ordering variations.  Each mode picks a different
 * combination of close vs join vs sleep ordering, landing in a different
 * sub-window of the kernel close-vs-fdget race.  Picked uniformly at
 * random per cycle so a single invocation exercises the whole set. */
enum cycle_mode {
	/* Close sv[0] (the racer's fd) first, then sv[1], then join.
	 * The classic ordering: file_close_fd_locked drops sv[0] from
	 * the table while the racer still holds a __fget'd ref, so
	 * __fput on sv[0] is queued behind syscall return. */
	CYCLE_NORMAL,
	/* Close peer sv[1] before sv[0].  recv() racers see EOF via
	 * peer-close and unblock before sv[0] hits file_close_fd_locked;
	 * exercises peer-side filp_close + final fput before the racer-
	 * fd teardown — opposite half of the teardown ordering. */
	CYCLE_PEER_FIRST,
	/* Close normally, then sleep again before joining.  The racer's
	 * syscall has already returned by the time we sleep, so this
	 * widens the window where the kernel may still be settling final
	 * fput / file_operations->release before pthread_join syncs. */
	CYCLE_POST_SLEEP,
	/* No explicit close in this cycle — defer to function exit,
	 * after pthread_join has returned and the racer thread is gone.
	 * The deferred close therefore drops the only remaining ref and
	 * runs synchronous fput, exercising the post-syscall teardown
	 * path rather than the mid-fdget race. */
	CYCLE_SKIP_CLOSE,
	/* Open 2..MULTI_PAIR_MAX pairs back-to-back with one racer each,
	 * then close all 2*K fds in shuffled order before joining all
	 * racers — sustained fdtable churn under multiple concurrent
	 * fdget references vs the serialised pair-at-a-time pattern. */
	CYCLE_MULTI_PAIR,
	CYCLE_MODE_NR,
};

/* Upper bound on pairs opened concurrently inside one cycle.  Capped at
 * 3 so the worst-case cycle still fits inside the parent's alarm(1)
 * window — racers run concurrently so cycle latency is bounded by
 * RACER_TIMEOUT_MS regardless of K. */
#define MULTI_PAIR_MAX		3

/* Upper bound on deferred-close backlog: worst case every cycle picks
 * CYCLE_SKIP_CLOSE and leaks two fds. */
#define DEFERRED_FD_MAX		(MAX_CYCLES * 2)

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
	int deferred_fds[DEFERRED_FD_MAX];
	unsigned int deferred_n = 0;

	(void)child;

	__atomic_add_fetch(&shm->stats.close_racer_runs, 1, __ATOMIC_RELAXED);

	cycles = 1 + ((unsigned int)rand() % MAX_CYCLES);

	for (i = 0; i < cycles; i++) {
		enum cycle_mode mode = (enum cycle_mode)(rand() % CYCLE_MODE_NR);
		struct racer_arg ra[MULTI_PAIR_MAX];
		pthread_t tid[MULTI_PAIR_MAX];
		int sv[MULTI_PAIR_MAX][2];
		bool spawned[MULTI_PAIR_MAX] = { false };
		unsigned int k = 1;
		unsigned int j;
		unsigned int n_spawned = 0;

		if (mode == CYCLE_MULTI_PAIR)
			k = 2 + ((unsigned int)rand() % 2);

		/* Open all K pairs and spawn racers BEFORE any close, so
		 * multi-pair mode actually has multiple concurrent fdget
		 * references in flight when the close phase starts. */
		for (j = 0; j < k; j++) {
			if (!make_fd_pair(sv[j])) {
				__atomic_add_fetch(&shm->stats.close_racer_failed,
						   1, __ATOMIC_RELAXED);
				continue;
			}
			ra[j].fd = sv[j][0];
			ra[j].op = (enum racer_op)(rand() % RACER_OP_NR);
			if (pthread_create(&tid[j], NULL,
					   racer_thread, &ra[j]) != 0) {
				/* EAGAIN under nproc/thread limits is the
				 * common case.  Bookkeep, close the fds we
				 * just opened, leave latch check for end-of-
				 * cycle so we never bail with already-
				 * spawned-but-unjoined racers. */
				__atomic_add_fetch(&shm->stats.close_racer_thread_spawn_fail,
						   1, __ATOMIC_RELAXED);
				close(sv[j][0]);
				close(sv[j][1]);
				spawn_fail_streak++;
				continue;
			}
			spawned[j] = true;
			n_spawned++;
		}
		if (n_spawned == 0) {
			if (spawn_fail_streak >= THREAD_SPAWN_LATCH)
				return true;
			continue;
		}
		spawn_fail_streak = 0;

		/* Variable race window — 0..100us picks a random sub-window
		 * of the racer's syscall to land the close in. */
		if ((rand() & 0xff) != 0)
			usleep((useconds_t)(1 + rand() % 100));

		switch (mode) {
		case CYCLE_PEER_FIRST:
			(void)close(sv[0][1]);
			(void)close(sv[0][0]);
			break;

		case CYCLE_SKIP_CLOSE:
			/* Defer to function exit so the racer is fully
			 * joined first; the deferred close then drops the
			 * last ref synchronously rather than racing fdget. */
			if (deferred_n + 2 <= DEFERRED_FD_MAX) {
				deferred_fds[deferred_n++] = sv[0][0];
				deferred_fds[deferred_n++] = sv[0][1];
			} else {
				(void)close(sv[0][0]);
				(void)close(sv[0][1]);
			}
			break;

		case CYCLE_MULTI_PAIR: {
			int order[MULTI_PAIR_MAX * 2];
			unsigned int n = 0;

			for (j = 0; j < k; j++) {
				if (!spawned[j])
					continue;
				order[n++] = (int)(j * 2);
				order[n++] = (int)(j * 2 + 1);
			}
			/* Fisher-Yates shuffle — interleaved close across
			 * multiple struct files in one cycle drives sustained
			 * fdtable churn rather than the rigid pair-at-a-time
			 * close ordering. */
			for (j = n; j > 1; j--) {
				unsigned int r = (unsigned int)rand() % j;
				int tmp = order[j - 1];

				order[j - 1] = order[r];
				order[r] = tmp;
			}
			for (j = 0; j < n; j++) {
				int idx = order[j];

				(void)close(sv[idx >> 1][idx & 1]);
			}
			break;
		}

		case CYCLE_NORMAL:
		case CYCLE_POST_SLEEP:
		default:
			(void)close(sv[0][0]);
			(void)close(sv[0][1]);
			if (mode == CYCLE_POST_SLEEP) {
				/* Short post-close sleep: racer's syscall has
				 * returned by now, so this widens the window
				 * where final fput / release may still be
				 * settling before pthread_join syncs. */
				usleep((useconds_t)(1 + rand() % 50));
			}
			break;
		}

		for (j = 0; j < k; j++) {
			if (spawned[j])
				(void)pthread_join(tid[j], NULL);
		}

		__atomic_add_fetch(&shm->stats.close_racer_pairs,
				   n_spawned, __ATOMIC_RELAXED);
	}

	/* Drain deferred closes from CYCLE_SKIP_CLOSE iterations.  All
	 * racer threads have been joined by now, so these closes hit the
	 * post-syscall teardown path rather than the mid-fdget race. */
	for (i = 0; i < deferred_n; i++)
		(void)close(deferred_fds[i]);

	return true;
}
