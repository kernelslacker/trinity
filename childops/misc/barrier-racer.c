/*
 * barrier-racer: synchronized syscall barrier fuzzer
 *
 * Trinity's normal multi-process fuzzing gives soft concurrency —
 * children overlap by natural scheduling, but the probability of two
 * children hitting exactly the same kernel object in the same
 * instruction window is low.  barrier-racer forces tighter overlap:
 * fork 2-4 inner workers, arm a process-shared pthread barrier so all
 * workers release simultaneously, then have each issue the same syscall
 * against the same shared kernel object.  This maximizes the race
 * window for UAF, refcount underflow, and locking bugs in subsystems
 * that assume single-caller semantics.
 *
 * The op is fully self-contained: setup, race, teardown all happen
 * inside one barrier_racer() call.  The barrier lives in a
 * MAP_ANONYMOUS | MAP_SHARED page, which is the cheapest way to get a
 * PTHREAD_PROCESS_SHARED barrier across fork() without shm_open.
 *
 * Race targets are selected uniformly at random from a curated catalog
 * covering the most exploitable kernel race classes:
 *   double-close, close-while-ioctl, mmap MAP_FIXED overlap,
 *   futex double-wake, dup2 target collision, concurrent ftruncate,
 *   epoll close-while-wait, concurrent fcntl flag flip, and
 *   sigprocmask vs blocking read.
 *
 * Future: integrate with the pthread-based close-while-using racer
 * once that lands — they share the barrier infrastructure.
 */

#include <errno.h>
#include <limits.h>
#include <linux/futex.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <stdlib.h>
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
 * Shared page used by all inner workers for one race round.
 * Lives in an anonymous MAP_SHARED mapping so the barrier is visible
 * across fork() without POSIX shm_open overhead.
 */
struct racer_shared {
	pthread_barrier_t barrier;

	/* Target parameters: set by setup(), read by worker(). */
	int fd;		/* primary fd to race on, or -1 */
	int fd2;	/* secondary fd (dup2 target, epoll pipe), or -1 */
	int futex_val;	/* futex word for FUTEX_WAKE targets */
	void *mmap_addr; /* base of MAP_FIXED reservation, or NULL */
};

struct race_target {
	bool (*setup)(struct racer_shared *s, unsigned long *direct_calls);
	void (*worker)(struct racer_shared *s);
	void (*cleanup)(struct racer_shared *s, unsigned long *direct_calls);
};

/* ------------------------------------------------------------------ */
/* double-close: race two close() calls on the same fd                */
/* ------------------------------------------------------------------ */

static bool setup_double_close(struct racer_shared *s, unsigned long *direct_calls)
{
	int pipefd[2];

	(*direct_calls)++;
	if (pipe(pipefd) < 0)
		return false;
	s->fd = pipefd[0];
	close(pipefd[1]);
	(*direct_calls)++;
	return true;
}

static void worker_double_close(struct racer_shared *s)
{
	close(s->fd);
}

static void cleanup_double_close(struct racer_shared *s, unsigned long *direct_calls)
{
	close(s->fd);	/* best-effort; may already be gone */
	(*direct_calls)++;
}

/* ------------------------------------------------------------------ */
/* close-while-ioctl: race close() vs ioctl(FIONREAD) on the same fd */
/* ------------------------------------------------------------------ */

static bool setup_close_ioctl(struct racer_shared *s, unsigned long *direct_calls)
{
	int pipefd[2];

	(*direct_calls)++;
	if (pipe(pipefd) < 0)
		return false;
	s->fd = pipefd[0];
	close(pipefd[1]);
	(*direct_calls)++;
	return true;
}

static void worker_close_ioctl(struct racer_shared *s)
{
	int val;

	if (rnd_u32() & 1)
		close(s->fd);
	else
		ioctl(s->fd, FIONREAD, &val);
}

static void cleanup_close_ioctl(struct racer_shared *s, unsigned long *direct_calls)
{
	close(s->fd);
	(*direct_calls)++;
}

/* ------------------------------------------------------------------ */
/* mmap MAP_FIXED overlap: two concurrent fixed-address remaps        */
/* ------------------------------------------------------------------ */

static bool setup_mmap_overlap(struct racer_shared *s, unsigned long *direct_calls)
{
	void *addr;

	/*
	 * Reserve a 4-page anonymous region so MAP_FIXED workers stomp
	 * a known-safe VA range rather than clobbering arbitrary mappings.
	 */
	(*direct_calls)++;
	addr = mmap(NULL, 4 * 4096, PROT_READ | PROT_WRITE,
		    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (addr == MAP_FAILED)
		return false;
	s->mmap_addr = addr;
	return true;
}

static void worker_mmap_overlap(struct racer_shared *s)
{
	void *ret;

	ret = mmap(s->mmap_addr, 4096, PROT_READ | PROT_WRITE,
		   MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
	if (ret != MAP_FAILED)
		munmap(ret, 4096);
}

static void cleanup_mmap_overlap(struct racer_shared *s, unsigned long *direct_calls)
{
	munmap(s->mmap_addr, 4 * 4096);
	(*direct_calls)++;
}

/* ------------------------------------------------------------------ */
/* futex double-wake: two concurrent FUTEX_WAKE on the same word      */
/* ------------------------------------------------------------------ */

static bool setup_futex_wake(struct racer_shared *s, unsigned long *direct_calls)
{
	(void)direct_calls;
	s->futex_val = 0;
	return true;
}

static void worker_futex_wake(struct racer_shared *s)
{
	trinity_raw_syscall(__NR_futex, &s->futex_val, FUTEX_WAKE, 1, NULL, NULL, 0);
}

static void cleanup_futex_wake(struct racer_shared *s, unsigned long *direct_calls)
{
	(void)s;
	(void)direct_calls;
}

/* ------------------------------------------------------------------ */
/* dup2 target collision: race dup2(old, target) vs dup2(old, target) */
/* ------------------------------------------------------------------ */

static bool setup_dup2_race(struct racer_shared *s, unsigned long *direct_calls)
{
	int pipefd[2];
	int target = -1;
	int try;

	(*direct_calls)++;
	if (pipe(pipefd) < 0)
		return false;

	/*
	 * Pick a target fd number well above the standard trio, but
	 * verify it isn't already in use.  Trinity holds dozens of fds
	 * above 10 by the time childops dispatch (kcov, fail_nth, fd-event
	 * ring, log, stats ring, shm, pool fds); closing one of them
	 * blindly would silently degrade the rest of this child's life.
	 */
	for (try = 0; try < 8; try++) {
		int candidate = 100 + rnd_modulo_u32(100);

		(*direct_calls)++;
		if (fcntl(candidate, F_GETFD) == -1 && errno == EBADF) {
			target = candidate;
			break;
		}
	}
	if (target == -1) {
		close(pipefd[0]);
		close(pipefd[1]);
		*direct_calls += 2;
		return false;
	}

	s->fd = pipefd[0];
	s->fd2 = target;
	close(pipefd[1]);
	(*direct_calls)++;
	return true;
}

static void worker_dup2_race(struct racer_shared *s)
{
	int newfd = dup2(s->fd, s->fd2);

	if (newfd >= 0)
		close(newfd);
}

static void cleanup_dup2_race(struct racer_shared *s, unsigned long *direct_calls)
{
	close(s->fd);
	close(s->fd2);
	*direct_calls += 2;
}

/* ------------------------------------------------------------------ */
/* ftruncate race: concurrent ftruncate to different lengths          */
/* ------------------------------------------------------------------ */

static bool setup_ftruncate_race(struct racer_shared *s, unsigned long *direct_calls)
{
	char path[PATH_MAX + 32];
	int fd;

	snprintf(path, sizeof(path), "%s/trinity-racer-XXXXXX",
		 trinity_tmpdir_abs());
	/* mkstemp is a libc helper that ultimately drives one open(2) attempt
	 * per candidate name.  Count it as one kernel call at the semantic
	 * level -- an underestimate on collision retries, but matches the
	 * granularity of the surrounding syscall tally. */
	(*direct_calls)++;
	fd = mkstemp(path);
	if (fd < 0)
		return false;
	unlink(path);
	(*direct_calls)++;
	s->fd = fd;
	return true;
}

static void worker_ftruncate_race(struct racer_shared *s)
{
	static const unsigned long sizes[] = { 0, 4096, 8192, 65536, 0 };

	int ret __attribute__((unused));
	ret = ftruncate(s->fd,
			(off_t)RAND_NEGATIVE_OR(sizes[rnd_modulo_u32(ARRAY_SIZE(sizes))]));
}

static void cleanup_ftruncate_race(struct racer_shared *s, unsigned long *direct_calls)
{
	close(s->fd);
	(*direct_calls)++;
}

/* ------------------------------------------------------------------ */
/* epoll close-while-wait: race epoll_wait() vs close(epollfd)        */
/* ------------------------------------------------------------------ */

static bool setup_epoll_race(struct racer_shared *s, unsigned long *direct_calls)
{
	int epfd, pipefd[2];
	struct epoll_event ev;

	(*direct_calls)++;
	epfd = epoll_create1(0);
	if (epfd < 0)
		return false;

	(*direct_calls)++;
	if (pipe(pipefd) < 0) {
		close(epfd);
		(*direct_calls)++;
		return false;
	}

	ev.events = EPOLLIN;
	ev.data.fd = pipefd[0];
	epoll_ctl(epfd, EPOLL_CTL_ADD, pipefd[0], &ev);
	(*direct_calls)++;

	s->fd  = epfd;
	s->fd2 = pipefd[0];
	close(pipefd[1]);
	(*direct_calls)++;
	return true;
}

static void worker_epoll_race(struct racer_shared *s)
{
	struct epoll_event events[1];

	if (rnd_u32() & 1)
		close(s->fd);
	else
		epoll_wait(s->fd, events, 1, 0);
}

static void cleanup_epoll_race(struct racer_shared *s, unsigned long *direct_calls)
{
	close(s->fd);
	close(s->fd2);
	*direct_calls += 2;
}

/* ------------------------------------------------------------------ */
/* fcntl flag flip: concurrent F_SETFL on the same fd                 */
/* ------------------------------------------------------------------ */

static bool setup_fcntl_race(struct racer_shared *s, unsigned long *direct_calls)
{
	int pipefd[2];

	(*direct_calls)++;
	if (pipe(pipefd) < 0)
		return false;
	s->fd = pipefd[0];
	close(pipefd[1]);
	(*direct_calls)++;
	return true;
}

static void worker_fcntl_race(struct racer_shared *s)
{
	int flags = fcntl(s->fd, F_GETFL);

	if (rnd_u32() & 1)
		fcntl(s->fd, F_SETFL, flags ^ O_NONBLOCK);
	else
		fcntl(s->fd, F_SETFL, flags | O_NONBLOCK);
}

static void cleanup_fcntl_race(struct racer_shared *s, unsigned long *direct_calls)
{
	close(s->fd);
	(*direct_calls)++;
}

/* ------------------------------------------------------------------ */
/* sigprocmask vs read: signal mask flip racing a blocking read        */
/* ------------------------------------------------------------------ */

static bool setup_signal_race(struct racer_shared *s, unsigned long *direct_calls)
{
	int pipefd[2];

	(*direct_calls)++;
	if (pipe(pipefd) < 0)
		return false;

	s->fd = pipefd[0];
	/* Pre-load a byte so the read() path doesn't block. */
	ssize_t nw __attribute__((unused));
	nw = write(pipefd[1], "x", 1);
	close(pipefd[1]);
	*direct_calls += 2;
	return true;
}

static void worker_signal_race(struct racer_shared *s)
{
	sigset_t set;
	char buf[4];

	if (rnd_u32() & 1) {
		sigemptyset(&set);
		sigaddset(&set, SIGUSR1);
		sigprocmask(SIG_BLOCK, &set, NULL);
	} else {
		ssize_t nr __attribute__((unused));
		nr = read(s->fd, buf, sizeof(buf));
	}
}

static void cleanup_signal_race(struct racer_shared *s, unsigned long *direct_calls)
{
	close(s->fd);
	(*direct_calls)++;
}

/* ------------------------------------------------------------------ */
/* Target dispatch table                                               */
/* ------------------------------------------------------------------ */

static const struct race_target targets[] = {
	{ setup_double_close,   worker_double_close,   cleanup_double_close   },
	{ setup_close_ioctl,    worker_close_ioctl,    cleanup_close_ioctl    },
	{ setup_mmap_overlap,   worker_mmap_overlap,   cleanup_mmap_overlap   },
	{ setup_futex_wake,     worker_futex_wake,     cleanup_futex_wake     },
	{ setup_dup2_race,      worker_dup2_race,      cleanup_dup2_race      },
	{ setup_ftruncate_race, worker_ftruncate_race, cleanup_ftruncate_race },
	{ setup_epoll_race,     worker_epoll_race,     cleanup_epoll_race     },
	{ setup_fcntl_race,     worker_fcntl_race,     cleanup_fcntl_race     },
	{ setup_signal_race,    worker_signal_race,    cleanup_signal_race    },
};

/* ------------------------------------------------------------------ */
/* Inner worker and outer op entry point                               */
/* ------------------------------------------------------------------ */

static void inner_worker(struct racer_shared *s, const struct race_target *t)
{
	pthread_barrier_wait(&s->barrier);
	t->worker(s);
	_exit(0);
}

bool barrier_racer(struct childdata *child)
{
	struct racer_shared *s;
	const struct race_target *target;
	pthread_barrierattr_t attr;
	unsigned int nworkers;
	pid_t pids[4];
	int i, alive, status;
	/* Direct-syscall tally covering every kernel call issued from the
	 * persistent trinity child body: the setup-page mmap, per-target
	 * setup/cleanup helpers (via *direct_calls out-param), the fork
	 * loop, spawn-fail kill+reap fallback, per-worker waitpid, and the
	 * setup-page munmap.  Inner workers run in forked processes and
	 * are excluded -- their syscalls do not attribute to the persistent
	 * child (matches the close-racer pattern where same-process racer
	 * threads WERE counted, but forked workers are separate PIDs). */
	unsigned long direct_calls = 0;

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	__atomic_add_fetch(&shm->stats.barrier_racer.runs, 1, __ATOMIC_RELAXED);

	nworkers = 2 + rnd_modulo_u32(3);	/* 2, 3, or 4 workers */
	target = &targets[rnd_modulo_u32(ARRAY_SIZE(targets))];

	/*
	 * Shared memory for the barrier + per-round parameters.
	 * MAP_SHARED so the pthread barrier (PTHREAD_PROCESS_SHARED) is
	 * visible to all forked workers without shm_open overhead.
	 */
	direct_calls++;
	s = mmap(NULL, sizeof(*s), PROT_READ | PROT_WRITE,
		 MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	if (s == MAP_FAILED)
		goto out_publish;

	s->fd       = -1;
	s->fd2      = -1;
	s->futex_val = 0;
	s->mmap_addr = NULL;

	if (pthread_barrierattr_init(&attr) != 0)
		goto out_unmap;

	if (pthread_barrierattr_setpshared(&attr, PTHREAD_PROCESS_SHARED) != 0) {
		pthread_barrierattr_destroy(&attr);
		goto out_unmap;
	}

	if (pthread_barrier_init(&s->barrier, &attr, nworkers) != 0) {
		pthread_barrierattr_destroy(&attr);
		goto out_unmap;
	}
	pthread_barrierattr_destroy(&attr);

	if (!target->setup(s, &direct_calls))
		goto out_barrier;

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	alive = 0;
	for (i = 0; i < (int)nworkers; i++) {
		pid_t pid;

		direct_calls++;
		pid = fork();

		if (pid < 0)
			break;
		if (pid == 0) {
			CHILDOP_GRANDCHILD_ENTER();
			inner_worker(s, target);
			_exit(0);	/* unreachable */
		}
		pids[alive++] = pid;
	}

	/*
	 * If we couldn't fork enough workers to fill the barrier slots,
	 * the unfilled slots will stall the barrier forever.  Kill any
	 * workers that did start before they block on the barrier, then
	 * skip to cleanup.
	 */
	if (alive < (int)nworkers) {
		for (i = 0; i < alive; i++)
			kill(pids[i], SIGKILL);
		for (i = 0; i < alive; i++)
			waitpid_eintr(pids[i], &status, 0);
		direct_calls += (unsigned long)alive * 2UL;
		goto out_cleanup;
	}

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);

	for (i = 0; i < alive; i++) {
		direct_calls++;
		if (waitpid_eintr(pids[i], &status, 0) < 0)
			continue;
		if (WIFSIGNALED(status))
			__atomic_add_fetch(&shm->stats.barrier_racer.inner_crashed,
					   1, __ATOMIC_RELAXED);
	}

out_cleanup:
	target->cleanup(s, &direct_calls);
out_barrier:
	pthread_barrier_destroy(&s->barrier);
out_unmap:
	munmap(s, sizeof(*s));
	direct_calls++;
out_publish:
	if (valid_op)
		childop_direct_syscalls_add(op, direct_calls);
	return true;
}
