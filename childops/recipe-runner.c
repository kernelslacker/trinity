/*
 * recipe_runner - resource-threaded multi-syscall sequences.
 *
 * Trinity picks syscalls independently, so deep kernel object states
 * (a socket in LISTEN with sockopts applied; a memfd written, ftruncated,
 * mmap'd, and sealed; a timerfd configured then read) are unreachable
 * via random isolated calls.  Most of the interesting UAF and refcount
 * bugs sit on the teardown path of an object that's been driven through
 * a specific construction sequence first; random independent calls never
 * reach the precondition.
 *
 * Each recipe is a small DAG: a syscall produces a resource (fd, key,
 * timer id), subsequent syscalls in the recipe consume it, and a
 * teardown step releases it.  Every code path — success, intermediate
 * failure, structural failure — converges on a single goto-cleanup
 * exit so we never leak fds and undo the FD-exhaustion fix.
 *
 * Recipe arg construction is intentionally inline and simple (NULL
 * pointers, page_size for buffers, sensible flags) rather than feeding
 * through trinity's sanitise/random_syscall machinery.  The point of a
 * recipe is the sequence, not argument fuzz; mixing the two would
 * pollute state and trigger errors before we ever reach the
 * interesting transitions.  Argument fuzzing remains the job of the
 * default CHILD_OP_SYSCALL path.
 */

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <linux/memfd.h>

#include "arch.h"
#include "child.h"
#include "compat.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC		0x0001U
#endif
#ifndef MFD_ALLOW_SEALING
#define MFD_ALLOW_SEALING	0x0002U
#endif

struct recipe {
	const char *name;
	bool (*run)(void);
};

/*
 * Recipe 1: timerfd lifecycle.
 *
 * Creates a one-shot relative timerfd, arms it for a few ms in the
 * future, reads its expiration count back (best-effort — may return
 * EAGAIN if the timer hasn't fired yet, that's fine), queries the
 * current setting, then closes.  Exercises the timerfd code path
 * end-to-end including the wait-queue plumbing the read side hits.
 */
static bool recipe_timerfd(void)
{
	struct itimerspec its;
	struct itimerspec cur;
	uint64_t expirations;
	ssize_t r __unused__;
	int fd;
	bool ok = false;

	fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
	if (fd < 0)
		goto out;

	memset(&its, 0, sizeof(its));
	its.it_value.tv_sec = 0;
	its.it_value.tv_nsec = 1000000;	/* 1 ms */
	if (timerfd_settime(fd, 0, &its, NULL) < 0)
		goto out;

	r = read(fd, &expirations, sizeof(expirations));

	if (timerfd_gettime(fd, &cur) < 0)
		goto out;

	ok = true;
out:
	if (fd >= 0)
		close(fd);
	return ok;
}

/*
 * Recipe 2: eventfd ping-pong.
 *
 * Creates an eventfd with semaphore semantics, writes a small counter,
 * reads it back, then writes again to verify the counter resets after
 * a non-semaphore read.  Closes cleanly.
 */
static bool recipe_eventfd(void)
{
	uint64_t v;
	ssize_t r __unused__;
	int fd;
	bool ok = false;

	fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (fd < 0)
		goto out;

	v = 1 + (rand() % 16);
	if (write(fd, &v, sizeof(v)) != (ssize_t)sizeof(v))
		goto out;

	if (read(fd, &v, sizeof(v)) != (ssize_t)sizeof(v))
		goto out;

	v = 7;
	r = write(fd, &v, sizeof(v));

	ok = true;
out:
	if (fd >= 0)
		close(fd);
	return ok;
}

/*
 * Recipe 3: pipe lifecycle (no-fork variant).
 *
 * Trinity already exercises pipe() heavily, but the typical kernel
 * path is "create, then random fcntl/ioctl noise" because fork is too
 * disruptive to inject into the child loop.  This recipe drives the
 * whole pipe through a deliberate sequence: create, write, read
 * back, flip O_NONBLOCK on each end, close.
 */
static bool recipe_pipe(void)
{
	int pfd[2] = { -1, -1 };
	char buf[16];
	bool ok = false;
	int flags;

	if (pipe(pfd) < 0)
		goto out;

	if (write(pfd[1], "trinity-recipe", 14) != 14)
		goto out;

	if (read(pfd[0], buf, sizeof(buf)) <= 0)
		goto out;

	flags = fcntl(pfd[0], F_GETFL);
	if (flags >= 0)
		(void)fcntl(pfd[0], F_SETFL, flags | O_NONBLOCK);

	flags = fcntl(pfd[1], F_GETFL);
	if (flags >= 0)
		(void)fcntl(pfd[1], F_SETFL, flags | O_NONBLOCK);

	ok = true;
out:
	if (pfd[0] >= 0)
		close(pfd[0]);
	if (pfd[1] >= 0)
		close(pfd[1]);
	return ok;
}

/*
 * Recipe 4: epoll lifecycle.
 *
 * Creates an epoll fd, adds an eventfd to it, waits with a 0ms timeout
 * (no event ready), modifies the registration, deletes it, then closes
 * both fds.  Exercises EPOLL_CTL_ADD / MOD / DEL on the same target —
 * the path that hits the rb-tree update and wake-callback registration.
 */
static bool recipe_epoll(void)
{
	struct epoll_event ev;
	struct epoll_event evs[4];
	int epfd = -1;
	int evfd = -1;
	bool ok = false;

	epfd = epoll_create1(EPOLL_CLOEXEC);
	if (epfd < 0)
		goto out;

	evfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (evfd < 0)
		goto out;

	memset(&ev, 0, sizeof(ev));
	ev.events = EPOLLIN;
	ev.data.fd = evfd;
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, evfd, &ev) < 0)
		goto out;

	(void)epoll_wait(epfd, evs, ARRAY_SIZE(evs), 0);

	ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
	(void)epoll_ctl(epfd, EPOLL_CTL_MOD, evfd, &ev);

	if (epoll_ctl(epfd, EPOLL_CTL_DEL, evfd, NULL) < 0)
		goto out;

	ok = true;
out:
	if (evfd >= 0)
		close(evfd);
	if (epfd >= 0)
		close(epfd);
	return ok;
}

/*
 * Recipe 5: signalfd lifecycle.
 *
 * Picks a real-time signal Trinity isn't using, blocks it, attaches a
 * signalfd, performs a non-blocking read (expected to return EAGAIN
 * since nothing is queued), then closes the fd and restores the prior
 * sigmask.  We avoid raise() so we don't perturb the existing child
 * sighandlers — the goal is the signalfd construction/teardown path,
 * not signal delivery itself.
 */
static bool recipe_signalfd(void)
{
	sigset_t ss, oldss;
	struct signalfd_siginfo si;
	ssize_t r __unused__;
	int sfd = -1;
	int sig;
	bool ok = false;
	bool mask_saved = false;

	/* SIGRTMIN+8..+14 — well clear of glibc's reserved RT signals
	 * and Trinity's own SIGALRM/SIGXCPU/SIGINT. */
	sig = SIGRTMIN + 8 + (rand() % 7);
	if (sig >= SIGRTMAX)
		goto out;

	sigemptyset(&ss);
	sigaddset(&ss, sig);
	if (sigprocmask(SIG_BLOCK, &ss, &oldss) < 0)
		goto out;
	mask_saved = true;

	sfd = signalfd(-1, &ss, SFD_NONBLOCK | SFD_CLOEXEC);
	if (sfd < 0)
		goto out;

	r = read(sfd, &si, sizeof(si));

	ok = true;
out:
	if (sfd >= 0)
		close(sfd);
	if (mask_saved)
		(void)sigprocmask(SIG_SETMASK, &oldss, NULL);
	return ok;
}

/*
 * Recipe 6: memfd seal lifecycle.
 *
 * Creates a sealable memfd, writes a page of data, ftruncates to a
 * page size, mmaps it RW, dirties the mapping, then munmaps and seals
 * with F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE.  This is the canonical
 * sequence that exercises the seal-vs-active-mapping accounting and
 * the writable-mapping refcount the seal path checks.
 */
static bool recipe_memfd_seal(void)
{
	int fd = -1;
	void *p = MAP_FAILED;
	char data[64];
	bool ok = false;

	fd = (int)syscall(__NR_memfd_create, "trinity-recipe",
			  MFD_CLOEXEC | MFD_ALLOW_SEALING);
	if (fd < 0)
		goto out;

	memset(data, 'r', sizeof(data));
	if (write(fd, data, sizeof(data)) != (ssize_t)sizeof(data))
		goto out;

	if (ftruncate(fd, page_size) < 0)
		goto out;

	p = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED)
		goto out;

	((volatile char *)p)[0] = (char)(rand() & 0xff);

	if (munmap(p, page_size) < 0)
		goto out;
	p = MAP_FAILED;

	if (fcntl(fd, F_ADD_SEALS,
		  F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE) < 0)
		goto out;

	ok = true;
out:
	if (p != MAP_FAILED)
		munmap(p, page_size);
	if (fd >= 0)
		close(fd);
	return ok;
}

/*
 * Recipe 7: TCP server lifecycle.
 *
 * socket → setsockopt(SO_REUSEADDR) → bind to 127.0.0.1 with port 0
 * (kernel chooses) → listen → accept (non-blocking, expected EAGAIN
 * since nobody connects) → shutdown → close.  Drives the listening
 * socket through its full state-machine setup and teardown so the
 * tcp_close, sk_state_change, and reqsk-queue cleanup paths run.
 */
static bool recipe_tcp_server(void)
{
	struct sockaddr_in sin;
	socklen_t slen;
	int s = -1;
	int one = 1;
	int flags;
	bool ok = false;

	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0)
		goto out;

	(void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = 0;
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) < 0)
		goto out;

	if (listen(s, 4) < 0)
		goto out;

	flags = fcntl(s, F_GETFL);
	if (flags >= 0)
		(void)fcntl(s, F_SETFL, flags | O_NONBLOCK);

	slen = sizeof(sin);
	{
		int conn = accept(s, (struct sockaddr *)&sin, &slen);
		if (conn >= 0)
			close(conn);
	}

	(void)shutdown(s, SHUT_RDWR);

	ok = true;
out:
	if (s >= 0)
		close(s);
	return ok;
}

/*
 * Recipe 8: inotify watch lifecycle.
 *
 * Init an inotify fd, add a watch on /tmp (always exists, attribute
 * changes are common enough to trigger occasional events but the
 * recipe doesn't rely on one firing), perform a non-blocking read
 * (typically EAGAIN), remove the watch, close.  Exercises the
 * inotify_handle_event / fsnotify_destroy_marks teardown paths.
 */
static bool recipe_inotify(void)
{
	char buf[1024];
	ssize_t r __unused__;
	int fd = -1;
	int wd = -1;
	bool ok = false;

	fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
	if (fd < 0)
		goto out;

	wd = inotify_add_watch(fd, "/tmp",
			       IN_CREATE | IN_DELETE | IN_ATTRIB);
	if (wd < 0)
		goto out;

	r = read(fd, buf, sizeof(buf));

	if (inotify_rm_watch(fd, wd) < 0)
		goto out;
	wd = -1;

	ok = true;
out:
	if (wd >= 0)
		(void)inotify_rm_watch(fd, wd);
	if (fd >= 0)
		close(fd);
	return ok;
}

/*
 * Recipe 9: SysV shared-memory segment lifecycle.
 *
 * shmget(IPC_PRIVATE) → shmat → write to the segment → shmdt → shmctl
 * (IPC_RMID).  IPC_PRIVATE keys produce per-process unique segments,
 * so concurrent recipe runs in sibling children don't collide.
 */
static bool recipe_shmget(void)
{
	void *addr = (void *)-1;
	int shmid = -1;
	bool ok = false;

	shmid = shmget(IPC_PRIVATE, page_size, IPC_CREAT | 0600);
	if (shmid < 0)
		goto out;

	addr = shmat(shmid, NULL, 0);
	if (addr == (void *)-1)
		goto out;

	((volatile char *)addr)[0] = (char)(rand() & 0xff);

	if (shmdt(addr) < 0)
		goto out;
	addr = (void *)-1;

	if (shmctl(shmid, IPC_RMID, NULL) < 0)
		goto out;
	shmid = -1;

	ok = true;
out:
	if (addr != (void *)-1)
		(void)shmdt(addr);
	if (shmid >= 0)
		(void)shmctl(shmid, IPC_RMID, NULL);
	return ok;
}

/*
 * Recipe 10: SysV message queue lifecycle.
 *
 * msgget(IPC_PRIVATE) → msgsnd → msgrcv → msgctl(IPC_RMID).
 * Uses a small fixed-size struct so we hit the common-case allocation
 * path without stressing the kernel's per-queue size limits.
 */
struct trinity_msgbuf {
	long mtype;
	char mtext[32];
};

static bool recipe_msgget(void)
{
	struct trinity_msgbuf m;
	int qid = -1;
	bool ok = false;

	qid = msgget(IPC_PRIVATE, IPC_CREAT | 0600);
	if (qid < 0)
		goto out;

	m.mtype = 1;
	memset(m.mtext, 'm', sizeof(m.mtext));
	if (msgsnd(qid, &m, sizeof(m.mtext), IPC_NOWAIT) < 0)
		goto out;

	if (msgrcv(qid, &m, sizeof(m.mtext), 0, IPC_NOWAIT) < 0)
		goto out;

	if (msgctl(qid, IPC_RMID, NULL) < 0)
		goto out;
	qid = -1;

	ok = true;
out:
	if (qid >= 0)
		(void)msgctl(qid, IPC_RMID, NULL);
	return ok;
}

/*
 * Recipe 11: SysV semaphore lifecycle.
 *
 * semget(IPC_PRIVATE, 1) → semop(P=-1) — but only after we've already
 * SETVAL'd the semaphore to 1 so the P doesn't block — then semop(V=+1)
 * → semctl(IPC_RMID).
 *
 * union semun is glibc-private and not declared in any header; callers
 * must provide their own definition per the man page.
 */
union trinity_semun {
	int val;
	struct semid_ds *buf;
	unsigned short *array;
};

static bool recipe_semget(void)
{
	struct sembuf op;
	union trinity_semun arg;
	int sid = -1;
	bool ok = false;

	sid = semget(IPC_PRIVATE, 1, IPC_CREAT | 0600);
	if (sid < 0)
		goto out;

	arg.val = 1;
	if (semctl(sid, 0, SETVAL, arg) < 0)
		goto out;

	op.sem_num = 0;
	op.sem_op = -1;
	op.sem_flg = IPC_NOWAIT;
	if (semop(sid, &op, 1) < 0)
		goto out;

	op.sem_op = 1;
	op.sem_flg = 0;
	if (semop(sid, &op, 1) < 0)
		goto out;

	if (semctl(sid, 0, IPC_RMID) < 0)
		goto out;
	sid = -1;

	ok = true;
out:
	if (sid >= 0)
		(void)semctl(sid, 0, IPC_RMID);
	return ok;
}

/*
 * Recipe 12: POSIX timer lifecycle.
 *
 * timer_create(SIGEV_NONE) — SIGEV_NONE means no notification fires
 * even if the timer expires, which keeps the recipe safe to run inside
 * the existing signal regime — settime relative for a few ms, gettime
 * to read it back, query overrun count, delete.
 */
static bool recipe_posix_timer(void)
{
	struct sigevent sev;
	struct itimerspec its, cur;
	timer_t tid = NULL;
	bool created = false;
	bool ok = false;

	memset(&sev, 0, sizeof(sev));
	sev.sigev_notify = SIGEV_NONE;
	if (timer_create(CLOCK_MONOTONIC, &sev, &tid) < 0)
		goto out;
	created = true;

	memset(&its, 0, sizeof(its));
	its.it_value.tv_sec = 0;
	its.it_value.tv_nsec = 1000000;	/* 1 ms */
	if (timer_settime(tid, 0, &its, NULL) < 0)
		goto out;

	if (timer_gettime(tid, &cur) < 0)
		goto out;

	(void)timer_getoverrun(tid);

	if (timer_delete(tid) < 0)
		goto out;
	created = false;

	ok = true;
out:
	if (created)
		(void)timer_delete(tid);
	return ok;
}

static const struct recipe recipes[] = {
	{ "timerfd",     recipe_timerfd     },
	{ "eventfd",     recipe_eventfd     },
	{ "pipe",        recipe_pipe        },
	{ "epoll",       recipe_epoll       },
	{ "signalfd",    recipe_signalfd    },
	{ "memfd_seal",  recipe_memfd_seal  },
	{ "tcp_server",  recipe_tcp_server  },
	{ "inotify",     recipe_inotify     },
	{ "shmget",      recipe_shmget      },
	{ "msgget",      recipe_msgget      },
	{ "semget",      recipe_semget      },
	{ "posix_timer", recipe_posix_timer },
};

bool recipe_runner(struct childdata *child)
{
	const struct recipe *r;
	bool ok;

	__atomic_add_fetch(&shm->stats.recipe_runs, 1, __ATOMIC_RELAXED);

	r = &recipes[rand() % ARRAY_SIZE(recipes)];

	/* Publish the active recipe name so post-mortem can attribute a
	 * kernel taint to the sequence in flight.  Cleared on completion
	 * regardless of success/failure so a stale name never lingers. */
	child->current_recipe_name = r->name;
	ok = r->run();
	child->current_recipe_name = NULL;

	if (ok)
		__atomic_add_fetch(&shm->stats.recipe_completed, 1, __ATOMIC_RELAXED);
	else
		__atomic_add_fetch(&shm->stats.recipe_partial, 1, __ATOMIC_RELAXED);

	return true;
}
