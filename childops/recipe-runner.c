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
#include <limits.h>
#include <mqueue.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/fanotify.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <linux/futex.h>
#include <linux/memfd.h>
#include <linux/userfaultfd.h>

#include "arch.h"
#include "child.h"
#include "compat.h"
#include "random.h"
#include "shm.h"
#include "stats.h"
#include "trinity.h"
#include "utils.h"

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC		0x0001U
#endif
#ifndef MFD_ALLOW_SEALING
#define MFD_ALLOW_SEALING	0x0002U
#endif

/*
 * A discoverable recipe sets *unsupported = true on its first failed
 * probe to indicate the kernel lacks the relevant feature (ENOSYS,
 * missing CONFIG_*, etc.).  The dispatcher latches the recipe off in
 * shm so siblings stop probing.  Non-discoverable recipes leave the
 * pointer NULL.
 */
struct recipe {
	const char *name;
	bool (*run)(bool *unsupported);
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
static bool recipe_timerfd(bool *unsupported __unused__)
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
static bool recipe_eventfd(bool *unsupported __unused__)
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
static bool recipe_pipe(bool *unsupported __unused__)
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
static bool recipe_epoll(bool *unsupported __unused__)
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
static bool recipe_signalfd(bool *unsupported __unused__)
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
static bool recipe_memfd_seal(bool *unsupported __unused__)
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
static bool recipe_tcp_server(bool *unsupported __unused__)
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
static bool recipe_inotify(bool *unsupported __unused__)
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
static bool recipe_shmget(bool *unsupported __unused__)
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

static bool recipe_msgget(bool *unsupported __unused__)
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

static bool recipe_semget(bool *unsupported __unused__)
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
static bool recipe_posix_timer(bool *unsupported __unused__)
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

/*
 * Recipe 13: POSIX message queue lifecycle.
 *
 * mq_open(O_CREAT | O_EXCL) → mq_send → mq_receive → mq_close →
 * mq_unlink.  CONFIG_POSIX_MQUEUE may be off on stripped-down kernels
 * — first failure with ENOSYS or ENOENT (mqueue not mounted) latches
 * the recipe off via *unsupported.
 *
 * The queue name embeds getpid() to keep concurrent recipe runs in
 * sibling children from racing on a shared name; O_EXCL gives us a
 * second layer of safety against name collisions on retry.
 */
static bool recipe_mq_open(bool *unsupported)
{
	struct mq_attr attr;
	char qname[64];
	mqd_t q = (mqd_t)-1;
	char buf[128];
	bool ok = false;

	snprintf(qname, sizeof(qname), "/trinity-recipe-%d-%u",
		 (int)getpid(), (unsigned int)rand());

	memset(&attr, 0, sizeof(attr));
	attr.mq_maxmsg = 4;
	attr.mq_msgsize = 64;
	q = mq_open(qname, O_CREAT | O_EXCL | O_RDWR | O_NONBLOCK,
		    0600, &attr);
	if (q == (mqd_t)-1) {
		if (errno == ENOSYS || errno == ENOENT) {
			*unsupported = true;
			__atomic_add_fetch(&shm->stats.recipe_unsupported, 1,
					   __ATOMIC_RELAXED);
		}
		goto out;
	}

	if (mq_send(q, "trinity", 7, 0) < 0)
		goto out;

	if (mq_receive(q, buf, sizeof(buf), NULL) < 0)
		goto out;

	if (mq_close(q) < 0)
		goto out;
	q = (mqd_t)-1;

	if (mq_unlink(qname) < 0)
		goto out;

	ok = true;
out:
	if (q != (mqd_t)-1) {
		(void)mq_close(q);
		(void)mq_unlink(qname);
	}
	return ok;
}

/*
 * Recipe 14: futex lifecycle on a shared anonymous mapping.
 *
 * mmap MAP_SHARED | MAP_ANONYMOUS → futex(FUTEX_WAIT) with a short
 * timeout (expected to return ETIMEDOUT immediately because the value
 * doesn't match) → futex(FUTEX_WAKE) on the same address (zero waiters
 * to wake) → munmap.  Exercises the futex hash-bucket lookup, the
 * timeout path, and the cleanup of the futex queue.
 *
 * Using MAP_SHARED puts the futex on the shared key path inside the
 * kernel, which is the more interesting variant — the private path is
 * what most application code hits.
 */
static bool recipe_futex(bool *unsupported __unused__)
{
	struct timespec ts;
	uint32_t *futex_addr = MAP_FAILED;
	bool ok = false;

	futex_addr = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
			  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (futex_addr == MAP_FAILED)
		goto out;

	*futex_addr = 0;

	ts.tv_sec = 0;
	ts.tv_nsec = 1000000;	/* 1 ms */
	/* Pass an expected value of 1, but the actual value is 0 — the
	 * kernel returns EAGAIN immediately without queuing.  This still
	 * exercises the hash lookup and the futex_wait_setup path. */
	(void)syscall(__NR_futex, futex_addr, FUTEX_WAIT, 1, &ts,
		      NULL, 0);

	(void)syscall(__NR_futex, futex_addr, FUTEX_WAKE, INT_MAX,
		      NULL, NULL, 0);

	ok = true;
out:
	if (futex_addr != MAP_FAILED)
		(void)munmap(futex_addr, page_size);
	return ok;
}

/*
 * Recipe 15: fanotify watch lifecycle.
 *
 * fanotify_init(FAN_CLASS_NOTIF | FAN_NONBLOCK) → fanotify_mark(ADD)
 * on /tmp → non-blocking read (typically EAGAIN) → fanotify_mark
 * (REMOVE) → close.  Requires CAP_SYS_ADMIN on most kernels — first
 * EPERM/ENOSYS latches the recipe off.
 */
static bool recipe_fanotify(bool *unsupported)
{
	char buf[1024];
	int fd = -1;
	bool marked = false;
	ssize_t r __unused__;
	bool ok = false;

	fd = fanotify_init(FAN_CLASS_NOTIF | FAN_NONBLOCK | FAN_CLOEXEC,
			   O_RDONLY);
	if (fd < 0) {
		if (errno == EPERM || errno == ENOSYS) {
			*unsupported = true;
			__atomic_add_fetch(&shm->stats.recipe_unsupported, 1,
					   __ATOMIC_RELAXED);
		}
		goto out;
	}

	if (fanotify_mark(fd, FAN_MARK_ADD,
			  FAN_MODIFY | FAN_ACCESS, AT_FDCWD, "/tmp") < 0)
		goto out;
	marked = true;

	r = read(fd, buf, sizeof(buf));

	if (fanotify_mark(fd, FAN_MARK_REMOVE,
			  FAN_MODIFY | FAN_ACCESS, AT_FDCWD, "/tmp") < 0)
		goto out;
	marked = false;

	ok = true;
out:
	if (marked)
		(void)fanotify_mark(fd, FAN_MARK_REMOVE,
				    FAN_MODIFY | FAN_ACCESS,
				    AT_FDCWD, "/tmp");
	if (fd >= 0)
		close(fd);
	return ok;
}

/*
 * Recipe 16: userfaultfd lifecycle.
 *
 * userfaultfd → ioctl(UFFDIO_API) → mmap a private region →
 * ioctl(UFFDIO_REGISTER) for missing-page faults → ioctl
 * (UFFDIO_UNREGISTER) → munmap → close.  We deliberately don't
 * touch the registered region from the same thread (that would block
 * forever waiting for a userfaultfd handler to fill the page).
 *
 * userfaultfd may be off (vm.unprivileged_userfaultfd=0 plus no
 * CAP_SYS_PTRACE, or kernel built without CONFIG_USERFAULTFD) —
 * EPERM/ENOSYS latches the recipe off.
 */
static bool recipe_userfaultfd(bool *unsupported)
{
	struct uffdio_api api;
	struct uffdio_register reg;
	struct uffdio_range range;
	void *region = MAP_FAILED;
	int fd = -1;
	bool registered = false;
	bool ok = false;

	fd = (int)syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
	if (fd < 0) {
		if (errno == EPERM || errno == ENOSYS) {
			*unsupported = true;
			__atomic_add_fetch(&shm->stats.recipe_unsupported, 1,
					   __ATOMIC_RELAXED);
		}
		goto out;
	}

	memset(&api, 0, sizeof(api));
	api.api = UFFD_API;
	if (ioctl(fd, UFFDIO_API, &api) < 0)
		goto out;

	region = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (region == MAP_FAILED)
		goto out;

	memset(&reg, 0, sizeof(reg));
	reg.range.start = (uintptr_t)region;
	reg.range.len = page_size;
	reg.mode = UFFDIO_REGISTER_MODE_MISSING;
	if (ioctl(fd, UFFDIO_REGISTER, &reg) < 0)
		goto out;
	registered = true;

	range.start = (uintptr_t)region;
	range.len = page_size;
	if (ioctl(fd, UFFDIO_UNREGISTER, &range) < 0)
		goto out;
	registered = false;

	ok = true;
out:
	if (registered) {
		range.start = (uintptr_t)region;
		range.len = page_size;
		(void)ioctl(fd, UFFDIO_UNREGISTER, &range);
	}
	if (region != MAP_FAILED)
		(void)munmap(region, page_size);
	if (fd >= 0)
		close(fd);
	return ok;
}

/*
 * Recipe 17: file-lease lifecycle.
 *
 * Open a fresh per-pid file under /tmp → unlink immediately so the
 * fd is the sole reference → fcntl(F_SETLEASE, F_RDLCK) to install a
 * read lease → F_GETLEASE to read it back → upgrade to F_WRLCK →
 * release with F_UNLCK → close.
 *
 * Drives the file_lock alloc/free path and the lm_setup / lm_change
 * vfs_setlease callbacks.  F_WRLCK upgrade requires no other openers
 * of the inode, which is guaranteed because the file is anonymous
 * (already unlinked) and the fd lives only in this process.
 *
 * F_SETLEASE may fail with EACCES (caller lacks CAP_LEASE and isn't
 * the owner — shouldn't happen since we just created the file but
 * not impossible under exotic credential setups), ENOLCK (kernel lock
 * cache exhausted), or EAGAIN (lease conflict raced).  Any of those
 * latches the recipe off via *unsupported.
 */
static bool recipe_vfs_leases(bool *unsupported)
{
	char path[64];
	int fd = -1;
	int lease;
	bool ok = false;

	snprintf(path, sizeof(path), "/tmp/trinity-recipe-lease-%d-%u",
		 (int)getpid(), (unsigned int)rand());

	fd = open(path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
	if (fd < 0)
		goto out;

	/* Unlink immediately — the file lives only via this fd, so
	 * concurrent recipe runs in sibling children can't race to open
	 * it and break the F_WRLCK upgrade preconditions. */
	(void)unlink(path);

	if (fcntl(fd, F_SETLEASE, F_RDLCK) < 0) {
		if (errno == EACCES || errno == ENOLCK || errno == EAGAIN) {
			*unsupported = true;
			__atomic_add_fetch(&shm->stats.recipe_unsupported, 1,
					   __ATOMIC_RELAXED);
		}
		goto out;
	}

	lease = fcntl(fd, F_GETLEASE);
	if (lease < 0)
		goto out;

	if (fcntl(fd, F_SETLEASE, F_WRLCK) < 0)
		goto out;

	if (fcntl(fd, F_SETLEASE, F_UNLCK) < 0)
		goto out;

	ok = true;
out:
	if (fd >= 0)
		close(fd);
	return ok;
}

/*
 * Recipe 18: anon-VMA split-and-coalesce lifecycle.
 *
 * mmap a 4-page private anonymous region → dirty every page so the
 * VMA owns populated PTEs → mprotect the middle two pages to PROT_READ
 * (splits one VMA into three: [RW][R][RW]) → mprotect them back to
 * RW (vma_merge collapses the three into one again) → munmap the
 * single middle page (re-splits with an unmapped hole) → munmap the
 * full original range (kernel walks the residual head + tail VMAs
 * across the punched gap).
 *
 * Exercises split_vma, vma_merge, and the munmap-with-hole path in
 * one sequence — all three are common UAF/refcount fault sites that
 * isolated random mmap/munmap calls rarely reach because they need a
 * specific multi-VMA layout to begin with.  The existing
 * mprotect-split childop drives the split path with random
 * arguments; this recipe forces the deterministic split→merge→hole
 * trajectory the random caller almost never hits.
 */
static bool recipe_mm_vma(bool *unsupported __unused__)
{
	void *region = MAP_FAILED;
	size_t total = (size_t)page_size * 4;
	char *base;
	bool ok = false;

	region = mmap(NULL, total, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (region == MAP_FAILED)
		goto out;
	base = region;

	base[0 * page_size] = 'a';
	base[1 * page_size] = 'b';
	base[2 * page_size] = 'c';
	base[3 * page_size] = 'd';

	/* Split: middle two pages drop to PROT_READ.  Single VMA
	 * becomes three: [RW][R][RW]. */
	if (mprotect(base + page_size, (size_t)page_size * 2,
		     PROT_READ) < 0)
		goto out;

	/* Coalesce: promote middle back to RW.  vma_merge should fold
	 * all three fragments back into one VMA. */
	if (mprotect(base + page_size, (size_t)page_size * 2,
		     PROT_READ | PROT_WRITE) < 0)
		goto out;

	/* Punch a hole — splits the (now-merged) VMA again, this time
	 * with a real unmapped gap between the surviving fragments. */
	if (munmap(base + page_size, page_size) < 0)
		goto out;

	/* Tear down everything that's left.  munmap across an unmapped
	 * region is well-defined; the kernel just unmaps what's still
	 * present.  This is the path we want to drive. */
	if (munmap(region, total) < 0)
		goto out;
	region = MAP_FAILED;

	ok = true;
out:
	if (region != MAP_FAILED)
		(void)munmap(region, total);
	return ok;
}

/*
 * Recipe 19: memfd-as-mmap-source lifecycle.
 *
 * memfd_create(MFD_CLOEXEC) → ftruncate to 4 pages → mmap MAP_SHARED
 * over the whole file → write a distinct byte to each page (faulting
 * in four shmem pages) → read each one back to verify the page-cache
 * round-trip → munmap → close.
 *
 * Distinct from recipe_memfd_seal: that recipe targets the seal
 * accounting path (sealable memfd, write-then-seal); this one drives
 * the plain memfd-as-anon-file mmap/fault path so the shmem fault
 * handler, page-cache insertion, and mapping teardown all run in one
 * sequence.  Together they cover both the storage and the locking
 * faces of memfd.
 *
 * memfd_create may be missing on stripped-down kernels (very old, or
 * built without CONFIG_MEMFD_CREATE) — ENOSYS latches the recipe off.
 */
static bool recipe_mm_memfd(bool *unsupported)
{
	int fd = -1;
	void *p = MAP_FAILED;
	size_t total = (size_t)page_size * 4;
	char *base;
	size_t i;
	bool ok = false;

	fd = (int)syscall(__NR_memfd_create, "trinity-recipe-mm-memfd",
			  MFD_CLOEXEC);
	if (fd < 0) {
		if (errno == ENOSYS) {
			*unsupported = true;
			__atomic_add_fetch(&shm->stats.recipe_unsupported, 1,
					   __ATOMIC_RELAXED);
		}
		goto out;
	}

	if (ftruncate(fd, (off_t)total) < 0)
		goto out;

	p = mmap(NULL, total, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED)
		goto out;
	base = p;

	for (i = 0; i < total; i += page_size)
		base[i] = (char)('m' + (i / page_size));

	for (i = 0; i < total; i += page_size)
		if (((volatile char *)base)[i] !=
		    (char)('m' + (i / page_size)))
			goto out;

	if (munmap(p, total) < 0)
		goto out;
	p = MAP_FAILED;

	ok = true;
out:
	if (p != MAP_FAILED)
		(void)munmap(p, total);
	if (fd >= 0)
		close(fd);
	return ok;
}

/*
 * Send a single fd over an AF_UNIX socket via SCM_RIGHTS ancillary
 * data.  Helper for recipe_net_unix_gc, which needs to construct a
 * deliberate fd-cycle topology in the unix garbage collector's view.
 *
 * Returns the sendmsg() return value (1 on success — the iov is one
 * filler byte; AF_UNIX sendmsg with empty iov but non-empty cmsg is
 * undefined on some kernels, so we always carry at least one data
 * byte).  Negative on failure with errno set.
 */
static ssize_t scm_send_one_fd(int sock, int fd)
{
	struct msghdr msg;
	struct iovec iov;
	struct cmsghdr *cmsg;
	char filler = 'g';
	char cmsgbuf[CMSG_SPACE(sizeof(int))];

	memset(&msg, 0, sizeof(msg));
	memset(cmsgbuf, 0, sizeof(cmsgbuf));

	iov.iov_base = &filler;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

	return sendmsg(sock, &msg, 0);
}

/*
 * Bound on racer-side blocking syscalls in 2nd-thread recipes.  Long
 * enough that a close() consistently lands while the racer is mid-
 * syscall, short enough that pthread_join() returns in well under one
 * alarm tick.  Mirrors close-racer.c's RACER_TIMEOUT_MS.
 */
#define RECIPE_RACER_TIMEOUT_MS		100

/*
 * Latch threshold: if pthread_create fails this many times back-to-back
 * inside a single recipe invocation, stop trying for the rest of it.
 * Mirrors close-racer.c's THREAD_SPAWN_LATCH.  fork_storm or cgroup_churn
 * can push us into EAGAIN territory on nproc/thread limits, and there is
 * no point hammering a limit that won't lift mid-op.
 */
#define RECIPE_THREAD_SPAWN_LATCH	3

/*
 * Recipe 20: AF_UNIX garbage-collector cycle lifecycle.
 *
 * Build two AF_UNIX socketpairs and use SCM_RIGHTS to wire a reference
 * cycle the kernel can only break via unix_gc():
 *
 *   socketpair() -> sv1[0] <-> sv1[1]
 *   socketpair() -> sv2[0] <-> sv2[1]
 *   sendmsg(sv1[0], SCM_RIGHTS, [sv2[1]])  // sv2[1] queued in sv1[1]
 *   sendmsg(sv2[0], SCM_RIGHTS, [sv1[1]])  // sv1[1] queued in sv2[1]
 *
 * After all four user fds are closed, sv1[1] and sv2[1] are kept alive
 * solely by the in-flight refs in each other's receive queues.  No fd
 * table holds them; each is reachable only via the other.  The unix
 * garbage collector (net/unix/garbage.c) has to walk the in-flight
 * graph, identify the unreachable cycle, and tear both down — the path
 * with the long history of UAFs and refcount mismatches (CVE-2021-0920,
 * CVE-2022-32296, the 2024 unix_gc rework, etc.).
 *
 * Random callers of sendmsg+SCM_RIGHTS in trinity rarely build a cycle
 * — they pass random fds, almost never both ends of a freshly-paired
 * socket — so the GC cycle path stays cold without a deliberate recipe
 * to drive it.
 *
 * Cleanup closes anything still open on every exit path.  In the happy
 * case all four fds are already cleared to -1 before we fall through.
 */
static bool recipe_net_unix_gc(bool *unsupported __unused__)
{
	int sv1[2] = { -1, -1 };
	int sv2[2] = { -1, -1 };
	bool ok = false;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv1) < 0)
		goto out;
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv2) < 0)
		goto out;

	if (scm_send_one_fd(sv1[0], sv2[1]) != 1)
		goto out;

	if (scm_send_one_fd(sv2[0], sv1[1]) != 1)
		goto out;

	/* Drop every user-visible reference.  sv1[1] and sv2[1] now live
	 * only via the SCM_RIGHTS payloads queued in each other — a cycle
	 * unreachable from any fdtable.  Closing in this order forces the
	 * GC to reckon with the cycle on the next teardown pass. */
	close(sv1[0]); sv1[0] = -1;
	close(sv1[1]); sv1[1] = -1;
	close(sv2[0]); sv2[0] = -1;
	close(sv2[1]); sv2[1] = -1;

	ok = true;
out:
	if (sv1[0] >= 0)
		close(sv1[0]);
	if (sv1[1] >= 0)
		close(sv1[1]);
	if (sv2[0] >= 0)
		close(sv2[0]);
	if (sv2[1] >= 0)
		close(sv2[1]);
	return ok;
}

/*
 * Racer thread for recipe_net_tcp.  Blocks in poll() with a bounded
 * timeout, then attempts accept() on the (possibly already-closed)
 * listen fd.  Both calls have hard ceilings: poll's is the timeout
 * argument; accept inherits the fd's O_NONBLOCK so it returns
 * immediately with EAGAIN/EBADF/EINVAL regardless of whether the
 * close raced ahead, mid-syscall, or behind it.
 *
 * EBADF is the fdget-vs-close lookup race we are hunting; EINVAL is
 * the in-flight close caught at the LISTEN-state check; success is
 * the close-after-accept-completed sub-window (no peer ever connects,
 * so accept won't actually return a connection — the path is reached
 * only via a pending SYN that landed under the bind+listen window).
 */
struct tcp_racer_arg {
	int listen_fd;
};

static void *tcp_racer_thread(void *arg)
{
	struct tcp_racer_arg *ra = arg;
	struct sockaddr_in sin;
	socklen_t slen = sizeof(sin);
	struct pollfd pfd;
	int conn;

	pfd.fd = ra->listen_fd;
	pfd.events = POLLIN;
	pfd.revents = 0;
	(void)poll(&pfd, 1, RECIPE_RACER_TIMEOUT_MS);

	conn = accept(ra->listen_fd, (struct sockaddr *)&sin, &slen);
	if (conn >= 0)
		close(conn);
	return NULL;
}

/*
 * Recipe 21: TCP listening-socket close-vs-accept race.
 *
 * Per cycle (1..MAX_CYCLES):
 *
 *   socket(AF_INET, SOCK_STREAM) -> setsockopt(SO_REUSEADDR) -> bind to
 *   127.0.0.1:0 (kernel picks port) -> listen -> O_NONBLOCK -> spawn
 *   racer thread blocked in poll(POLLIN, 100ms) + accept() -> usleep
 *   0..100us race-window jitter -> close(s) (the race) -> pthread_join.
 *
 * Targets the kernel paths inet_csk_listen_stop, inet_csk_destroy_sock,
 * tcp_close, and the request-sock-queue teardown that fire when a
 * listening socket is destroyed while another task is mid-accept().
 * Threads share the fdtable, which is the bug class — a sibling
 * process closing the same numeric fd in its own table never races
 * with our fdget.  Distinct from recipe_tcp_server (recipe 7) which
 * runs accept-then-close serially on a single thread; this one drives
 * the *concurrent* accept-vs-close window.
 *
 * Bounded racer syscalls (poll with timeout, accept on O_NONBLOCK fd)
 * mean plain pthread_join always returns within ~100ms.  Sidesteps the
 * wedge problem where pthread_cancel against a thread stuck in an
 * uninterruptible read is unreliable and detached threads leak state.
 *
 * THREAD_SPAWN_LATCH=3 consecutive pthread_create failures bails for
 * the rest of the invocation — under nproc/thread limits the EAGAIN
 * won't lift mid-op while fork_storm or cgroup_churn are competing for
 * the budget.
 *
 * Returns ok=true if any cycle reached close+join.  All-cycles-failed
 * counts as partial.  Per-cycle failures are tolerated mid-loop because
 * one bad cycle (e.g. ephemeral port exhaustion under sibling load)
 * shouldn't penalise the whole recipe.
 */
#define RECIPE_NET_TCP_MAX_CYCLES	4

static bool recipe_net_tcp(bool *unsupported __unused__)
{
	unsigned int cycles;
	unsigned int i;
	unsigned int spawn_fail_streak = 0;
	unsigned int completed = 0;

	cycles = 1 + ((unsigned int)rand() % RECIPE_NET_TCP_MAX_CYCLES);

	for (i = 0; i < cycles; i++) {
		struct tcp_racer_arg ra;
		struct sockaddr_in sin;
		pthread_t tid;
		int s = -1;
		int one = 1;
		int flags;
		int rc;

		s = socket(AF_INET, SOCK_STREAM, 0);
		if (s < 0)
			continue;

		(void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
				 &one, sizeof(one));

		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_port = 0;
		sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
			close(s);
			continue;
		}

		if (listen(s, 4) < 0) {
			close(s);
			continue;
		}

		flags = fcntl(s, F_GETFL);
		if (flags >= 0)
			(void)fcntl(s, F_SETFL, flags | O_NONBLOCK);

		ra.listen_fd = s;
		rc = pthread_create(&tid, NULL, tcp_racer_thread, &ra);
		if (rc != 0) {
			close(s);
			if (++spawn_fail_streak >= RECIPE_THREAD_SPAWN_LATCH)
				break;
			continue;
		}
		spawn_fail_streak = 0;

		/* Variable race window — 0..100us picks a random sub-window
		 * of the racer's poll/accept to land the close in. */
		if ((rand() & 0xff) != 0)
			usleep((useconds_t)(rand() % 101));

		(void)close(s);

		(void)pthread_join(tid, NULL);

		completed++;
	}

	return completed > 0;
}

/*
 * Recipe 25: userfaultfd write-protect lifecycle.
 *
 * open /dev/userfaultfd (or fall back to the userfaultfd() syscall on
 * older kernels) -> UFFDIO_API to negotiate -> mmap a 2-page private
 * anonymous region -> touch both pages so PTEs are present ->
 * UFFDIO_REGISTER with MISSING|WP -> UFFDIO_WRITEPROTECT(MODE_WP) to
 * apply WP across both pages -> UFFDIO_WRITEPROTECT(mode=DONTWAKE) to
 * clear it again -> UFFDIO_UNREGISTER -> munmap -> close.
 *
 * Distinct from recipe 16 (recipe_userfaultfd) which only exercises
 * the MISSING register-mode path.  The WP path is much newer (5.7+
 * for anon, 5.19+ for shmem) and lives on its own ioctl with its own
 * change_pte_range walker (mwriteprotect_range -> uffd_wp_range ->
 * change_protection_range).  The set + clear sequence drives the WP
 * bit toggle in both directions through the same VMA and the same
 * present-PTE walk -- the path the 2024 madvise-vs-WP race fix and
 * the 5.19 shmem-WP backports addressed.
 *
 * Random callers of ioctl rarely guess UFFDIO_WRITEPROTECT against a
 * uffd that's been registered with MODE_WP, so the WP-toggle path
 * stays cold without a deliberate driver.  Touching the pages before
 * registering is required: UFFDIO_WRITEPROTECT walks present PTEs
 * only; an un-faulted region would no-op the toggle and we wouldn't
 * drive the change_protection path we care about.
 *
 * Latch shape covers every way the feature can be absent:
 *   - /dev/userfaultfd open ENOENT     (no devtmpfs entry, older kernel)
 *   - /dev/userfaultfd open EPERM/EACCES (DAC denial)
 *   - userfaultfd() syscall ENOSYS     (CONFIG_USERFAULTFD off)
 *   - userfaultfd() syscall EPERM      (CAP_SYS_PTRACE missing under
 *                                       unprivileged_userfaultfd=0)
 *   - UFFDIO_REGISTER with MODE_WP returning EINVAL
 *                                      (kernel pre-WP support, or arch
 *                                       lacks pte_uffd_wp)
 *   - UFFDIO_WRITEPROTECT itself returning EINVAL
 *                                      (half-supported backport: WP
 *                                       register flag landed but the
 *                                       toggle ioctl did not)
 *
 * Once latched, the dispatcher stops siblings from re-probing the
 * unsupported feature on every recipe pick.
 */
static bool recipe_uffd_wp(bool *unsupported)
{
	struct uffdio_api api;
	struct uffdio_register reg;
	struct uffdio_range range;
	struct uffdio_writeprotect wp;
	void *region = MAP_FAILED;
	size_t len = (size_t)page_size * 2;
	int fd = -1;
	bool registered = false;
	bool ok = false;

	fd = open("/dev/userfaultfd", O_CLOEXEC | O_RDWR | O_NONBLOCK);
	if (fd < 0) {
		int open_errno = errno;

		/* /dev/userfaultfd is missing or denied -- fall back to the
		 * userfaultfd() syscall, which on older kernels is the only
		 * way in (and gates on CAP_SYS_PTRACE under
		 * unprivileged_userfaultfd=0). */
		fd = (int)syscall(__NR_userfaultfd,
				  O_CLOEXEC | O_NONBLOCK);
		if (fd < 0) {
			if (errno == EPERM || errno == EACCES ||
			    errno == ENOSYS || open_errno == ENOENT) {
				*unsupported = true;
				__atomic_add_fetch(&shm->stats.recipe_unsupported,
						   1, __ATOMIC_RELAXED);
			}
			goto out;
		}
	}

	memset(&api, 0, sizeof(api));
	api.api = UFFD_API;
	if (ioctl(fd, UFFDIO_API, &api) < 0)
		goto out;

	region = mmap(NULL, len, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (region == MAP_FAILED)
		goto out;

	/* Populate PTEs.  UFFDIO_WRITEPROTECT walks present PTEs only;
	 * an un-faulted region would no-op the toggle. */
	((volatile char *)region)[0] = 'a';
	((volatile char *)region)[page_size] = 'b';

	memset(&reg, 0, sizeof(reg));
	reg.range.start = (uintptr_t)region;
	reg.range.len = len;
	reg.mode = UFFDIO_REGISTER_MODE_MISSING | UFFDIO_REGISTER_MODE_WP;
	if (ioctl(fd, UFFDIO_REGISTER, &reg) < 0) {
		if (errno == EINVAL) {
			*unsupported = true;
			__atomic_add_fetch(&shm->stats.recipe_unsupported, 1,
					   __ATOMIC_RELAXED);
		}
		goto out;
	}
	registered = true;

	/* Set WP across both pages -- drives mwriteprotect_range ->
	 * uffd_wp_range -> change_protection_range with the WP bit
	 * being applied to present PTEs. */
	memset(&wp, 0, sizeof(wp));
	wp.range.start = (uintptr_t)region;
	wp.range.len = len;
	wp.mode = UFFDIO_WRITEPROTECT_MODE_WP;
	if (ioctl(fd, UFFDIO_WRITEPROTECT, &wp) < 0) {
		if (errno == EINVAL) {
			*unsupported = true;
			__atomic_add_fetch(&shm->stats.recipe_unsupported, 1,
					   __ATOMIC_RELAXED);
		}
		goto out;
	}

	/* Clear WP -- same walker, opposite direction.  DONTWAKE skips
	 * the wake step (we have no waiters), so this drives the toggle
	 * without the wake-side bookkeeping that's already covered by
	 * the MISSING-mode recipe. */
	wp.mode = UFFDIO_WRITEPROTECT_MODE_DONTWAKE;
	if (ioctl(fd, UFFDIO_WRITEPROTECT, &wp) < 0)
		goto out;

	range.start = (uintptr_t)region;
	range.len = len;
	if (ioctl(fd, UFFDIO_UNREGISTER, &range) < 0)
		goto out;
	registered = false;

	ok = true;
out:
	if (registered) {
		range.start = (uintptr_t)region;
		range.len = len;
		(void)ioctl(fd, UFFDIO_UNREGISTER, &range);
	}
	if (region != MAP_FAILED)
		(void)munmap(region, len);
	if (fd >= 0)
		close(fd);
	return ok;
}

/*
 * Recipe 24: fsnotify cross-fd watch lifecycle.
 *
 * inotify_init1 (watcher fd) -> open a fresh per-pid file under /tmp
 * (modifier fd, kept distinct from the watcher) -> inotify_add_watch
 * on that path -> write/fchmod/close on the modifier fd to drive
 * three distinct event types (IN_MODIFY, IN_ATTRIB, IN_CLOSE_WRITE)
 * -> non-blocking read on the watcher to drain the queued events ->
 * unlink the file -> non-blocking read again to catch the
 * IN_DELETE_SELF + automatic mark teardown -> inotify_rm_watch ->
 * close watcher.
 *
 * The cross-fd shape is the point.  Recipe 8 (recipe_inotify) only
 * exercises init / add_watch / read / rm_watch / close on /tmp without
 * driving any modifications from a separate fd, so the notification
 * delivery path (fsnotify_call_mark_by_event_type, the per-mark hlist
 * walk that dispatches into inotify_handle_inode_event, the event-
 * queue alloc inside inotify_handle_event) never runs.  Driving the
 * mod operations from a fd that the watcher does not own forces
 * fsnotify to route an event to a mark whose installer holds a
 * different file struct -- the cross-context lifetime path that has
 * historically leaked under teardown races (the 2024 fsnotify_mark
 * refcount fixes, the inotify event-queue bounds tightening, the
 * recurring IN_DELETE_SELF auto-removal UAFs).
 *
 * Random write/fchmod/close calls in trinity rarely hit a path that
 * is actively being watched, and the standalone inotify_add_watch in
 * recipe 8 never fires events because /tmp is too noisy for any
 * specific event to be attributed to it.  The deterministic
 * watcher + fresh-file + cross-fd-mod sequence makes the notification
 * delivery edge fire on every invocation.
 *
 * ENOSYS on inotify_init1 (extremely unlikely on modern kernels but
 * possible on stripped-down builds without CONFIG_INOTIFY_USER)
 * latches the recipe off.  Per-event read failures and individual
 * mod failures are tolerated -- the recipe cares about driving the
 * dispatch path, not about specific event counts arriving.
 */
static bool recipe_fsnotify_xwatch(bool *unsupported)
{
	char path[64];
	char buf[1024];
	int wfd = -1;
	int wd = -1;
	int mod = -1;
	ssize_t r __unused__;
	bool ok = false;

	snprintf(path, sizeof(path), "/tmp/trinity-recipe-fsx-%d-%u",
		 (int)getpid(), (unsigned int)rand());

	wfd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
	if (wfd < 0) {
		if (errno == ENOSYS) {
			*unsupported = true;
			__atomic_add_fetch(&shm->stats.recipe_unsupported, 1,
					   __ATOMIC_RELAXED);
		}
		goto out;
	}

	mod = open(path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
	if (mod < 0)
		goto out;

	wd = inotify_add_watch(wfd, path,
			       IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE |
			       IN_DELETE_SELF);
	if (wd < 0)
		goto out;

	/* Drive three notification types from the modifier fd that the
	 * watcher does not own.  Each call routes into fsnotify with a
	 * file struct distinct from the one held by the inotify mark --
	 * the cross-context delivery path. */
	if (write(mod, "x", 1) != 1)
		goto out;
	(void)fchmod(mod, 0644);
	close(mod);
	mod = -1;

	/* Drain queued events.  Best-effort -- the read path is what we
	 * care about, not the byte count.  EAGAIN is acceptable on a
	 * heavily loaded box where the wake hasn't propagated yet. */
	r = read(wfd, buf, sizeof(buf));

	if (unlink(path) < 0)
		goto out;

	/* IN_DELETE_SELF + automatic mark teardown.  The watcher mark
	 * stays armed across the unlink and gets torn down by fsnotify
	 * itself rather than the explicit rm_watch below -- that's the
	 * implicit-teardown path the dispatcher has to walk. */
	r = read(wfd, buf, sizeof(buf));

	if (inotify_rm_watch(wfd, wd) < 0 && errno != EINVAL)
		goto out;
	wd = -1;

	ok = true;
out:
	if (wd >= 0)
		(void)inotify_rm_watch(wfd, wd);
	if (mod >= 0)
		close(mod);
	if (wfd >= 0)
		close(wfd);
	(void)unlink(path);
	return ok;
}

/*
 * Recipe 23: AF_INET raw socket sweep.
 *
 * Walks several proto values through socket(AF_INET, SOCK_RAW, X) ->
 * setsockopt -> bind -> shutdown -> close in one pass.  Drives
 * raw_create, raw_hash_sk / raw_v4_hash, the IP-level setsockopt
 * dispatcher, raw_bind, and raw_close in sequence so the per-proto
 * demuxer state lives across multiple lifecycle stages within a
 * single recipe invocation.
 *
 * Random callers of socket() rarely pick AF_INET + SOCK_RAW + a
 * specific IPPROTO; trinity's standard arg picker hits AF_INET with
 * SOCK_STREAM/SOCK_DGRAM and almost never builds the raw-protocol
 * fanout.  The IP_HDRINCL + IP_PKTINFO + IP_RECVERR option triplet
 * each takes its own slot in the inet_sk option mask, and walking all
 * three on the same socket exercises the option-set ordering the
 * isolated-syscall path almost never reaches.
 *
 * Raw sockets are CAP_NET_RAW gated.  EPERM/EACCES on the first
 * socket() call latches the recipe off so siblings stop probing.
 * Subsequent per-proto failures inside the loop are tolerated --
 * kernels can leave specific ipprotos unimplemented (or restricted via
 * /proc/sys/net/ipv4) without the whole feature being absent.
 */
static bool recipe_net_raw(bool *unsupported)
{
	static const int protos[] = {
		IPPROTO_RAW,
		IPPROTO_ICMP,
		IPPROTO_UDP,
		IPPROTO_TCP,
	};
	struct sockaddr_in sin;
	unsigned int i;
	unsigned int completed = 0;

	for (i = 0; i < ARRAY_SIZE(protos); i++) {
		int s;
		int one = 1;

		s = socket(AF_INET, SOCK_RAW, protos[i]);
		if (s < 0) {
			if (i == 0 && (errno == EPERM || errno == EACCES ||
				       errno == ENOSYS)) {
				*unsupported = true;
				__atomic_add_fetch(&shm->stats.recipe_unsupported,
						   1, __ATOMIC_RELAXED);
				return false;
			}
			continue;
		}

		/* Walk a few IP-level option entries.  IP_HDRINCL is
		 * implicit on IPPROTO_RAW but setting it explicitly drives
		 * the option path; IP_PKTINFO and IP_RECVERR each take their
		 * own slot in the inet_sk option mask. */
		(void)setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
		(void)setsockopt(s, IPPROTO_IP, IP_PKTINFO, &one, sizeof(one));
		(void)setsockopt(s, IPPROTO_IP, IP_RECVERR, &one, sizeof(one));

		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_port = 0;
		sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		(void)bind(s, (struct sockaddr *)&sin, sizeof(sin));

		(void)shutdown(s, SHUT_RDWR);
		close(s);
		completed++;
	}

	return completed > 0;
}

/*
 * Recipe 22: AF_UNIX SOCK_STREAM out-of-band data lifecycle.
 *
 *   socketpair(AF_UNIX, SOCK_STREAM)
 *   send 8 inline bytes                    // normal data ahead of OOB
 *   send 1 byte, MSG_OOB                   // splits the receive queue
 *   send 4 more inline bytes               // data after the OOB marker
 *   recv 1 byte, MSG_OOB                   // consume the OOB byte
 *   recv up to 16 bytes, normal            // drain around the gap
 *   shutdown(SHUT_WR)                      // stops further writes
 *   recv (best-effort) any straggler
 *   close
 *
 * Drives unix_stream_sendmsg's MSG_OOB path (the urg skb tagging), the
 * unix_stream_read_generic / unix_stream_recv_urg split-and-rejoin
 * logic, and the receive-queue manipulation that has to keep the OOB
 * gap consistent across a normal recv that straddles it.  Sending data
 * both before and after the OOB byte is the structural minimum for
 * exercising the gap-around path — a single OOB byte alone hits a
 * trivial fast path that elides most of the bookkeeping.
 *
 * AF_UNIX OOB has been a recurring source of bugs since it was added
 * (commit 314001f0bf92, 5.15) — skb-extension lifetime issues, the
 * 2023 unix_stream_recv_urg accounting fixes, the splice-vs-OOB races.
 * Random callers of send/recv almost never set MSG_OOB on a SOCK_STREAM
 * AF_UNIX socket, so the path stays cold without a dedicated recipe.
 *
 * EOPNOTSUPP (CONFIG_AF_UNIX_OOB unset, or building on a kernel
 * predating the OOB support) latches the recipe off via *unsupported.
 * EINVAL on OOB send is the same signal under some kernel
 * configurations and is handled the same way.
 */
static bool recipe_net_unix_oob(bool *unsupported)
{
	int sv[2] = { -1, -1 };
	char buf[16];
	char oob;
	ssize_t r __unused__;
	bool ok = false;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0)
		goto out;

	if (send(sv[0], "trinity8", 8, 0) != 8)
		goto out;

	if (send(sv[0], "U", 1, MSG_OOB) != 1) {
		if (errno == EOPNOTSUPP || errno == EINVAL) {
			*unsupported = true;
			__atomic_add_fetch(&shm->stats.recipe_unsupported, 1,
					   __ATOMIC_RELAXED);
		}
		goto out;
	}

	if (send(sv[0], "tail", 4, 0) != 4)
		goto out;

	/* Pull the OOB byte first.  On AF_UNIX SOCK_STREAM the OOB byte
	 * is held in a side slot until consumed; subsequent normal recv
	 * has to skip the gap it left in the inline stream. */
	if (recv(sv[1], &oob, 1, MSG_OOB) != 1)
		goto out;

	/* Drain the inline data — the kernel must stitch together the
	 * pre-OOB and post-OOB segments into one contiguous read.  Best-
	 * effort: short reads are fine, the path under test is the queue
	 * walk, not the byte count. */
	r = recv(sv[1], buf, sizeof(buf), 0);

	if (shutdown(sv[0], SHUT_WR) < 0)
		goto out;

	/* Final non-blocking drain to flush any straggler skb the
	 * shutdown path may have transitioned in.  EAGAIN/0 are both
	 * acceptable; this read is for path coverage, not correctness. */
	r = recv(sv[1], buf, sizeof(buf), MSG_DONTWAIT);

	ok = true;
out:
	if (sv[0] >= 0)
		close(sv[0]);
	if (sv[1] >= 0)
		close(sv[1]);
	return ok;
}

/*
 * Racer thread for recipe_timerfd_xclose.  Blocks in poll() with a
 * bounded timeout, then drains a single non-blocking read on the
 * (possibly already-closed) timerfd.  Both calls have hard ceilings:
 * poll's is the timeout argument; read inherits TFD_NONBLOCK so it
 * returns immediately with EAGAIN/EBADF/EINVAL regardless of whether
 * the close raced ahead, mid-syscall, or behind it.
 *
 * EBADF on either call is the fdget-vs-close lookup race we are
 * hunting; success on read is the close-after-read-completed sub-
 * window where the timer expired before the close landed.
 */
struct timerfd_xclose_racer_arg {
	int tfd;
};

static void *timerfd_xclose_racer_thread(void *arg)
{
	struct timerfd_xclose_racer_arg *ra = arg;
	struct pollfd pfd;
	uint64_t expirations;
	ssize_t r __unused__;

	pfd.fd = ra->tfd;
	pfd.events = POLLIN;
	pfd.revents = 0;
	(void)poll(&pfd, 1, RECIPE_RACER_TIMEOUT_MS);

	r = read(ra->tfd, &expirations, sizeof(expirations));
	return NULL;
}

/*
 * Recipe 26: timerfd cross-thread close-vs-read race.
 *
 * Per cycle (1..MAX_CYCLES):
 *
 *   timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC) ->
 *   timerfd_settime(50ms initial + 50ms periodic) -> spawn racer
 *   thread blocked in poll(POLLIN, 100ms) + read() -> usleep 0..100us
 *   race-window jitter -> close(tfd) (the race) -> pthread_join.
 *
 * Targets the kernel paths timerfd_release, timerfd_remove_cancel_on_set,
 * and the wait-queue cleanup that fire when a timerfd is destroyed
 * while another task is mid-poll() or mid-read() on it.  Threads share
 * the fdtable, which is the bug class -- a sibling process closing the
 * same numeric fd in its own table never races with our fdget.  Distinct
 * from recipe 1 (recipe_timerfd) which runs settime/read/gettime
 * serially on a single thread; this one drives the *concurrent*
 * read-vs-close window.
 *
 * Bounded racer syscalls (poll with timeout, read on TFD_NONBLOCK fd)
 * mean plain pthread_join always returns within ~100ms.  Sidesteps the
 * wedge problem where pthread_cancel against a thread stuck in an
 * uninterruptible read is unreliable and detached threads leak state.
 *
 * THREAD_SPAWN_LATCH=3 consecutive pthread_create failures bails for
 * the rest of the invocation -- under nproc/thread limits the EAGAIN
 * won't lift mid-op while fork_storm or cgroup_churn are competing for
 * the budget.
 *
 * timerfd may be missing on stripped-down kernels (no
 * CONFIG_TIMERFD_CREATE).  ENOSYS / EINVAL / EPERM on the very first
 * timerfd_create latches the recipe off via *unsupported.
 *
 * Returns ok=true if any cycle reached close+join.  Per-cycle failures
 * are tolerated mid-loop because one bad cycle (e.g. ephemeral resource
 * pressure under sibling load) shouldn't penalise the whole recipe.
 */
#define RECIPE_TIMERFD_XCLOSE_MAX_CYCLES	4

static bool recipe_timerfd_xclose(bool *unsupported)
{
	struct itimerspec its;
	unsigned int cycles;
	unsigned int i;
	unsigned int spawn_fail_streak = 0;
	unsigned int completed = 0;

	cycles = 1 + ((unsigned int)rand() % RECIPE_TIMERFD_XCLOSE_MAX_CYCLES);

	for (i = 0; i < cycles; i++) {
		struct timerfd_xclose_racer_arg ra;
		pthread_t tid;
		int tfd;
		int rc;

		tfd = timerfd_create(CLOCK_MONOTONIC,
				     TFD_NONBLOCK | TFD_CLOEXEC);
		if (tfd < 0) {
			if (i == 0 && (errno == ENOSYS || errno == EINVAL ||
				       errno == EPERM)) {
				*unsupported = true;
				__atomic_add_fetch(&shm->stats.recipe_unsupported,
						   1, __ATOMIC_RELAXED);
				return false;
			}
			continue;
		}

		memset(&its, 0, sizeof(its));
		its.it_value.tv_sec = 0;
		its.it_value.tv_nsec = 50 * 1000 * 1000;	/* 50 ms */
		its.it_interval.tv_sec = 0;
		its.it_interval.tv_nsec = 50 * 1000 * 1000;
		if (timerfd_settime(tfd, 0, &its, NULL) < 0) {
			close(tfd);
			continue;
		}

		ra.tfd = tfd;
		rc = pthread_create(&tid, NULL,
				    timerfd_xclose_racer_thread, &ra);
		if (rc != 0) {
			close(tfd);
			if (++spawn_fail_streak >= RECIPE_THREAD_SPAWN_LATCH)
				break;
			continue;
		}
		spawn_fail_streak = 0;

		/* Variable race window -- 0..100us picks a random sub-window
		 * of the racer's poll/read to land the close in. */
		if ((rand() & 0xff) != 0)
			usleep((useconds_t)(rand() % 101));

		(void)close(tfd);

		(void)pthread_join(tid, NULL);

		completed++;
	}

	return completed > 0;
}

/*
 * Recipe 27: signalfd queue-drain and mask-update lifecycle.
 *
 * Single-threaded.  Block 3 RT signals via sigprocmask, attach a
 * signalfd watching all 3, queue 3 sigqueue() deliveries with payloads,
 * drain via read() in a loop until EAGAIN, update the signalfd mask
 * via signalfd(sfd, &reduced) to drop one watched signal, queue one
 * more delivery on the dropped signal and one on a still-watched
 * signal, drain via read() again, then drain any residual via
 * sigtimedwait() so nothing is pending when we restore the original
 * mask.
 *
 * Distinct from recipe 5 (recipe_signalfd) which only drives
 * create / EAGAIN-read / close on a single signal with no actual
 * delivery.  This recipe drives:
 *   - the multi-entry signalfd_read path (multiple struct
 *     signalfd_siginfo packed into one read buffer when the queue
 *     holds more than one)
 *   - the signalfd update-mask path (signalfd() with a non-(-1) fd
 *     argument), which lives on the signalfd_setup_pipe / context
 *     update path and rewires ctx->sigmask while the fd is still
 *     installed
 *   - the queue accounting that has to keep dropped-signal
 *     deliveries out of the signalfd reader's view but still in the
 *     task's pending set for sigtimedwait to drain
 *
 * Random callers of signalfd() rarely target an existing fd to update
 * its mask, and almost never inject sigqueue() with payloads against
 * an fd they're about to drain, so the multi-entry read + mask-update
 * path stays cold without a deliberate driver.
 *
 * sigtimedwait drain on the way out is mandatory: an unblocked SIGRT
 * with a delivery still queued in task->pending would fire on the
 * sigprocmask restore and either kill the child or get caught by
 * Trinity's signal handler with confusing provenance.
 *
 * Latch shape covers every way the feature can be absent:
 *   - signalfd() ENOSYS         (CONFIG_SIGNALFD off, very stripped)
 *   - signalfd() update EINVAL  (kernel rejects mask-update via an
 *                                extant fd under specific config combos)
 */
static bool recipe_signalfd_delivery(bool *unsupported)
{
	sigset_t ss, reduced, oldss;
	struct signalfd_siginfo buf[8];
	union sigval sv;
	struct timespec zero_ts;
	siginfo_t drained;
	pid_t self;
	ssize_t r __unused__;
	int sigs[3];
	int sfd = -1;
	bool mask_saved = false;
	bool ok = false;

	/* SIGRTMIN+8..+10 -- well clear of glibc's reserved RT signals
	 * and Trinity's own SIGALRM/SIGXCPU/SIGINT.  Matches the
	 * existing recipe_signalfd's RT-signal regime. */
	sigs[0] = SIGRTMIN + 8;
	sigs[1] = SIGRTMIN + 9;
	sigs[2] = SIGRTMIN + 10;
	if (sigs[2] >= SIGRTMAX)
		goto out;

	sigemptyset(&ss);
	sigaddset(&ss, sigs[0]);
	sigaddset(&ss, sigs[1]);
	sigaddset(&ss, sigs[2]);
	if (sigprocmask(SIG_BLOCK, &ss, &oldss) < 0)
		goto out;
	mask_saved = true;

	sfd = signalfd(-1, &ss, SFD_NONBLOCK | SFD_CLOEXEC);
	if (sfd < 0) {
		if (errno == ENOSYS) {
			*unsupported = true;
			__atomic_add_fetch(&shm->stats.recipe_unsupported, 1,
					   __ATOMIC_RELAXED);
		}
		goto out;
	}

	self = getpid();

	/* Queue three deliveries, one per watched signal, with distinct
	 * payloads.  sigqueue() routes through the per-signal pending
	 * queue with a real siginfo; plain raise() / kill() take a fast
	 * path that elides the queue entry. */
	sv.sival_int = 0x10;
	(void)sigqueue(self, sigs[0], sv);
	sv.sival_int = 0x20;
	(void)sigqueue(self, sigs[1], sv);
	sv.sival_int = 0x30;
	(void)sigqueue(self, sigs[2], sv);

	/* Drain the signalfd until EAGAIN.  Each read pulls 1..N
	 * struct signalfd_siginfo entries; the kernel packs as many as
	 * fit in our buffer and the queue holds. */
	while ((r = read(sfd, buf, sizeof(buf))) > 0)
		;

	/* Update mask via signalfd() with the existing fd -- drops
	 * sigs[2] from the watched set.  Drives the mask-update path
	 * that random callers rarely hit. */
	sigemptyset(&reduced);
	sigaddset(&reduced, sigs[0]);
	sigaddset(&reduced, sigs[1]);
	if (signalfd(sfd, &reduced, SFD_NONBLOCK | SFD_CLOEXEC) < 0) {
		if (errno == EINVAL) {
			*unsupported = true;
			__atomic_add_fetch(&shm->stats.recipe_unsupported, 1,
					   __ATOMIC_RELAXED);
		}
		goto out;
	}

	/* Inject the dropped signal -- it should land in task->pending
	 * but stay invisible to the signalfd reader -- plus a still-
	 * watched one.  Best-effort: a kernel bug here is exactly what
	 * we want exposed, so we don't assert on the read return. */
	sv.sival_int = 0x40;
	(void)sigqueue(self, sigs[2], sv);
	sv.sival_int = 0x50;
	(void)sigqueue(self, sigs[0], sv);

	while ((r = read(sfd, buf, sizeof(buf))) > 0)
		;

	ok = true;
out:
	if (sfd >= 0)
		close(sfd);

	/* Drain any residual pending signals before restoring the mask.
	 * sigtimedwait with a zero timeout is the only safe way to
	 * dequeue a sigqueue() delivery that signalfd's mask-update
	 * dropped from view but left in task->pending. */
	if (mask_saved) {
		zero_ts.tv_sec = 0;
		zero_ts.tv_nsec = 0;
		while (sigtimedwait(&ss, &drained, &zero_ts) >= 0)
			;
		(void)sigprocmask(SIG_SETMASK, &oldss, NULL);
	}
	return ok;
}

/*
 * Recipe 28: epoll watched-fd implicit-close lifecycle.
 *
 * Single-threaded.  epoll_create1 -> create N (=4) eventfds ->
 * EPOLL_CTL_ADD all of them -> close half of them WITHOUT
 * EPOLL_CTL_DEL first (kernel must do the implicit removal via
 * eventpoll_release_file in __fput) -> EPOLL_CTL_ADD a fresh fd to
 * exercise the rb-tree against the just-mutated tree -> epoll_wait
 * (0ms) to walk rdllist and per-epitem ready-list -> EPOLL_CTL_DEL
 * the surviving registrations explicitly -> close everything.
 *
 * Drives the eventpoll_release_file -> ep_remove path that fires when
 * a watched fd is closed without being explicitly EPOLL_CTL_DEL'd
 * first.  The file's f_ep list management has to drop the struct
 * epitem ref atomically with the fd close, walking back into the epoll
 * instance's rbtree and rdllist from the file side -- the path with
 * a long history of UAFs and refcount mismatches.
 *
 * Distinct from recipe 4 (recipe_epoll) which only drives the explicit
 * ADD/MOD/DEL path on a single watched fd.  This recipe is the close-
 * without-DEL variant -- the implicit removal that the standard
 * recipe never reaches.  Random callers of close() rarely close a fd
 * that's currently registered on an epoll set, so the implicit-removal
 * edge stays cold without a deliberate driver.
 *
 * Adding a fresh fd between the implicit-close burst and the
 * epoll_wait drives the rb-tree insertion against a tree the implicit
 * cleanup just mutated -- the path most likely to expose ordering
 * bugs in the rb-tree update under a concurrent ep_release walk.
 *
 * Latch shape covers the ways the feature can be absent on the very
 * first epoll_create1:
 *   - ENOSYS  (CONFIG_EPOLL off, very stripped)
 * Plus EINVAL on the first EPOLL_CTL_ADD with EPOLLIN against an
 * eventfd, which is implausible in practice but flags a half-wired
 * epoll surface (the create syscall present, the ctl path stubbed).
 */
#define RECIPE_EPOLL_XCLOSE_NFDS	4

static bool recipe_epoll_xclose(bool *unsupported)
{
	struct epoll_event ev;
	struct epoll_event evs[RECIPE_EPOLL_XCLOSE_NFDS + 1];
	int evfds[RECIPE_EPOLL_XCLOSE_NFDS];
	int extra = -1;
	int epfd = -1;
	unsigned int i;
	bool ok = false;

	for (i = 0; i < ARRAY_SIZE(evfds); i++)
		evfds[i] = -1;

	epfd = epoll_create1(EPOLL_CLOEXEC);
	if (epfd < 0) {
		if (errno == ENOSYS) {
			*unsupported = true;
			__atomic_add_fetch(&shm->stats.recipe_unsupported, 1,
					   __ATOMIC_RELAXED);
		}
		goto out;
	}

	for (i = 0; i < ARRAY_SIZE(evfds); i++) {
		evfds[i] = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
		if (evfds[i] < 0)
			goto out;

		memset(&ev, 0, sizeof(ev));
		ev.events = EPOLLIN | EPOLLET;
		ev.data.fd = evfds[i];
		if (epoll_ctl(epfd, EPOLL_CTL_ADD, evfds[i], &ev) < 0) {
			if (i == 0 && errno == EINVAL) {
				*unsupported = true;
				__atomic_add_fetch(&shm->stats.recipe_unsupported,
						   1, __ATOMIC_RELAXED);
			}
			goto out;
		}
	}

	/* Close half of the watched fds without an EPOLL_CTL_DEL first.
	 * The kernel must drop the corresponding epitem entries via
	 * eventpoll_release_file as part of __fput.  No EPOLL_CTL_DEL =
	 * the implicit-removal path is what we want to drive. */
	for (i = 0; i < ARRAY_SIZE(evfds) / 2; i++) {
		close(evfds[i]);
		evfds[i] = -1;
	}

	/* Add a fresh fd after the implicit removals -- exercises the
	 * rb-tree insertion against a tree the implicit-cleanup path
	 * just mutated. */
	extra = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (extra >= 0) {
		memset(&ev, 0, sizeof(ev));
		ev.events = EPOLLIN;
		ev.data.fd = extra;
		(void)epoll_ctl(epfd, EPOLL_CTL_ADD, extra, &ev);
	}

	/* Drain whatever's ready.  Best-effort -- the eventfds are all
	 * 0 so nothing is expected, but the wait still walks rdllist
	 * and the per-epitem ready-list which is the path under test. */
	(void)epoll_wait(epfd, evs, ARRAY_SIZE(evs), 0);

	/* Tear down the surviving registrations explicitly so we
	 * exercise both ep_remove paths in one recipe. */
	for (i = ARRAY_SIZE(evfds) / 2; i < ARRAY_SIZE(evfds); i++) {
		if (evfds[i] >= 0) {
			(void)epoll_ctl(epfd, EPOLL_CTL_DEL, evfds[i], NULL);
			close(evfds[i]);
			evfds[i] = -1;
		}
	}

	if (extra >= 0) {
		(void)epoll_ctl(epfd, EPOLL_CTL_DEL, extra, NULL);
		close(extra);
		extra = -1;
	}

	ok = true;
out:
	for (i = 0; i < ARRAY_SIZE(evfds); i++)
		if (evfds[i] >= 0)
			close(evfds[i]);
	if (extra >= 0)
		close(extra);
	if (epfd >= 0)
		close(epfd);
	return ok;
}

static const struct recipe recipes[] = {
	{ "timerfd",      recipe_timerfd      },
	{ "eventfd",      recipe_eventfd      },
	{ "pipe",         recipe_pipe         },
	{ "epoll",        recipe_epoll        },
	{ "signalfd",     recipe_signalfd     },
	{ "memfd_seal",   recipe_memfd_seal   },
	{ "tcp_server",   recipe_tcp_server   },
	{ "inotify",      recipe_inotify      },
	{ "shmget",       recipe_shmget       },
	{ "msgget",       recipe_msgget       },
	{ "semget",       recipe_semget       },
	{ "posix_timer",  recipe_posix_timer  },
	{ "mq_open",      recipe_mq_open      },
	{ "futex",        recipe_futex        },
	{ "fanotify",     recipe_fanotify     },
	{ "userfaultfd",  recipe_userfaultfd  },
	{ "vfs_leases",   recipe_vfs_leases   },
	{ "mm_vma",       recipe_mm_vma       },
	{ "mm_memfd",     recipe_mm_memfd     },
	{ "net_unix_gc",  recipe_net_unix_gc  },
	{ "net_tcp",      recipe_net_tcp      },
	{ "net_unix_oob", recipe_net_unix_oob },
	{ "net_raw",      recipe_net_raw      },
	{ "fsnotify_xwatch", recipe_fsnotify_xwatch },
	{ "uffd_wp",      recipe_uffd_wp      },
	{ "timerfd_xclose", recipe_timerfd_xclose },
	{ "signalfd_delivery", recipe_signalfd_delivery },
	{ "epoll_xclose", recipe_epoll_xclose },
};

/*
 * Build-time guarantee that the catalog fits in the shm bookkeeping
 * arrays sized via MAX_RECIPES in stats.h.  Bumping the catalog past
 * MAX_RECIPES without growing the arrays would silently overflow
 * shm->recipe_disabled and shm->stats.recipe_completed_per.
 */
_Static_assert(ARRAY_SIZE(recipes) <= MAX_RECIPES,
	       "recipe catalog outgrew MAX_RECIPES; bump it in stats.h");

bool recipe_runner(struct childdata *child)
{
	const struct recipe *r;
	unsigned int idx;
	unsigned int tries;
	bool unsupported = false;
	bool ok;

	__atomic_add_fetch(&shm->stats.recipe_runs, 1, __ATOMIC_RELAXED);

	/* Pick a recipe that hasn't been latched off.  A few retries are
	 * enough — even if every discovery-probe recipe is disabled, at
	 * worst one in four picks will land on a non-discoverable one. */
	for (tries = 0; tries < 8; tries++) {
		idx = (unsigned int)rand() % (unsigned int)ARRAY_SIZE(recipes);
		if (!__atomic_load_n(&shm->recipe_disabled[idx],
				     __ATOMIC_RELAXED))
			break;
	}
	if (tries == 8)
		return true;	/* nothing runnable on this kernel */

	r = &recipes[idx];

	output(1, "recipe: running %s\n", r->name);

	/* Publish the active recipe name so post-mortem can attribute a
	 * kernel taint to the sequence in flight.  Cleared on completion
	 * regardless of success/failure so a stale name never lingers. */
	child->current_recipe_name = r->name;
	ok = r->run(&unsupported);
	child->current_recipe_name = NULL;

	if (unsupported)
		__atomic_store_n(&shm->recipe_disabled[idx], true,
				 __ATOMIC_RELAXED);

	if (ok) {
		__atomic_add_fetch(&shm->stats.recipe_completed, 1,
				   __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.recipe_completed_per[idx], 1,
				   __ATOMIC_RELAXED);
	} else {
		__atomic_add_fetch(&shm->stats.recipe_partial, 1,
				   __ATOMIC_RELAXED);
	}

	return true;
}

/*
 * Emit per-recipe completion counts and, where applicable, the
 * latched-disabled state.  Called from dump_stats() so the catalog
 * layout stays private to this file.
 */
void recipe_runner_dump_stats(void)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(recipes); i++) {
		unsigned long n = __atomic_load_n(
			&shm->stats.recipe_completed_per[i],
			__ATOMIC_RELAXED);
		bool disabled = __atomic_load_n(
			&shm->recipe_disabled[i],
			__ATOMIC_RELAXED);

		if (n == 0 && !disabled)
			continue;

		output(0, "  %-14s %lu%s\n",
			recipes[i].name, n,
			disabled ? " (disabled — kernel feature absent)" : "");
	}
}
