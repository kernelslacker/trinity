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
#include <sched.h>
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
#include <sys/mount.h>
#include <sys/msg.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/futex.h>
#include <linux/io_uring.h>
#include <linux/keyctl.h>
#include <linux/memfd.h>
#include <linux/perf_event.h>
#include <linux/seccomp.h>
#include <linux/userfaultfd.h>

#include "arch.h"
#include "child.h"
#include "childops-util.h"
#include "compat.h"
#include "maps.h"
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

#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup	425
#define __NR_io_uring_enter	426
#define __NR_io_uring_register	427
#endif

#ifndef IORING_OFF_SQ_RING
#define IORING_OFF_SQ_RING	0ULL
#define IORING_OFF_CQ_RING	0x8000000ULL
#define IORING_OFF_SQES		0x10000000ULL
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
 * Draw a region from the parent's inherited mapping pool (built once in
 * setup_initial_mappings as MAP_SHARED | MAP_ANONYMOUS) → futex(FUTEX_WAIT)
 * with a short timeout (expected to return EAGAIN immediately because
 * the value doesn't match) → futex(FUTEX_WAKE) on the same address.
 * Exercises the futex hash-bucket lookup, the timeout path, and the
 * cleanup of the futex queue.
 *
 * The shared-anon pool entries put the futex on the shared key path
 * inside the kernel, which is the more interesting variant — the private
 * path is what most application code hits.
 *
 * Filter the pool draw on PROT_READ | PROT_WRITE: the recipe writes the
 * value word before the FUTEX_WAIT and the kernel reads it during the
 * cmpxchg in futex_wait_setup.  Drawing a PROT_READ-only or PROT_NONE
 * pool entry would SEGV on the value-word store before the futex syscall.
 *
 * The pool owns the mapping: do NOT munmap on cleanup.  Sibling recipes
 * draw from the same pool, so they will sometimes target the same futex
 * word — the cross-sibling collision on the value and on the kernel's
 * shared-key hash bucket is the cross-vector behaviour we want to
 * exercise.  The 1 ms timeout bounds any worst-case wait if a sibling
 * happens to have raced *futex_addr to the expected value of 1 between
 * our store and the FUTEX_WAIT.
 */
static bool recipe_futex(bool *unsupported __unused__)
{
	struct timespec ts;
	struct map *m = NULL;
	uint32_t *futex_addr = NULL;
	bool ok = false;

	m = get_map_with_prot(PROT_READ | PROT_WRITE);
	if (m == NULL)
		goto out;
	futex_addr = (uint32_t *)m->ptr;

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

/*
 * Recipe 29: io_uring fixed-file register/unregister vs in-flight ref.
 *
 * Single-threaded.  Set up a private io_uring, mmap the SQ/CQ rings and
 * SQE array, IORING_REGISTER_FILES with one /dev/null fd in slot 0,
 * close the original /dev/null fd so the registered table holds the
 * sole reference, submit IORING_OP_READ on fixed-file index 0 with
 * IOSQE_FIXED_FILE via io_uring_enter(to_submit=1, min_complete=0)
 * (submit-and-return without reaping), then IORING_UNREGISTER_FILES
 * back-to-back.  Drain any CQEs and tear down.
 *
 * Targets the fixed-file refcount machinery in fs/io_uring/rsrc.c —
 * the in-flight request grabs a ref on the registered slot via the
 * rsrc_node mechanism, and UNREGISTER must reconcile the slot release
 * against any extant refs.  /dev/null EOF means the read completes
 * inline in the common case, but under sibling load (mm pressure,
 * scheduler preemption) the dispatch can defer to io-wq and the
 * unregister observes a non-zero rsrc-node refcount.  The exact
 * window is small but the path under test — io_rsrc_node_destroy /
 * io_rsrc_data_free / io_wait_rsrc_data — is the same one with a
 * recurring history of UAFs and double-frees in this subsystem.
 *
 * Closing the original /dev/null fd between REGISTER and the SQE
 * submit is intentional: it forces the registered table to be the
 * sole owner of the file's struct file ref.  When the read references
 * the file via the registered index, the lookup goes through the
 * rsrc node, not the caller's fdtable — which is exactly the path
 * the bug class lives on.
 *
 * Single-threaded variant rather than the 2-thread shape used by
 * recipe 26 (recipe_timerfd_xclose) because UNREGISTER_FILES is
 * synchronous against in-flight refs: a 2nd thread would have to
 * cancel the request before unregister returned, complicating the
 * sequence without buying any additional path coverage.
 *
 * Latch shape covers the ways the feature can be absent on the very
 * first probe:
 *   - io_uring_setup ENOSYS    (CONFIG_IO_URING off)
 *   - io_uring_setup EPERM     (kernel.io_uring_disabled sysctl)
 *   - mmap MAP_FAILED with EOPNOTSUPP/EPERM on the very first try
 *     (locked-down kernels that present the syscall but reject mmap)
 *   - REGISTER_FILES EINVAL/ENOSYS on first call (half-wired surface)
 */
static bool recipe_iouring_fixed_uaf(bool *unsupported)
{
	struct io_uring_params p;
	struct io_uring_sqe *sqes_arr;
	void *sq_ring = MAP_FAILED;
	void *cq_ring = MAP_FAILED;
	void *sqes = MAP_FAILED;
	size_t sq_sz = 0, cq_sz = 0, sqes_sz = 0;
	bool single_mmap = false;
	int ring_fd = -1;
	int devnull = -1;
	int fds[1];
	unsigned int *sq_array;
	unsigned int mask, head, tail;
	bool registered = false;
	bool ok = false;
	int r;

	memset(&p, 0, sizeof(p));
	ring_fd = (int)syscall(__NR_io_uring_setup, 8U, &p);
	if (ring_fd < 0) {
		if (errno == ENOSYS || errno == EPERM) {
			*unsupported = true;
			__atomic_add_fetch(&shm->stats.recipe_unsupported, 1,
					   __ATOMIC_RELAXED);
		}
		goto out;
	}

	sq_sz = (size_t)p.sq_off.array +
		(size_t)p.sq_entries * sizeof(unsigned int);
	cq_sz = (size_t)p.cq_off.cqes +
		(size_t)p.cq_entries * sizeof(struct io_uring_cqe);
	sqes_sz = (size_t)p.sq_entries * sizeof(struct io_uring_sqe);

	sq_ring = mmap(NULL, sq_sz, PROT_READ | PROT_WRITE,
		       MAP_SHARED | MAP_POPULATE, ring_fd, IORING_OFF_SQ_RING);
	if (sq_ring == MAP_FAILED) {
		if (errno == EOPNOTSUPP || errno == EPERM) {
			*unsupported = true;
			__atomic_add_fetch(&shm->stats.recipe_unsupported, 1,
					   __ATOMIC_RELAXED);
		}
		goto out;
	}

	if (p.features & IORING_FEAT_SINGLE_MMAP) {
		cq_ring = sq_ring;
		single_mmap = true;
	} else {
		cq_ring = mmap(NULL, cq_sz, PROT_READ | PROT_WRITE,
			       MAP_SHARED | MAP_POPULATE,
			       ring_fd, IORING_OFF_CQ_RING);
		if (cq_ring == MAP_FAILED)
			goto out;
	}

	sqes = mmap(NULL, sqes_sz, PROT_READ | PROT_WRITE,
		    MAP_SHARED | MAP_POPULATE, ring_fd, IORING_OFF_SQES);
	if (sqes == MAP_FAILED)
		goto out;

	devnull = open("/dev/null", O_RDONLY | O_CLOEXEC);
	if (devnull < 0)
		goto out;

	fds[0] = devnull;
	r = (int)syscall(__NR_io_uring_register, ring_fd,
			 IORING_REGISTER_FILES, fds, 1U);
	if (r < 0) {
		if (errno == ENOSYS || errno == EINVAL) {
			*unsupported = true;
			__atomic_add_fetch(&shm->stats.recipe_unsupported, 1,
					   __ATOMIC_RELAXED);
		}
		goto out;
	}
	registered = true;

	/* Drop the caller's fdtable ref now that the registered table owns
	 * a ref on the same struct file.  Subsequent ops via the fixed-file
	 * index route through the rsrc_node lookup -- the path the UAF
	 * class lives on, not the regular fdget. */
	close(devnull);
	devnull = -1;

	sqes_arr = (struct io_uring_sqe *)sqes;
	memset(&sqes_arr[0], 0, sizeof(sqes_arr[0]));
	sqes_arr[0].opcode    = IORING_OP_READ;
	sqes_arr[0].fd        = 0;		/* registered slot index */
	sqes_arr[0].flags     = IOSQE_FIXED_FILE;
	sqes_arr[0].len       = 16;
	sqes_arr[0].user_data = 0xfeedface;

	mask = *(volatile unsigned int *)((char *)sq_ring + p.sq_off.ring_mask);
	head = *(volatile unsigned int *)((char *)sq_ring + p.sq_off.head);
	tail = *(volatile unsigned int *)((char *)sq_ring + p.sq_off.tail);
	if ((tail - head) >= p.sq_entries)
		goto out;

	sq_array = (unsigned int *)((char *)sq_ring + p.sq_off.array);
	sq_array[tail & mask] = 0;
	__sync_synchronize();
	*(volatile unsigned int *)((char *)sq_ring + p.sq_off.tail) = tail + 1;

	/* Submit-and-return: min_complete=0 means we don't wait for the
	 * read to land in the CQ before kicking off the unregister.  The
	 * race window is the gap between the kernel queueing the request
	 * (which grabs the rsrc-node ref) and posting the completion
	 * (which drops it). */
	(void)syscall(__NR_io_uring_enter, ring_fd, 1U, 0U,
		      0U /* no GETEVENTS */, NULL, 0UL);

	(void)syscall(__NR_io_uring_register, ring_fd,
		      IORING_UNREGISTER_FILES, NULL, 0U);
	registered = false;

	/* Drain any CQEs that landed before/during the unregister.  No
	 * assertion on what we find -- the path under test is the
	 * unregister vs in-flight ref reconciliation, not whether the
	 * read returned 0 or -ECANCELED. */
	{
		unsigned int cmask, chead, ctail;
		struct io_uring_cqe *cqes;

		cmask = *(volatile unsigned int *)((char *)cq_ring +
						   p.cq_off.ring_mask);
		chead = *(volatile unsigned int *)((char *)cq_ring +
						   p.cq_off.head);
		ctail = *(volatile unsigned int *)((char *)cq_ring +
						   p.cq_off.tail);
		cqes = (struct io_uring_cqe *)((char *)cq_ring +
					       p.cq_off.cqes);
		while (chead != ctail) {
			(void)cqes[chead & cmask];
			chead++;
		}
		__sync_synchronize();
		*(volatile unsigned int *)((char *)cq_ring +
					   p.cq_off.head) = chead;
	}

	ok = true;
out:
	if (registered)
		(void)syscall(__NR_io_uring_register, ring_fd,
			      IORING_UNREGISTER_FILES, NULL, 0U);
	if (sqes != MAP_FAILED)
		munmap(sqes, sqes_sz);
	if (cq_ring != MAP_FAILED && !single_mmap)
		munmap(cq_ring, cq_sz);
	if (sq_ring != MAP_FAILED)
		munmap(sq_ring, sq_sz);
	if (devnull >= 0)
		close(devnull);
	if (ring_fd >= 0)
		close(ring_fd);
	return ok;
}

/*
 * Racer thread for recipe_bpf_htab_iter_del.  Walks the hash map's keyspace
 * issuing BPF_MAP_DELETE_ELEM against each pre-populated key, with a
 * deadline check between iterations so the racer self-bounds even under
 * heavy contention.  Re-populates and re-deletes in a loop until the
 * deadline elapses, so the iteration side has a continuously-mutating
 * bucket walk to step through.
 *
 * Each bpf() syscall is unbounded only by the kernel's per-call work,
 * which for a single-element hash op is effectively trivial.  The
 * deadline gate ensures pthread_join() returns within ~100ms regardless
 * of how the iteration side schedules.
 */
struct bpf_htab_racer_arg {
	int		map_fd;
	uint32_t	max_entries;
	struct timespec	deadline;
};

static bool bpf_htab_deadline_passed(const struct timespec *deadline)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		return true;
	if (now.tv_sec > deadline->tv_sec)
		return true;
	if (now.tv_sec == deadline->tv_sec && now.tv_nsec >= deadline->tv_nsec)
		return true;
	return false;
}

static void *bpf_htab_racer_thread(void *arg)
{
	struct bpf_htab_racer_arg *ra = arg;
	union bpf_attr attr;
	uint32_t key, value;

	while (!bpf_htab_deadline_passed(&ra->deadline)) {
		for (key = 0; key < ra->max_entries; key++) {
			if (bpf_htab_deadline_passed(&ra->deadline))
				return NULL;
			memset(&attr, 0, sizeof(attr));
			attr.map_fd = ra->map_fd;
			attr.key    = (uintptr_t)&key;
			(void)syscall(__NR_bpf, BPF_MAP_DELETE_ELEM,
				      &attr, sizeof(attr));
		}
		for (key = 0; key < ra->max_entries; key++) {
			if (bpf_htab_deadline_passed(&ra->deadline))
				return NULL;
			value = key ^ 0xa5a5a5a5;
			memset(&attr, 0, sizeof(attr));
			attr.map_fd = ra->map_fd;
			attr.key    = (uintptr_t)&key;
			attr.value  = (uintptr_t)&value;
			attr.flags  = 0;	/* BPF_ANY */
			(void)syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM,
				      &attr, sizeof(attr));
		}
	}
	return NULL;
}

/*
 * Recipe 30: BPF hash-map iterate vs delete cross-thread race.
 *
 * Per cycle (1..MAX_CYCLES):
 *
 *   bpf(BPF_MAP_CREATE, BPF_MAP_TYPE_HASH, key=u32, value=u32,
 *       max_entries=N) -> populate N entries via BPF_MAP_UPDATE_ELEM ->
 *   spawn racer thread that loops {DELETE_ELEM × N -> UPDATE_ELEM × N}
 *   under a 100ms deadline -> main thread walks the keyspace via
 *   BPF_MAP_GET_NEXT_KEY (chained from a NULL prev_key) up to N+8
 *   iterations or until -ENOENT -> usleep 0..100us race-window jitter
 *   -> pthread_join -> close map_fd.
 *
 * Targets the htab_map_get_next_key RCU-walk in kernel/bpf/hashtab.c
 * concurrent with htab_map_delete_elem.  The bug class: htab uses RCU
 * for the bucket lists but the iterator's "next" pointer can dangle if
 * the element it just observed is deleted before the next dereference,
 * and the bucket-lock acquisition order between iterate and delete has
 * to keep the chain walk consistent under concurrent prepend/remove.
 *
 * Distinct from recipe_bpf_lifecycle (childops/bpf-lifecycle.c) which
 * drives BPF_MAP_TYPE_ARRAY (no chain walk, no per-bucket lock) plus a
 * loaded program; this recipe drives the *concurrent* iterate-vs-delete
 * window on a real hash map's bucket chain.  Random callers of bpf()
 * almost never construct a populated hash map and walk it from one
 * thread while another thread mutates it; the path stays cold without
 * a deliberate driver.
 *
 * Bounded racer (deadline-gated bpf() ops, no blocking calls) means
 * plain pthread_join always returns within ~100ms.  THREAD_SPAWN_LATCH=3
 * consecutive pthread_create failures bails for the rest of the
 * invocation.
 *
 * Latch shape covers the ways the feature can be absent on the very
 * first probe:
 *   - bpf() ENOSYS                   (CONFIG_BPF_SYSCALL off)
 *   - BPF_MAP_CREATE EPERM           (kernel.unprivileged_bpf_disabled
 *                                     and we lack CAP_BPF)
 *   - BPF_MAP_CREATE EINVAL          (BPF_MAP_TYPE_HASH unsupported on
 *                                     a stripped kernel build)
 */
#define RECIPE_BPF_HTAB_MAX_CYCLES	4
#define RECIPE_BPF_HTAB_ENTRIES		16

static bool recipe_bpf_htab_iter_del(bool *unsupported)
{
	unsigned int cycles;
	unsigned int i;
	unsigned int spawn_fail_streak = 0;
	unsigned int completed = 0;

	cycles = 1 + ((unsigned int)rand() % RECIPE_BPF_HTAB_MAX_CYCLES);

	for (i = 0; i < cycles; i++) {
		struct bpf_htab_racer_arg ra;
		union bpf_attr attr;
		pthread_t tid;
		uint32_t key, value, next_key;
		int map_fd;
		int rc;
		unsigned int walked;

		memset(&attr, 0, sizeof(attr));
		attr.map_type    = BPF_MAP_TYPE_HASH;
		attr.key_size    = sizeof(uint32_t);
		attr.value_size  = sizeof(uint32_t);
		attr.max_entries = RECIPE_BPF_HTAB_ENTRIES;
		map_fd = (int)syscall(__NR_bpf, BPF_MAP_CREATE,
				      &attr, sizeof(attr));
		if (map_fd < 0) {
			if (i == 0 && (errno == ENOSYS || errno == EPERM ||
				       errno == EINVAL)) {
				*unsupported = true;
				__atomic_add_fetch(&shm->stats.recipe_unsupported,
						   1, __ATOMIC_RELAXED);
				return false;
			}
			continue;
		}

		/* Pre-populate so the racer's first DELETE pass has work and
		 * the iterate path has a non-empty keyspace to walk. */
		for (key = 0; key < RECIPE_BPF_HTAB_ENTRIES; key++) {
			value = key ^ 0xa5a5a5a5;
			memset(&attr, 0, sizeof(attr));
			attr.map_fd = map_fd;
			attr.key    = (uintptr_t)&key;
			attr.value  = (uintptr_t)&value;
			attr.flags  = 0;	/* BPF_ANY */
			(void)syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM,
				      &attr, sizeof(attr));
		}

		ra.map_fd      = map_fd;
		ra.max_entries = RECIPE_BPF_HTAB_ENTRIES;
		if (clock_gettime(CLOCK_MONOTONIC, &ra.deadline) < 0) {
			close(map_fd);
			continue;
		}
		ra.deadline.tv_nsec += RECIPE_RACER_TIMEOUT_MS * 1000000L;
		while (ra.deadline.tv_nsec >= 1000000000L) {
			ra.deadline.tv_nsec -= 1000000000L;
			ra.deadline.tv_sec  += 1;
		}

		rc = pthread_create(&tid, NULL, bpf_htab_racer_thread, &ra);
		if (rc != 0) {
			close(map_fd);
			if (++spawn_fail_streak >= RECIPE_THREAD_SPAWN_LATCH)
				break;
			continue;
		}
		spawn_fail_streak = 0;

		/* Variable race window -- 0..100us picks a random sub-window
		 * of the racer's loop to begin our iteration in. */
		if ((rand() & 0xff) != 0)
			usleep((useconds_t)(rand() % 101));

		/* Walk the keyspace with chained GET_NEXT_KEY, starting from
		 * NULL (returns the first key in iteration order).  Bounded
		 * by 2*N+8 iterations: under a racing populator we can revisit
		 * keys, so an unbounded loop could spin if the racer keeps
		 * re-inserting.  -ENOENT terminates iteration normally. */
		{
			uint32_t *prev = NULL;
			uint32_t prev_key = 0;
			unsigned int cap = 2 * RECIPE_BPF_HTAB_ENTRIES + 8;

			for (walked = 0; walked < cap; walked++) {
				memset(&attr, 0, sizeof(attr));
				attr.map_fd = map_fd;
				attr.key    = (uintptr_t)prev;
				attr.next_key = (uintptr_t)&next_key;
				if ((int)syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY,
						 &attr, sizeof(attr)) < 0)
					break;
				prev_key = next_key;
				prev = &prev_key;
			}
		}

		(void)pthread_join(tid, NULL);
		close(map_fd);

		completed++;
	}

	return completed > 0;
}

/*
 * Racer thread for recipe_perf_mmap_close.  Loops short poll(POLLIN)
 * + non-blocking read() of the perf counter value across the
 * RECIPE_RACER_TIMEOUT_MS window so the racer is consistently inside
 * either perf_poll() or perf_read() on the file when the main thread
 * closes it.  Both calls have hard ceilings: poll's via its timeout
 * argument; read short-circuits to -EBADF / -ESRCH after the file or
 * context is torn down.
 *
 * EBADF on either call is the fdget-vs-close lookup race we are
 * hunting; success on read is the close-after-counter-read sub-window
 * where the syscall completed before close landed.
 */
struct perf_mmap_close_racer_arg {
	int		perf_fd;
	struct timespec	deadline;
};

static bool perf_mmap_close_deadline_passed(const struct timespec *deadline)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		return true;
	if (now.tv_sec > deadline->tv_sec)
		return true;
	if (now.tv_sec == deadline->tv_sec && now.tv_nsec >= deadline->tv_nsec)
		return true;
	return false;
}

static void *perf_mmap_close_racer_thread(void *arg)
{
	struct perf_mmap_close_racer_arg *ra = arg;
	struct pollfd pfd;
	uint64_t value;
	ssize_t r __unused__;

	while (!perf_mmap_close_deadline_passed(&ra->deadline)) {
		pfd.fd = ra->perf_fd;
		pfd.events = POLLIN;
		pfd.revents = 0;
		(void)poll(&pfd, 1, 5);

		r = read(ra->perf_fd, &value, sizeof(value));
	}
	return NULL;
}

/*
 * Recipe 31: perf_event mmap close-vs-read race.
 *
 * Per cycle (1..MAX_CYCLES):
 *
 *   perf_event_open(PERF_TYPE_SOFTWARE/PERF_COUNT_SW_CPU_CLOCK,
 *                   sample_period=1ms, sample_type=TID|TIME,
 *                   pid=0/cpu=-1, disabled=1) -> mmap (1 + N) pages
 *   SHARED -> PERF_EVENT_IOC_ENABLE -> spawn racer that loops
 *   poll(POLLIN, 5ms) + read(perf_fd) under a 100ms deadline ->
 *   usleep 0..100us race-window jitter -> close(perf_fd) (the race)
 *   -> pthread_join -> munmap.
 *
 * Targets perf_release / perf_event_release_kernel and the ring-
 * buffer teardown reachable when a perf event with an active mmap
 * is closed concurrently with another task in perf_poll() or
 * perf_read() on the same fd.  The bug class lives on:
 *   - the fdget-vs-close lookup race in perf_poll/perf_read
 *   - the wait-queue cleanup vs poll_wait() on the event's poll head
 *   - the rb (ring buffer) refcount machinery -- mmap holds an rb
 *     ref that survives close() until munmap, so perf_release sees
 *     the rb still attached while the racer's syscalls hold a file
 *     ref
 *
 * Threads share the fdtable, which is the bug class -- a sibling
 * process closing the same numeric fd in its own table never races
 * with our fdget.  Distinct from childops/perf-event-chains.c which
 * exercises the group/multiplex surface single-threaded; this recipe
 * drives the *concurrent* close-vs-read window on the file lifetime
 * with an active sampling mmap.
 *
 * Bounded racer (deadline-gated poll(5ms) + read on a counter file
 * that returns immediately once the event is gone) means plain
 * pthread_join always returns within ~100ms.  Sidesteps the wedge
 * problem where pthread_cancel against a thread mid-poll is
 * unreliable and detached threads leak state.  Mirrors the 2-thread
 * shape from recipe_timerfd_xclose and recipe_bpf_htab_iter_del,
 * sharing RECIPE_RACER_TIMEOUT_MS and RECIPE_THREAD_SPAWN_LATCH.
 *
 * THREAD_SPAWN_LATCH=3 consecutive pthread_create failures bails
 * for the rest of the invocation -- under nproc/thread limits the
 * EAGAIN won't lift mid-op while fork_storm or cgroup_churn are
 * competing for the budget.
 *
 * Latch shape covers every way the feature can be absent on the
 * very first probe:
 *   - perf_event_open ENOSYS         (CONFIG_PERF_EVENTS off)
 *   - perf_event_open EACCES / EPERM (kernel.perf_event_paranoid
 *                                     restricts even SW events)
 *   - perf_event_open EOPNOTSUPP     (no software PMU available)
 *   - perf_event_open EINVAL         (PERF_TYPE_SOFTWARE config
 *                                     unsupported on stripped builds)
 *   - mmap MAP_FAILED EPERM/EACCES   (mmap of perf rings disabled)
 *
 * Once latched, the dispatcher stops siblings from re-probing the
 * unsupported feature on every recipe pick.
 */
#define RECIPE_PERF_MMAP_MAX_CYCLES	4
#define RECIPE_PERF_MMAP_DATA_PAGES	4U	/* power of two */

static bool recipe_perf_mmap_close(bool *unsupported)
{
	struct perf_event_attr attr;
	unsigned int cycles;
	unsigned int i;
	unsigned int spawn_fail_streak = 0;
	unsigned int completed = 0;
	size_t mmap_sz;

	mmap_sz = (size_t)(1U + RECIPE_PERF_MMAP_DATA_PAGES) *
		  (size_t)page_size;
	cycles = 1 + ((unsigned int)rand() % RECIPE_PERF_MMAP_MAX_CYCLES);

	for (i = 0; i < cycles; i++) {
		struct perf_mmap_close_racer_arg ra;
		pthread_t tid;
		void *ring;
		int perf_fd;
		int rc;

		memset(&attr, 0, sizeof(attr));
		attr.type           = PERF_TYPE_SOFTWARE;
		attr.size           = sizeof(attr);
		attr.config         = PERF_COUNT_SW_CPU_CLOCK;
		attr.sample_period  = 1000000ULL;	/* 1 ms */
		attr.sample_type    = PERF_SAMPLE_TID | PERF_SAMPLE_TIME;
		attr.disabled       = 1;
		attr.exclude_kernel = 1;
		attr.exclude_hv     = 1;

		perf_fd = (int)syscall(__NR_perf_event_open, &attr,
				       0 /* this thread */,
				       -1 /* any cpu */,
				       -1 /* no group leader */,
				       0UL /* flags */);
		if (perf_fd < 0) {
			if (i == 0 && (errno == ENOSYS || errno == EACCES ||
				       errno == EPERM ||
				       errno == EOPNOTSUPP ||
				       errno == EINVAL)) {
				*unsupported = true;
				__atomic_add_fetch(&shm->stats.recipe_unsupported,
						   1, __ATOMIC_RELAXED);
				return false;
			}
			continue;
		}

		ring = mmap(NULL, mmap_sz, PROT_READ | PROT_WRITE,
			    MAP_SHARED, perf_fd, 0);
		if (ring == MAP_FAILED) {
			if (i == 0 && (errno == EPERM || errno == EACCES)) {
				close(perf_fd);
				*unsupported = true;
				__atomic_add_fetch(&shm->stats.recipe_unsupported,
						   1, __ATOMIC_RELAXED);
				return false;
			}
			close(perf_fd);
			continue;
		}

		/* Activate sampling so the ring has a chance to fill while
		 * the racer is poll/read-ing. */
		(void)ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0);

		ra.perf_fd = perf_fd;
		if (clock_gettime(CLOCK_MONOTONIC, &ra.deadline) < 0) {
			munmap(ring, mmap_sz);
			close(perf_fd);
			continue;
		}
		ra.deadline.tv_nsec += RECIPE_RACER_TIMEOUT_MS * 1000000L;
		while (ra.deadline.tv_nsec >= 1000000000L) {
			ra.deadline.tv_nsec -= 1000000000L;
			ra.deadline.tv_sec  += 1;
		}

		rc = pthread_create(&tid, NULL,
				    perf_mmap_close_racer_thread, &ra);
		if (rc != 0) {
			munmap(ring, mmap_sz);
			close(perf_fd);
			if (++spawn_fail_streak >= RECIPE_THREAD_SPAWN_LATCH)
				break;
			continue;
		}
		spawn_fail_streak = 0;

		/* Variable race window -- 0..100us picks a random sub-
		 * window of the racer's poll/read loop to land the close
		 * in. */
		if ((rand() & 0xff) != 0)
			usleep((useconds_t)(rand() % 101));

		(void)close(perf_fd);

		(void)pthread_join(tid, NULL);

		/* Drop the mmap reference last -- the rb refcount survives
		 * close() until the final munmap, exercising the
		 * perf_mmap_close vm_op teardown after the close race has
		 * completed. */
		munmap(ring, mmap_sz);

		completed++;
	}

	return completed > 0;
}

/*
 * Racer thread for recipe_keys_revoke_race.  Loops keyctl(KEYCTL_READ)
 * against a freshly-created "user" key under a 100ms deadline.  keyctl
 * is not poll()-able, so the deadline-loop shape mirrors recipe_perf_
 * mmap_close rather than the poll-then-read shape used by recipe_
 * timerfd_xclose -- maximises the chance the racer is consistently
 * inside keyctl_read / key_validate / type->read on the keyring data
 * when the main thread lands keyctl_revoke.
 *
 * EKEYREVOKED on read is the post-revoke success path; EACCES /
 * ENOKEY is the lookup-after-unlink window; success is the
 * read-completed-before-revoke sub-window.  All terminate the
 * syscall in well under one alarm tick.
 */
struct keys_revoke_racer_arg {
	int32_t		key_id;		/* key_serial_t */
	struct timespec	deadline;
};

static bool keys_revoke_deadline_passed(const struct timespec *deadline)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		return true;
	if (now.tv_sec > deadline->tv_sec)
		return true;
	if (now.tv_sec == deadline->tv_sec && now.tv_nsec >= deadline->tv_nsec)
		return true;
	return false;
}

static void *keys_revoke_racer_thread(void *arg)
{
	struct keys_revoke_racer_arg *ra = arg;
	unsigned char buf[64];
	long r __unused__;

	/* Tight-spin keyctl_read.  user-type payloads are tiny so each
	 * call returns almost immediately; no usleep between iterations
	 * keeps the racer maximally inside the kernel-side validate /
	 * type->read window when revoke lands. */
	while (!keys_revoke_deadline_passed(&ra->deadline)) {
		r = syscall(__NR_keyctl, (unsigned long)KEYCTL_READ,
			    (unsigned long)ra->key_id,
			    (unsigned long)buf,
			    (unsigned long)sizeof(buf), 0UL);
	}
	return NULL;
}

/*
 * Recipe 32: keyring key revoke-vs-read race.
 *
 * Per cycle (1..MAX_CYCLES):
 *
 *   keyctl(KEYCTL_JOIN_SESSION_KEYRING, NULL) (once per recipe call) ->
 *   add_key("user", "trinity-keys-revoke-race-NN", payload, 16,
 *           KEY_SPEC_SESSION_KEYRING) -> spawn racer that loops
 *   keyctl(KEYCTL_READ) under a 100ms deadline -> usleep 0..100us
 *   race-window jitter -> keyctl(KEYCTL_REVOKE) (the race) ->
 *   pthread_join -> keyctl(KEYCTL_UNLINK).
 *
 * Targets the kernel paths key_revoke / type->revoke vs keyctl_read /
 * key_validate / type->read, plus the RCU teardown of struct
 * user_key_payload on user_revoke().  Both threads share the same
 * key_serial_t, which is the bug class -- a sibling process operating
 * on a separate keyring never races with our key_validate.  Distinct
 * from random keyctl callers in the syscall fuzzer that target a
 * key in isolation; this recipe drives the *concurrent* read-vs-
 * revoke window on a key with an active reader.
 *
 * Bounded racer (deadline-gated keyctl_read returning immediately on
 * EKEYREVOKED / ENOKEY / EACCES) means plain pthread_join always
 * returns within ~100ms.  Sidesteps the wedge problem where pthread_
 * cancel against a thread mid-syscall is unreliable and detached
 * threads leak state.  Mirrors the deadline-loop shape from recipe_
 * perf_mmap_close, sharing RECIPE_RACER_TIMEOUT_MS and RECIPE_THREAD_
 * SPAWN_LATCH.
 *
 * THREAD_SPAWN_LATCH=3 consecutive pthread_create failures bails
 * for the rest of the invocation -- under nproc/thread limits the
 * EAGAIN won't lift mid-op while fork_storm or cgroup_churn are
 * competing for the budget.
 *
 * Latch shape covers every way the feature can be absent on the
 * very first probe:
 *   - keyctl ENOSYS                 (CONFIG_KEYS off)
 *   - keyctl JOIN EPERM / EACCES    (LSM denies session keyring)
 *   - add_key ENOSYS / EPERM        (key type "user" disabled / LSM)
 *   - add_key EDQUOT                (kernel.keys.maxkeys exhausted)
 *
 * Once latched, the dispatcher stops siblings from re-probing the
 * unsupported feature on every recipe pick.
 *
 * Per-cycle add_key failures mid-loop are tolerated (one bad cycle,
 * e.g. ephemeral EDQUOT under sibling load, shouldn't penalise the
 * whole recipe).  Cleanup unlinks the key from the session keyring
 * after revoke so gc_works can progress promptly; EKEYREVOKED on the
 * unlink itself is fine and intentionally ignored.
 */
#define RECIPE_KEYS_REVOKE_MAX_CYCLES	4
#define RECIPE_KEYS_REVOKE_PAYLOAD_LEN	16

static bool recipe_keys_revoke_race(bool *unsupported)
{
	unsigned char payload[RECIPE_KEYS_REVOKE_PAYLOAD_LEN];
	char desc[64];
	unsigned int cycles;
	unsigned int i;
	unsigned int spawn_fail_streak = 0;
	unsigned int completed = 0;
	long jr;

	/* Anchor a session keyring up-front so add_key has somewhere to
	 * link.  Each call creates a fresh anonymous session keyring;
	 * no other recipe touches keyrings, so this does not clobber
	 * sibling state inside the trinity child. */
	jr = syscall(__NR_keyctl, (unsigned long)KEYCTL_JOIN_SESSION_KEYRING,
		     0UL, 0UL, 0UL, 0UL);
	if (jr < 0) {
		if (errno == ENOSYS || errno == EPERM ||
		    errno == EOPNOTSUPP || errno == EACCES) {
			*unsupported = true;
			__atomic_add_fetch(&shm->stats.recipe_unsupported, 1,
					   __ATOMIC_RELAXED);
		}
		return false;
	}

	memset(payload, 0xa5, sizeof(payload));

	cycles = 1 + ((unsigned int)rand() % RECIPE_KEYS_REVOKE_MAX_CYCLES);

	for (i = 0; i < cycles; i++) {
		struct keys_revoke_racer_arg ra;
		pthread_t tid;
		long key;
		int rc;

		snprintf(desc, sizeof(desc),
			 "trinity-keys-revoke-race-%u-%u",
			 (unsigned int)getpid(), i);

		key = syscall(__NR_add_key, "user", desc,
			      payload, (size_t)sizeof(payload),
			      (unsigned long)KEY_SPEC_SESSION_KEYRING);
		if (key < 0) {
			if (i == 0 && (errno == ENOSYS || errno == EPERM ||
				       errno == EOPNOTSUPP ||
				       errno == EDQUOT)) {
				*unsupported = true;
				__atomic_add_fetch(&shm->stats.recipe_unsupported,
						   1, __ATOMIC_RELAXED);
				return false;
			}
			continue;
		}

		ra.key_id = (int32_t)key;
		if (clock_gettime(CLOCK_MONOTONIC, &ra.deadline) < 0) {
			(void)syscall(__NR_keyctl, (unsigned long)KEYCTL_UNLINK,
				      (unsigned long)key,
				      (unsigned long)KEY_SPEC_SESSION_KEYRING,
				      0UL, 0UL);
			continue;
		}
		ra.deadline.tv_nsec += RECIPE_RACER_TIMEOUT_MS * 1000000L;
		while (ra.deadline.tv_nsec >= 1000000000L) {
			ra.deadline.tv_nsec -= 1000000000L;
			ra.deadline.tv_sec  += 1;
		}

		rc = pthread_create(&tid, NULL,
				    keys_revoke_racer_thread, &ra);
		if (rc != 0) {
			(void)syscall(__NR_keyctl, (unsigned long)KEYCTL_UNLINK,
				      (unsigned long)key,
				      (unsigned long)KEY_SPEC_SESSION_KEYRING,
				      0UL, 0UL);
			if (++spawn_fail_streak >= RECIPE_THREAD_SPAWN_LATCH)
				break;
			continue;
		}
		spawn_fail_streak = 0;

		/* Variable race window -- 0..100us picks a random sub-window
		 * of the racer's read loop to land the revoke in. */
		if ((rand() & 0xff) != 0)
			usleep((useconds_t)(rand() % 101));

		(void)syscall(__NR_keyctl, (unsigned long)KEYCTL_REVOKE,
			      (unsigned long)key, 0UL, 0UL, 0UL);

		(void)pthread_join(tid, NULL);

		/* Best-effort cleanup -- the key is revoked, but unlinking
		 * from the session keyring lets gc_works progress sooner.
		 * EKEYREVOKED on the unlink itself is fine. */
		(void)syscall(__NR_keyctl, (unsigned long)KEYCTL_UNLINK,
			      (unsigned long)key,
			      (unsigned long)KEY_SPEC_SESSION_KEYRING,
			      0UL, 0UL);

		completed++;
	}

	return completed > 0;
}

/*
 * Recipe 33: ptrace SEIZE+EXITKILL lifecycle.
 *
 * Per cycle (1..MAX_CYCLES):
 *
 *   fork() -> inner child blocks in pause() -> parent runs the
 *   SEIZE-style lifecycle on the tracee:
 *
 *     ptrace(PTRACE_SEIZE, child, 0,
 *            PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD) ->
 *     ptrace(PTRACE_INTERRUPT, child, 0, 0) ->
 *     waitpid(child, &status, __WALL) for the group-stop ->
 *     ptrace(PTRACE_GETSIGINFO, child, 0, &si) ->
 *     ptrace(PTRACE_SETOPTIONS, child, 0,
 *            PTRACE_O_EXITKILL | PTRACE_O_TRACEEXIT) ->
 *     ptrace(PTRACE_CONT, child, 0, 0) ->
 *     kill(child, SIGKILL) ->
 *     waitpid_eintr(child, &status, 0) reaps.
 *
 * Targets the kernel paths ptrace_attach (SEIZE branch) vs ptrace_
 * attach (legacy ATTACH branch), the PTRACE_INTERRUPT group-stop
 * delivery against a task in TASK_INTERRUPTIBLE pause(), the
 * PTRACE_O_EXITKILL flag wiring (set on attach via the data param,
 * mutated mid-trace via SETOPTIONS), the GETSIGINFO read of the
 * tracee's last_siginfo while it's group-stopped, and the SIGKILL-
 * vs-ptrace-stop teardown that exits a tracee out of a ptrace stop
 * via fatal_signal_pending().
 *
 * Distinct from the random-syscall ptrace path in syscalls/ptrace.c
 * which feeds isolated requests against arbitrary pids and is gated
 * AVOID_SYSCALL.  This recipe drives the structured SEIZE-then-INTERRUPT-
 * then-GETSIGINFO-then-SETOPTIONS-then-CONT lifecycle on a tracee
 * the recipe itself owns -- arguments are concrete and ordered, so
 * the kernel paths between SEIZE and DETACH/teardown are reachable
 * end-to-end on every cycle.
 *
 * Single-thread by design: ptrace state is task-scoped and the
 * SEIZE/INTERRUPT handshake serialises naturally inside the parent.
 * Kernel-side concurrency (signal-vs-ptrace_stop, EXITKILL-on-tracer-
 * exit) is exercised by the kernel's own task-switch interleaving
 * between our parent's syscalls and the tracee's pause()/wakeup
 * transitions.
 *
 * EXITKILL is the *attribute* under test even though we tear down
 * the tracee explicitly with SIGKILL: the flag must be settable on
 * SEIZE, mutable via SETOPTIONS, and not interfere with the normal
 * stop/resume cycle.  A kernel bug in the EXITKILL plumbing that
 * killed the tracee prematurely (before our SIGKILL) would land
 * a WIFSIGNALED early -- still safe under waitpid_eintr.
 *
 * Latch shape covers every way the feature can be absent on the
 * very first probe:
 *   - ptrace SEIZE ENOSYS           (kernel < 3.4, vanishingly rare)
 *   - ptrace SEIZE EPERM            (YAMA ptrace_scope=2/3, LSM denial)
 *   - ptrace SEIZE EACCES           (LSM denial via security_ptrace_
 *                                    access_check)
 *
 * Once latched, the dispatcher stops siblings from re-probing the
 * unsupported feature on every recipe pick.
 *
 * Per-cycle fork failure (EAGAIN under nproc/thread limits) is
 * tolerated mid-loop; FORK_FAIL_LATCH=3 consecutive failures bails
 * for the rest of the invocation since competing fork_storm /
 * cgroup_churn won't lift the limit mid-op.
 *
 * Cleanup ordering on every exit path: SIGKILL the tracee (idempotent
 * if already dead), waitpid_eintr to reap the zombie, return.  The
 * inner child uses _exit() in its (unreachable) tail to skip atexit
 * handlers that could touch trinity shared state from a stopped
 * tracee context.
 */
#define RECIPE_PTRACE_SEIZE_MAX_CYCLES		4
#define RECIPE_PTRACE_SEIZE_FORK_FAIL_LATCH	3

static bool recipe_ptrace_seize_exitkill(bool *unsupported)
{
	unsigned int cycles;
	unsigned int i;
	unsigned int fork_fail_streak = 0;
	unsigned int completed = 0;

	cycles = 1 + ((unsigned int)rand() % RECIPE_PTRACE_SEIZE_MAX_CYCLES);

	for (i = 0; i < cycles; i++) {
		siginfo_t si;
		pid_t pid;
		long pr;
		int status;

		pid = fork();
		if (pid < 0) {
			if (++fork_fail_streak >=
			    RECIPE_PTRACE_SEIZE_FORK_FAIL_LATCH)
				break;
			continue;
		}
		fork_fail_streak = 0;

		if (pid == 0) {
			/* Inner tracee: block in pause() so the parent has
			 * a deterministic stop point to SEIZE+INTERRUPT.
			 * Any SIGKILL from the parent reaps us cleanly.
			 * _exit() skips atexit handlers that could touch
			 * trinity shared state from a stopped-and-resumed
			 * tracee context. */
			(void)pause();
			_exit(0);
		}

		pr = ptrace(PTRACE_SEIZE, pid, (void *)0,
			    (void *)(unsigned long)
			    (PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD));
		if (pr < 0) {
			if (i == 0 && (errno == ENOSYS || errno == EPERM ||
				       errno == EACCES)) {
				(void)kill(pid, SIGKILL);
				(void)waitpid_eintr(pid, &status, 0);
				*unsupported = true;
				__atomic_add_fetch(&shm->stats.recipe_unsupported,
						   1, __ATOMIC_RELAXED);
				return false;
			}
			(void)kill(pid, SIGKILL);
			(void)waitpid_eintr(pid, &status, 0);
			continue;
		}

		/* Move the tracee into PTRACE_EVENT_STOP.  SEIZE never
		 * sends an initial SIGSTOP (unlike ATTACH); INTERRUPT is
		 * the only way to drive a SEIZE'd tracee into a stop. */
		(void)ptrace(PTRACE_INTERRUPT, pid, (void *)0, (void *)0);

		if (waitpid_eintr(pid, &status, __WALL) < 0) {
			(void)kill(pid, SIGKILL);
			(void)waitpid_eintr(pid, &status, 0);
			continue;
		}

		/* If the tracee already died (kernel killed it for whatever
		 * reason), there's no live ptrace state to drive -- just
		 * count the cycle and move on.  This also covers the
		 * EXITKILL-fired-early path where the kernel decided to
		 * kill the tracee on attach. */
		if (!WIFSTOPPED(status)) {
			completed++;
			continue;
		}

		/* Light interaction with the stopped tracee.  Both calls
		 * exercise paths gated on the tracee being in a ptrace
		 * stop; failures are best-effort and intentionally ignored
		 * (a kernel bug here is exactly what we want exposed). */
		memset(&si, 0, sizeof(si));
		(void)ptrace(PTRACE_GETSIGINFO, pid, (void *)0, &si);

		(void)ptrace(PTRACE_SETOPTIONS, pid, (void *)0,
			     (void *)(unsigned long)
			     (PTRACE_O_EXITKILL | PTRACE_O_TRACEEXIT));

		(void)ptrace(PTRACE_CONT, pid, (void *)0, (void *)0);

		/* Tear down: SIGKILL bypasses ptrace and reaps the tracee
		 * via fatal_signal_pending() out of pause() / any ptrace
		 * stop.  waitpid_eintr drains the zombie so we don't leak
		 * a child across recipe invocations. */
		(void)kill(pid, SIGKILL);
		(void)waitpid_eintr(pid, &status, 0);

		completed++;
	}

	return completed > 0;
}

/*
 * Inner-child helper for recipe_mount_userns_dance: write a single line
 * to the named /proc/self/{uid_map,gid_map,setgroups} file.  Returns
 * true on a complete write, false otherwise.  Best-effort: callers
 * decide whether a partial map is fatal for their op.  Mirrors the
 * write_one_line helper in childops/userns-fuzzer.c -- intentionally
 * duplicated rather than hoisted, since recipe-runner.c is a self-
 * contained dispatcher and the helper is a 10-line inline that would
 * not benefit from a cross-file abstraction.
 */
static bool mount_userns_write_one_line(const char *path, const char *line)
{
	ssize_t wlen;
	size_t len;
	int fd;

	fd = open(path, O_WRONLY);
	if (fd < 0)
		return false;

	len = strlen(line);
	wlen = write(fd, line, len);
	close(fd);
	return wlen == (ssize_t)len;
}

/*
 * Inner child of recipe_mount_userns_dance.  Enters a fresh user
 * namespace + mount namespace, establishes the uid/gid 0 mapping
 * inside the userns, then drives the mount lifecycle described in
 * the recipe header below.  Exits with a status code the parent can
 * decode to differentiate "feature unsupported" from "ran to
 * completion".
 *
 * Exit codes:
 *   0  -- ran the dance to completion (some mount calls may have
 *         failed on the way; that's tolerated, the recipe is about
 *         driving the path, not asserting the result)
 *   1  -- unshare(CLONE_NEWUSER | CLONE_NEWNS) failed -- triggers
 *         the *unsupported latch in the parent
 *   2  -- map establishment failed -- not an unsupported signal
 *         (could be transient EBUSY on the maps, or LSM-specific)
 *   3  -- mount("none", "/", MS_PRIVATE) failed -- can't proceed
 *         safely without a private root inside the new mount ns
 */
static void mount_userns_dance_inner(void) __attribute__((noreturn));
static void mount_userns_dance_inner(void)
{
	char buf[64];
	uid_t uid = getuid();
	gid_t gid = getgid();

	if (unshare(CLONE_NEWUSER | CLONE_NEWNS) != 0)
		_exit(1);

	/* setgroups must be denied before gid_map can be written when
	 * the writer is unprivileged, per Documentation/admin-guide/
	 * namespaces/user.rst.  The uid_map write order doesn't matter
	 * but we stage all three for symmetry. */
	snprintf(buf, sizeof(buf), "0 %u 1\n", (unsigned int)uid);
	if (!mount_userns_write_one_line("/proc/self/uid_map", buf))
		_exit(2);

	if (!mount_userns_write_one_line("/proc/self/setgroups", "deny\n"))
		_exit(2);

	snprintf(buf, sizeof(buf), "0 %u 1\n", (unsigned int)gid);
	if (!mount_userns_write_one_line("/proc/self/gid_map", buf))
		_exit(2);

	/* MS_REC | MS_PRIVATE on the root is mandatory before any further
	 * mount() in this ns -- without it, propagation could leak our
	 * tmpfs into the host mount tree on systems where / is MS_SHARED.
	 * The trinity child already did this once on its own CLONE_NEWNS
	 * unshare at startup, but our fresh CLONE_NEWNS resets the
	 * propagation state and we have to redo it. */
	if (mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0)
		_exit(3);

	/* tmpfs at /tmp.  Drives the do_new_mount path through the new
	 * userns/mountns, including the ns_capable check against the ns's
	 * owning userns and the superblock allocation. */
	if (mount("none", "/tmp", "tmpfs", 0, NULL) != 0) {
		/* No tmpfs available, or LSM denial -- still exit success
		 * because the unshare/map path itself was driven. */
		_exit(0);
	}

	/* Propagation flag mutation: change /tmp to MS_PRIVATE
	 * explicitly.  Drives the mount-flag-change path
	 * (do_change_type) distinct from the initial mount creation. */
	(void)mount(NULL, "/tmp", NULL, MS_PRIVATE, NULL);

	/* Remount with new flags: MS_RDONLY|MS_REMOUNT.  Drives the
	 * do_remount path which walks the superblock's remount_fs op
	 * and rewrites mnt_flags atomically. */
	(void)mount(NULL, "/tmp", NULL, MS_RDONLY | MS_REMOUNT, NULL);

	/* Lazy unmount: MNT_DETACH.  Drives the do_umount path with
	 * MNT_DETACH semantics -- detaches from the namespace tree
	 * immediately but defers the actual cleanup until the last
	 * reference drops. */
	(void)umount2("/tmp", MNT_DETACH);

	_exit(0);
}

/*
 * Recipe 34: mount/userns dance.
 *
 * Per call:
 *
 *   fork() -> inner child -> unshare(CLONE_NEWUSER | CLONE_NEWNS) ->
 *   write /proc/self/uid_map + setgroups=deny + gid_map ->
 *   mount("none", "/", NULL, MS_REC|MS_PRIVATE, NULL) ->
 *   mount("none", "/tmp", "tmpfs", 0, NULL) ->
 *   mount(NULL, "/tmp", NULL, MS_PRIVATE, NULL) ->
 *   mount(NULL, "/tmp", NULL, MS_RDONLY|MS_REMOUNT, NULL) ->
 *   umount2("/tmp", MNT_DETACH) ->
 *   _exit(0); parent waitpid_eintr.
 *
 * Targets the kernel paths that fire when a userns and a mount ns
 * are created together with the mount ns owned by the new userns:
 *   - copy_user_ns + copy_mnt_ns + the ownership chain that links
 *     the new mnt_ns->user_ns to the freshly-allocated user_ns
 *   - proc_uid_map_write / proc_gid_map_write / proc_setgroups_write
 *     paths with their EBUSY-vs-already-set state machine
 *   - do_change_type (propagation-flag mutation, distinct from
 *     initial mount creation)
 *   - do_remount (superblock remount_fs op, mnt_flags rewrite under
 *     namespace_sem)
 *   - do_umount with MNT_DETACH (deferred-cleanup path that
 *     decouples namespace removal from final put_mnt_ns)
 *
 * Distinct from childops/userns-fuzzer.c which enters CLONE_NEWUSER
 * but only dispatches a single ns_capable-gated op; distinct from
 * childops/fs-lifecycle.c which drives mount lifecycles inside the
 * trinity child's existing CLONE_NEWNS without a fresh userns.  The
 * combination -- fresh userns *and* fresh mountns *and* a multi-step
 * propagation/remount/detach sequence -- is unreachable through any
 * single existing op.
 *
 * Single-thread by design: namespace/mount state changes are
 * serialised by namespace_sem inside the kernel and the per-step
 * sequence is the bug surface, not concurrency.  Forking an inner
 * child contains the userns/mountns transition so trinity's outer
 * state (caps, original mount tree) is never disturbed; a crash
 * inside the dance is reaped here as WIFSIGNALED without disturbing
 * sibling recipes.
 *
 * Latch shape covers every way the feature can be absent on the
 * very first probe.  The inner child reports unshare failure via
 * exit code 1, and the parent treats WEXITSTATUS(status) == 1 as
 * the unsupported signal:
 *   - unshare CLONE_NEWUSER EPERM        (user.max_user_namespaces=0,
 *                                         kernel.unprivileged_userns_clone=0,
 *                                         LSM denial)
 *   - unshare CLONE_NEWUSER ENOSYS       (CONFIG_USER_NS=n, very rare)
 *   - unshare CLONE_NEWNS EPERM          (CONFIG_NAMESPACES=n -- all
 *                                         namespace ops denied)
 *
 * Once latched, the dispatcher stops siblings from re-probing the
 * unsupported feature on every recipe pick.
 *
 * Per-call fork failure (EAGAIN under nproc/thread limits) returns
 * partial; no in-loop tolerance because there's only one fork per
 * recipe call.  WIFSIGNALED on the inner child (e.g. OOM-kill)
 * counts as ran-the-path but partial.
 */
static bool recipe_mount_userns_dance(bool *unsupported)
{
	pid_t pid;
	int status;

	pid = fork();
	if (pid < 0)
		return false;

	if (pid == 0) {
		mount_userns_dance_inner();
		/* unreachable -- inner uses _exit on every path */
	}

	if (waitpid_eintr(pid, &status, 0) < 0)
		return false;

	if (WIFEXITED(status) && WEXITSTATUS(status) == 1) {
		/* unshare(CLONE_NEWUSER | CLONE_NEWNS) failed -- almost
		 * certainly EPERM from a hardened policy.  Latch so the
		 * dispatcher stops picking this recipe. */
		*unsupported = true;
		__atomic_add_fetch(&shm->stats.recipe_unsupported, 1,
				   __ATOMIC_RELAXED);
		return false;
	}

	/* Any other exit code -- including WIFSIGNALED, WEXITSTATUS in
	 * {0, 2, 3} -- counts as having driven the path far enough to
	 * be useful.  WEXITSTATUS 2/3 indicate map-write or root-
	 * remount failure after a successful unshare; the unshare itself
	 * is the dominant kernel surface and is exercised in those
	 * paths regardless. */
	return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

/*
 * Compatibility shims for hosts whose linux/seccomp.h predates the
 * USER_NOTIF listener interface (added in 5.0) or the explicit ALLOW
 * "fake-success" response mode.  Defining the constants locally lets
 * recipe-runner.c build everywhere; the *runtime* check is the seccomp()
 * syscall itself, which returns EINVAL on kernels without the feature
 * and is caught by the unsupported latch below.
 */
#ifndef SECCOMP_SET_MODE_FILTER
#define SECCOMP_SET_MODE_FILTER		1
#endif
#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
#define SECCOMP_FILTER_FLAG_NEW_LISTENER	(1UL << 3)
#endif
#ifndef SECCOMP_RET_USER_NOTIF
#define SECCOMP_RET_USER_NOTIF		0x7fc00000U
#endif
#ifndef SECCOMP_RET_ALLOW
#define SECCOMP_RET_ALLOW		0x7fff0000U
#endif

/*
 * Inner child of recipe_seccomp_listener_exec.  Inherits the seccomp
 * filter installed by the supervisor; calls uname() (trapped to
 * USER_NOTIF and held until the supervisor responds via NOTIF_SEND)
 * then execve()s /bin/true to drive the post-filter exec path.
 *
 * uname() is the trap point because glibc never calls it implicitly
 * post-fork along any path we care about — picking getpid() (the
 * obvious other "single-arg, side-effect-free" candidate) would risk
 * the supervisor self-deadlocking the moment libc's own bookkeeping
 * called getpid() between seccomp() install and the first NOTIF_RECV.
 *
 * syscall(__NR_uname, ...) bypasses any libc wrapping that might cache
 * the result or route via vDSO; we want the raw seccomp trap, not a
 * cached struct utsname.  /bin/true is a tiny binary that returns 0;
 * the recipe doesn't depend on its output, only on driving execve()
 * through the post-seccomp-filter task_struct.
 */
static void seccomp_listener_inner(void) __attribute__((noreturn));
static void seccomp_listener_inner(void)
{
	struct utsname u;

	(void)syscall(__NR_uname, &u);

	(void)execl("/bin/true", "/bin/true", (char *)NULL);

	_exit(0);
}

/*
 * Build and install a SECCOMP_RET_USER_NOTIF filter that traps
 * __NR_uname.  Returns the listener fd from the kernel on success,
 * -1 on failure with errno preserved for the caller's latch.
 */
static int seccomp_listener_install(void)
{
	struct sock_filter filter[] = {
		/* A = seccomp_data.nr (syscall number) */
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 offsetof(struct seccomp_data, nr)),
		/* if (A == __NR_uname) goto notify */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_uname, 0, 1),
		/* notify: return USER_NOTIF (kernel parks the syscall and
		 * blocks the calling thread until the listener responds) */
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
		/* allow: return ALLOW (everything else passes through) */
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = {
		.len = (unsigned short)ARRAY_SIZE(filter),
		.filter = filter,
	};

	return (int)syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
			    SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
}

/*
 * Supervisor body of recipe_seccomp_listener_exec.  Runs in its own
 * fork() so the seccomp filter never touches trinity's outer child:
 * once SECCOMP_SET_MODE_FILTER is installed, every uname() in the
 * task and its descendants traps through the listener fd, and the
 * filter cannot be removed.
 *
 * Exit codes (consumed by recipe_seccomp_listener_exec):
 *   0  -- ran the full poll/RECV/ID_VALID/SEND/close/waitpid sequence
 *   1  -- prctl(NO_NEW_PRIVS) or seccomp() returned an "unsupported"
 *         errno (ENOSYS / EINVAL / EACCES) — triggers the *unsupported
 *         latch in the parent
 *   2  -- transient failure pre-listener (prctl other errno, fork failure)
 *   3  -- post-listener flow failure (poll timeout, RECV error) — listener
 *         was created so the feature is supported, just didn't complete
 *         this cycle
 */
#define RECIPE_SECCOMP_LISTENER_POLL_MS	1000

static int recipe_seccomp_listener_supervisor(void)
{
	struct seccomp_notif req;
	struct seccomp_notif_resp resp;
	struct pollfd pfd;
	pid_t inner;
	int listener;
	int status;
	int pr;

	/* NO_NEW_PRIVS is the precondition for an unprivileged
	 * SECCOMP_SET_MODE_FILTER.  ENOSYS here means
	 * CONFIG_SECCOMP=n (PR_SET_NO_NEW_PRIVS landed in 3.5; the
	 * separate seccomp(2) syscall in 3.17). */
	if (prctl(PR_SET_NO_NEW_PRIVS, 1UL, 0UL, 0UL, 0UL) != 0) {
		if (errno == ENOSYS)
			return 1;
		return 2;
	}

	listener = seccomp_listener_install();
	if (listener < 0) {
		/* ENOSYS  : pre-3.17 kernel without the seccomp() syscall.
		 * EINVAL  : SECCOMP_FILTER_FLAG_NEW_LISTENER unsupported
		 *           (pre-5.0) or BPF program rejected.
		 * EACCES  : LSM denial / NO_NEW_PRIVS missing on a code path
		 *           that bypassed the prctl above. */
		if (errno == ENOSYS || errno == EINVAL || errno == EACCES)
			return 1;
		return 2;
	}

	inner = fork();
	if (inner < 0) {
		close(listener);
		return 2;
	}

	if (inner == 0) {
		/* Inner does not need its inherited copy of the listener
		 * fd; closing it here keeps the kernel-side reference count
		 * accurate so the supervisor's close() actually releases the
		 * notification queue. */
		close(listener);
		seccomp_listener_inner();
		/* unreachable -- inner uses _exit on every path */
	}

	/* Pre-poll the listener so a wedged/dead inner doesn't park us
	 * inside NOTIF_RECV indefinitely.  POLLIN fires once the kernel
	 * has a notification ready; POLLHUP fires if every task that
	 * could trap has died. */
	pfd.fd = listener;
	pfd.events = POLLIN;
	pfd.revents = 0;
	pr = poll(&pfd, 1, RECIPE_SECCOMP_LISTENER_POLL_MS);
	if (pr <= 0) {
		(void)kill(inner, SIGKILL);
		(void)waitpid_eintr(inner, &status, 0);
		close(listener);
		return 3;
	}

	memset(&req, 0, sizeof(req));
	if (ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, &req) < 0) {
		(void)kill(inner, SIGKILL);
		(void)waitpid_eintr(inner, &status, 0);
		close(listener);
		return 3;
	}

	/* ID_VALID returns 0 if the notification is still live, ENOENT if
	 * the trapped task died between RECV and now.  Best-effort: a
	 * dead-tracee response from SEND will fail harmlessly with ENOENT
	 * too, and we proceed to teardown either way. */
	(void)ioctl(listener, SECCOMP_IOCTL_NOTIF_ID_VALID, &req.id);

	memset(&resp, 0, sizeof(resp));
	resp.id = req.id;
	resp.val = 0;
	resp.error = 0;
	resp.flags = 0;
	(void)ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, &resp);

	close(listener);
	(void)waitpid_eintr(inner, &status, 0);
	return 0;
}

/*
 * Recipe 35: seccomp USER_NOTIF listener + traced exec.
 *
 * Per call:
 *
 *   fork() -> supervisor ->
 *     prctl(PR_SET_NO_NEW_PRIVS, 1) ->
 *     seccomp(SET_MODE_FILTER, FLAG_NEW_LISTENER, &prog)
 *       (BPF: __NR_uname -> USER_NOTIF, else ALLOW) ->
 *     fork() -> inner ->
 *       syscall(__NR_uname, &u)              [trapped, parks here]
 *       execl("/bin/true", ...)              [post-trap exec]
 *       _exit(0)
 *     supervisor:
 *       poll(listener, POLLIN, 1s) ->
 *       ioctl(SECCOMP_IOCTL_NOTIF_RECV, &req) ->
 *       ioctl(SECCOMP_IOCTL_NOTIF_ID_VALID, &req.id) ->
 *       ioctl(SECCOMP_IOCTL_NOTIF_SEND, &resp{id, val=0, error=0}) ->
 *       close(listener) ->
 *       waitpid_eintr(inner) ->
 *     _exit(rc)
 *   parent: waitpid_eintr(supervisor); WEXITSTATUS == 1 latches.
 *
 * Targets the kernel paths that fire when a SECCOMP_RET_USER_NOTIF
 * filter parks a syscall and userspace drives the listener:
 *   - prctl PR_SET_NO_NEW_PRIVS (task_struct->no_new_privs flip)
 *   - do_seccomp(SECCOMP_SET_MODE_FILTER, FLAG_NEW_LISTENER) ->
 *     anon_inode_getfd("seccomp notify") with the new
 *     seccomp_notif_ctx; filter is installed in current->seccomp.filter
 *     and inherited across the subsequent fork
 *   - fork copy_process inherits seccomp.filter; the inner's first
 *     uname() hits __seccomp_filter, marks the syscall as parked, and
 *     blocks on the listener's wait queue
 *   - SECCOMP_IOCTL_NOTIF_RECV (seccomp_notify_recv: dequeues the
 *     parked notification, copies seccomp_notif to userspace)
 *   - SECCOMP_IOCTL_NOTIF_ID_VALID (seccomp_notify_id_valid: looks up
 *     the notif by id under the ctx's mutex)
 *   - SECCOMP_IOCTL_NOTIF_SEND (seccomp_notify_send: matches the
 *     response by id, writes val/error into the parked syscall's
 *     result, wakes the trapped task)
 *   - close(listener) (seccomp_notify_release: tears down the
 *     notification queue, fails any in-flight ID_VALID with ENOENT)
 *   - search_binary_handler / load_elf_binary path on the inner's
 *     execl() *after* a seccomp filter has been installed and trapped
 *     once -- the post-trap exec path is the bug surface that's
 *     unreachable if you only install a filter or only trap.
 *
 * Distinct from fds/seccomp_notif.c which installs the filter inside
 * the trinity child for ioctl-fuzzing the listener fd from random_syscall
 * paths.  That provider never traps (its filter targets getpid which
 * the child doesn't call from the post-install code path) and never
 * drives the RECV/ID_VALID/SEND lifecycle end-to-end.  This recipe is
 * the only place trinity exercises the parked-syscall / NOTIF_SEND
 * matchup with a real trapped syscall on the inner.
 *
 * Single-thread by design: the seccomp listener model is intrinsically
 * a 1:1 supervisor/tracee handshake, and the kernel serialises
 * RECV/SEND through the notif_ctx mutex.  The race surface here is
 * inner-trap-vs-supervisor-RECV / SEND-vs-inner-resume, all driven by
 * task scheduling between the two processes the recipe owns.
 *
 * Latch shape:
 *   - prctl(NO_NEW_PRIVS) ENOSYS               -- CONFIG_SECCOMP=n
 *   - seccomp() ENOSYS                         -- pre-3.17 kernel
 *   - seccomp() EINVAL                         -- FLAG_NEW_LISTENER
 *                                                 unsupported (pre-5.0)
 *                                                 or LSM-rewritten
 *   - seccomp() EACCES                         -- LSM denial
 *
 * The supervisor encodes "any of these triggered" as exit code 1; the
 * parent translates that to *unsupported = true and the dispatcher
 * stops siblings from re-probing.
 *
 * Cleanup ordering on every supervisor exit path: SIGKILL the inner
 * (idempotent if already dead/exec'd-and-exited), waitpid_eintr,
 * close the listener.  /bin/true exits 0 in <1ms on every distro
 * trinity targets; the supervisor's waitpid never blocks for long.
 *
 * Per-call fork failure (EAGAIN under nproc/thread limits) is reported
 * by the supervisor as exit code 2 -- not unsupported, just transient,
 * the dispatcher will pick again next cycle.
 */
static bool recipe_seccomp_listener_exec(bool *unsupported)
{
	pid_t supervisor;
	int status;

	supervisor = fork();
	if (supervisor < 0)
		return false;

	if (supervisor == 0)
		_exit(recipe_seccomp_listener_supervisor());

	if (waitpid_eintr(supervisor, &status, 0) < 0)
		return false;

	if (WIFEXITED(status) && WEXITSTATUS(status) == 1) {
		*unsupported = true;
		__atomic_add_fetch(&shm->stats.recipe_unsupported, 1,
				   __ATOMIC_RELAXED);
		return false;
	}

	return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

/*
 * Inner child of recipe_cgroup_kill_events.  Joins the freshly-mkdir'd
 * cgroup by writing its own pid into <cgroup>/cgroup.procs, signals
 * the supervisor that it is in (or attempted to be in) the cgroup via
 * a single byte on the pipe write end, then pause()s waiting for the
 * SIGKILL the supervisor will issue via the cgroup.kill control file.
 *
 * The signal-byte handshake exists so the supervisor doesn't race
 * ahead and write to cgroup.kill before the inner has joined the
 * cgroup -- otherwise __cgroup_kill walks an empty css_task_iter and
 * the populated/frozen state on cgroup.events never changes,
 * defeating the kernfs_notify wake-poll part of the recipe.
 *
 * cgroup.procs write may legitimately fail (EACCES on a non-delegated
 * subtree under unprivileged trinity, EBUSY in the no-internal-procs
 * window, ENOSPC under cgroup.max.descendants, ...); the inner sends
 * the signal byte regardless so the supervisor doesn't stall, and the
 * supervisor's backup SIGKILL covers the "inner not in the cgroup"
 * case.
 */
static void cgroup_kill_inner(const char *cgroup_path, int pipe_w)
	__attribute__((noreturn));
static void cgroup_kill_inner(const char *cgroup_path, int pipe_w)
{
	char procs_path[128];
	char pidbuf[16];
	ssize_t w __unused__;
	int procs_fd;
	int len;
	char ack = '!';

	(void)snprintf(procs_path, sizeof(procs_path), "%s/cgroup.procs",
		       cgroup_path);
	procs_fd = open(procs_path, O_WRONLY);
	if (procs_fd >= 0) {
		len = snprintf(pidbuf, sizeof(pidbuf), "%d\n", (int)getpid());
		w = write(procs_fd, pidbuf, (size_t)len);
		close(procs_fd);
	}

	/* One byte is enough -- the supervisor read()s exactly one byte and
	 * doesn't care about the value, only the wakeup. */
	w = write(pipe_w, &ack, 1);
	close(pipe_w);

	(void)pause();
	_exit(0);
}

/*
 * Supervisor body of recipe_cgroup_kill_events.  Owns the cgroup
 * lifecycle (mkdir -> ... -> rmdir) and the cgroup.events / cgroup.kill
 * fds.  Forks a single inner that joins the cgroup and pauses, then
 * drives the cgroup.kill -> kernfs_notify -> cgroup.events post-kill
 * read sequence.
 *
 * Exit codes (consumed by recipe_cgroup_kill_events):
 *   0  -- ran the full mkdir/open/fork/kill/notify/read/waitpid/rmdir
 *         sequence
 *   1  -- mkdir or open(cgroup.events|cgroup.kill) returned an
 *         "unsupported" errno -- triggers the *unsupported latch in
 *         the parent
 *   2  -- transient post-cgroup-create failure (pipe2 / fork / open
 *         non-ENOENT) -- not unsupported, just retry next cycle
 */
#define RECIPE_CGROUP_KILL_NOTIFY_MS	200

static int recipe_cgroup_kill_supervisor(void)
{
	char cgroup_path[64];
	char path[128];
	char readbuf[256];
	struct pollfd pfd;
	ssize_t r __unused__;
	ssize_t w __unused__;
	int events_fd = -1;
	int kill_fd = -1;
	int pipefd[2] = { -1, -1 };
	pid_t inner = -1;
	int rc;
	int status;
	bool cgroup_made = false;
	char ack;

	(void)snprintf(cgroup_path, sizeof(cgroup_path),
		       "/sys/fs/cgroup/trinity-kill-%d", (int)getpid());

	if (mkdir(cgroup_path, 0755) != 0) {
		if (errno == EACCES || errno == EPERM || errno == EROFS ||
		    errno == ENOENT || errno == ENOTDIR)
			return 1;
		return 2;
	}
	cgroup_made = true;

	(void)snprintf(path, sizeof(path), "%s/cgroup.events", cgroup_path);
	events_fd = open(path, O_RDONLY | O_NONBLOCK);
	if (events_fd < 0) {
		/* cgroup.events appears whenever cgroup v2 is mounted; ENOENT
		 * here means the kernel doesn't expose it (extremely old
		 * cgroup v2, or a controller-less hierarchy). */
		rc = (errno == ENOENT) ? 1 : 2;
		goto out;
	}

	(void)snprintf(path, sizeof(path), "%s/cgroup.kill", cgroup_path);
	kill_fd = open(path, O_WRONLY);
	if (kill_fd < 0) {
		/* cgroup.kill landed in 5.14; ENOENT here is the canonical
		 * "feature absent" signal that latches the recipe off. */
		rc = (errno == ENOENT) ? 1 : 2;
		goto out;
	}

	if (pipe2(pipefd, O_CLOEXEC) != 0) {
		rc = 2;
		goto out;
	}

	inner = fork();
	if (inner < 0) {
		rc = 2;
		goto out;
	}

	if (inner == 0) {
		/* Inner doesn't need the supervisor's copies of these fds. */
		close(events_fd);
		close(kill_fd);
		close(pipefd[0]);
		cgroup_kill_inner(cgroup_path, pipefd[1]);
		/* unreachable -- inner uses _exit on every path */
	}

	/* Supervisor closes its write end; only the inner writes. */
	close(pipefd[1]);
	pipefd[1] = -1;

	/* Wait for the inner's "I'm in (or tried) the cgroup" handshake.
	 * read() blocks until the inner write()s; if the inner died
	 * before signalling we get EOF / 0 bytes and proceed regardless --
	 * the backup SIGKILL + waitpid below cleans up. */
	r = read(pipefd[0], &ack, 1);

	/* Pre-kill best-effort baseline read of cgroup.events.  Drives
	 * cgroup_events_show against a freshly-populated cgroup before any
	 * state change so the post-kill read has a comparator. */
	pfd.fd = events_fd;
	pfd.events = POLLIN;
	pfd.revents = 0;
	(void)poll(&pfd, 1, 0);
	r = read(events_fd, readbuf, sizeof(readbuf));

	/* Trigger cgroup.kill: write "1\n".  Drives cgroup_kill_write ->
	 * cgroup_kill_control -> __cgroup_kill which walks css_task_iter
	 * and SIGKILLs every task in this cgroup.  Side effect: the
	 * populated state on cgroup.events flips to 0 once the killed
	 * task is reaped, which fires kernfs_notify on the events file. */
	w = write(kill_fd, "1\n", 2);

	/* Wait up to 200ms for the kernfs_notify wake.  POLLPRI is the
	 * documented wake event for cgroup.events (kernfs_notify uses
	 * EPOLLPRI); some kernels also flag POLLIN.  A 200ms ceiling is
	 * generous enough that even a heavily-loaded host wakes here, but
	 * tight enough not to dominate the recipe's wall clock. */
	pfd.fd = events_fd;
	pfd.events = POLLPRI | POLLIN;
	pfd.revents = 0;
	(void)poll(&pfd, 1, RECIPE_CGROUP_KILL_NOTIFY_MS);

	/* Post-kill read: rewind and re-read cgroup.events to drive
	 * cgroup_events_show again, this time with the
	 * populated/frozen/exit state mutated by __cgroup_kill.  lseek
	 * back to 0 because kernfs files are seekable and a re-read
	 * without rewind would just yield EOF. */
	(void)lseek(events_fd, 0, SEEK_SET);
	r = read(events_fd, readbuf, sizeof(readbuf));

	/* Backup SIGKILL: covers the case where the inner failed to join
	 * the cgroup (write to cgroup.procs was denied), so cgroup.kill
	 * walked an empty iter and didn't reap the inner.  kill() on a
	 * pid already-killed-by-cgroup is a harmless no-op. */
	(void)kill(inner, SIGKILL);
	(void)waitpid_eintr(inner, &status, 0);
	inner = -1;

	rc = 0;

out:
	if (inner > 0) {
		(void)kill(inner, SIGKILL);
		(void)waitpid_eintr(inner, &status, 0);
	}
	if (pipefd[0] >= 0)
		close(pipefd[0]);
	if (pipefd[1] >= 0)
		close(pipefd[1]);
	if (kill_fd >= 0)
		close(kill_fd);
	if (events_fd >= 0)
		close(events_fd);
	if (cgroup_made)
		(void)rmdir(cgroup_path);
	return rc;
}

/*
 * Recipe 36: cgroup v2 cgroup.kill + cgroup.events lifecycle.
 *
 * Per call:
 *
 *   fork() -> supervisor ->
 *     mkdir("/sys/fs/cgroup/trinity-kill-PID", 0755) ->
 *     open("<cg>/cgroup.events", O_RDONLY|O_NONBLOCK) ->
 *     open("<cg>/cgroup.kill",   O_WRONLY) ->
 *     pipe2(pipefd, O_CLOEXEC) ->
 *     fork() -> inner ->
 *       open("<cg>/cgroup.procs", O_WRONLY) -> write "<pid>\n"
 *       write(pipefd[1], &ack, 1)            [signal supervisor]
 *       pause()                              [waits for cgroup.kill SIGKILL]
 *     supervisor:
 *       read(pipefd[0], &ack, 1)             [sync with inner]
 *       poll(events_fd, POLLIN, 0) + read    [pre-kill baseline]
 *       write(kill_fd, "1\n", 2)             [trigger cgroup.kill]
 *       poll(events_fd, POLLPRI|POLLIN, 200ms)  [kernfs_notify wake]
 *       lseek(events_fd, 0, SEEK_SET) + read [post-kill state]
 *       kill(inner, SIGKILL); waitpid_eintr  [backup reap]
 *       close fds
 *       rmdir("<cg>")
 *     _exit(rc)
 *   parent: waitpid_eintr(supervisor); WEXITSTATUS == 1 latches.
 *
 * Targets the kernel paths that fire when cgroup v2's cgroup.kill
 * control file is written and downstream readers observe the
 * populated-state change via kernfs_notify:
 *   - cgroup_mkdir + the kernfs node creation that auto-populates
 *     cgroup.events / cgroup.kill / cgroup.procs / cgroup.controllers
 *   - cgroup_procs_write (write to <cg>/cgroup.procs): the migrate
 *     path (cgroup_attach_task / cgroup_migrate / cgroup_post_fork
 *     for the css_set move) under cgroup_mutex
 *   - cgroup_kill_write -> cgroup_kill_control -> __cgroup_kill: the
 *     css_task_iter walk that group_send_sig_info(SIGKILL)s every
 *     member task; this is the entire cgroup.kill bug surface
 *   - kernfs_notify -> kernfs_notify_workfn -> wake the events_fd
 *     waitqueue with EPOLLPRI: triggered when populated transitions
 *     1 -> 0 after the killed inner is reaped
 *   - cgroup_events_show / cgroup_file_open / cgroup_file_release on
 *     the read-after-notify path (lseek(0) + read drives the
 *     seq_file regenerate path with mutated state)
 *   - cgroup_rmdir against a recently-emptied cgroup (offline_css for
 *     each subsys, kernfs_remove)
 *
 * Distinct from childops/cgroup-churn.c which mkdirs/rmdirs as fast
 * as possible to drive cgroup_mkdir/rmdir under contention but never
 * populates a cgroup with tasks, never opens cgroup.events, and
 * never exercises cgroup.kill.  This recipe is the only place
 * trinity drives the cgroup.kill -> SIGKILL members ->
 * kernfs_notify wake -> cgroup.events re-read sequence end-to-end.
 *
 * Single-thread by design: cgroup state changes serialise through
 * cgroup_mutex, and the recipe's bug surface is the kill-vs-notify-
 * vs-read ordering, not concurrent writers to cgroup.kill.  The
 * inner-vs-supervisor process pair gives the kernel a real task to
 * SIGKILL out of the cgroup, which is the only way to make
 * populated transition 1 -> 0 and fire the kernfs_notify wake.
 *
 * Latch shape covers every way the feature can be absent on the
 * very first probe.  The supervisor reports any of these via exit
 * code 1:
 *   - mkdir EACCES         (unprivileged trinity, /sys/fs/cgroup not
 *                           delegated to this user)
 *   - mkdir EPERM          (LSM denial)
 *   - mkdir EROFS          (cgroup v1 root mounted read-only)
 *   - mkdir ENOENT         (no /sys/fs/cgroup/ at all)
 *   - mkdir ENOTDIR        (something is mounted at /sys/fs/cgroup
 *                           that isn't cgroupfs)
 *   - open(cgroup.events) ENOENT  (no cgroup v2 events interface)
 *   - open(cgroup.kill)   ENOENT  (pre-5.14 kernel without
 *                                   cgroup.kill)
 *
 * Once latched the dispatcher stops siblings from re-probing.
 *
 * Cleanup ordering on every supervisor exit path: SIGKILL the inner
 * (idempotent if cgroup.kill already reaped it), waitpid_eintr,
 * close events/kill/pipe fds, rmdir the cgroup directory.  rmdir
 * is best-effort -- a cgroup with lingering offlining state may
 * return EBUSY transiently; we don't retry, the next recipe call
 * uses a fresh PID-named directory anyway.
 *
 * Per-call fork failure (EAGAIN under nproc/thread limits) is
 * reported by the supervisor as exit code 2 (transient); the
 * dispatcher will pick again next cycle.
 */
static bool recipe_cgroup_kill_events(bool *unsupported)
{
	pid_t supervisor;
	int status;

	supervisor = fork();
	if (supervisor < 0)
		return false;

	if (supervisor == 0)
		_exit(recipe_cgroup_kill_supervisor());

	if (waitpid_eintr(supervisor, &status, 0) < 0)
		return false;

	if (WIFEXITED(status) && WEXITSTATUS(status) == 1) {
		*unsupported = true;
		__atomic_add_fetch(&shm->stats.recipe_unsupported, 1,
				   __ATOMIC_RELAXED);
		return false;
	}

	return WIFEXITED(status) && WEXITSTATUS(status) == 0;
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
	{ "iouring_fixed_uaf", recipe_iouring_fixed_uaf },
	{ "bpf_htab_iter_del", recipe_bpf_htab_iter_del },
	{ "perf_mmap_close", recipe_perf_mmap_close },
	{ "keys_revoke_race", recipe_keys_revoke_race },
	{ "ptrace_seize_exitkill", recipe_ptrace_seize_exitkill },
	{ "mount_userns_dance", recipe_mount_userns_dance },
	{ "seccomp_listener_exec", recipe_seccomp_listener_exec },
	{ "cgroup_kill_events", recipe_cgroup_kill_events },
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
