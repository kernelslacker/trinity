/*
 * Part of the recipe_runner catalogue; see recipe-runner.c for the
 * design rationale and recipe-runner-internal.h for the shared
 * declarations and macros.
 */

#include <errno.h>
#include <limits.h>
#include <mqueue.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
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
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <linux/futex.h>
#include <linux/memfd.h>
#include <linux/userfaultfd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "arch.h"
#include "syscall-gate.h"
#include "maps.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"
#include "pids.h"

#include "childops/recipe/internal.h"

#include "kernel/eventfd.h"
#include "kernel/fcntl.h"
#include "kernel/timerfd.h"
#include "kernel/memfd.h"
/*
 * Recipe 2: eventfd ping-pong.
 *
 * Creates an eventfd with semaphore semantics, writes a small counter,
 * reads it back, then writes again to verify the counter resets after
 * a non-semaphore read.  Closes cleanly.
 */
bool recipe_eventfd(bool *unsupported __unused__)
{
	uint64_t v;
	ssize_t r __unused__;
	int fd;
	bool ok = false;

	fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (fd < 0)
		goto out;

	v = 1 + rnd_modulo_u32(16);
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
 * Recipe 4: epoll lifecycle.
 *
 * Creates an epoll fd, adds an eventfd to it, waits with a 0ms timeout
 * (no event ready), modifies the registration, deletes it, then closes
 * both fds.  Exercises EPOLL_CTL_ADD / MOD / DEL on the same target —
 * the path that hits the rb-tree update and wake-callback registration.
 */
bool recipe_epoll(bool *unsupported __unused__)
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
bool recipe_signalfd(bool *unsupported __unused__)
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
	sig = SIGRTMIN + 8 + (int)rnd_modulo_u32(7);
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
