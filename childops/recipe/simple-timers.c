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
 * Recipe 1: timerfd lifecycle.
 *
 * Creates a one-shot relative timerfd, arms it for a few ms in the
 * future, reads its expiration count back (best-effort — may return
 * EAGAIN if the timer hasn't fired yet, that's fine), queries the
 * current setting, then closes.  Exercises the timerfd code path
 * end-to-end including the wait-queue plumbing the read side hits.
 */
bool recipe_timerfd(bool *unsupported __unused__)
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
 * Recipe 12: POSIX timer lifecycle.
 *
 * timer_create(SIGEV_NONE) — SIGEV_NONE means no notification fires
 * even if the timer expires, which keeps the recipe safe to run inside
 * the existing signal regime — settime relative for a few ms, gettime
 * to read it back, query overrun count, delete.
 */
bool recipe_posix_timer(bool *unsupported __unused__)
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
