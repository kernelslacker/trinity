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
#include "child.h"
#include "childop-outcome.h"
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
 * Arm 1 — SIGEV_NONE: no notification fires even if the timer expires,
 * keeping the recipe safe inside the existing signal regime.  Drives
 * settime / gettime / getoverrun / delete.
 *
 * Arm 2 — SIGEV_THREAD_ID: targets the calling thread's TID with a
 * private RT signal that is blocked before the timer is created and
 * drained via sigtimedwait() on the way out.  This exercises the
 * posix_timer_event() → send_sigqueue() → per-task signal delivery
 * path that SIGEV_NONE completely bypasses.
 *
 * Note: RLIMIT_RTPRIO hard limit is 0 on this host, so the
 * SCHED_RR / sched_setscheduler arm is omitted — it requires
 * CAP_SYS_NICE or a nonzero RLIMIT_RTPRIO and would fail in the
 * fuzz child.
 */
bool recipe_posix_timer(bool *unsupported __unused__)
{
	const enum child_op_type op = this_child()->op_type;
	struct sigevent sev;
	struct itimerspec its, cur;
	timer_t tid = NULL;
	bool created = false;
	bool ok = false;

	/* ---- arm 1: SIGEV_NONE ---- */
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

	/* ---- arm 2: SIGEV_THREAD_ID ---- */
	{
		sigset_t ss, oldss;
		siginfo_t si;
		struct timespec ts = { 0, 0 };
		timer_t tid2 = NULL;
		bool created2 = false;
		bool mask_saved = false;
		int sig;

		/* SIGRTMIN+8: well clear of glibc's reserved RT signals
		 * (SIGRTMIN+0..+2) and Trinity's own SIGALRM/SIGXCPU/SIGINT.
		 * Matches the existing RT-signal regime in recipe_signalfd
		 * and recipe_signalfd_delivery. */
		sig = SIGRTMIN + 8;
		if (sig >= SIGRTMAX)
			goto arm2_done;

		sigemptyset(&ss);
		sigaddset(&ss, sig);
		if (sigprocmask(SIG_BLOCK, &ss, &oldss) < 0)
			goto arm2_done;
		mask_saved = true;

		memset(&sev, 0, sizeof(sev));
		sev.sigev_notify		 = SIGEV_THREAD_ID;
		sev.sigev_signo			 = sig;
		sev._sigev_un._tid		 = (pid_t)syscall(__NR_gettid);
		sev.sigev_value.sival_int = 0x5e; /* arbitrary cookie */

		if (timer_create(CLOCK_MONOTONIC, &sev, &tid2) < 0)
			goto arm2_restore;
		created2 = true;

		memset(&its, 0, sizeof(its));
		its.it_value.tv_sec  = 0;
		its.it_value.tv_nsec = 5000000;	/* 5 ms */
		if (timer_settime(tid2, 0, &its, NULL) < 0)
			goto arm2_cleanup;

		/* Wait up to 50 ms for the RT signal delivery via
		 * posix_timer_event() -> send_sigqueue().  Best-effort:
		 * EINTR / EAGAIN are both fine. */
		ts.tv_sec  = 0;
		ts.tv_nsec = 50000000;
		(void)sigtimedwait(&ss, &si, &ts);

arm2_cleanup:
		if (created2)
			(void)timer_delete(tid2);

arm2_restore:
		/* Drain any residual pending delivery before unblocking so
		 * nothing escapes into the task's unblocked signal set. */
		ts.tv_sec  = 0;
		ts.tv_nsec = 0;
		while (sigtimedwait(&ss, &si, &ts) >= 0)
			;
		if (mask_saved)
			(void)sigprocmask(SIG_SETMASK, &oldss, NULL);
arm2_done:
		;
	}

	ok = true;
out:
	if (created)
		(void)timer_delete(tid);
	/* One raw syscall: syscall(__NR_gettid) in the SIGEV_THREAD_ID arm. */
	childop_direct_syscalls_add(op, 1);
	return ok;
}
