/*
SYSCALL_DEFINE6(epoll_pwait, int, epfd, struct epoll_event __user *, events,
                int, maxevents, int, timeout, const sigset_t __user *, sigmask,
                size_t, sigsetsize)

SYSCALL_DEFINE6(epoll_pwait2, int, epfd, struct epoll_event __user *, events,
                int, maxevents, const struct __kernel_timespec __user *, timeout,
                const sigset_t __user *, sigmask, size_t, sigsetsize)

 * When  successful, returns the number of file descriptors ready for the requested I/O,
 * or zero if no file descriptor became ready during the requested timeout milliseconds.
 * When an error occurs, returns -1 and errno is set appropriately.
 */
#include <limits.h>
#include <signal.h>
#include <sys/epoll.h>
#include <time.h>
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

static int pick_maxevents(void)
{
	switch (rnd_modulo_u32(10)) {
	case 0:		return 1;
	case 1:
	case 2:
	case 3:		return 8;
	case 4:
	case 5:		return 64;
	case 6:
	case 7:		return 1024;
	case 8:		return 0;
	default:	return -1;
	}
}

static unsigned long pick_timeout_ms(void)
{
	switch (rnd_modulo_u32(10)) {
	case 0:		return (unsigned long) -1;
	case 1:
	case 2:		return 0;
	case 3:
	case 4:
	case 5:
	case 6:		return 1 + rnd_modulo_u32(100);
	case 7:		return INT_MAX;
	case 8:		return (unsigned long)(unsigned int) -2;
	default:	return rnd_u32();
	}
}

/*
 * sigmask + sigsetsize buckets.  The kernel checks sigsetsize ==
 * sizeof(sigset_t) before copying the mask in (kernel/signal.c::
 * sigmask_to_save), so wrong-size buckets exercise the early reject
 * path.  NULL sigmask is a common real-world pattern (caller did not
 * want signal-mask swap semantics) and skips the
 * sigprocmask/restore_user_sigmask paths entirely.
 */
static void pick_sigmask(struct syscallrecord *rec)
{
	sigset_t *mask;

	switch (rnd_modulo_u32(10)) {
	case 0:
	case 1:
	case 2:
		/* NULL: no mask swap. */
		rec->a5 = 0;
		rec->a6 = sizeof(sigset_t);
		return;
	case 3:
	case 4:
		/* Empty mask, correct size. */
		mask = (sigset_t *) get_writable_struct(sizeof(sigset_t));
		if (mask == NULL)
			return;
		sigemptyset(mask);
		rec->a5 = (unsigned long) mask;
		rec->a6 = sizeof(sigset_t);
		return;
	case 5:
	case 6:
		/* Block a real signal so the kernel's swap path has work. */
		mask = (sigset_t *) get_writable_struct(sizeof(sigset_t));
		if (mask == NULL)
			return;
		sigemptyset(mask);
		sigaddset(mask, SIGUSR1);
		sigaddset(mask, SIGUSR2);
		rec->a5 = (unsigned long) mask;
		rec->a6 = sizeof(sigset_t);
		return;
	case 7:
		/* Correct buffer, intentionally-wrong size. */
		mask = (sigset_t *) get_writable_struct(sizeof(sigset_t));
		if (mask == NULL)
			return;
		sigemptyset(mask);
		rec->a5 = (unsigned long) mask;
		rec->a6 = 0;
		return;
	case 8:
		mask = (sigset_t *) get_writable_struct(sizeof(sigset_t));
		if (mask == NULL)
			return;
		sigemptyset(mask);
		rec->a5 = (unsigned long) mask;
		rec->a6 = sizeof(sigset_t) * 2;
		return;
	default:
		/* Leave whatever ARG_ADDRESS/ARG_LEN produced. */
		rec->a6 = sizeof(sigset_t);
		return;
	}
}

static void size_events_buffer(struct syscallrecord *rec)
{
	long mx = (long) rec->a3;
	unsigned long bytes = (mx > 0 ? mx : 1) * sizeof(struct epoll_event);

	avoid_shared_buffer_out(&rec->a2, bytes);
}

static void sanitise_epoll_pwait(struct syscallrecord *rec)
{
	rec->a3 = (unsigned long) pick_maxevents();
	rec->a4 = pick_timeout_ms();
	pick_sigmask(rec);
	size_events_buffer(rec);
}

/*
 * epoll_pwait2's a4 is a timespec* rather than an int timeout, so
 * point it at a writable timespec with a short, valid duration most of
 * the time.  The kernel rejects tv_nsec >= 1e9 with EINVAL, so the
 * invalid bucket keeps that path warm without stalling the child.
 */
static void pick_timespec(struct syscallrecord *rec)
{
	struct timespec *ts;

	switch (rnd_modulo_u32(8)) {
	case 0:
		/* NULL: block forever (caller-controlled cancellation). */
		rec->a4 = 0;
		return;
	case 1:
	case 2:
	case 3:
		ts = (struct timespec *) get_writable_struct(sizeof(*ts));
		if (ts == NULL)
			return;
		ts->tv_sec = 0;
		ts->tv_nsec = (1 + rnd_modulo_u32(100)) * 1000000L;	/* 1..100 ms */
		rec->a4 = (unsigned long) ts;
		return;
	case 4:
		ts = (struct timespec *) get_writable_struct(sizeof(*ts));
		if (ts == NULL)
			return;
		ts->tv_sec = 0;
		ts->tv_nsec = 0;					/* poll-only */
		rec->a4 = (unsigned long) ts;
		return;
	case 5:
		ts = (struct timespec *) get_writable_struct(sizeof(*ts));
		if (ts == NULL)
			return;
		ts->tv_sec = LONG_MAX;
		ts->tv_nsec = 0;
		rec->a4 = (unsigned long) ts;
		return;
	default:
		ts = (struct timespec *) get_writable_struct(sizeof(*ts));
		if (ts == NULL)
			return;
		ts->tv_sec = rnd_u32();
		ts->tv_nsec = 1000000000L + rnd_modulo_u32(1000);	/* invalid */
		rec->a4 = (unsigned long) ts;
		return;
	}
}

static void sanitise_epoll_pwait2(struct syscallrecord *rec)
{
	rec->a3 = (unsigned long) pick_maxevents();
	pick_timespec(rec);
	pick_sigmask(rec);
	size_events_buffer(rec);
}

static void post_epoll_pwait(struct syscallrecord *rec)
{
	long retval    = (long) rec->retval;
	long maxevents = (long) rec->a3;

	if (retval == -1L)
		return;
	if (maxevents <= 0)
		return;
	if (retval > maxevents) {
		outputerr("post_epoll_pwait: rejecting retval %ld > maxevents %ld\n",
			 retval, maxevents);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}
}

struct syscallentry syscall_epoll_pwait = {
	.name = "epoll_pwait",
	.num_args = 6,
	.argtype = { [0] = ARG_FD_EPOLL, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "epfd", [1] = "events", [2] = "maxevents", [3] = "timeout", [4] = "sigmask", [5] = "sigsetsize" },
	.sanitise = sanitise_epoll_pwait,
	.post = post_epoll_pwait,
	.rettype = RET_BORING,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};

struct syscallentry syscall_epoll_pwait2 = {
	.name = "epoll_pwait2",
	.num_args = 6,
	.argtype = { [0] = ARG_FD_EPOLL, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "epfd", [1] = "events", [2] = "maxevents", [3] = "timeout", [4] = "sigmask", [5] = "sigsetsize" },
	.sanitise = sanitise_epoll_pwait2,
	.post = post_epoll_pwait,
	.rettype = RET_BORING,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
