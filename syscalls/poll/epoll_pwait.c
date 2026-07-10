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
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "stats.h"
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
		avoid_shared_buffer_inout(&rec->a5, sizeof(sigset_t));
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
		avoid_shared_buffer_inout(&rec->a5, sizeof(sigset_t));
		rec->a6 = sizeof(sigset_t);
		return;
	case 7:
		/* Correct buffer, intentionally-wrong size. */
		mask = (sigset_t *) get_writable_struct(sizeof(sigset_t));
		if (mask == NULL)
			return;
		sigemptyset(mask);
		rec->a5 = (unsigned long) mask;
		avoid_shared_buffer_inout(&rec->a5, sizeof(sigset_t));
		rec->a6 = 0;
		return;
	case 8:
		mask = (sigset_t *) get_writable_struct(sizeof(sigset_t));
		if (mask == NULL)
			return;
		sigemptyset(mask);
		rec->a5 = (unsigned long) mask;
		avoid_shared_buffer_inout(&rec->a5, sizeof(sigset_t));
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

/*
 * Attribute why (a3 > 0 && a2 == 0) still holds at sanitise exit --
 * the state the arg-coupling validator will reject as EFAULT-shaped
 * without dispatching the syscall.  Bumps the appropriate cause
 * counter on shm->stats; no-op on the common path where a2 remains
 * non-zero.  See stats.h for the bucket definitions.
 */
static void record_null_events_cause(unsigned long initial_a2,
				     struct syscallrecord *rec)
{
	if ((long) rec->a3 <= 0 || rec->a2 != 0)
		return;
	if (initial_a2 == 0)
		__atomic_add_fetch(&shm->stats.epoll_wait_null_events_alloc_fail,
				   1, __ATOMIC_RELAXED);
	else
		__atomic_add_fetch(&shm->stats.epoll_wait_null_events_shared_reject,
				   1, __ATOMIC_RELAXED);
}

static void sanitise_epoll_pwait(struct syscallrecord *rec)
{
	unsigned long initial_a2 = rec->a2;

	rec->a3 = (unsigned long) pick_maxevents();
	rec->a4 = pick_timeout_ms();
	pick_sigmask(rec);
	size_events_buffer(rec);
	record_null_events_cause(initial_a2, rec);
}

static void sanitise_epoll_pwait2(struct syscallrecord *rec)
{
	unsigned long initial_a2 = rec->a2;

	rec->a3 = (unsigned long) pick_maxevents();
	pick_sigmask(rec);
	size_events_buffer(rec);
	record_null_events_cause(initial_a2, rec);

	/*
	 * a4 (timeout) is typed ARG_TIMESPEC; the generator publishes
	 * a writable pool buffer (or NULL ~10%) for us.  NEED_ALARM caps
	 * any blocking arm a large tv_sec bucket would otherwise produce.
	 */
}

static void post_epoll_pwait(struct syscallrecord *rec)
{
	long retval    = (long) rec->retval;
	long maxevents = (long) get_arg_snapshot(rec, 3);

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
	.argtype = { [0] = ARG_FD_EPOLL, [1] = ARG_NON_NULL_ADDRESS, [2] = ARG_LEN, [4] = ARG_ADDRESS, [5] = ARG_LEN },
	.argname = { [0] = "epfd", [1] = "events", [2] = "maxevents", [3] = "timeout", [4] = "sigmask", [5] = "sigsetsize" },
	.sanitise = sanitise_epoll_pwait,
	.post = post_epoll_pwait,
	.rettype = RET_BORING,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
	/* a3 (maxevents) read in post -- shared with epoll_pwait2 via
	 * post_epoll_pwait().  See syscall_epoll_wait for rationale. */
	.arg_snapshot_mask = (1u << 2),
};

struct syscallentry syscall_epoll_pwait2 = {
	.name = "epoll_pwait2",
	.num_args = 6,
	.argtype = { [0] = ARG_FD_EPOLL, [1] = ARG_NON_NULL_ADDRESS, [2] = ARG_LEN, [3] = ARG_TIMESPEC, [4] = ARG_ADDRESS, [5] = ARG_LEN },
	.argname = { [0] = "epfd", [1] = "events", [2] = "maxevents", [3] = "timeout", [4] = "sigmask", [5] = "sigsetsize" },
	.sanitise = sanitise_epoll_pwait2,
	.post = post_epoll_pwait,
	.rettype = RET_BORING,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
	.arg_snapshot_mask = (1u << 2),
};
