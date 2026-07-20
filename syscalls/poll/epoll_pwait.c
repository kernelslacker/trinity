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
#include <stdint.h>
#include <sys/epoll.h>
#include "output-poison.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "stats.h"
#include "trinity.h"
#include "utils.h"

/*
 * Kernel-side sigset size: _NSIG (64) / 8 = 8 bytes.  Userspace
 * sizeof(sigset_t) on glibc is 128 bytes; set_user_sigmask() rejects
 * anything != 8 with -EINVAL, so we must pass 8 as sigsetsize for the
 * mask-accept path to be exercised at all.
 */
#define KERNEL_SIGSET_SIZE 8

/*
 * Snapshot of the events OUT-buffer pointer, its byte size, and the
 * per-call poison seed, captured at sanitise time and consumed by the
 * shared post handler.  See syscalls/poll/epoll_wait.c for the full
 * rationale -- this file mirrors that oracle for the pwait / pwait2
 * entries which both go through post_epoll_pwait().
 */
#define EPOLL_PWAIT_POST_STATE_MAGIC	0x45505057UL	/* "EPPW" */
#define EPOLL_PWAIT_POISON_SEED		0x45504F4C50574121ULL /* "EPOLPWA!" */
struct epoll_pwait_post_state {
	unsigned long magic;
	unsigned long events;
	size_t buf_bytes;
	uint64_t poison_seed;
};

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
 * sigmask + sigsetsize buckets.  set_user_sigmask() checks sigsetsize
 * == 8 (KERNEL_SIGSET_SIZE, _NSIG/8) before copying the mask in and
 * rejects anything else with -EINVAL, so the mask-accept arms must
 * pass 8 (not glibc's 128-byte sizeof(sigset_t)) or the mask path is
 * never exercised.  The bad-size buckets (cases 7 and 8) intentionally
 * pass non-8 values to keep the EINVAL early-reject path covered.
 * NULL sigmask is a common real-world pattern (caller did not want
 * signal-mask swap semantics) and skips the entire mask install path.
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
		rec->a6 = KERNEL_SIGSET_SIZE;
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
		rec->a6 = KERNEL_SIGSET_SIZE;
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
		rec->a6 = KERNEL_SIGSET_SIZE;
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
 * Untouched-buffer oracle setup, shared by pwait and pwait2 which both
 * take the same struct epoll_event __user *events (a2) OUT slot and both
 * dispatch through post_epoll_pwait() below.  Stamp the poison AFTER
 * size_events_buffer() has picked the final address so the poison lands
 * on the page the kernel will actually see.  Use a FIXED seed (not RNG)
 * so --dry-run stays byte-identical to a build without this oracle.
 * Gated on range_readable_user() so a writable-pool draw that
 * avoid_shared_buffer_out moved to an address no longer provably mapped
 * does not SIGSEGV the sanitiser inside poison_output_struct's byte-walk;
 * on skip poison_seed stays 0 and the post handler no-ops the arm.
 */
static void install_events_poison(struct syscallrecord *rec)
{
	struct epoll_pwait_post_state *snap;
	long mx = (long) rec->a3;

	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic       = EPOLL_PWAIT_POST_STATE_MAGIC;
	snap->events      = rec->a2;
	snap->buf_bytes   = 0;
	snap->poison_seed = 0;

	if (mx > 0 && rec->a2 != 0) {
		size_t poison_bytes = (size_t) mx * sizeof(struct epoll_event);
		void *buf = (void *)(unsigned long) rec->a2;

		if (range_readable_user(buf, poison_bytes)) {
			snap->buf_bytes   = poison_bytes;
			snap->poison_seed = poison_output_struct(buf, poison_bytes,
								 EPOLL_PWAIT_POISON_SEED);
		}
	}

	post_state_install(rec, snap);
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
		__atomic_add_fetch(&shm->stats.epoll_volatility.wait_null_events_alloc_fail,
				   1, __ATOMIC_RELAXED);
	else
		__atomic_add_fetch(&shm->stats.epoll_volatility.wait_null_events_shared_reject,
				   1, __ATOMIC_RELAXED);
}

static void sanitise_epoll_pwait(struct syscallrecord *rec)
{
	unsigned long initial_a2 = rec->a2;

	rec->post_state = 0;

	rec->a3 = (unsigned long) pick_maxevents();
	rec->a4 = pick_timeout_ms();
	pick_sigmask(rec);
	size_events_buffer(rec);
	record_null_events_cause(initial_a2, rec);
	install_events_poison(rec);
}

static void sanitise_epoll_pwait2(struct syscallrecord *rec)
{
	unsigned long initial_a2 = rec->a2;

	rec->post_state = 0;

	rec->a3 = (unsigned long) pick_maxevents();
	pick_sigmask(rec);
	size_events_buffer(rec);
	record_null_events_cause(initial_a2, rec);
	install_events_poison(rec);

	/*
	 * a4 (timeout) is typed ARG_TIMESPEC; the generator publishes
	 * a writable pool buffer (or NULL ~10%) for us.  NEED_ALARM caps
	 * any blocking arm a large tv_sec bucket would otherwise produce.
	 */
}

/*
 * Kernel ABI: epoll_pwait / epoll_pwait2 on success returns the count of
 * ready file descriptors copied into the user events array -- a value in
 * [0, maxevents] computed by ep_send_events() walking fs/eventpoll.c's
 * ready list.  Anything > maxevents (excluding -1UL) is a structural ABI
 * regression -- see the sibling comment in epoll_wait.c for the failure
 * modes.
 *
 * Second oracle: untouched-buffer.  On retval > 0 the kernel wrote
 * exactly retval * sizeof(struct epoll_event) bytes; a byte-identical
 * poison pattern across those bytes means ep_send_events() claimed a
 * completion count without running copy_to_user.  retval == 0 and every
 * negative return are silent.  Measure-only: no re-issue, no argument
 * mutation, no oracle output beyond the counter bump.
 */
static void post_epoll_pwait(struct syscallrecord *rec)
{
	struct epoll_pwait_post_state *snap;
	long retval    = (long) rec->retval;
	long maxevents = (long) get_arg_snapshot(rec, 3);
	size_t check_bytes;

	snap = post_state_claim_owned(rec, EPOLL_PWAIT_POST_STATE_MAGIC,
				      __func__);
	if (snap == NULL)
		return;

	if (retval == -1L)
		goto out_release;
	if (maxevents <= 0)
		goto out_release;
	if (retval > maxevents) {
		outputerr("post_epoll_pwait: rejecting retval %ld > maxevents %ld\n",
			 retval, maxevents);
		post_handler_corrupt_ptr_bump(rec, NULL);
		goto out_release;
	}

	if (retval <= 0)
		goto out_release;
	if (snap->poison_seed == 0)
		goto out_release;

	check_bytes = (size_t) retval * sizeof(struct epoll_event);
	if (check_bytes > snap->buf_bytes)
		check_bytes = snap->buf_bytes;

	if (check_output_struct_user_or_skip((void *)(unsigned long) snap->events,
					     check_bytes,
					     snap->poison_seed))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

out_release:
	post_state_release(rec, snap);
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
