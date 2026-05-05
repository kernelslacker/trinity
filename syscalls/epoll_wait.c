/*
 * SYSCALL_DEFINE4(epoll_wait, int, epfd, struct epoll_event __user *, events, int, maxevents, int, timeout)
 *
 * When  successful, returns the number of file descriptors ready for the requested I/O,
 * or zero if no file descriptor became ready during the requested timeout milliseconds.
 * When an error occurs, returns -1 and errno is set appropriately.
 */
#include <sys/epoll.h>
#include "random.h"
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

static void sanitise_epoll_wait(struct syscallrecord *rec)
{
	/* timeout: -1 = block, 0 = return immediately, >0 = ms to wait */
	switch (rand() % 4) {
	case 0: rec->a4 = (unsigned long) -1; break;	/* block */
	case 1: rec->a4 = 0; break;			/* immediate */
	default: rec->a4 = 1 + (rand() % 100); break;	/* short wait */
	}
	avoid_shared_buffer(&rec->a2, rec->a3 * sizeof(struct epoll_event));
}

/*
 * Kernel ABI: epoll_wait(2) on success returns the count of ready file
 * descriptors copied into the user events array — a value in [0, maxevents]
 * computed by ep_send_events() walking fs/eventpoll.c's ready list. Failure
 * returns -1UL with EBADF/EFAULT/EINTR/EINVAL via the syscall return path.
 * Anything > maxevents (excluding -1UL) is a structural ABI regression: a
 * sign-extension tear in the syscall return path, a torn write of the count
 * by a parallel signal-restart path, or -errno leaking through the success
 * return slot instead of the errno slot.
 */
static void post_epoll_wait(struct syscallrecord *rec)
{
	if ((long) rec->retval == -1L)
		return;
	if (rec->retval > rec->a3) {
		outputerr("post_epoll_wait: rejecting retval %ld > maxevents %ld\n",
			  (long) rec->retval, (long) rec->a3);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}
}

struct syscallentry syscall_epoll_wait = {
	.name = "epoll_wait",
	.num_args = 4,
	.argtype = { [0] = ARG_FD_EPOLL, [1] = ARG_NON_NULL_ADDRESS, [2] = ARG_RANGE },
	.argname = { [0] = "epfd", [1] = "events", [2] = "maxevents", [3] = "timeout" },
	.arg_params[2].range.low = 1,
	.arg_params[2].range.hi = 128,
	.sanitise = sanitise_epoll_wait,
	.post = post_epoll_wait,
	.rettype = RET_BORING,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
