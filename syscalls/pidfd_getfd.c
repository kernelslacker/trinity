/*
 * SYSCALL_DEFINE3(pidfd_getfd, int, pidfd, int, fd, unsigned int, flags)
 */
#include <unistd.h>
#include <linux/pidfd.h>
#include "random.h"
#include "sanitise.h"

static unsigned long pidfd_getfd_flags[] = {
	0,
};


#ifdef PIDFD_SELF_THREAD
static void sanitise_pidfd_getfd(struct syscallrecord *rec)
{
	/* Sometimes use a self-referencing sentinel instead of a real pidfd. */
	if (rand() % 4 == 0)
		rec->a1 = RAND_BOOL() ? (unsigned long)PIDFD_SELF_THREAD
				      : (unsigned long)PIDFD_SELF_THREAD_GROUP;
}
#endif

struct syscallentry syscall_pidfd_getfd = {
	.name = "pidfd_getfd",
	.group = GROUP_PROCESS,
	.num_args = 3,
	.argtype = { [0] = ARG_FD_PIDFD, [1] = ARG_FD, [2] = ARG_LIST },
	.argname = { [0] = "pidfd", [1] = "fd", [2] = "flags" },
	.arg_params[2].list = ARGLIST(pidfd_getfd_flags),
	.rettype = RET_FD,
#ifdef PIDFD_SELF_THREAD
	.sanitise = sanitise_pidfd_getfd,
#endif
	.post = generic_post_close_fd,
};
