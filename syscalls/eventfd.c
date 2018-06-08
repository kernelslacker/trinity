/*
 * SYSCALL_DEFINE1(eventfd, unsigned int, count)
 *
 * On success, eventfd() returns a new eventfd file descriptor.
 * On error, -1 is returned and errno is set to indicate the error.
 *
 * eventfd() calls eventfd2() with a zero'd flags arg.
 */
#include "objects.h"
#include "sanitise.h"
#include "utils.h"

static void post_eventfd_create(struct syscallrecord *rec)
{
	struct object *new;
	int fd = rec->retval;

	if (fd == -1)
		return;

	new = alloc_object();
	new->eventfdobj.fd = fd;
	new->eventfdobj.count = rec->a1;
	new->eventfdobj.flags = rec->a2;
	add_object(new, OBJ_LOCAL, OBJ_FD_EVENTFD);
}

struct syscallentry syscall_eventfd = {
	.name = "eventfd",
	.num_args = 1,
	.arg1name = "count",
	.arg1type = ARG_LEN,
	.rettype = RET_FD,
	.post = post_eventfd_create,
};

/*
 * SYSCALL_DEFINE2(eventfd2, unsigned int, count, int, flags)
 *
 * On success, eventfd() returns a new eventfd file descriptor.
 * On error, -1 is returned and errno is set to indicate the error.
 */

#include "sanitise.h"
#include "compat.h"

static unsigned long eventfd2_flags[] = {
	EFD_CLOEXEC, EFD_NONBLOCK, EFD_SEMAPHORE,
};

struct syscallentry syscall_eventfd2 = {
	.name = "eventfd2",
	.num_args = 2,
	.arg1name = "count",
	.arg1type = ARG_LEN,
	.arg2name = "flags",
	.arg2type = ARG_LIST,
	.arg2list = ARGLIST(eventfd2_flags),
	.rettype = RET_FD,
	.post = post_eventfd_create,
};
