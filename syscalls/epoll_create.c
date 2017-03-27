/*
 * SYSCALL_DEFINE1(epoll_create, int, size)
 *
 * On success, returns a nonnegative file descriptor.
 * On error, -1 is returned, and errno is set to indicate the error.
 */
#include "objects.h"
#include "sanitise.h"
#include "tables.h"
#include "utils.h"

static void post_epoll_create(struct syscallrecord *rec)
{
	struct object *new;
	struct epollobj *eo;
	int fd = rec->retval;

	if (fd == -1)
		return;

	new = alloc_object();
	eo = &new->epollobj;
	eo->fd = fd;
	if (this_syscallname("epoll_create1")) {
		eo->create1 = TRUE;
		eo->flags = rec->a1;
	} else {
		eo->create1 = FALSE;
		eo->flags = 0;
	}
	add_object(new, OBJ_LOCAL, OBJ_FD_EPOLL);
}

struct syscallentry syscall_epoll_create = {
	.name = "epoll_create",
	.num_args = 1,
	.arg1name = "size",
	.arg1type = ARG_LEN,
	.rettype = RET_FD,
	.post = post_epoll_create,
};

/*
 * SYSCALL_DEFINE1(epoll_create1, int, flags)
 *
 * On success, returns a nonnegative file descriptor.
 * On error, -1 is returned, and errno is set to indicate the error.
*
 * If flags is 0, then, other than the fact that the obsolete size argument is dropped,
 * epoll_create1() is the same as epoll_create().
 */

#define EPOLL_CLOEXEC 02000000

static unsigned long epoll_create_flags[] = {
	EPOLL_CLOEXEC,
};

struct syscallentry syscall_epoll_create1 = {
	.name = "epoll_create1",
	.num_args = 1,
	.arg1name = "flags",
	.arg1type = ARG_LIST,
	.arg1list = ARGLIST(epoll_create_flags),
	.rettype = RET_FD,
	.post = post_epoll_create,
};
