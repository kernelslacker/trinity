/*
 * SYSCALL_DEFINE0(inotify_init)
 */
#include "objects.h"
#include "sanitise.h"
#include "tables.h"
#include "utils.h"

static void post_inotify_init(struct syscallrecord *rec)
{
	struct object *new;
	int fd = rec->retval;

	if (fd == -1)
		return;

	new = alloc_object();
	new->inotifyobj.fd = fd;
	if (this_syscallname("inotify_init1"))
		new->inotifyobj.flags = rec->a1;
	else
		new->inotifyobj.flags = 0;
	add_object(new, OBJ_LOCAL, OBJ_FD_INOTIFY);
}

struct syscallentry syscall_inotify_init = {
	.name = "inotify_init",
	.num_args = 0,
	.group = GROUP_VFS,
	.rettype = RET_FD,
	.post = post_inotify_init,
};

/*
 * SYSCALL_DEFINE1(inotify_init1, int, flags)
 */

#define IN_CLOEXEC 02000000
#define IN_NONBLOCK 04000

static unsigned long inotify_init1_flags[] = {
	IN_CLOEXEC , IN_NONBLOCK,
};

struct syscallentry syscall_inotify_init1 = {
	.name = "inotify_init1",
	.num_args = 1,
	.arg1name = "flags",
	.arg1type = ARG_LIST,
	.arg1list = ARGLIST(inotify_init1_flags),
	.group = GROUP_VFS,
	.rettype = RET_FD,
	.post = post_inotify_init,
};
