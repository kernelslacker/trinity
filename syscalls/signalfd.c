/*
 * SYSCALL_DEFINE3(signalfd, int, ufd, sigset_t __user *, user_mask, size_t, sizemask)
 */
#include <signal.h>
#include <unistd.h>
#include "objects.h"
#include "sanitise.h"

static void sanitise_signalfd(struct syscallrecord *rec)
{
	sigset_t *set;

	set = (sigset_t *) get_writable_struct(sizeof(*set));
	if (!set)
		return;
	sigemptyset(set);
	sigaddset(set, SIGUSR1);
	sigaddset(set, SIGUSR2);

	rec->a2 = (unsigned long) set;
	rec->a3 = sizeof(sigset_t);
}

static void post_signalfd(struct syscallrecord *rec)
{
	struct object *new;
	int fd = rec->retval;

	if ((long)rec->retval < 0)
		return;
	if (fd < 0 || fd >= (1 << 20))
		return;

	new = alloc_object();
	new->signalfdobj.fd = fd;
	add_object(new, OBJ_LOCAL, OBJ_FD_SIGNALFD);
}

struct syscallentry syscall_signalfd = {
	.name = "signalfd",
	.group = GROUP_SIGNAL,
	.num_args = 3,
	.argtype = { [0] = ARG_FD, [1] = ARG_ADDRESS, [2] = ARG_LEN },
	.argname = { [0] = "ufd", [1] = "user_mask", [2] = "sizemask" },
	.sanitise = sanitise_signalfd,
	.post = post_signalfd,
	.rettype = RET_FD,
	.ret_objtype = OBJ_FD_SIGNALFD,
	.flags = NEED_ALARM,
};

/*
 * SYSCALL_DEFINE4(signalfd4, int, ufd, sigset_t __user *, user_mask,
	 size_t, sizemask, int, flags)
 */

#define SFD_CLOEXEC 02000000
#define SFD_NONBLOCK 04000

static unsigned long signalfd4_flags[] = {
	SFD_CLOEXEC, SFD_NONBLOCK,
};

static void sanitise_signalfd4(struct syscallrecord *rec)
{
	sigset_t *set;

	set = (sigset_t *) get_writable_struct(sizeof(*set));
	if (!set)
		return;
	sigemptyset(set);
	sigaddset(set, SIGUSR1);
	sigaddset(set, SIGUSR2);

	rec->a2 = (unsigned long) set;
	rec->a3 = sizeof(sigset_t);
}

struct syscallentry syscall_signalfd4 = {
	.name = "signalfd4",
	.group = GROUP_SIGNAL,
	.num_args = 4,
	.argtype = { [0] = ARG_FD, [1] = ARG_ADDRESS, [2] = ARG_LEN, [3] = ARG_LIST },
	.argname = { [0] = "ufd", [1] = "user_mask", [2] = "sizemask", [3] = "flags" },
	.arg_params[3].list = ARGLIST(signalfd4_flags),
	.sanitise = sanitise_signalfd4,
	.post = post_signalfd,
	.rettype = RET_FD,
	.ret_objtype = OBJ_FD_SIGNALFD,
	.flags = NEED_ALARM,
};
