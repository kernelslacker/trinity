/*
 * SYSCALL_DEFINE2(setns, int, fd, int, nstype)
 */
#include <fcntl.h>
#include <sched.h>
#include "random.h"
#include "sanitise.h"
#include "sanitiser-fd.h"

#include "kernel/sched.h"
static const char *ns_entries[] = {
	"/proc/self/ns/mnt",
	"/proc/self/ns/pid",
	"/proc/self/ns/net",
	"/proc/self/ns/user",
	"/proc/self/ns/ipc",
	"/proc/self/ns/uts",
	"/proc/self/ns/cgroup",
	"/proc/self/ns/time",
};

static unsigned long setns_types[] = {
	0, CLONE_NEWIPC, CLONE_NEWNET, CLONE_NEWUTS,
	CLONE_NEWNS, CLONE_NEWUSER, CLONE_NEWPID,
	CLONE_NEWCGROUP, CLONE_NEWTIME,
};

/*
 * setns takes a namespace fd, such as the /proc/self/ns/ ones opened below,
 * or a pidfd.  Any other fd returns EINVAL: the kernel finds neither a
 * namespace file nor a pid behind it.
 *
 * The fd we open is ours, not the pool's: .cleanup closes it, and only it.
 * When the open fails a1 keeps the pool fd the generator drew, which must
 * stay open.
 */
static void sanitise_setns(struct syscallrecord *rec)
{
	const char *path;
	int fd;

	path = RAND_ARRAY(ns_entries);
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return;

	sanitiser_own_fd(rec, fd);
	rec->a1 = fd;
}

struct syscallentry syscall_setns= {
	.name = "setns",
	.group = GROUP_NS,
	.num_args = 2,
	.argtype = { [0] = ARG_FD, [1] = ARG_LIST },
	.argname = { [0] = "fd", [1] = "nstype" },
	.arg_params[1].list = ARGLIST(setns_types),
	/* Not REEXEC_SANITISE_OK: setns rewrites the child's namespace state (cwd, root); re-exec repeats it. */
	.flags = NEED_ALARM | KCOV_REMOTE_HEAVY,
	.sanitise = sanitise_setns,
	.cleanup = cleanup_sanitiser_fd,
	.rettype = RET_ZERO_SUCCESS,
};
