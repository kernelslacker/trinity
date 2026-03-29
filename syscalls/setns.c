/*
 * SYSCALL_DEFINE2(setns, int, fd, int, nstype)
 */
#include <fcntl.h>
#include <sched.h>
#include <unistd.h>
#include "random.h"
#include "sanitise.h"

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
};

/*
 * setns requires a namespace fd obtained from /proc/self/ns/.
 * Generic fds always return EINVAL because the kernel checks for
 * ns_operations on the file's inode.
 */
static void sanitise_setns(struct syscallrecord *rec)
{
	const char *path;
	int fd;

	path = RAND_ARRAY(ns_entries);
	fd = open(path, O_RDONLY);
	if (fd >= 0)
		rec->a1 = fd;
}

static void post_setns(struct syscallrecord *rec)
{
	int fd = rec->a1;

	/*
	 * Close the namespace fd we opened in sanitise.
	 * We can't easily distinguish our fd from the generic one,
	 * but closing an already-closed or random fd is harmless here
	 * compared to leaking namespace fds.
	 */
	if (fd >= 0)
		close(fd);
}

struct syscallentry syscall_setns= {
	.name = "setns",
	.group = GROUP_PROCESS,
	.num_args = 2,
	.argtype = { [0] = ARG_FD, [1] = ARG_LIST },
	.argname = { [0] = "fd", [1] = "nstype" },
	.arg_params[1].list = ARGLIST(setns_types),
	.flags = NEED_ALARM,
	.sanitise = sanitise_setns,
	.post = post_setns,
};
