/*
 * SYSCALL_DEFINE1(fsync, unsigned int, fd)
 *
 * On success, these system calls return zero.
 * On error, -1 is returned, and errno is set appropriately.
 */
#include "files.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"

/*
 * ARG_FD picks uniformly from every open fd in the child -- sockets,
 * pipes, eventfds, epoll fds, memfd handles, kcov fds -- so most draws
 * bounce with EBADF / EINVAL / ESPIPE at the entry gate before any
 * writeback code runs.  Repoint a1 at a writeable pagecache-backed
 * regular file on the majority of draws so the call reaches
 * vfs_fsync_range -> mark_inode_dirty -> journal commit paths, while
 * keeping a minority slice on the raw ARG_FD draw so the reject arms
 * stay exercised.  Self-contained: fdatasync's sibling entry ships its
 * own copy of the same shaping rather than share a helper.
 */
static void sanitise_fsync(struct syscallrecord *rec)
{
	if (rnd_modulo_u32(100) < 85) {
		int fd = get_rand_writeable_pagecache_fd();

		if (fd >= 0)
			rec->a1 = (unsigned long) fd;
	}
}

struct syscallentry syscall_fsync = {
	.name = "fsync",
	.num_args = 1,
	.argtype = { [0] = ARG_FD },
	.argname = { [0] = "fd" },
	.rettype = RET_ZERO_SUCCESS,
	.sanitise = sanitise_fsync,
	.flags = NEED_ALARM | EXPENSIVE,
	.group = GROUP_VFS,
};
