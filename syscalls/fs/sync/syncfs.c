/*
 * SYSCALL_DEFINE1(syncfs, int, fd)
 */
#include "files.h"
#include "rnd.h"
#include "sanitise.h"

static void sanitise_syncfs(struct syscallrecord *rec)
{
	int fd;

	/*
	 * syncfs writes back the whole filesystem that backs the passed
	 * fd, so a bad or anonymous fd short-circuits at the VFS entry
	 * (EBADF) without ever reaching sync_filesystem or a per-fs
	 * ->sync_fs.  ARG_FD alone picks uniformly from every fd class
	 * the child holds -- pipes / sockets / eventfds / memfds --
	 * whose superblocks are anon_inodefs / sockfs / pipefs and
	 * carry nothing worth flushing.  Bias the majority of draws at
	 * the writable pagecache pool so a1 lands on a regular file
	 * whose superblock is a real on-disk filesystem, and keep a
	 * minority of pure-random picks so the EBADF reject arm stays
	 * exercised.
	 */
	if (rnd_modulo_u32(100) >= 80)
		return;

	fd = get_rand_writeable_pagecache_fd();
	if (fd >= 0)
		rec->a1 = fd;
}

struct syscallentry syscall_syncfs = {
	.name = "syncfs",
	.num_args = 1,
	.argtype = { [0] = ARG_FD },
	.argname = { [0] = "fd" },
	.rettype = RET_ZERO_SUCCESS,
	.sanitise = sanitise_syncfs,
	.flags = NEED_ALARM | EXPENSIVE,
	.group = GROUP_VFS,
};
