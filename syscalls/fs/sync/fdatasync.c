/*
 * SYSCALL_DEFINE1(fdatasync, unsigned int, fd)
 *
 * On success, returns zero.
 * On error, -1 is returned, and errno is set appropriately.
 */
#include "files.h"
#include "rnd.h"
#include "sanitise.h"

static void sanitise_fdatasync(struct syscallrecord *rec)
{
	int fd;

	/*
	 * Generic ARG_FD picks across every fd class the child holds --
	 * pipes / sockets / directories / ttys / character devices -- and
	 * fdatasync rejects almost all of them at the VFS prologue
	 * (EINVAL on files with no ->fsync, ESPIPE on pipes/FIFOs,
	 * EISDIR on directories) without ever reaching
	 * __filemap_fdatawrite_range or a per-fs ->fsync.  Bias the
	 * majority of draws at the writable pagecache pool so the call
	 * lands on a regular file whose dirty pages can be flushed for
	 * real; keep a minority of pure-random picks so the EBADF /
	 * EINVAL / ESPIPE / EISDIR reject arms stay exercised.
	 */
	if (rnd_modulo_u32(100) >= 75)
		return;

	fd = get_rand_writeable_pagecache_fd();
	if (fd >= 0)
		rec->a1 = fd;
}

struct syscallentry syscall_fdatasync = {
	.name = "fdatasync",
	.num_args = 1,
	.argtype = { [0] = ARG_FD },
	.argname = { [0] = "fd" },
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM | EXPENSIVE,
	.group = GROUP_VFS,
	.sanitise = sanitise_fdatasync,
};
