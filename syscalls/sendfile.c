/*
 * SYSCALL_DEFINE4(sendfile, int, out_fd, int, in_fd, off_t __user *, offset, size_t, count)
 */
#include <stdint.h>
#include <sys/types.h>
#include "fd.h"
#include "files.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

/* ~25% bias toward a page-cache-backed in_fd; mirrors splice's fd_in swap. */
static void bias_sendfile_in_fd(struct syscallrecord *rec)
{
	if (rnd_modulo_u32(100) < 25) {
		int fd = get_rand_pagecache_fd();

		if (fd >= 0)
			rec->a2 = fd;
	}
}

static void sanitise_sendfile(struct syscallrecord *rec)
{
	off_t *offset = (off_t *) get_writable_address(sizeof(off_t));
	if (offset == NULL)
		return;
	*offset = RAND_RANGE(0ULL, 1ULL << 30);
	rec->a3 = (unsigned long) offset;
	bias_sendfile_in_fd(rec);
	avoid_shared_buffer_inout(&rec->a3, sizeof(off_t));
	reroll_protected_fd_arg(&rec->a1);
}

static void sanitise_sendfile64(struct syscallrecord *rec)
{
	off_t *offset = (off_t *) get_writable_address(sizeof(off_t));
	if (offset == NULL)
		return;
	*offset = RAND_RANGE(0ULL, 1ULL << 30);
	rec->a3 = (unsigned long) offset;
	bias_sendfile_in_fd(rec);
	avoid_shared_buffer_inout(&rec->a3, sizeof(off_t));
	reroll_protected_fd_arg(&rec->a1);
}

struct syscallentry syscall_sendfile = {
	.name = "sendfile",
	.num_args = 4,
	.argtype = { [0] = ARG_FD, [1] = ARG_FD, [2] = ARG_ADDRESS, [3] = ARG_LEN },
	.argname = { [0] = "out_fd", [1] = "in_fd", [2] = "offset", [3] = "count" },
	.sanitise = sanitise_sendfile,
	.flags = NEED_ALARM | IGNORE_ENOSYS,
	.group = GROUP_VFS,
	.rettype = RET_NUM_BYTES,
	.bound_arg = 4,
};

/*
 * SYSCALL_DEFINE4(sendfile64, int, out_fd, int, in_fd, loff_t __user *, offset, size_t, count)
 */

struct syscallentry syscall_sendfile64 = {
	.name = "sendfile64",
	.num_args = 4,
	.argtype = { [0] = ARG_FD, [1] = ARG_FD, [2] = ARG_ADDRESS, [3] = ARG_LEN },
	.argname = { [0] = "out_fd", [1] = "in_fd", [2] = "offset", [3] = "count" },
	.sanitise = sanitise_sendfile64,
	.flags = NEED_ALARM | IGNORE_ENOSYS,
	.group = GROUP_VFS,
	.rettype = RET_NUM_BYTES,
	.bound_arg = 4,
};
