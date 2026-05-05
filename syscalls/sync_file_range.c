/*
 * SYSCALL_DEFINE(sync_file_range)(int fd, loff_t offset, loff_t nbytes, unsigned int flags)
 * SYSCALL_DEFINE(sync_file_range2)(int fd, unsigned int flags, loff_t offset, loff_t nbytes)
 */
#include <linux/fs.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include "arch.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "tables.h"
#include "trinity.h"

static void sanitise_sync_file_range(struct syscallrecord *rec)
{
	long endbyte;
	loff_t nbytes;
	loff_t off;

retry:
	off = rand64() & 0x0fffffffffffffffUL;
	nbytes = rand64() & 0x0fffffffffffffffUL;
	endbyte = off + nbytes;
	if (endbyte < off)
		goto retry;

	if (off >= (0x100000000LL << PAGE_SHIFT))
		goto retry;

	if (this_syscallname("sync_file_range2") == false) {
		rec->a2 = off;
		rec->a3 = nbytes;
	} else {
		rec->a3 = off;
		rec->a4 = nbytes;
	}
}

static unsigned long sync_file_range_flags[] = {
	SYNC_FILE_RANGE_WAIT_BEFORE, SYNC_FILE_RANGE_WRITE, SYNC_FILE_RANGE_WAIT_AFTER,
};

struct syscallentry syscall_sync_file_range = {
	.name = "sync_file_range",
	.num_args = 4,
	.sanitise = sanitise_sync_file_range,
	.argtype = { [0] = ARG_FD, [2] = ARG_LEN, [3] = ARG_LIST },
	.argname = { [0] = "fd", [1] = "offset", [2] = "nbytes", [3] = "flags" },
	.arg_params[3].list = ARGLIST(sync_file_range_flags),
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};

/*
 * ARM & PowerPC have different argument order.
 * See edd5cd4a9424f22b0fa08bef5e299d41befd5622 in kernel tree.
 */
struct syscallentry syscall_sync_file_range2 = {
	.name = "sync_file_range2",
	.num_args = 4,
	.sanitise = sanitise_sync_file_range,
	.argtype = { [0] = ARG_FD, [1] = ARG_LIST, [3] = ARG_LEN },
	.argname = { [0] = "fd", [1] = "flags", [2] = "offset", [3] = "nbytes" },
	.arg_params[1].list = ARGLIST(sync_file_range_flags),
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
