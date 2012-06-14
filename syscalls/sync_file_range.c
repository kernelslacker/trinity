/*
 * SYSCALL_DEFINE(sync_file_range)(int fd, loff_t offset, loff_t nbytes, unsigned int flags)
 */
#include <linux/fs.h>
#include <fcntl.h>
#include <stdlib.h>

#include "trinity.h"
#include "sanitise.h"
#include "arch.h"
#include "shm.h"

static void sanitise_sync_file_range(int childno)
{
	long endbyte;
	loff_t off = shm->a2[childno];

retry:
	off = rand() & 0xfffffff;
	shm->a3[childno] = rand() & 0xfffffff;

	endbyte = off + shm->a2[childno];


	if (endbyte < off)
		goto retry;

	if (off >= (0x100000000LL << PAGE_SHIFT))
		goto retry;

	shm->a2[childno] = off;
}

struct syscall syscall_sync_file_range = {
	.name = "sync_file_range",
	.num_args = 4,
	.sanitise = sanitise_sync_file_range,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "offset",
	.arg3name = "nbytes",
	.arg3type = ARG_LEN,
	.arg4name = "flags",
	.arg4type = ARG_LIST,
        .arg4list = {
		.num = 3,
		.values = { SYNC_FILE_RANGE_WAIT_BEFORE, SYNC_FILE_RANGE_WRITE, SYNC_FILE_RANGE_WAIT_AFTER },
        },
};
