/*
 * SYSCALL_DEFINE(sync_file_range)(int fd, loff_t offset, loff_t nbytes, unsigned int flags)
 */
#define _GNU_SOURCE
#include <linux/fs.h>
#include <fcntl.h>
#include <stdlib.h>

#include "trinity.h"
#include "sanitise.h"
#include "arch.h"

static void sanitise_sync_file_range(__unused__ unsigned long *fd,
	unsigned long *offset,
	__unused__ unsigned long *nbytes,
	__unused__ unsigned long *a4,
	__unused__ unsigned long *a5,
	__unused__ unsigned long *a6)
{
	long endbyte;
	loff_t off = *offset;

retry:
	off = rand() & 0xfffffff;
	*nbytes = rand() & 0xfffffff;

	endbyte = off + *nbytes;


	if (endbyte < off)
		goto retry;

	if (off >= (0x100000000LL << PAGE_SHIFT))
		goto retry;

	*offset = off;

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
