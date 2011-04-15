/*
 * SYSCALL_DEFINE(sync_file_range)(int fd, loff_t offset, loff_t nbytes, unsigned int flags)
 */

#include <fcntl.h>

{
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
},
