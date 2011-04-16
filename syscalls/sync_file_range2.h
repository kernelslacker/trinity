/*
 * asmlinkage long SyS_sync_file_range2(long fd, long flags,
 *                                      loff_t offset, loff_t nbytes)
 */
{
        .name = "sync_file_range2",
        .num_args = 4,
        .sanitise = sanitise_sync_file_range,
        .arg1name = "fd",
        .arg1type = ARG_FD,
        .arg2name = "flags",
	.arg2type = ARG_LIST,
        .arg2list = {
		.num = 3,
		.values = { SYNC_FILE_RANGE_WAIT_BEFORE, SYNC_FILE_RANGE_WRITE, SYNC_FILE_RANGE_WAIT_AFTER },
        },
        .arg3name = "offset",
        .arg4name = "nbytes",
        .arg4type = ARG_LEN,
},
