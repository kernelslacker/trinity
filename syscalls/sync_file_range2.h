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
        .arg3name = "offset",
        .arg4name = "nbytes",
        .arg4type = ARG_LEN,
},

