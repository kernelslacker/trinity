/*
 * SYSCALL_DEFINE3(shmctl, int, shmid, int, cmd, struct shmid_ds __user *, buf)
 */
{
	.name = "shmctl",
	.num_args = 3,
	.arg1name = "shmid",
	.arg2name = "cmd",
	.arg3name = "buf",
},
