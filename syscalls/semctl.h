/*
 * SYSCALL_DEFINE(semctl)(int semid, int semnum, int cmd, union semun arg)
 */
{
	.name = "semctl",
	.num_args = 4,
	.arg1name = "semid",
	.arg2name = "semnum",
	.arg3name = "cmd",
	.arg4name = "arg",
},
