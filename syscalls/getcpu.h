/*
 * SYSCALL_DEFINE3(getcpu, unsigned __user *, cpup, unsigned __user *, nodep,
                 struct getcpu_cache __user *, unused)
 */
{
	.name = "getcpu",
	.num_args = 3,
	.arg1name = "cpup",
	.arg1type = ARG_ADDRESS,
	.arg2name = "nodep",
	.arg2type = ARG_ADDRESS,
	.arg3name = "unused",
	.arg3type = ARG_ADDRESS,
},
