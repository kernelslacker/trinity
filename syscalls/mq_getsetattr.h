/*
 * SYSCALL_DEFINE3(mq_getsetattr, mqd_t, mqdes,
	const struct mq_attr __user *, u_mqstat,
	struct mq_attr __user *, u_omqstat)
 */
{
	.name = "mq_getsetattr",
	.num_args = 3,
	.arg1name = "mqdes",
	.arg2name = "u_mqstat",
	.arg2type = ARG_ADDRESS,
	.arg3name = "u_omqstat",
	.arg3type = ARG_ADDRESS,
},
