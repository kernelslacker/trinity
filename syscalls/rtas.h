/*
 * int ppc_rtas(struct rtas_args __user *uargs)
 */
{
	.name = "rtas",
	.num_args = 1,
	.arg1name = "uargs",
	.arg1type = ARG_ADDRESS,
},
