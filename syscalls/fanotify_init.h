/*
 * SYSCALL_DEFINE2(fanotify_init, unsigned int, flags, unsigned int, event_f_flags)
 */
{
	.name = "fanotify_init",
	.num_args = 2,
	.arg1name = "flags",
	.arg2name = "event_f_flags",
	.flags = CAPABILITY_CHECK,
},
