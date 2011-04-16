/*
 * SYSCALL_DEFINE2(eventfd2, unsigned int, count, int, flags)
 */

#define EFD_SEMAPHORE 1
#define EFD_CLOEXEC 02000000
#define EFD_NONBLOCK 04000

{
	.name = "eventfd2",
	.num_args = 2,
	.arg1name = "count",
	.arg1type = ARG_LEN,
	.arg2name = "flags",
	.arg2type = ARG_LIST,
	.arg2list = {
		.num = 3,
		.values = { EFD_CLOEXEC, EFD_NONBLOCK, EFD_SEMAPHORE },
	},

},
