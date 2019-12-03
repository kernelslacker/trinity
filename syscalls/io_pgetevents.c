/*
 * SYSCALL_DEFINE6(io_pgetevents,
 *                 aio_context_t, ctx_id,
 *                 long, min_nr,
 *                 long, nr,
 *                 struct io_event __user *, events,
 *                 struct __kernel_timespec __user *, timeout,
 *                 const struct __aio_sigset __user *, usig)
 */

#include "syscall.h"

struct syscallentry syscall_io_pgetevents = {
	.name = "io_pgetevents,",
	.num_args = 6,

	.arg1name = "ctx_id",
	.arg2name = "min_nr",
	.arg2type = ARG_LEN,
	.arg3name = "nr",
	.arg3type = ARG_LEN,
	.arg4name = "events",
	.arg5name = "timeout",
	.arg6name = "usig",
};
