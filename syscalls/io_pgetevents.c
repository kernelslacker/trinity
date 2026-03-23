/*
 * SYSCALL_DEFINE6(io_pgetevents,
 *                 aio_context_t, ctx_id,
 *                 long, min_nr,
 *                 long, nr,
 *                 struct io_event __user *, events,
 *                 struct __kernel_timespec __user *, timeout,
 *                 const struct __aio_sigset __user *, usig)
 */
#include <linux/aio_abi.h>
#include <string.h>
#include <time.h>
#include "random.h"
#include "sanitise.h"

static void sanitise_io_pgetevents(struct syscallrecord *rec)
{
	struct io_event *events;
	struct timespec *ts;
	long nr;

	nr = 1 + (rand() % 16);
	events = (struct io_event *) get_writable_address(nr * sizeof(*events));
	memset(events, 0, nr * sizeof(*events));

	ts = (struct timespec *) get_writable_address(sizeof(*ts));
	ts->tv_sec = 0;
	ts->tv_nsec = rand() % 1000000;	/* up to 1ms */

	rec->a2 = 1;		/* min_nr */
	rec->a3 = nr;
	rec->a4 = (unsigned long) events;
	rec->a5 = (unsigned long) ts;
	rec->a6 = 0;		/* usig=NULL — no signal mask */
}

struct syscallentry syscall_io_pgetevents = {
	.name = "io_pgetevents",
	.num_args = 6,
	.arg1name = "ctx_id",
	.arg1type = ARG_ADDRESS,
	.arg2name = "min_nr",
	.arg3name = "nr",
	.arg4name = "events",
	.arg5name = "timeout",
	.arg6name = "usig",
	.group = GROUP_VFS,
	.sanitise = sanitise_io_pgetevents,
};
