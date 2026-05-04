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
#include "objects.h"
#include "random.h"
#include "sanitise.h"
#include "utils.h"

static void sanitise_io_pgetevents(struct syscallrecord *rec)
{
	struct io_event *events;
	struct timespec *ts;
	long nr;

	rec->a1 = get_random_aio_ctx();

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

static void post_io_pgetevents(struct syscallrecord *rec)
{
	long ret = (long) rec->retval;

	if (ret == -1L)
		return;
	if (ret < 0 || ret > (long) rec->a3)
		post_handler_corrupt_ptr_bump(rec, NULL);
}

struct syscallentry syscall_io_pgetevents = {
	.name = "io_pgetevents",
	.num_args = 6,
	.argname = { [0] = "ctx_id", [1] = "min_nr", [2] = "nr", [3] = "events", [4] = "timeout", [5] = "usig" },
	.group = GROUP_VFS,
	.sanitise = sanitise_io_pgetevents,
	.post = post_io_pgetevents,
};
