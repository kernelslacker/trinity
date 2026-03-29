/*
 * SYSCALL_DEFINE5(io_getevents, aio_context_t, ctx_id,
	long, min_nr,
	long, nr,
	struct io_event __user *, events,
	struct timespec __user *, timeout)
 */
#include <linux/aio_abi.h>
#include <string.h>
#include <time.h>
#include "random.h"
#include "sanitise.h"

static void sanitise_io_getevents(struct syscallrecord *rec)
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
}

struct syscallentry syscall_io_getevents = {
	.name = "io_getevents",
	.num_args = 5,
	.argtype = { [0] = ARG_ADDRESS },
	.argname = { [0] = "ctx_id", [1] = "min_nr", [2] = "nr", [3] = "events", [4] = "timeout" },
	.group = GROUP_VFS,
	.sanitise = sanitise_io_getevents,
};
