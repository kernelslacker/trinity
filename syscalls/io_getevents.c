/*
 * SYSCALL_DEFINE5(io_getevents, aio_context_t, ctx_id,
	long, min_nr,
	long, nr,
	struct io_event __user *, events,
	struct timespec __user *, timeout)
 */
#include <linux/aio_abi.h>
#include <string.h>
#include "objects.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "utils.h"

static void sanitise_io_getevents(struct syscallrecord *rec)
{
	struct io_event *events;
	long nr;

	nr = 1 + (rnd_modulo_u32(16));
	events = (struct io_event *) get_writable_address(nr * sizeof(*events));
	if (events == NULL)
		return;
	memset(events, 0, nr * sizeof(*events));

	rec->a2 = 1;		/* min_nr */
	rec->a3 = nr;
	rec->a4 = (unsigned long) events;

	avoid_shared_buffer_out(&rec->a4, rec->a3 * sizeof(struct io_event));
}

struct syscallentry syscall_io_getevents = {
	.name = "io_getevents",
	.num_args = 5,
	.argtype = { [0] = ARG_AIO_CTX, [1] = ARG_LEN, [2] = ARG_LEN, [3] = ARG_ADDRESS, [4] = ARG_TIMESPEC },
	.argname = { [0] = "ctx_id", [1] = "min_nr", [2] = "nr", [3] = "events", [4] = "timeout" },
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
	.sanitise = sanitise_io_getevents,
	.bound_arg = 3,
};
