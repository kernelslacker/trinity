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
#include "objects.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "utils.h"

static void sanitise_io_pgetevents(struct syscallrecord *rec)
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
	rec->a6 = 0;		/* usig=NULL — no signal mask */

	avoid_shared_buffer_out(&rec->a4, rec->a3 * sizeof(struct io_event));

	/*
	 * a5 (timeout) is typed ARG_TIMESPEC; the generator publishes
	 * a writable pool buffer (or NULL ~10%) for us.  NEED_ALARM caps
	 * any blocking arm a large tv_sec bucket would otherwise produce.
	 */
}

struct syscallentry syscall_io_pgetevents = {
	.name = "io_pgetevents",
	.num_args = 6,
	.argtype = { [0] = ARG_AIO_CTX, [1] = ARG_LEN, [2] = ARG_LEN, [3] = ARG_ADDRESS, [4] = ARG_TIMESPEC },
	.argname = { [0] = "ctx_id", [1] = "min_nr", [2] = "nr", [3] = "events", [4] = "timeout", [5] = "usig" },
	.group = GROUP_VFS,
	.flags = NEED_ALARM,
	.sanitise = sanitise_io_pgetevents,
	.bound_arg = 3,
};
