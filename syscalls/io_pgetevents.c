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
#include "objects.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "utils.h"

static void sanitise_io_pgetevents(struct syscallrecord *rec)
{
	struct io_event *events;
	unsigned long ctx;
	long nr;

	/*
	 * Precondition: ctx_id (a1) must be a live aio_context_t the kernel
	 * has on hand or io_pgetevents short-circuits with -EINVAL inside
	 * lookup_ioctx() before the per-ring event-queue drain runs.
	 * gen_arg_aio_ctx returns 0 (or 1/8 of the time a raw rand64) until
	 * a real io_setup has published into OBJ_AIO_CTX; seed one inline so
	 * io_pgetevents reaches the productive kernel path even on the very
	 * first call in the child.
	 */
	ctx = seed_aio_ctx_if_empty();
	if (ctx != 0)
		rec->a1 = ctx;

	nr = 1 + (rnd_modulo_u32(16));
	events = (struct io_event *) get_writable_address(nr * sizeof(*events));
	if (events == NULL)
		return;
	memset(events, 0, nr * sizeof(*events));

	/*
	 * min_nr biased toward 0 (60%) so io_pgetevents exercises the
	 * non-blocking reap path (drain whatever has already completed and
	 * return immediately) instead of always landing in
	 * read_events()->wait_event_hrtimeout(), which blocks until either
	 * min_nr events complete or NEED_ALARM's SIGALRM tears the call
	 * down.  The blocking arm still gets the remaining 40% so the
	 * wait / timeout / signal-mask interaction path stays covered.
	 */
	rec->a2 = (rnd_modulo_u32(100) < 60) ? 0 : 1;
	rec->a3 = nr;
	rec->a4 = (unsigned long) events;
	rec->a6 = 0;		/* usig=NULL -- no signal mask */

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
	.argtype = { [0] = ARG_AIO_CTX, [1] = ARG_LEN, [2] = ARG_LEN, [3] = ARG_ADDRESS, [4] = ARG_TIMESPEC, [5] = ARG_ADDRESS },
	.argname = { [0] = "ctx_id", [1] = "min_nr", [2] = "nr", [3] = "events", [4] = "timeout", [5] = "usig" },
	.group = GROUP_VFS,
	.flags = NEED_ALARM,
	.sanitise = sanitise_io_pgetevents,
	.bound_arg = 3,
};
