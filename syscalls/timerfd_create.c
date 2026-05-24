/*
 * SYSCALL_DEFINE2(timerfd_create, int, clockid, int, flags)
 */
#include <time.h>
#include "objects.h"
#include "random.h"
#include "sanitise.h"
#include "compat.h"

static unsigned long timerfd_create_clockids[] = {
	CLOCK_REALTIME, CLOCK_MONOTONIC, CLOCK_BOOTTIME,
	CLOCK_REALTIME_ALARM, CLOCK_BOOTTIME_ALARM,
};

/*
 * timerfd_create_flags[] stays wired to ARG_LIST so the generator
 * has a default, but sanitise_timerfd_create() overrides rec->a2
 * below with an explicit bucket draw.  The two-entry ARG_LIST pool
 * almost never produces the zero-flags arm, the full combo, or the
 * invalid-high-bit reject path.
 */
static unsigned long timerfd_create_flags[] = {
	TFD_NONBLOCK, TFD_CLOEXEC,
};

static void sanitise_timerfd_create(struct syscallrecord *rec)
{
	unsigned int pick = rnd_modulo_u32(20);

	switch (pick) {
	case 0 ... 5:
		rec->a2 = 0;
		break;
	case 6 ... 10:
		rec->a2 = TFD_CLOEXEC;
		break;
	case 11 ... 15:
		rec->a2 = TFD_NONBLOCK;
		break;
	case 16 ... 18:
		rec->a2 = TFD_CLOEXEC | TFD_NONBLOCK;
		break;
	default:
		/* Invalid high bit -- kernel reject path. */
		rec->a2 = 0x80000000UL;
		break;
	}
}

static void post_timerfd_create(struct syscallrecord *rec)
{
	struct object *new;
	int fd = rec->retval;

	if ((long)rec->retval < 0)
		return;

	new = alloc_object();
	new->timerfdobj.fd = fd;
	new->timerfdobj.clockid = rec->a1;
	new->timerfdobj.flags = rec->a2;
	add_object(new, OBJ_LOCAL, OBJ_FD_TIMERFD);
}

struct syscallentry syscall_timerfd_create = {
	.name = "timerfd_create",
	.group = GROUP_TIME,
	.num_args = 2,
	.argtype = { [0] = ARG_OP, [1] = ARG_LIST },
	.argname = { [0] = "clockid", [1] = "flags" },
	.arg_params[0].list = ARGLIST(timerfd_create_clockids),
	.arg_params[1].list = ARGLIST(timerfd_create_flags),
	.sanitise = sanitise_timerfd_create,
	.rettype = RET_FD,
	.ret_objtype = OBJ_FD_TIMERFD,
	.post = post_timerfd_create,
};
