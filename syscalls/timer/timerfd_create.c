/*
 * SYSCALL_DEFINE2(timerfd_create, int, clockid, int, flags)
 */
#include <time.h>
#include "publish_resource.h"
#include "random.h"
#include "sanitise.h"
#include "utils.h"

#include "kernel/timerfd.h"
#include "kernel/time.h"
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

/*
 * Publish the new fd tagged with the clockid and flags it was made with:
 * timerfd_settime's sanitiser reads the clockid back to decide whether
 * TFD_TIMER_CANCEL_ON_SET applies, and a wrong tag has it hand the
 * kernel a flag the timer's clock refuses, or keep it from one it takes.
 * Both come from the slots the kernel was handed, shadowed at dispatch:
 * chain substitution or a RedQueen pin can rewrite either after the
 * sanitiser drew its own.
 */
static void post_timerfd_create(struct syscallrecord *rec)
{
	unsigned long retval;
	int fd;

	/*
	 * Snapshot rec->retval once.  rec lives in the child's shm
	 * region; the original handler read rec->retval at the int fd
	 * cast used for publish_resource() and again at the (long) <
	 * 0 success-vs-error guard, so a sibling-child stomp or a
	 * signal-handler reschedule rewriting the slot between the
	 * two reads can let the guard see a non-negative value while
	 * publish_resource() consumes a stomped fd -- tagging
	 * OBJ_FD_TIMERFD with an fd the kernel never gave us -- or
	 * conversely let the guard see a negative stomp while a real
	 * fd is silently dropped.  Same multi-read race the epoll
	 * post handlers had.
	 */
	retval = rec->retval;
	fd = (int) retval;

	if ((long) retval < 0)
		return;

	{
		struct resource_meta meta = {
			.flags = get_arg_snapshot(rec, 2),
			.aux = get_arg_snapshot(rec, 1),
		};
		publish_resource(OBJ_FD_TIMERFD, fd, &meta);
	}
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
	/* clockid (a1) and flags (a2): the fd is tagged with the ones the
	 * kernel made the timer with. */
	.arg_snapshot_mask = (1u << 0) | (1u << 1),
	.flags = REEXEC_SANITISE_OK,
};
