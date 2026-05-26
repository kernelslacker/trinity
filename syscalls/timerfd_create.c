/*
 * SYSCALL_DEFINE2(timerfd_create, int, clockid, int, flags)
 */
#include <time.h>
#include "deferred-free.h"
#include "publish_resource.h"
#include "random.h"
#include "sanitise.h"
#include "compat.h"
#include "utils.h"

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

/*
 * Snapshot of the (clockid, flags) pair the post handler uses to
 * publish the new OBJ_FD_TIMERFD.  The old post handler read both
 * fields directly off rec->a1 / rec->a2; a sibling thread scribbling
 * those slots between the syscall returning and the post handler
 * running would mis-tag the published timerfd, so downstream
 * timerfd_settime / timerfd_gettime consumers would feed the kernel
 * absolute vs relative timeouts against the wrong clockid (e.g.
 * CLOCK_REALTIME_ALARM expectations against a CLOCK_MONOTONIC fd) or
 * an inverted TFD_NONBLOCK / TFD_CLOEXEC pair.  Stashing the snap in
 * rec->post_state — a slot the syscall ABI does not expose — keeps
 * the post handler immune to such scribbles.
 */
#define TIMERFD_POST_STATE_MAGIC	0x54464443UL	/* "TFDC" */
struct timerfd_post_state {
	unsigned long magic;
	unsigned long clockid;
	unsigned long flags;
};

static void sanitise_timerfd_create(struct syscallrecord *rec)
{
	struct timerfd_post_state *snap;
	unsigned int pick = rnd_modulo_u32(20);

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;

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

	/*
	 * Snapshot the inputs the post handler reads.  The kernel only
	 * looks at the low bits of clockid / flags, so a sibling scribble
	 * of rec->a1 / rec->a2 between the syscall returning and the post
	 * handler running would mis-tag the published OBJ_FD_TIMERFD with
	 * a clockid the fd was not actually created against.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic   = TIMERFD_POST_STATE_MAGIC;
	snap->clockid = rec->a1;
	snap->flags   = rec->a2;
	rec->post_state = (unsigned long) snap;
}

static void post_timerfd_create(struct syscallrecord *rec)
{
	struct timerfd_post_state *snap =
		(struct timerfd_post_state *) rec->post_state;
	int fd = rec->retval;

	if (snap == NULL)
		return;

	/*
	 * Magic-cookie check: a sibling scribble of rec->post_state with
	 * a heap-shaped pointer to a foreign allocation would let the
	 * wrong bytes pose as a timerfd_post_state.  A cookie mismatch
	 * means snap does not point at our struct -- abandon without
	 * publishing an object or freeing rather than tag a new
	 * OBJ_FD_TIMERFD with wild bytes (and don't deferred_freeptr() a
	 * pointer we don't own).
	 */
	if (snap->magic != TIMERFD_POST_STATE_MAGIC) {
		outputerr("post_timerfd_create: rejected snap with bad magic 0x%lx "
			  "(post_state-stomped to foreign allocation?)\n",
			  snap->magic);
		rec->post_state = 0;
		return;
	}

	if ((long)rec->retval < 0)
		goto out_free;

	{
		struct resource_meta meta = {
			.flags = snap->flags,
			.aux = snap->clockid,
		};
		publish_resource(OBJ_FD_TIMERFD, fd, &meta);
	}

out_free:
	deferred_freeptr(&rec->post_state);
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
