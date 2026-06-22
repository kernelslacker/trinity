/*
 * SYSCALL_DEFINE1(eventfd, unsigned int, count)
 *
 * On success, eventfd() returns a new eventfd file descriptor.
 * On error, -1 is returned and errno is set to indicate the error.
 *
 * eventfd() calls eventfd2() with a zero'd flags arg.
 */
#include "publish_resource.h"
#include "random.h"
#include "sanitise.h"

static void post_eventfd_create(struct syscallrecord *rec)
{
	int fd = rec->retval;

	if (fd < 0)
		return;

	struct resource_meta meta = {
		.extra_int = rec->a1,	/* count */
		.flags = rec->a2,
	};
	publish_resource(OBJ_FD_EVENTFD, fd, &meta);
}

struct syscallentry syscall_eventfd = {
	.name = "eventfd",
	.num_args = 1,
	.argtype = { [0] = ARG_LEN },
	.argname = { [0] = "count" },
	.rettype = RET_FD,
	.ret_objtype = OBJ_FD_EVENTFD,
	.post = post_eventfd_create,
	.group = GROUP_IPC,
};

/*
 * SYSCALL_DEFINE2(eventfd2, unsigned int, count, int, flags)
 *
 * On success, eventfd() returns a new eventfd file descriptor.
 * On error, -1 is returned and errno is set to indicate the error.
 */

#include "sanitise.h"
#include "compat.h"

/*
 * eventfd2_flags[] stays wired to ARG_LIST so the generator has a
 * default, but sanitise_eventfd2() overrides rec->a2 below with an
 * explicit bucket draw over all 2^3 subsets of CLOEXEC/NONBLOCK/
 * SEMAPHORE plus an invalid-high-bit arm.
 */
static unsigned long eventfd2_flags[] = {
	EFD_CLOEXEC, EFD_NONBLOCK, EFD_SEMAPHORE,
};

static void sanitise_eventfd2(struct syscallrecord *rec)
{
	unsigned int pick = rnd_modulo_u32(20);

	switch (pick) {
	case 0 ... 3:
		rec->a2 = 0;
		break;
	case 4 ... 6:
		rec->a2 = EFD_CLOEXEC;
		break;
	case 7 ... 8:
		rec->a2 = EFD_NONBLOCK;
		break;
	case 9 ... 11:
		/* Switches read consumer semantics. */
		rec->a2 = EFD_SEMAPHORE;
		break;
	case 12 ... 13:
		rec->a2 = EFD_CLOEXEC | EFD_NONBLOCK;
		break;
	case 14 ... 15:
		rec->a2 = EFD_CLOEXEC | EFD_SEMAPHORE;
		break;
	case 16 ... 17:
		rec->a2 = EFD_NONBLOCK | EFD_SEMAPHORE;
		break;
	case 18:
		rec->a2 = EFD_CLOEXEC | EFD_NONBLOCK | EFD_SEMAPHORE;
		break;
	default:
		/* Invalid high bit -- kernel reject path. */
		rec->a2 = 0x80000000UL;
		break;
	}
}

struct syscallentry syscall_eventfd2 = {
	.name = "eventfd2",
	.num_args = 2,
	.argtype = { [0] = ARG_LEN, [1] = ARG_LIST },
	.argname = { [0] = "count", [1] = "flags" },
	.arg_params[1].list = ARGLIST(eventfd2_flags),
	.sanitise = sanitise_eventfd2,
	.rettype = RET_FD,
	.ret_objtype = OBJ_FD_EVENTFD,
	.post = post_eventfd_create,
	.group = GROUP_IPC,
};
