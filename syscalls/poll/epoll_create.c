/*
 * SYSCALL_DEFINE1(epoll_create, int, size)
 *
 * On success, returns a nonnegative file descriptor.
 * On error, -1 is returned, and errno is set to indicate the error.
 */
#include "kernel/epoll.h"
#include "objects.h"
#include "random.h"
#include "sanitise.h"
#include "tables.h"

static void post_epoll_create(struct syscallrecord *rec)
{
	struct object *new;
	struct epollobj *eo;
	int fd = rec->retval;

	if ((long)rec->retval < 0)
		return;

	new = alloc_object();
	eo = &new->epollobj;
	eo->fd = fd;
	if (current_entry_is_epoll_create1()) {
		eo->create1 = true;
		eo->flags = rec->a1;
	} else {
		eo->create1 = false;
		eo->flags = 0;
	}
	add_object(new, OBJ_LOCAL, OBJ_FD_EPOLL);
}

/*
 * The kernel ignores the numeric value of size on all supported
 * releases, but ep_alloc() still rejects size <= 0 with -EINVAL.
 * ARG_LEN's default draw almost never hits the boundary buckets on
 * purpose, so override rec->a1 with an explicit distribution that
 * biases toward small positive sizes while keeping the -EINVAL arm
 * and a couple of historical edge points warm.
 */
static void sanitise_epoll_create(struct syscallrecord *rec)
{
	switch (rnd_modulo_u32(10)) {
	case 0:
		rec->a1 = 0;
		break;
	case 1:
		rec->a1 = (unsigned long) -1;
		break;
	case 2:
		rec->a1 = 0x80000000UL;
		break;
	case 3:
		rec->a1 = 262144;
		break;
	case 4:
		rec->a1 = 262145;
		break;
	case 5:
		rec->a1 = 1;
		break;
	default:
		rec->a1 = 1 + rnd_modulo_u32(1024);
		break;
	}
}

struct syscallentry syscall_epoll_create = {
	.name = "epoll_create",
	.num_args = 1,
	.argtype = { [0] = ARG_LEN },
	.argname = { [0] = "size" },
	.sanitise = sanitise_epoll_create,
	.rettype = RET_FD,
	.ret_objtype = OBJ_FD_EPOLL,
	.post = post_epoll_create,
	.group = GROUP_VFS,
};

/*
 * SYSCALL_DEFINE1(epoll_create1, int, flags)
 *
 * On success, returns a nonnegative file descriptor.
 * On error, -1 is returned, and errno is set to indicate the error.
*
 * If flags is 0, then, other than the fact that the obsolete size argument is dropped,
 * epoll_create1() is the same as epoll_create().
 */

/*
 * epoll_create1_flags[] stays wired to ARG_LIST so the generator has
 * a default pool, but sanitise_epoll_create1() overrides rec->a1
 * below with an explicit bucket draw.  EPOLLWAKEUP is a valid
 * epoll_event bit that the create1 flag check rejects with -EINVAL
 * -- include it (and an invalid high bit) so the reject arm gets
 * deliberate coverage instead of relying on random flag bits.
 */
static unsigned long epoll_create1_flags[] = {
	EPOLL_CLOEXEC, EPOLLWAKEUP,
};

static void sanitise_epoll_create1(struct syscallrecord *rec)
{
	switch (rnd_modulo_u32(20)) {
	case 0 ... 4:
		rec->a1 = 0;
		break;
	case 5 ... 12:
		rec->a1 = EPOLL_CLOEXEC;
		break;
	case 13 ... 15:
		rec->a1 = EPOLLWAKEUP;
		break;
	case 16 ... 17:
		rec->a1 = EPOLL_CLOEXEC | EPOLLWAKEUP;
		break;
	default:
		/* Invalid high bit -- kernel reject path. */
		rec->a1 = 0x80000000UL;
		break;
	}
}

struct syscallentry syscall_epoll_create1 = {
	.name = "epoll_create1",
	.num_args = 1,
	.argtype = { [0] = ARG_LIST },
	.argname = { [0] = "flags" },
	.arg_params[0].list = ARGLIST(epoll_create1_flags),
	.sanitise = sanitise_epoll_create1,
	.rettype = RET_FD,
	.ret_objtype = OBJ_FD_EPOLL,
	.post = post_epoll_create,
	.group = GROUP_VFS,
};
