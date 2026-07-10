/*
 * SYSCALL_DEFINE0(inotify_init)
 */
#include "publish_resource.h"
#include "random.h"
#include "sanitise.h"
#include "tables.h"

static void post_inotify_init(struct syscallrecord *rec)
{
	int fd = rec->retval;

	if (fd < 0)
		return;

	struct resource_meta meta = {
		.flags = current_entry_is_inotify_init1() ? rec->a1 : 0,
	};
	publish_resource(OBJ_FD_INOTIFY, fd, &meta);
}

struct syscallentry syscall_inotify_init = {
	.name = "inotify_init",
	.num_args = 0,
	.group = GROUP_VFS,
	.rettype = RET_FD,
	.ret_objtype = OBJ_FD_INOTIFY,
	.post = post_inotify_init,
};

/*
 * SYSCALL_DEFINE1(inotify_init1, int, flags)
 */

#define IN_CLOEXEC 02000000
#define IN_NONBLOCK 04000

/*
 * inotify_init1_flags[] stays wired to ARG_LIST so the generator has
 * a default, but sanitise_inotify_init1() overrides rec->a1 below
 * with an explicit bucket draw.  The two-entry ARG_LIST pool almost
 * never produces the zero-flags arm, the full combo, or the
 * invalid-high-bit reject path.
 */
static unsigned long inotify_init1_flags[] = {
	IN_CLOEXEC , IN_NONBLOCK,
};

static void sanitise_inotify_init1(struct syscallrecord *rec)
{
	unsigned int pick = rnd_modulo_u32(20);

	switch (pick) {
	case 0 ... 5:
		rec->a1 = 0;
		break;
	case 6 ... 10:
		rec->a1 = IN_CLOEXEC;
		break;
	case 11 ... 15:
		rec->a1 = IN_NONBLOCK;
		break;
	case 16 ... 18:
		rec->a1 = IN_CLOEXEC | IN_NONBLOCK;
		break;
	default:
		/* Invalid high bit -- kernel reject path. */
		rec->a1 = 0x80000000UL;
		break;
	}
}

struct syscallentry syscall_inotify_init1 = {
	.name = "inotify_init1",
	.num_args = 1,
	.argtype = { [0] = ARG_LIST },
	.argname = { [0] = "flags" },
	.arg_params[0].list = ARGLIST(inotify_init1_flags),
	.sanitise = sanitise_inotify_init1,
	.group = GROUP_VFS,
	.rettype = RET_FD,
	.ret_objtype = OBJ_FD_INOTIFY,
	.post = post_inotify_init,
};
