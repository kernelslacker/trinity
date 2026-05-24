/*
 * SYSCALL_DEFINE0(inotify_init)
 */
#include "objects.h"
#include "random.h"
#include "sanitise.h"
#include "tables.h"

static void post_inotify_init(struct syscallrecord *rec)
{
	struct object *new;
	int fd = rec->retval;

	if ((long)rec->retval < 0)
		return;

	new = alloc_object();
	new->inotifyobj.fd = fd;
	if (current_entry_is_inotify_init1())
		new->inotifyobj.flags = rec->a1;
	else
		new->inotifyobj.flags = 0;
	add_object(new, OBJ_LOCAL, OBJ_FD_INOTIFY);
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
