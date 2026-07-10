/*
 *  SYSCALL_DEFINE2(fsopen, const char __user *, _fs_name, unsigned int, flags)
 */
#include "kernel/mount.h"
#include "rnd.h"
#include "sanitise.h"

static unsigned long fsopen_flags[] = {
	FSOPEN_CLOEXEC
};

static void sanitise_fsopen(struct syscallrecord *rec)
{
	unsigned int flagpick;

	/*
	 * Flags distribution:
	 *   70%  zero
	 *   25%  FSOPEN_CLOEXEC
	 *    5%  random bits (most reserved -- EINVAL gate)
	 */
	flagpick = rnd_modulo_u32(20);
	if (flagpick < 14)
		rec->a2 = 0;
	else if (flagpick < 19)
		rec->a2 = FSOPEN_CLOEXEC;
	else
		rec->a2 = rnd_u32();
}

struct syscallentry syscall_fsopen = {
	.name = "fsopen",
	.num_args = 2,
	.argtype = { [0] = ARG_FSTYPE_NAME, [1] = ARG_OP },
	.argname = { [0] = "_fs_name", [1] = "flags" },
	.arg_params[1].list = ARGLIST(fsopen_flags),
	.rettype = RET_FD,
	.ret_objtype = OBJ_FD_FS_CTX,
	.group = GROUP_VFS,
	.flags = NEEDS_ROOT | KCOV_REMOTE_HEAVY,
	.sanitise = sanitise_fsopen,
	.post = post_fs_ctx_fd,
};
