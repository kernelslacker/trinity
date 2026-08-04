/*
 *  SYSCALL_DEFINE3(fsmount, int, fs_fd, unsigned int, flags, unsigned int, attr_flags)
 */
#include "kernel/mount.h"
#include "object-types.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"

static unsigned long fsmount_flags[] = {
	FSMOUNT_CLOEXEC,
	FSMOUNT_NAMESPACE,
};

/*
 * Non-atime attr bits for fsmount's attr_flags argument.  The atime
 * field inside MOUNT_ATTR__ATIME is a value-encoded sub-enum -- the
 * kernel's build_mount_kattr() EINVALs on any combination that is not
 * exactly one of {RELATIME=0, NOATIME, STRICTATIME}.  Keep these
 * independent flags in an ARG_LIST and draw the atime mode separately
 * in sanitise_fsmount(), OR-ing one valid choice in at the end.
 * MOUNT_ATTR_IDMAP intentionally excluded: not in FSMOUNT_VALID_FLAGS
 * (valid only for mount_setattr), so the kernel EINVALs immediately on
 * any pick that sets the bit.
 */
static unsigned long fsmount_attr_nonatime[] = {
	MOUNT_ATTR_RDONLY,
	MOUNT_ATTR_NOSUID,
	MOUNT_ATTR_NODEV,
	MOUNT_ATTR_NOEXEC,
	MOUNT_ATTR_NODIRATIME,
	MOUNT_ATTR_NOSYMFOLLOW,
};

static unsigned long fsmount_atime_modes[] = {
	MOUNT_ATTR_RELATIME, MOUNT_ATTR_NOATIME, MOUNT_ATTR_STRICTATIME,
};

static void sanitise_fsmount(struct syscallrecord *rec)
{
	/*
	 * ARG_LIST has already OR'd a random subset of the non-atime flags
	 * into rec->a2.  Roughly half the time, also request a specific
	 * atime mode.  RELATIME (==0) is a no-op on the bitmask and is
	 * included in the draw so that "no explicit atime request" is still
	 * a reachable outcome from this branch.
	 */
	if (RAND_BOOL())
		rec->a2 |= fsmount_atime_modes[rnd_modulo_u32(ARRAY_SIZE(fsmount_atime_modes))];
}

struct syscallentry syscall_fsmount = {
	.name = "fsmount",
	.num_args = 3,
	.argtype = { [0] = ARG_FD_FS_CTX, [1] = ARG_LIST, [2] = ARG_LIST },
	.argname = { [0] = "fs_fd", [1] = "flags", [2] = "attr_flags" },
	.arg_params[1].list = ARGLIST(fsmount_flags),
	.arg_params[2].list = ARGLIST(fsmount_attr_nonatime),
	.sanitise = sanitise_fsmount,
	.rettype = RET_FD,
	.ret_objtype = OBJ_FD_MOUNT,
	.group = GROUP_VFS_MOUNT,
	.flags = NEEDS_ROOT | KCOV_REMOTE_HEAVY,
	.post = post_mount_fd,
};
