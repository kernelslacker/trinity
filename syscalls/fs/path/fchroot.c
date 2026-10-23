/*
 * SYSCALL_DEFINE2(fchroot, int, fd, unsigned int, flags)
 *
 * flags must be 0.  fd == FD_FAILFS_ROOT (-10004) swaps the root into failfs
 * without CAP_SYS_CHROOT when no_new_privs is set, fs->users == 1 and the
 * caller is not chrooted, which is why this entry is not NEEDS_ROOT.
 */
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "kernel/fcntl.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "sanitiser-fd.h"
#include "tmpdir.h"
#include "utils.h"

/*
 * Every value here is invalid today -- flags has exactly one legal
 * value, zero.  The list supplies WHAT garbage the validation arm sees;
 * the sanitiser below decides HOW OFTEN it sees any, because a uniform
 * draw over this list would spend most of the call budget bouncing off
 * the first line of the syscall and never reach the branch that
 * matters.  When a future kernel defines a real flag here, it moves
 * from this list into the sanitiser's legal draw.
 */
static unsigned long fchroot_flags[] = {
	0x1, 0x2, 0x4, 0x80000000, 0xffffffff,
};

static void sanitise_fchroot(struct syscallrecord *rec)
{
	/*
	 * Seven draws in eight are legal, so the call gets past the
	 * flags gate and reaches the fd branches.  The eighth keeps the
	 * -EINVAL arm live with whatever ARG_OP drew from the list.
	 */
	if (rnd_modulo_u32(8) != 0)
		rec->a2 = 0;

	/*
	 * ARG_FD left a random fd in a1.  A random fd is almost always a
	 * non-directory, so the generic draw dies at d_can_lookup with
	 * -ENOTDIR before reaching either permission check.
	 *
	 * Split the draws three ways:
	 *
	 *   FD_FAILFS_ROOT  -- the unprivileged branch.  Nothing else in
	 *                      the tree emits this sentinel, and it is
	 *                      reachable only by naming it exactly.
	 *   a real dirfd    -- opens the trinity tmpdir O_PATH|O_DIRECTORY
	 *                      so d_can_lookup succeeds and the call
	 *                      penetrates as far as file_permission() and
	 *                      ns_capable().  O_PATH specifically: the
	 *                      commit message claims fchroot works with
	 *                      O_PATH fds, and fd_raw is what lets it, so
	 *                      that is the claim worth exercising.  This
	 *                      sanitiser runs in the child, before
	 *                      do_extrafork() forks, so the descriptor is
	 *                      the child's: .cleanup closes it once the
	 *                      call is done, not before the kernel reads it.
	 *   untouched       -- whatever ARG_FD produced, keeping the
	 *                      -EBADF / -ENOTDIR reject arms alive.
	 */
	switch (rnd_modulo_u32(3)) {
	case 0:
		rec->a1 = (unsigned long)(long)FD_FAILFS_ROOT;
		break;
	case 1: {
		int fd = open(trinity_tmpdir_abs(), O_PATH | O_DIRECTORY | O_CLOEXEC);

		if (fd >= 0) {
			sanitiser_own_fd(rec, fd);
			rec->a1 = (unsigned long)fd;
		}
		break;
	}
	default:
		break;
	}
}

struct syscallentry syscall_fchroot = {
	.name = "fchroot",
	.num_args = 2,
	.argtype = { [0] = ARG_FD, [1] = ARG_OP },
	.argname = { [0] = "fd", [1] = "flags" },
	.arg_params[1].list = ARGLIST(fchroot_flags),
	.rettype = RET_ZERO_SUCCESS,
	/* A successful call is not something a fuzz child survives usefully:
	 * every later path lookup resolves against the new root, and if that
	 * root is failfs, a filesystem whose purpose is to fail operations,
	 * the child spends the rest of its life collecting errors.  EXTRA_FORK
	 * keeps the swap in a throwaway grandchild, as execve's does:
	 * irreversible process state, contained.
	 *
	 * EXTRA_FORK spawns a helper process per dispatch, the same explicit
	 * re-exec disqualifier execve carries: a re-exec would fork another
	 * grandchild.  AVOID_REEXEC is unconditional, so no later per-call
	 * REEXEC_OK publish can reopen it. */
	.flags = EXTRA_FORK | AVOID_REEXEC,
	.group = GROUP_VFS_PATH,
	.sanitise = sanitise_fchroot,
	.cleanup = cleanup_sanitiser_fd,
};
