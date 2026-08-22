/*
 * SYSCALL_DEFINE2(fchroot, int, fd, unsigned int, flags)
 *
 * On success, zero is returned.
 * On error, -1 is returned, and errno is set appropriately.
 *
 * Linux 7.3, 20370a5f5d9b ("fs: add fchroot()"), part of the failfs
 * series.  fd-based counterpart to chroot(2), and rather more than that:
 * it composes with O_PATH fds and with detached mount trees from
 * open_tree(OPEN_TREE_CLONE), and it carries a second, separately
 * guarded entry point that chroot(2) has no equivalent of.
 *
 * The kernel side, in order, because the order is what makes this
 * fuzzable at all:
 *
 *   1. flags must be zero            -> -EINVAL
 *   2. fd == FD_FAILFS_ROOT (-10004) -> chroot into failfs, guarded by
 *      EITHER CAP_SYS_CHROOT in the caller's userns, OR all three of
 *      no_new_privs set, fs->users == 1, and !current_chrooted()
 *   3. otherwise: fd_raw lookup -> -EBADF, d_can_lookup -> -ENOTDIR,
 *      file_permission(MAY_EXEC | MAY_CHDIR), ns_capable(CAP_SYS_CHROOT)
 *
 * Step 2 is the interesting one and the reason this entry is not
 * NEEDS_ROOT the way chroot is.  It is a root swap reachable WITHOUT
 * CAP_SYS_CHROOT, gated by three hand-written conditions that have to
 * agree -- one of which (no_new_privs) trinity's own prctl fuzzing can
 * set, and one of which (fs->users) is about sharing that a clone()
 * elsewhere in the same child can change underneath it.  Hand-written
 * multi-condition guards in front of a privileged state change are the
 * shape worth pointing a fuzzer at.
 *
 * EXTRA_FORK because a SUCCESSFUL call is not something a fuzz child
 * survives usefully: every subsequent path lookup resolves against the
 * new root, and if that root is failfs -- a filesystem whose stated
 * purpose is to fail operations -- the child spends the rest of its
 * life collecting errors from syscalls that would otherwise be doing
 * work.  Running it in a throwaway grandchild keeps the swap and its
 * consequences inside a process that exits immediately.  Same rationale
 * as execve's EXTRA_FORK: irreversible process state, contained.
 */
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "kernel/fcntl.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "trinity.h"
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
	 *                      that is the claim worth exercising.
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
			/*
			 * Leaked deliberately: this runs in the EXTRA_FORK
			 * grandchild, which _exit()s straight after the
			 * call, so the descriptor dies with it.  Closing it
			 * here would close it before the kernel reads it.
			 */
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
	.flags = EXTRA_FORK,
	.group = GROUP_VFS_PATH,
	.sanitise = sanitise_fchroot,
};
