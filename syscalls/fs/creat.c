/*
 * SYSCALL_DEFINE2(creat, const char __user *, pathname, int, mode)
 *
 * returns the new file descriptor on success.
 * returns -1 if an error occurred (in which case, errno is set appropriately).
 */
#include <sys/stat.h>
#include <unistd.h>
#include "pathnames.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"

static void sanitise_creat(struct syscallrecord *rec)
{
	char *path;

	/*
	 * ARG_PATHNAME plumbed a random pathname into rec->a1, but the
	 * random path is most often not a real dirent -- creat is
	 * equivalent to open(path, O_CREAT|O_WRONLY|O_TRUNC, mode) and
	 * bounces at the path walk before ever reaching do_filp_open on
	 * the create-and-truncate arm.
	 *
	 * Half the draws now repoint at one of the trinity-testfile<N>
	 * absolute paths so the syscall lands on a real trinity-owned
	 * inode: creat on an existing file re-enters the O_TRUNC path
	 * (setattr / notify_change on a real inode) and the mode bits
	 * below get to influence i_mode on the inode-materialise side of
	 * a race.  The other half preserves the random draw so the
	 * ENOENT-on-nonexistent-dirent arm stays exercised.
	 */
	if (rnd_modulo_u32(2) == 0) {
		path = get_testfile_path();
		if (path != NULL)
			rec->a1 = (unsigned long) path;
	}

	/*
	 * Fold in security-relevant mode bits on a small fraction of
	 * draws.  ARG_MODE_T picks one of fifteen mode bits per iteration
	 * and flips a coin, so setuid / setgid / sticky each land in
	 * i_mode with ~3% probability from the generic draw alone -- too
	 * thin to consistently exercise the cap_convert_nscap /
	 * setattr_should_drop_sgid / sticky-dir-permission gates that
	 * only fire when those bits actually reach the inode at create
	 * time.  The two arms are mutually exclusive so the paired
	 * setuid+setgid combo does not stack with sticky on the same
	 * call.
	 */
	if (ONE_IN(10))
		rec->a2 |= S_ISUID | S_ISGID;
	else if (ONE_IN(10))
		rec->a2 |= S_ISVTX;
}

static void post_creat(struct syscallrecord *rec)
{
	int fd = rec->retval;

	if (fd < 0 || fd >= (1 << 20))
		return;
	close(fd);
}

struct syscallentry syscall_creat = {
	.name = "creat",
	.num_args = 2,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_MODE_T },
	.argname = { [0] = "pathname", [1] = "mode" },
	.rettype = RET_FD,
	/*
	 * REEXEC_SANITISE_OK: sanitise_creat only rewrites input args
	 * in place -- an ARG_PATHNAME pointer sourced from the shared
	 * testfile pool and mode bits ORed into rec->a2.  No nested
	 * pointer chains, no INOUT / output buffers, no shared-buffer
	 * relocation, no post_state oracle -- safe to keep on the CMP
	 * RedQueen re-exec path.
	 */
	.flags = NEED_ALARM | REEXEC_SANITISE_OK,
	.sanitise = sanitise_creat,
	.post = post_creat,
	.group = GROUP_VFS,
};
