/*
 * SYSCALL_DEFINE5(setxattr, const char __user *, pathname,
	 const char __user *, name, const void __user *, value,
	 size_t, size, int, flags)
 */

#include <stdio.h>
#include <string.h>
#include "pathnames.h"
#include "rnd.h"
#include "sanitise.h"
#include "trinity.h"
#include "xattr.h"

/*
 * Mirrors the MAX_TESTFILES bound in fds/testfiles.c so we land inside
 * the same trinity-testfile<N> inodes the rest of the fuzzer
 * (xattr-thrash, flock-thrash, fremovexattr, lremovexattr, llistxattr)
 * touches; cross-process contention concentrates on the same per-inode
 * i_xattrs rwsem.
 */
#define NR_TESTFILES 4

/*
 * Curated name we plant ahead of the trinity-dispatched setxattr.
 * Matches planted_xattr_name in fremovexattr / lremovexattr /
 * lgetxattr / llistxattr / lsetxattr so a single round of testfile
 * xattrs is shared across the whole xattr-family precondition surface
 * -- setxattr's write lands on the same (inode, name) tuple the
 * sibling xattr syscalls read/remove, concentrating cross-process
 * contention on one entry in i_xattrs instead of scattering across
 * the random ARG_XATTR_NAME pool.
 */
static const char planted_xattr_name[] = "user.trinity_plant";

static void sanitise_setxattr(struct syscallrecord *rec)
{
	char *path;
	char *name;

	xattr_set_value((const char *) rec->a2, &rec->a3, &rec->a4);
	avoid_shared_buffer_inout(&rec->a3, rec->a4);
	xattr_pick_set_flags(&rec->a5);

	/*
	 * ARG_PATHNAME plumbed a random pathname into rec->a1 and
	 * ARG_XATTR_NAME filled rec->a2 with a namespace-shaped name
	 * from the curated pool, but the random path is most often not
	 * a real file at all (ENOENT at path walk) and, even when it
	 * does land on a real file, the drawn name often lands in a
	 * namespace the fs bails out of at the front of vfs_setxattr
	 * (EOPNOTSUPP on security.* or trusted.* without the right
	 * creds, ENOTSUP on filesystems that only carry user.*).
	 * Either way the call returns before ever reaching the per-fs
	 * xattr handler dispatch and the simple_xattr_set fast path
	 * that the per-inode i_xattrs rwsem guards.  Same "high calls,
	 * low edges" cold-syscall shape that fremovexattr /
	 * lremovexattr / llistxattr were in before their testfile
	 * precondition fixes.
	 *
	 * Half the draws now repoint at one of the trinity-testfile<N>
	 * absolute paths AND overwrite rec->a2 with the shared
	 * planted_xattr_name (user.trinity_plant) so the subsequent
	 * setxattr lands inside the real per-inode set path -- the
	 * handler dispatch and the i_xattrs rwsem on a known-existing
	 * inode, writing to the same (inode, name) tuple the sibling
	 * xattr syscalls read/remove.  setxattr is itself the set, so
	 * no precondition setxattr() plant is needed: the trinity-
	 * dispatched call IS the write.  The other half preserves the
	 * slot exactly as the generic draw left it so the ENOENT /
	 * namespace-reject arms stay exercised.
	 */
	if (rnd_modulo_u32(2) != 0)
		return;

	name = (char *) rec->a2;
	if (name == NULL)
		return;

	path = get_testfile_path();
	if (path == NULL)
		return;

	/*
	 * The ARG_XATTR_NAME buffer at rec->a2 is XATTR_NAME_BUFSZ (256)
	 * bytes and is overwritten in place; it comfortably fits the
	 * planted value.
	 */
	rec->a1 = (unsigned long) path;
	memcpy(name, planted_xattr_name, sizeof(planted_xattr_name));
}

struct syscallentry syscall_setxattr = {
	.name = "setxattr",
	.num_args = 5,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_XATTR_NAME, [2] = ARG_ADDRESS, [3] = ARG_LEN, [4] = ARG_LIST },
	.argname = { [0] = "pathname", [1] = "name", [2] = "value", [3] = "size", [4] = "flags" },
	.arg_params[4].list = ARGLIST(xattr_set_flags),
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_XATTR,
	.sanitise = sanitise_setxattr,
};
