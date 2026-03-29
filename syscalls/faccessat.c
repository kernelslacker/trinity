/*
 * SYSCALL_DEFINE3(faccessat, int, dfd, const char __user *, filename, int, mode)
 *
 * On success, (all requested permissions granted) faccessat() returns 0.
 * On error, -1 is returned and errno is set to indicate the error.
 */
#include <unistd.h>
#include "sanitise.h"

static unsigned long access_modes[] = {
	F_OK, R_OK, W_OK, X_OK,
};

struct syscallentry syscall_faccessat = {
	.name = "faccessat",
	.num_args = 3,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_LIST },
	.argname = { [0] = "dfd", [1] = "filename", [2] = "mode" },
	.arg_params[2].list = ARGLIST(access_modes),
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};

#define AT_FDCWD                -100    /* Special value used to indicate
                                           openat should use the current
                                           working directory. */
#define AT_SYMLINK_NOFOLLOW     0x100   /* Do not follow symbolic links.  */
#define AT_EACCESS              0x200   /* Test access permitted for
                                           effective IDs, not real IDs.  */
#define AT_REMOVEDIR            0x200   /* Remove directory instead of
                                           unlinking file.  */
#define AT_SYMLINK_FOLLOW       0x400   /* Follow symbolic links.  */
#define AT_NO_AUTOMOUNT         0x800   /* Suppress terminal automount traversal */
#define AT_EMPTY_PATH           0x1000  /* Allow empty relative pathname */

#define AT_STATX_SYNC_TYPE      0x6000  /* Type of synchronisation required from statx() */
#define AT_STATX_SYNC_AS_STAT   0x0000  /* - Do whatever stat() does */
#define AT_STATX_FORCE_SYNC     0x2000  /* - Force the attributes to be sync'd with the server */
#define AT_STATX_DONT_SYNC      0x4000  /* - Don't sync attributes with the server */

#define AT_RECURSIVE            0x8000  /* Apply to the entire subtree */


static unsigned long faccessat2_flags[] = {
	AT_FDCWD, AT_SYMLINK_NOFOLLOW, AT_EACCESS, AT_REMOVEDIR,
	AT_SYMLINK_FOLLOW, AT_NO_AUTOMOUNT, AT_EMPTY_PATH, AT_STATX_SYNC_TYPE,
	AT_STATX_SYNC_AS_STAT, AT_STATX_FORCE_SYNC, AT_STATX_DONT_SYNC, AT_RECURSIVE,
};

struct syscallentry syscall_faccessat2 = {
	.name = "faccessat2",
	.num_args = 4,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_LIST, [3] = ARG_LIST },
	.argname = { [0] = "dfd", [1] = "filename", [2] = "mode", [3] = "flags" },
	.arg_params[2].list = ARGLIST(access_modes),
	.arg_params[3].list = ARGLIST(faccessat2_flags),
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
