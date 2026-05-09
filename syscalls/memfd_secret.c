/*
 * SYSCALL_DEFINE1(memfd_secret, unsigned int, flags)
 */

#include <fcntl.h>
#include <unistd.h>
#include "sanitise.h"
#include "memfd.h"
#include "compat.h"

static unsigned long memfd_secret_flags[] = {
	O_CLOEXEC,
};

struct syscallentry syscall_memfd_secret = {
	.name = "memfd_secret",
	.num_args = 1,
	.argtype = { [0] = ARG_LIST },
	.argname = { [0] = "flag" },
	.arg_params[0].list = ARGLIST(memfd_secret_flags),
	.rettype = RET_FD,
	.ret_objtype = OBJ_FD_MEMFD_SECRET,
	/*
	 * No .post: the dispatcher's register_returned_fd() claims the
	 * fd into the OBJ_FD_MEMFD_SECRET OBJ_LOCAL pool via the
	 * .ret_objtype annotation, and memfd_secret_destructor handles
	 * close() at child teardown.  Replaces the previous
	 * generic_post_close_fd hook, which closed the fd immediately
	 * and so prevented any consumer from picking it up.
	 */
	.group = GROUP_VFS,
};
