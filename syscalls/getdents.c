/*
 * SYSCALL_DEFINE3(getdents, unsigned int, fd,
    struct linux_dirent __user *, dirent, unsigned int, count)
 */
#include <limits.h>
#include "arch.h"
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

static void sanitise_getdents(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a2, rec->a3 ? rec->a3 : page_size);
}

/*
 * Kernel ABI: getdents{,64} returns the number of bytes written into the
 * caller-provided dirent buffer, bounded above by the requested buffer
 * size argument (count, rec->a3) — vfs_readdir / iterate_dir cannot emit
 * more bytes than the buffer can hold without ENOSPC-style failure. 0 on
 * end-of-directory, -1UL on failure (EBADF, EFAULT, EINVAL, ENOTDIR,
 * ENOENT). Anything in (count, -1UL) — or any other "negative" besides
 * -1UL — is a structural ABI violation: a sign-extension tear of the
 * int return on a 32-bit-on-64 compat path, a torn copy of ctx->pos /
 * dir_context bookkeeping into the return slot, a sibling-thread
 * scribble of rec->retval between syscall return and post entry, or
 * filldir() emitting past the declared count and the kernel reporting
 * the over-write back to userspace verbatim.
 *
 * The pre-existing handler tree treated this call as boring (no .post)
 * so a wild retval landed in stats unobserved. Reject before any sample
 * gate: emit an oracle line via outputerr matching the rest of the
 * post-handler family, bump the corrupt-retval counter via
 * post_handler_corrupt_ptr_bump(), and return.
 */
static void post_getdents(struct syscallrecord *rec)
{
	unsigned long retval = (unsigned long) rec->retval;
	unsigned long count = rec->a3;

	if (retval == (unsigned long)-1L)
		return;

	if (retval > LONG_MAX || retval > count) {
		outputerr("post_getdents: rejected retval %ld outside [0, count=%lu] and != -1UL\n",
			  (long) retval, count);
		post_handler_corrupt_ptr_bump(rec, NULL);
		return;
	}
}

struct syscallentry syscall_getdents = {
	.name = "getdents",
	.num_args = 3,
	.argtype = { [0] = ARG_FD, [1] = ARG_NON_NULL_ADDRESS, [2] = ARG_LEN },
	.argname = { [0] = "fd", [1] = "dirent", [2] = "count" },
	.sanitise = sanitise_getdents,
	.post = post_getdents,
	.rettype = RET_NUM_BYTES,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};


/*
 * SYSCALL_DEFINE3(getdents64, unsigned int, fd,
	 struct linux_dirent64 __user *, dirent, unsigned int, count)
 */

struct syscallentry syscall_getdents64 = {
	.name = "getdents64",
	.num_args = 3,
	.argtype = { [0] = ARG_FD, [1] = ARG_NON_NULL_ADDRESS, [2] = ARG_LEN },
	.argname = { [0] = "fd", [1] = "dirent", [2] = "count" },
	.sanitise = sanitise_getdents,
	.post = post_getdents,
	.rettype = RET_NUM_BYTES,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
