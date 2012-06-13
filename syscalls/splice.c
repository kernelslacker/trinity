/*
 * SYSCALL_DEFINE6(splice, int, fd_in, loff_t __user *, off_in,
	int, fd_out, loff_t __user *, off_out,
	size_t, len, unsigned int, flags)
 */
# define SPLICE_F_MOVE          1       /* Move pages instead of copying.  */
# define SPLICE_F_NONBLOCK      2       /* Don't block on the pipe splicing
                                           (but we may still block on the fd
                                           we splice from/to).  */
# define SPLICE_F_MORE          4       /* Expect more data.  */
# define SPLICE_F_GIFT          8       /* Pages passed in are a gift.  */

#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_splice = {
	.name = "splice",
	.num_args = 6,
	.arg1name = "fd_in",
	.arg1type = ARG_FD,
	.arg2name = "off_in",
	.arg2type = ARG_ADDRESS,
	.arg3name = "fd_out",
	.arg3type = ARG_FD,
	.arg4name = "off_out",
	.arg4type = ARG_ADDRESS2,
	.arg5name = "len",
	.arg5type = ARG_LEN,
	.arg6name = "flags",
	.arg6type = ARG_LIST,
	.arg6list = {
		.num = 4,
		.values = { SPLICE_F_MOVE, SPLICE_F_NONBLOCK, SPLICE_F_MORE, SPLICE_F_GIFT },
	},
};
