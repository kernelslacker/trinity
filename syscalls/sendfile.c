/*
 * SYSCALL_DEFINE4(sendfile, int, out_fd, int, in_fd, off_t __user *, offset, size_t, count)
 */
#include <stdint.h>
#include <sys/types.h>
#include "random.h"
#include "sanitise.h"
#include "trinity.h"

static off_t sendfile_offset;
static off_t sendfile64_offset;

static void sanitise_sendfile(struct syscallrecord *rec)
{
	sendfile_offset = RAND_RANGE(0, 1ULL << 30);
	rec->a3 = (unsigned long) &sendfile_offset;
}

static void sanitise_sendfile64(struct syscallrecord *rec)
{
	sendfile64_offset = RAND_RANGE(0, 1ULL << 30);
	rec->a3 = (unsigned long) &sendfile64_offset;
}

struct syscallentry syscall_sendfile = {
	.name = "sendfile",
	.num_args = 4,
	.argtype = { [0] = ARG_FD, [1] = ARG_FD, [2] = ARG_ADDRESS, [3] = ARG_LEN },
	.argname = { [0] = "out_fd", [1] = "in_fd", [2] = "offset", [3] = "count" },
	.sanitise = sanitise_sendfile,
	.flags = NEED_ALARM | IGNORE_ENOSYS,
	.group = GROUP_VFS,
};

/*
 * SYSCALL_DEFINE4(sendfile64, int, out_fd, int, in_fd, loff_t __user *, offset, size_t, count)
 */

struct syscallentry syscall_sendfile64 = {
	.name = "sendfile64",
	.num_args = 4,
	.argtype = { [0] = ARG_FD, [1] = ARG_FD, [2] = ARG_ADDRESS, [3] = ARG_LEN },
	.argname = { [0] = "out_fd", [1] = "in_fd", [2] = "offset", [3] = "count" },
	.sanitise = sanitise_sendfile64,
	.flags = NEED_ALARM | IGNORE_ENOSYS,
	.group = GROUP_VFS,
};
