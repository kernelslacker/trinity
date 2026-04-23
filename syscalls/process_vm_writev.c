/*
 * SYSCALL_DEFINE6(process_vm_writev, pid_t, pid, const struct iovec __user *, lvec,
 *                unsigned long, liovcnt, const struct iovec __user *, rvec,
 *                unsigned long, riovcnt, unsigned long, flags)
 */
#include <sys/uio.h>
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

static unsigned long process_vm_writev_flags[] = {
	0,	// currently no flags defined, mbz
};

/*
 * The kernel writes data from lvec INTO rvec in the target process.
 * get_pid() returns our own pid 15% of the time, and 70% of the time
 * a sibling child PID -- all forked from the same parent, so all
 * sharing the same MAP_SHARED alloc_shared regions at the same
 * addresses.  Any rvec entry that lands in a tracked shared region
 * lets the kernel scribble whatever was in lvec on top of trinity's
 * own bookkeeping, with effects ranging from silent metric corruption
 * to allocator chaos.
 *
 * Walk the rvec array (already populated by alloc_iovec via the
 * ARG_IOVEC generator) and zero out any iov_base whose range
 * overlaps a shared region.  Zero len plus zero base makes the
 * kernel skip that entry without erroring the whole call.
 */
static void sanitise_process_vm_writev(struct syscallrecord *rec)
{
	struct iovec *rvec = (struct iovec *)rec->a4;
	unsigned long count = rec->a5;
	unsigned long i;

	if (rvec == NULL || count == 0)
		return;

	if (count > 256)
		count = 256;

	for (i = 0; i < count; i++) {
		if (rvec[i].iov_base == NULL || rvec[i].iov_len == 0)
			continue;
		if (range_overlaps_shared((unsigned long)rvec[i].iov_base,
					  rvec[i].iov_len)) {
			rvec[i].iov_base = NULL;
			rvec[i].iov_len = 0;
		}
	}
}

struct syscallentry syscall_process_vm_writev = {
	.name = "process_vm_writev",
	.group = GROUP_PROCESS,
	.num_args = 6,
	.argtype = { [0] = ARG_PID, [1] = ARG_IOVEC, [2] = ARG_IOVECLEN, [3] = ARG_IOVEC, [4] = ARG_IOVECLEN, [5] = ARG_LIST },
	.argname = { [0] = "pid", [1] = "lvec", [2] = "liovcnt", [3] = "rvec", [4] = "riovcnt", [5] = "flags" },
	.arg_params[5].list = ARGLIST(process_vm_writev_flags),
	.sanitise = sanitise_process_vm_writev,
};
