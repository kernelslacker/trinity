/*
 * SYSCALL_DEFINE6(process_vm_readv, pid_t, pid, const struct iovec __user *, lvec,
 *                unsigned long, liovcnt, const struct iovec __user *, rvec,
 *                unsigned long, riovcnt, unsigned long, flags)
 */
#include <limits.h>
#include <sys/uio.h>
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

static unsigned long process_vm_readv_flags[] = {
	0,	// currently no flags defined, mbz
};

/*
 * The kernel reads data from rvec in the target process and writes it
 * INTO lvec in our address space.  get_pid() returns our own pid 15%
 * of the time, and 70% of the time a sibling child PID -- all forked
 * from the same parent, so all sharing the same MAP_SHARED alloc_shared
 * regions at the same addresses.  Any lvec entry that lands in a
 * tracked shared region lets the kernel scribble whatever the target
 * had at rvec on top of trinity's own bookkeeping, with effects ranging
 * from silent metric corruption to allocator chaos.
 *
 * Walk the lvec array (already populated by alloc_iovec via the
 * ARG_IOVEC generator) and zero out any iov_base whose range
 * overlaps a shared region.  Zero len plus zero base makes the
 * kernel skip that entry without erroring the whole call.
 */
static void sanitise_process_vm_readv(struct syscallrecord *rec)
{
	struct iovec *lvec = (struct iovec *)rec->a2;
	unsigned long count = rec->a3;
	unsigned long i;

	if (lvec == NULL || count == 0)
		return;

	if (count > 256)
		count = 256;

	for (i = 0; i < count; i++) {
		if (lvec[i].iov_base == NULL || lvec[i].iov_len == 0)
			continue;
		if (range_overlaps_shared((unsigned long)lvec[i].iov_base,
					  lvec[i].iov_len)) {
			lvec[i].iov_base = NULL;
			lvec[i].iov_len = 0;
		}
	}
}

static void post_process_vm_readv(struct syscallrecord *rec)
{
	long ret = (long) rec->retval;

	if (ret == -1L)
		return;
	if (ret < 0 || ret > SSIZE_MAX)
		post_handler_corrupt_ptr_bump(rec, NULL);
}

struct syscallentry syscall_process_vm_readv = {
	.name = "process_vm_readv",
	.group = GROUP_PROCESS,
	.num_args = 6,
	.argtype = { [0] = ARG_PID, [1] = ARG_IOVEC, [2] = ARG_IOVECLEN, [3] = ARG_IOVEC, [4] = ARG_IOVECLEN, [5] = ARG_LIST },
	.argname = { [0] = "pid", [1] = "lvec", [2] = "liovcnt", [3] = "rvec", [4] = "riovcnt", [5] = "flags" },
	.arg_params[5].list = ARGLIST(process_vm_readv_flags),
	.sanitise = sanitise_process_vm_readv,
	.post = post_process_vm_readv,
};
