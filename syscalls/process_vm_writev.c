/*
 * SYSCALL_DEFINE6(process_vm_writev, pid_t, pid, const struct iovec __user *, lvec,
 *                unsigned long, liovcnt, const struct iovec __user *, rvec,
 *                unsigned long, riovcnt, unsigned long, flags)
 */
#include <limits.h>
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
 * to allocator chaos.  The same shape applies to the per-child libc
 * brk arena: a fuzzed iov_base landing in [heap_start, heap_end) lets
 * the kernel write on top of a glibc chunk header, surfacing later as
 * a glibc heap-corruption assert via the next malloc anywhere in
 * trinity (the dominant non-ASAN cluster: __zmalloc -> malloc ->
 * malloc_printerr -> abort).
 *
 * Walk the rvec array (already populated by alloc_iovec via the
 * ARG_IOVEC generator) via the second-pass scrub helper, which zeros
 * out any iov_base whose range overlaps either a shared region or the
 * libc brk arena.  Zero len plus zero base makes the kernel skip that
 * entry without erroring the whole call.
 */
static void sanitise_process_vm_writev(struct syscallrecord *rec)
{
	scrub_iovec_for_kernel_write((struct iovec *)rec->a4, rec->a5);
}

static void post_process_vm_writev(struct syscallrecord *rec)
{
	long ret = (long) rec->retval;

	if (ret == -1L)
		return;
	if (ret < 0 || ret > SSIZE_MAX)
		post_handler_corrupt_ptr_bump(rec, NULL);
}

struct syscallentry syscall_process_vm_writev = {
	.name = "process_vm_writev",
	.group = GROUP_PROCESS,
	.num_args = 6,
	.argtype = { [0] = ARG_PID, [1] = ARG_IOVEC, [2] = ARG_IOVECLEN, [3] = ARG_IOVEC, [4] = ARG_IOVECLEN, [5] = ARG_LIST },
	.argname = { [0] = "pid", [1] = "lvec", [2] = "liovcnt", [3] = "rvec", [4] = "riovcnt", [5] = "flags" },
	.arg_params[5].list = ARGLIST(process_vm_writev_flags),
	.sanitise = sanitise_process_vm_writev,
	.post = post_process_vm_writev,
};
