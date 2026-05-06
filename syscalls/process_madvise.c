/*
 * SYSCALL_DEFINE5(process_madvise, int, pidfd, const struct iovec __user *, vec,
 *                 size_t, vlen, int, behavior, unsigned int, flags)
 */
#include <sys/mman.h>
#include <sys/uio.h>
#include "compat.h"
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

static unsigned long process_madvise_behaviours[] = {
	MADV_COLD, MADV_PAGEOUT, MADV_WILLNEED, MADV_COLLAPSE,
};
static unsigned long process_madvise_flags[] = {
	0,
};

/*
 * The kernel walks vec[] and applies the advice to the target process at
 * each iov_base.  get_pid() returns our own pid 15% of the time, so the
 * pidfd pool legitimately contains self-pidfds; siblings forked from the
 * same parent share VA layout closely enough that a sibling pidfd is
 * almost as dangerous.  Behaviours like MADV_PAGEOUT and MADV_COLLAPSE
 * zap PTEs in the target's mapping.  kcov's mmap inserts pages with
 * vm_insert_page and ships no fault handler, so once those PTEs are gone
 * the next kc->trace_buf[] read in kcov_collect SIGBUSes -- the dominant
 * unique-signature crash class in trinity userland fuzz runs.  The same
 * shape applies to the per-child libc brk arena: an iov_base landing in
 * [heap_start, heap_end) lets MADV_PAGEOUT zap PTEs underneath glibc
 * chunk metadata, surfacing later as a glibc heap-corruption assert.
 *
 * regular madvise's sanitiser uses range_overlaps_shared() against
 * (rec->a1, rec->a2); process_madvise can't do that because the kernel
 * dereferences vec as an iovec[] rather than treating the addr/len pair
 * as a single range.  Switch the args to ARG_IOVEC/ARG_IOVECLEN so
 * alloc_iovec() runs avoid_shared_buffer() per entry, and walk vec
 * here via the second-pass scrub helper as belt-and-suspenders for the
 * case where avoid_shared_buffer couldn't find a replacement (heap
 * exhausted, len > available) or a sibling scribbled the iovec heap
 * allocation between sanitise and the kernel reading the array.
 */
static void sanitise_process_madvise(struct syscallrecord *rec)
{
	scrub_iovec_for_kernel_write((struct iovec *)rec->a2, rec->a3);
}

struct syscallentry syscall_process_madvise = {
	.name = "process_madvise",
	.num_args = 5,
	.argtype = { [0] = ARG_FD_PIDFD, [1] = ARG_IOVEC, [2] = ARG_IOVECLEN, [3] = ARG_OP, [4] = ARG_OP },
	.argname = { [0] = "pidfd", [1] = "vec", [2] = "vlen", [3] = "behaviour", [4] = "flags" },
	.arg_params[3].list = ARGLIST(process_madvise_behaviours),
	.arg_params[4].list = ARGLIST(process_madvise_flags),
	.group = GROUP_VM,
	.sanitise = sanitise_process_madvise,
};
