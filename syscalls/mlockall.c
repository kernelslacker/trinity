/*
 * SYSCALL_DEFINE1(mlockall, int, flags)
 */
#include <stdlib.h>
#include <sys/mman.h>
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"

#ifndef MCL_CURRENT
#define MCL_CURRENT     1
#endif
#ifndef MCL_FUTURE
#define MCL_FUTURE      2
#endif
#ifndef MCL_ONFAULT
#define MCL_ONFAULT	4
#endif

static unsigned long mlockall_flags[] = {
	MCL_CURRENT, MCL_FUTURE, MCL_ONFAULT,
};

#ifdef __SANITIZE_ADDRESS__
/*
 * mlockall(MCL_FUTURE) sets VM_LOCKED on every subsequent mmap in this
 * child.  ASAN's allocator extends its shadow region via internal mmap
 * (no MAP_LOCKED of its own), but the inherited VM_LOCKED still routes
 * the new vma through mlock_future_check(); when the locked-page count
 * would exceed RLIMIT_MEMLOCK the kernel returns -EAGAIN.  libasan
 * treats shadow-extension failures as fatal and aborts the child with
 * "AddressSanitizer failed to allocate ... (error code: 11)" -- the
 * top frame is __zmalloc, but the actual __zmalloc never sees a NULL
 * because libasan calls _exit() inside its allocator.
 *
 * Non-ASAN builds survive the same scenario via the malloc-NULL ->
 * munlockall+retry fallback in __zmalloc (utils.c).  That fallback
 * cannot help under ASAN because the abort happens below malloc's
 * return point, so undo MCL_FUTURE here at the syscall boundary.
 *
 * The mlock_pressure childop already exercises a tightly-scoped
 * MCL_FUTURE intercept cycle (mlockall(MCL_FUTURE) -> mmap probes ->
 * munlockall), so dropping the persistent MCL_FUTURE from the syscall
 * fuzz path under ASAN does not lose meaningful kernel coverage.
 */
static void post_mlockall(struct syscallrecord *rec)
{
	(void) rec;
	munlockall();
}
#endif

struct syscallentry syscall_mlockall = {
	.name = "mlockall",
	.num_args = 1,
	.argtype = { [0] = ARG_LIST },
	.argname = { [0] = "flags" },
	.arg_params[0].list = ARGLIST(mlockall_flags),
	.group = GROUP_VM,
	.rettype = RET_ZERO_SUCCESS,
#ifdef __SANITIZE_ADDRESS__
	.post = post_mlockall,
#endif
};
