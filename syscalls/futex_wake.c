/*
 * SYSCALL_DEFINE4(futex_wake, void __user *, uaddr,
 *		unsigned long, mask, int, nr, unsigned int, flags)
 */
#include "random.h"
#include "sanitise.h"
#include "compat.h"
#include "trinity.h"
#include "utils.h"

#ifndef FUTEX2_SIZE_U8
#define FUTEX2_SIZE_U8		0x00
#define FUTEX2_SIZE_U16		0x01
#define FUTEX2_SIZE_U32		0x02
#define FUTEX2_SIZE_U64		0x03
#define FUTEX2_NUMA		0x04
#endif

#ifndef FUTEX2_PRIVATE
#define FUTEX2_PRIVATE		0x80
#endif

#ifndef FUTEX2_MPOL
#define FUTEX2_MPOL		0x08
#endif

static unsigned long futex2_flags[] = {
	FUTEX2_SIZE_U8, FUTEX2_SIZE_U16, FUTEX2_SIZE_U32, FUTEX2_SIZE_U64,
	FUTEX2_NUMA, FUTEX2_PRIVATE, FUTEX2_MPOL,
};

static void sanitise_futex_wake(struct syscallrecord *rec)
{
	/* mask: generate a useful comparison mask */
	switch (rand() % 4) {
	case 0: rec->a2 = 0xffffffff; break;	/* all bits (common case) */
	case 1: rec->a2 = 0xff; break;		/* U8 futex */
	case 2: rec->a2 = 0xffff; break;	/* U16 futex */
	default: rec->a2 = rand32(); break;	/* random mask */
	}
}

/*
 * Kernel ABI: sys_futex_wake returns the number of waiters woken on
 * success -- capped by the requested nr argument (rec->a3) -- or -1UL on
 * failure (errno set on the libc side). Anything in (nr, -1UL) is a
 * structural ABI violation: a sign-extension tear of the int return on a
 * 32-bit-on-64 compat path, a sibling-thread scribble of rec->retval
 * between syscall return and post entry, or kernel-side accounting that
 * over-counted a wake. This validator runs unconditionally (no sample
 * gate) so a wild value is caught on every call.
 */
static void post_futex_wake(struct syscallrecord *rec)
{
	unsigned long retval = rec->retval;
	unsigned long val_arg = rec->a3;

	if (retval == (unsigned long)-1L)
		return;

	if (retval > val_arg) {
		outputerr("post_futex_wake: rejected woken-count %lu outside [0, %lu] (kernel ABI violation)\n",
			  retval, val_arg);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}
}

struct syscallentry syscall_futex_wake = {
	.name = "futex_wake",
	.num_args = 4,
	.argtype = { [0] = ARG_ADDRESS, [2] = ARG_RANGE, [3] = ARG_LIST },
	.argname = { [0] = "uaddr", [1] = "mask", [2] = "nr", [3] = "flags" },
	.arg_params[2].range.low = 1,
	.arg_params[2].range.hi = 128,
	.arg_params[3].list = ARGLIST(futex2_flags),
	.sanitise = sanitise_futex_wake,
	.post = post_futex_wake,
	.group = GROUP_IPC,
};
