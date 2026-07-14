/*
 * SYSCALL_DEFINE4(futex_wake, void __user *, uaddr,
 *		unsigned long, mask, int, nr, unsigned int, flags)
 */
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/futex.h"

static void sanitise_futex_wake(struct syscallrecord *rec)
{
	unsigned long flags;

	/* mask: generate a useful comparison mask */
	switch (rnd_modulo_u32(4)) {
	case 0: rec->a2 = 0xffffffff; break;	/* all bits (common case) */
	case 1: rec->a2 = 0xff; break;		/* U8 futex */
	case 2: rec->a2 = 0xffff; break;	/* U16 futex */
	default: rec->a2 = rand32(); break;	/* random mask */
	}

	/* flags: only FUTEX2_SIZE_U32 is valid for normal futexes; OR in
	 * PRIVATE/NUMA/MPOL modifiers to exercise the composed form
	 * instead of picking a lone size that yields immediate -EINVAL.
	 */
	flags = FUTEX2_SIZE_U32;
	if (RAND_BOOL())
		flags |= FUTEX2_PRIVATE;
	if (ONE_IN(4))
		flags |= FUTEX2_NUMA;
	if (ONE_IN(8))
		flags |= FUTEX2_MPOL;
	rec->a4 = flags;
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
	unsigned long val_arg = get_arg_snapshot(rec, 3);

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
	.argtype = { [0] = ARG_ADDRESS, [2] = ARG_RANGE },
	.argname = { [0] = "uaddr", [1] = "mask", [2] = "nr", [3] = "flags" },
	.arg_params[2].range.low = 1,
	.arg_params[2].range.hi = 128,
	.sanitise = sanitise_futex_wake,
	.post = post_futex_wake,
	.group = GROUP_IPC,
	/* a3 (nr) drives post_futex_wake's retval bound: the kernel ABI
	 * caps the woken-count at the requested nr, and the post oracle
	 * rejects any retval outside [0, nr] as a structural violation.
	 * Reading a3 live from the shared rec would let a sibling stomp
	 * between syscall return and the post handler swing the bound to
	 * a fabricated value -- masking a real over-count or fabricating
	 * a violation from a clean call.  Shadow a3 so the bound comes
	 * from the dispatch-time value the kernel actually saw; mismatch
	 * bumps arg_shadow_stomp from inside get_arg_snapshot(). */
	.arg_snapshot_mask = (1u << 2),
};
