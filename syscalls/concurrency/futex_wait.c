/*
 * SYSCALL_DEFINE6(futex_wait, void __user *, uaddr,
 *		unsigned long, val, unsigned long, mask,
 *		unsigned int, flags,
 *		struct __kernel_timespec __user *, timeout,
 *		clockid_t, clockid)
 */
#include <time.h>
#include "random.h"
#include "rnd.h"
#include "sanitise.h"

#include "kernel/futex.h"

static unsigned long futex_wait_clockids[] = {
	CLOCK_REALTIME, CLOCK_MONOTONIC,
};

/* futex_flags_valid() takes only FUTEX2_SIZE_U32 for now: the rest are
 * drawn one time in sixteen, for the EINVAL. */
static const unsigned int futex2_refused_sizes[] = {
	FUTEX2_SIZE_U8, FUTEX2_SIZE_U16, FUTEX2_SIZE_U64,
};

static void sanitise_futex_wait(struct syscallrecord *rec)
{
	/* val: write a known value to uaddr so the comparison can succeed */
	static __thread struct timespec timeout_clamp;
	struct timespec *timeout;
	unsigned long flags;
	unsigned int size;
	__u32 *futex_word;

	/* A FUTEX2_NUMA call reads a node id from the word after: no node,
	 * for the mempolicy or the caller's node to pick. */
	futex_word = (__u32 *) get_writable_struct(2 * sizeof(*futex_word));
	if (!futex_word)
		return;
	*futex_word = rand32();
	futex_word[1] = (__u32) FUTEX_NO_NODE;
	rec->a1 = (unsigned long) futex_word;
	rec->a2 = *futex_word;	/* match the value we just wrote */

	/* The mask below is aligned to the drawn size, the rare refused
	 * U8/U16 included. */
	size = ONE_IN(16) ? RAND_ARRAY(futex2_refused_sizes) : FUTEX2_SIZE_U32;

	/* mask: align width to the drawn size */
	switch (size) {
	case FUTEX2_SIZE_U8:
		rec->a3 = 0xff;
		break;
	case FUTEX2_SIZE_U16:
		rec->a3 = 0xffff;
		break;
	default:	/* U32 / U64 */
		rec->a3 = RAND_BOOL() ? 0xffffffff : rand32();
		break;
	}

	/* flags: pair the drawn size with optional PRIVATE/NUMA/MPOL
	 * modifiers. */
	flags = size;
	if (RAND_BOOL())
		flags |= FUTEX2_PRIVATE;
	if (ONE_IN(4))
		flags |= FUTEX2_NUMA;
	if (ONE_IN(8))
		flags |= FUTEX2_MPOL;
	rec->a4 = flags;

	/*
	 * timeout: futex2 treats this as an ABSOLUTE deadline.  Always
	 * supply a clamped, already-expired timespec so the call exercises
	 * the value-match + wait-entry + timeout-setup path and returns
	 * immediately with ETIMEDOUT, instead of either (a) being rejected
	 * with -EINVAL when get_timespec64() reads pool garbage with
	 * tv_nsec >= 1e9, or (b) arming an hrtimer for a far-future
	 * absolute deadline drawn from a residual valid pool timespec and
	 * parking the child past the NEED_ALARM dodge until the parent's
	 * 30s SIGKILL.  It comes from the call's pool, which a compat call,
	 * reading the slot as its low 32 bits, can reach; the per-thread
	 * scratch only when the pool has none to give, so the call never
	 * goes out without the clamp.
	 */
	timeout = get_writable_struct(sizeof(*timeout));
	if (timeout == NULL)
		timeout = &timeout_clamp;
	timeout->tv_sec = 0;
	timeout->tv_nsec = rnd_modulo_u32(1000000);	/* up to 1ms */
	time_struct_for_abi(rec, timeout, 1);
	rec->a5 = (unsigned long) timeout;
}

struct syscallentry syscall_futex_wait = {
	.name = "futex_wait",
	.num_args = 6,
	.argtype = { [0] = ARG_ADDRESS, [4] = ARG_ADDRESS, [5] = ARG_OP },
	.argname = { [0] = "uaddr", [1] = "val", [2] = "mask", [3] = "flags", [4] = "timeout", [5] = "clockid" },
	.arg_params[5].list = ARGLIST(futex_wait_clockids),
	.sanitise = sanitise_futex_wait,
	.rettype = RET_ZERO_SUCCESS,
	/*
	 * SKIP_BLANKET_SCRUB: sanitise_futex_wait() writes a known value
	 * into *uaddr via get_writable_struct() and sets a2 (val) to match,
	 * so the kernel-side futex_wait comparison can succeed and the call
	 * actually enters the wait queue.  get_writable_struct() draws from
	 * the OBJ_MMAP / OBJ_SYSV_SHM pool — the SysV shm half of that pool
	 * is by construction inside range_in_tracked_shared() and routinely
	 * trips range_overlaps_shared() in the blanket walk.  Letting the
	 * blanket relocate a1 to an unrelated writable page drops the
	 * value-match invariant: the kernel reads pool garbage at the new
	 * VA, the comparison fails, the syscall returns -EAGAIN, and the
	 * wait-queue path is never exercised.  The argtype[4] = ARG_ADDRESS
	 * slot (timeout) has the same exposure: the sanitiser-supplied
	 * timespec would be swapped for one whose tv_sec / tv_nsec are
	 * random pool bytes, yielding -EINVAL or near-forever timeouts.
	 */
	.flags = NEED_ALARM | SKIP_BLANKET_SCRUB | REEXEC_SANITISE_OK,
	.group = GROUP_IPC,
};
