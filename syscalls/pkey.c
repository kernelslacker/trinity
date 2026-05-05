/*
 * SYSCALL_DEFINE2(pkey_alloc, unsigned long, flags, unsigned long, init_val)
 */

#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

#define PKEY_DISABLE_ACCESS     0x1
#define PKEY_DISABLE_WRITE      0x2
/* PKEY_UNRESTRICTED added in Linux v6.15 (asm-generic/mman-common.h). */
#ifndef PKEY_UNRESTRICTED
#define PKEY_UNRESTRICTED       0x0
#endif

static unsigned long pkey_alloc_initvals[] = {
	PKEY_UNRESTRICTED,
	PKEY_DISABLE_ACCESS,
	PKEY_DISABLE_WRITE,
};

static void sanitise_pkey_alloc(struct syscallrecord *rec)
{
	// no flags defined right now.
	rec->a1 = 0;
}

/*
 * sys_pkey_alloc returns a pkey id allocated from the per-mm pkey
 * bitmap. On x86 the hardware PKRU register has 16 slots, so
 * arch_max_pkey() returns 16 and mm_pkey_alloc() can only hand back
 * an id in [0, 15]. Failure paths return negative errno (-EINVAL for
 * unsupported flags or init_val bits, -ENOSPC when the bitmap is
 * exhausted, -ENOTSUP under arch_set_user_pkey_access()), all of
 * which the syscall return path collapses to retval=-1UL with errno
 * set. A retval outside [0, 15] U {-1UL} is therefore a structural
 * ABI violation: a sign-extension at the syscall boundary, a
 * 32-on-64 compat tear, or a sibling thread scribbling the return
 * slot between syscall return and post-hook entry.
 */
static void post_pkey_alloc(struct syscallrecord *rec)
{
	long ret = (long) rec->retval;

	if ((unsigned long) rec->retval == -1UL)
		return;
	if (ret < 0 || ret > 15) {
		outputerr("post_pkey_alloc: rejected retval 0x%lx outside [0, 15] (and not -1)\n",
		          (unsigned long) rec->retval);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}
}

struct syscallentry syscall_pkey_alloc = {
	.name = "pkey_alloc",
	.num_args = 2,
	.argtype = { [1] = ARG_LIST },
	.argname = { [0] = "flags", [1] = "init_val" },
	.arg_params[1].list = ARGLIST(pkey_alloc_initvals),
	.sanitise = sanitise_pkey_alloc,
	.post = post_pkey_alloc,
	.group = GROUP_VM,
};

struct syscallentry syscall_pkey_free = {
	.name = "pkey_free",
	.num_args = 1,
	.argtype = { [0] = ARG_RANGE },
	.argname = { [0] = "key" },
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = 15,
	.group = GROUP_VM,
};
