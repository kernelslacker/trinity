/*
 * SYSCALL_DEFINE4(rseq, struct rseq __user *, rseq, u32, rseq_len,
 *                 int, flags, u32, sig)
 */
#include <linux/rseq.h>
#include <string.h>
#include "random.h"
#include "sanitise.h"

enum rseq_flags_compat {
	RSEQ_FLAG_UNREGISTER_COMPAT = (1 << 0),
};

#ifndef RSEQ_FLAG_SLICE_EXT_DEFAULT_ON
#define RSEQ_FLAG_SLICE_EXT_DEFAULT_ON (1 << 1)
#endif

static unsigned long rseq_flags[] = {
	RSEQ_FLAG_UNREGISTER_COMPAT,
	RSEQ_FLAG_SLICE_EXT_DEFAULT_ON,
};

static void sanitise_rseq(struct syscallrecord *rec)
{
	struct rseq *rs;

	/*
	 * struct rseq must be aligned to 32 bytes.
	 * Allocate extra to ensure alignment.
	 */
	rs = (struct rseq *) get_writable_address(sizeof(*rs) + 64);
	if (rs == NULL)
		return;
	rs = (struct rseq *)(((unsigned long)rs + 31) & ~31UL);
	memset(rs, 0, sizeof(*rs) + 32);

	rec->a1 = (unsigned long) rs;
	avoid_shared_buffer_inout(&rec->a1, sizeof(struct rseq));

	/*
	 * Exercise the kernel's rseq_len validation buckets: zero (reject),
	 * undersized (reject as below the minimum ABI size), current ABI
	 * (success path), and oversized (future-compat path that requires
	 * the trailing bytes to be zero).  Bias heavily toward the current
	 * size so most iterations still reach the registration logic.
	 */
	if (ONE_IN(16))
		rec->a2 = 0;
	else if (ONE_IN(16))
		rec->a2 = sizeof(*rs) / 2;
	else if (ONE_IN(16))
		rec->a2 = sizeof(*rs) + 32;
	else
		rec->a2 = sizeof(*rs);

	/* Use a fixed signature value. The kernel checks this at CS abort. */
	rec->a4 = 0x53053053;
}

struct syscallentry syscall_rseq = {
	.name = "rseq",
	.num_args = 4,
	.argtype = { [1] = ARG_LEN, [2] = ARG_LIST },
	.argname = { [0] = "rseq", [1] = "rseq_len", [2] = "flags", [3] = "sig" },
	.arg_params[2].list = ARGLIST(rseq_flags),
	.sanitise = sanitise_rseq,
	.group = GROUP_PROCESS,
	.rettype = RET_ZERO_SUCCESS,
};
