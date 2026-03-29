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

static unsigned long rseq_flags[] = {
	RSEQ_FLAG_UNREGISTER_COMPAT,
};

static void sanitise_rseq(struct syscallrecord *rec)
{
	struct rseq *rs;

	/*
	 * struct rseq must be aligned to 32 bytes.
	 * Allocate extra to ensure alignment.
	 */
	rs = (struct rseq *) get_writable_address(sizeof(*rs) + 32);
	rs = (struct rseq *)(((unsigned long)rs + 31) & ~31UL);
	memset(rs, 0, sizeof(*rs));

	rec->a1 = (unsigned long) rs;
	rec->a2 = sizeof(*rs);

	/* Use a fixed signature value. The kernel checks this at CS abort. */
	rec->a4 = 0x53053053;
}

struct syscallentry syscall_rseq = {
	.name = "rseq",
	.num_args = 4,
	.argtype = { [2] = ARG_LIST },
	.argname = { [0] = "rseq", [1] = "rseq_len", [2] = "flags", [3] = "sig" },
	.arg_params[2].list = ARGLIST(rseq_flags),
	.sanitise = sanitise_rseq,
	.group = GROUP_PROCESS,
};
