/*
 * SYSCALL_DEFINE3(mseal, unsigned long, start, size_t, len, unsigned long, flags)
 */
#include "random.h"
#include "rnd.h"
#include "sanitise.h"

static void sanitise_mseal(struct syscallrecord *rec)
{
	if (range_overlaps_shared(rec->a1, rec->a2)) {
		rec->a1 = 0;
		rec->a2 = 0;
	}

	/*
	 * Mostly send 0 so we exercise the success path; occasionally
	 * send something the kernel must reject.  Bias toward single-bit
	 * flips over fully-random because every legitimate flag gain is
	 * one new bit, and a single-bit walk catches `flags & ~ALLOWED_MASK`
	 * regressions sooner than a uniform random 64-bit value.
	 */
	if (ONE_IN(16)) {
		rec->a3 = 1UL << (rnd_modulo_u32(64));
	} else if (ONE_IN(64)) {
		rec->a3 = rand64();
	} else {
		rec->a3 = 0;	/* no flags defined yet, must be zero */
	}
}

struct syscallentry syscall_mseal = {
	.name = "mseal",
	.num_args = 3,
	.argtype = { [0] = ARG_MMAP, [1] = ARG_LEN },
	.argname = { [0] = "start", [1] = "len", [2] = "flags" },
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VM,
	.sanitise = sanitise_mseal,
};
