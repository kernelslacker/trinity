/*
 * SYSCALL_DEFINE5(riscv_hwprobe, struct riscv_hwprobe __user *, pairs,
 *		size_t, pair_count, size_t, cpusetsize,
 *		unsigned long __user *, cpus, unsigned int, flags)
 *
 * RISCV_HWPROBE_WHICH_CPUS makes cpus an in/out mask and the pairs
 * keys/values filters; otherwise cpusetsize 0 requires cpus == NULL.
 */
#if defined(__riscv) && __riscv_xlen == 64

#include <asm/hwprobe.h>
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "utils.h"

#ifndef RISCV_HWPROBE_WHICH_CPUS
#define RISCV_HWPROBE_WHICH_CPUS	(1 << 0)
#endif

#define HWPROBE_MAX_PAIRS	16
#define HWPROBE_MAX_KEY		16

static unsigned long hwprobe_flags[] = {
	0, RISCV_HWPROBE_WHICH_CPUS,
};

static void sanitise_riscv_hwprobe(struct syscallrecord *rec)
{
	struct riscv_hwprobe *pairs;
	unsigned int nr, i;

	nr = 1 + rnd_modulo_u32(HWPROBE_MAX_PAIRS);
	pairs = get_writable_struct(nr * sizeof(*pairs));
	if (pairs == NULL) {
		rec->a2 = 0;
		return;
	}

	for (i = 0; i < nr; i++) {
		/* mostly defined keys, some past the end */
		pairs[i].key = ONE_IN(8) ? (int64_t)rnd_u64() :
					   (int64_t)rnd_modulo_u32(HWPROBE_MAX_KEY + 2);
		/* only read as a filter under WHICH_CPUS */
		pairs[i].value = ONE_IN(2) ? 0 : rnd_u64();
	}

	rec->a1 = (unsigned long) pairs;
	rec->a2 = nr;

	if (rec->a3 == 0 && rec->a5 == 0)
		rec->a4 = 0;
}

struct syscallentry syscall_riscv_hwprobe = {
	.name = "riscv_hwprobe",
	.num_args = 5,
	.argtype = { [0] = ARG_NON_NULL_ADDRESS, [1] = ARG_LEN, [2] = ARG_LEN,
		     [3] = ARG_CPUMASK, [4] = ARG_LIST },
	.argname = { [0] = "pairs", [1] = "pair_count", [2] = "cpusetsize",
		     [3] = "cpus", [4] = "flags" },
	.arg_params[4].list = ARGLIST(hwprobe_flags),
	.sanitise = sanitise_riscv_hwprobe,
	.group = GROUP_PROCESS,
	.rettype = RET_ZERO_SUCCESS,
	.flags = REEXEC_SANITISE_OK,
};

#endif
