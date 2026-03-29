/* (x86-64 only)
 *  long sys_arch_prctl(int code, unsigned long addr)
 *
 * On success, arch_prctl() returns 0
 * On error, -1 is returned, and errno is set to indicate the error.
 */

#if defined(__i386__) || defined (__x86_64__)

#include "sanitise.h"
#include <asm/prctl.h>
#include <sys/prctl.h>

static unsigned long arch_prctl_flags[] = {
	ARCH_SET_FS, ARCH_GET_FS, ARCH_SET_GS, ARCH_GET_GS
};

struct syscallentry syscall_arch_prctl = {
	.name = "arch_prctl",
	.flags = AVOID_SYSCALL,
	.num_args = 2,
	.argtype = { [0] = ARG_OP, [1] = ARG_ADDRESS },
	.argname = { [0] = "code", [1] = "addr" },
	.arg_params[0].list = ARGLIST(arch_prctl_flags),
	.rettype = RET_BORING,
};
#endif
