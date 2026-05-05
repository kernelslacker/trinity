/*
 * SYSCALL_DEFINE5(kexec_file_load, int, kernel_fd, int, initrd_fd,
 * unsigned long, cmdline_len, const char __user *, cmdline_ptr,
 * unsigned long, flags)
 */

#define KEXEC_FILE_UNLOAD       0x00000001
#define KEXEC_FILE_ON_CRASH     0x00000002
#define KEXEC_FILE_NO_INITRAMFS 0x00000004

#include "sanitise.h"

static unsigned long kexec_file_load_flags[] = {
	KEXEC_FILE_UNLOAD, KEXEC_FILE_ON_CRASH, KEXEC_FILE_NO_INITRAMFS,
};

struct syscallentry syscall_kexec_file_load = {
	.name = "kexec_file_load",
	.num_args = 5,
	.argtype = { [0] = ARG_FD, [1] = ARG_FD, [2] = ARG_LEN, [3] = ARG_ADDRESS, [4] = ARG_LIST },
	.argname = { [0] = "kernel_fd", [1] = "initrd_fd", [2] = "cmdline_len", [3] = "cmdline_ptr", [4] = "flags" },
	.arg_params[4].list = ARGLIST(kexec_file_load_flags),
	.group = GROUP_PROCESS,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEEDS_ROOT,
};
