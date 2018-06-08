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
	.arg1name = "kernel_fd",
	.arg1type = ARG_FD,
	.arg2name = "initrd_fd",
	.arg2type = ARG_FD,
	.arg3name = "cmdline_len",
	.arg3type = ARG_LEN,
	.arg4name = "cmdline_ptr",
	.arg4type = ARG_ADDRESS,
	.arg5name = "flags",
	.arg5type = ARG_LIST,
	.arg5list = ARGLIST(kexec_file_load_flags),
};
