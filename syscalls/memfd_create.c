/*
 * SYSCALL_DEFINE2(memfd_create, const char __user *, uname, unsigned int, flag
 */

#include "sanitise.h"
#include "memfd.h"
#include "compat.h"

static unsigned long memfd_create_flags[] = {
	MFD_CLOEXEC, MFD_ALLOW_SEALING, MFD_HUGETLB,
	MFD_NOEXEC_SEAL, MFD_EXEC,
};

struct syscallentry syscall_memfd_create = {
	.name = "memfd_create",
	.num_args = 2,
	.arg1name = "uname",
	.arg1type = ARG_ADDRESS,
	.arg2name = "flag",
	.arg2type = ARG_LIST,
	.arg2list = ARGLIST(memfd_create_flags),
	.rettype = RET_FD,
};
