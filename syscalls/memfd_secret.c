/*
 * SYSCALL_DEFINE1(memfd_secret, unsigned int, flags)
 */

#include "sanitise.h"
#include "memfd.h"
#include "compat.h"

static unsigned long memfd_secret_flags[] = {
	0,
};

struct syscallentry syscall_memfd_secret = {
	.name = "memfd_secret",
	.num_args = 1,
	.arg1name = "flag",
	.arg1type = ARG_LIST,
	.arg1list = ARGLIST(memfd_secret_flags),
};
