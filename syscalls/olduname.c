/*
 * SYSCALL_DEFINE1(uname, struct old_utsname __user *, name)
 */
#include "arch.h"
#include "sanitise.h"

static void sanitise_olduname(struct syscallrecord *rec)
{
	/*
	 * struct old_utsname / oldold_utsname have no portable userspace
	 * declaration; one page is a generous overestimate of the kernel's
	 * writeback window for any of the legacy uname variants.
	 */
	avoid_shared_buffer(&rec->a1, page_size);
}

struct syscallentry syscall_olduname = {
	.name = "olduname",
	.num_args = 1,
	.argtype = { [0] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "name" },
	.sanitise = sanitise_olduname,
	.group = GROUP_PROCESS,
};
