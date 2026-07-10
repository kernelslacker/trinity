/*
 * SYSCALL_DEFINE4(migrate_pages, pid_t, pid, unsigned long, maxnode,
	 const unsigned long __user *, old_nodes,
	 const unsigned long __user *, new_nodes)
 */
#include "nodemask.h"
#include "rnd.h"
#include "sanitise.h"

static void sanitise_migrate_pages(struct syscallrecord *rec)
{
	/* maxnode is the bit count the kernel uses to size its
	 * copy_from_user(ceil(maxnode/8)) of each nodemask.  Cap at
	 * NODEMASK_POOL_BITS so the copy stays inside the ARG_NODEMASK
	 * pool buffer the foundation generator hands to a3/a4. */
	rec->a2 = 1 + rnd_modulo_u32(NODEMASK_POOL_BITS);
}

struct syscallentry syscall_migrate_pages = {
	.name = "migrate_pages",
	.num_args = 4,
	.argtype = { [0] = ARG_PID, [1] = ARG_LEN, [2] = ARG_NODEMASK, [3] = ARG_NODEMASK },
	.argname = { [0] = "pid", [1] = "maxnode", [2] = "old_nodes", [3] = "new_nodes" },
	.group = GROUP_VM,
	.sanitise = sanitise_migrate_pages,
	.rettype = RET_BORING,
};
