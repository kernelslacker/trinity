/*
 * SYSCALL_DEFINE4(migrate_pages, pid_t, pid, unsigned long, maxnode,
	 const unsigned long __user *, old_nodes,
	 const unsigned long __user *, new_nodes)
 */
#include "random.h"
#include "sanitise.h"

#define MAX_NUMNODES 64

static void fill_nodemask(unsigned long *mask)
{
	mask[0] = 0;
	mask[1] = 0;

	switch (rand() % 3) {
	case 0: /* node 0 only */
		mask[0] = 1;
		break;
	case 1: /* first few nodes */
		mask[0] = (1UL << (1 + (rand() % 4))) - 1;
		break;
	default: /* random bits */
		mask[0] = rand32();
		break;
	}
}

static void sanitise_migrate_pages(struct syscallrecord *rec)
{
	unsigned long *old_nodes, *new_nodes;
	unsigned int maxnode;

	maxnode = 1 + (rand() % MAX_NUMNODES);

	old_nodes = (unsigned long *) get_writable_address(sizeof(unsigned long) * 2);
	fill_nodemask(old_nodes);

	new_nodes = (unsigned long *) get_writable_address(sizeof(unsigned long) * 2);
	fill_nodemask(new_nodes);

	rec->a2 = maxnode;
	rec->a3 = (unsigned long) old_nodes;
	rec->a4 = (unsigned long) new_nodes;
}

struct syscallentry syscall_migrate_pages = {
	.name = "migrate_pages",
	.num_args = 4,
	.arg1name = "pid",
	.arg1type = ARG_PID,
	.arg2name = "maxnode",
	.arg3name = "old_nodes",
	.arg4name = "new_nodes",
	.group = GROUP_VM,
	.sanitise = sanitise_migrate_pages,
};
