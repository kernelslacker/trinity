/*
 * SYSCALL_DEFINE4(migrate_pages, pid_t, pid, unsigned long, maxnode,
	 const unsigned long __user *, old_nodes,
	 const unsigned long __user *, new_nodes)
 */
#include <stdio.h>
#include <stdlib.h>
#include "random.h"
#include "sanitise.h"

#define MAX_NUMNODES 64

/*
 * Probe the highest NUMA node number from sysfs. Returns 0 on failure
 * (single-node system). Result is cached after the first call.
 */
static unsigned int get_max_node(void)
{
	static unsigned int cached = UINT_MAX;
	FILE *fp;
	char buf[64];
	unsigned int max = 0;

	if (cached != UINT_MAX)
		return cached;

	fp = fopen("/sys/devices/system/node/online", "r");
	if (!fp) {
		cached = 0;
		return 0;
	}

	if (fgets(buf, sizeof(buf), fp)) {
		char *p = buf;
		while (*p) {
			char *end;
			unsigned long v = strtoul(p, &end, 10);
			if (end == p)
				break;
			if (v > max)
				max = (unsigned int) v;
			p = end;
			if (*p == '-' || *p == ',')
				p++;
		}
	}

	fclose(fp);
	cached = max;
	return max;
}

static void fill_nodemask(unsigned long *mask, unsigned int max_node)
{
	unsigned long node_mask;

	mask[0] = 0;
	mask[1] = 0;

	/* Build a bitmask covering all valid nodes 0..max_node. */
	if (max_node >= sizeof(unsigned long) * 8)
		node_mask = ~0UL;
	else
		node_mask = (2UL << max_node) - 1;

	switch (rand() % 3) {
	case 0: /* node 0 only */
		mask[0] = 1;
		break;
	case 1: /* subset of valid nodes */
		mask[0] = node_mask & ((1UL << (1 + (rand() % (max_node + 1)))) - 1);
		break;
	default: /* random bits within valid node range */
		mask[0] = rand32() & node_mask;
		break;
	}
}

static void sanitise_migrate_pages(struct syscallrecord *rec)
{
	unsigned long *old_nodes, *new_nodes;
	unsigned int maxnode, max_node;

	max_node = get_max_node();
	maxnode = 1 + (rand() % (max_node < MAX_NUMNODES - 1 ? max_node + 1 : MAX_NUMNODES));

	old_nodes = (unsigned long *) get_writable_address(sizeof(unsigned long) * 2);
	fill_nodemask(old_nodes, max_node);

	new_nodes = (unsigned long *) get_writable_address(sizeof(unsigned long) * 2);
	fill_nodemask(new_nodes, max_node);

	rec->a2 = maxnode;
	rec->a3 = (unsigned long) old_nodes;
	rec->a4 = (unsigned long) new_nodes;
}

struct syscallentry syscall_migrate_pages = {
	.name = "migrate_pages",
	.num_args = 4,
	.argtype = { [0] = ARG_PID },
	.argname = { [0] = "pid", [1] = "maxnode", [2] = "old_nodes", [3] = "new_nodes" },
	.group = GROUP_VM,
	.sanitise = sanitise_migrate_pages,
};
