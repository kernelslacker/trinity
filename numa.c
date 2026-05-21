#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "numa.h"
#include "random.h"
#include "rnd.h"
#include "trinity.h"

/* Linux caps NUMA nodes at MAX_NUMNODES (1024 on x86_64 with current
 * configs).  The pool is bounded by what /sys exposes, so a small
 * fixed array is plenty -- a sparse system with 8 nodes still parses
 * cleanly. */
#define MAX_NUMA_NODES	1024

static int numa_node_pool[MAX_NUMA_NODES];
static unsigned int nr_numa_nodes;

void init_numa_nodes(void)
{
	FILE *f;
	char buf[4096];
	char *p;

	f = fopen("/sys/devices/system/node/online", "r");
	if (f == NULL)
		goto fallback;

	if (fgets(buf, sizeof(buf), f) == NULL) {
		fclose(f);
		goto fallback;
	}
	fclose(f);

	/* Parse cpulist syntax: "0", "0-3", "0,2,4", "0-1,3,5-7". */
	p = buf;
	while (*p && nr_numa_nodes < MAX_NUMA_NODES) {
		char *endp;
		long lo, hi;
		long n;

		while (*p && (isspace((unsigned char)*p) || *p == ','))
			p++;
		if (!*p)
			break;

		lo = strtol(p, &endp, 10);
		if (endp == p)
			break;
		p = endp;

		if (*p == '-') {
			p++;
			hi = strtol(p, &endp, 10);
			if (endp == p)
				break;
			p = endp;
		} else {
			hi = lo;
		}

		if (lo < 0 || hi < lo)
			break;

		for (n = lo; n <= hi && nr_numa_nodes < MAX_NUMA_NODES; n++)
			numa_node_pool[nr_numa_nodes++] = (int) n;
	}

	if (nr_numa_nodes == 0)
		goto fallback;

	return;

fallback:
	numa_node_pool[0] = 0;
	nr_numa_nodes = 1;
}

int random_numa_node(void)
{
	if (nr_numa_nodes == 0)
		return 0;
	return numa_node_pool[rnd_modulo_u32(nr_numa_nodes)];
}
