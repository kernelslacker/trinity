#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

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

/*
 * The next range of a cpulist ("0", "0-3", "0,2,4", "0-1,3,5-7") at *@p, in
 * [*@lo, *@hi], with *@p moved past it.  False at the end of the list, with
 * *@p left at the NUL, and at a malformed range, with *@p left at it.
 */
static bool next_list_range(const char **p, long *lo, long *hi)
{
	const char *s = *p;
	char *endp;

	while (*s && (isspace((unsigned char)*s) || *s == ','))
		s++;
	*p = s;
	if (!*s)
		return false;

	*lo = strtol(s, &endp, 10);
	if (endp == s)
		return false;
	s = endp;

	if (*s == '-') {
		s++;
		*hi = strtol(s, &endp, 10);
		if (endp == s)
			return false;
		s = endp;
	} else {
		*hi = *lo;
	}

	if (*lo < 0 || *hi < *lo)
		return false;
	*p = s;
	return true;
}

void init_numa_nodes(void)
{
	FILE *f;
	char buf[4096];
	const char *p;
	long lo, hi, n;

	f = fopen("/sys/devices/system/node/online", "re");
	if (f == NULL)
		goto fallback;

	if (fgets(buf, sizeof(buf), f) == NULL) {
		fclose(f);
		goto fallback;
	}
	fclose(f);

	p = buf;
	while (nr_numa_nodes < MAX_NUMA_NODES && next_list_range(&p, &lo, &hi)) {
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
