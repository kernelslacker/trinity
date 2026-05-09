#pragma once

/*
 * NUMA node id pool for ARG_NUMA_NODE.  Populated once at startup from
 * /sys/devices/system/node/online; falls back to {0} when the file is
 * absent (uniprocessor / NUMA disabled).
 */
void init_numa_nodes(void);
int random_numa_node(void);
