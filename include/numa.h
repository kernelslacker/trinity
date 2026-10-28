#pragma once

/*
 * NUMA node id pool for ARG_NUMA_NODE.  Populated once at startup from
 * /sys/devices/system/node/online; falls back to {0} when the file is
 * absent (uniprocessor / NUMA disabled).
 */
void init_numa_nodes(void);
int random_numa_node(void);

/*
 * The ids a cpulist ("0-3,8-11") names, 8 there; 0 for an empty or a
 * malformed list.
 */
unsigned int cpulist_weight(const char *list);

/*
 * num_possible_cpus() as the kernel counts it, the cpus that
 * /sys/devices/system/cpu/possible lists: a per-cpu bpf map moves a row
 * of one value per possible cpu.  sysconf(_SC_NPROCESSORS_CONF) is only
 * the fallback, since glibc may count the cpuN directories instead, and a
 * possible cpu that is not present has none.
 */
unsigned int possible_cpus(void);
