/*
 * SYSCALL_DEFINE3(getcpu, unsigned __user *, cpup, unsigned __user *, nodep,
                 struct getcpu_cache __user *, unused)
 */
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "arch.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"

static void sanitise_getcpu(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a1, sizeof(unsigned int));
	avoid_shared_buffer(&rec->a2, sizeof(unsigned int));
	avoid_shared_buffer(&rec->a3, page_size);
}

#if defined(SYS_getcpu) || defined(__NR_getcpu)
/*
 * Parse a sysfs cpulist/nodelist (single line, comma-separated ranges
 * like "0-3,7,9-11" or just "0-N") and return the highest id mentioned.
 * Returns -1 on any parse failure or empty input.  Used to discover the
 * possible-cpu / possible-node upper bounds straight from the kernel's
 * own view rather than depending on libnuma being linked in.
 */
static long parse_sysfs_max(const char *path)
{
	FILE *f;
	char buf[1024];
	const char *p;
	long max_id = -1;

	f = fopen(path, "r");
	if (!f)
		return -1;
	if (!fgets(buf, sizeof(buf), f)) {
		fclose(f);
		return -1;
	}
	fclose(f);

	p = buf;
	while (*p) {
		long lo, hi;
		char *end;

		while (*p == ' ' || *p == '\t' || *p == ',' || *p == '\n')
			p++;
		if (!*p)
			break;
		lo = strtol(p, &end, 10);
		if (end == p)
			break;
		p = end;
		hi = lo;
		if (*p == '-') {
			p++;
			hi = strtol(p, &end, 10);
			if (end == p)
				break;
			p = end;
		}
		if (hi > max_id)
			max_id = hi;
	}

	return max_id;
}

/*
 * Walk /sys/devices/system/node/ counting nodeN directories.  Fallback
 * for hosts where /sys/devices/system/node/possible is unreadable;
 * returns the highest N found, or -1 if the directory itself is gone
 * (non-NUMA kernel built without CONFIG_NUMA).
 */
static long count_sysfs_nodes(void)
{
	DIR *d;
	struct dirent *de;
	long max_node = -1;

	d = opendir("/sys/devices/system/node");
	if (!d)
		return -1;
	while ((de = readdir(d)) != NULL) {
		long n;
		char *end;

		if (strncmp(de->d_name, "node", 4) != 0)
			continue;
		n = strtol(de->d_name + 4, &end, 10);
		if (end == de->d_name + 4 || *end != '\0')
			continue;
		if (n > max_node)
			max_node = n;
	}
	closedir(d);

	return max_node;
}

/*
 * Oracle: getcpu(2) writes the calling thread's current CPU and NUMA
 * node into two __user unsigned int slots.  We can't re-call getcpu and
 * compare values — the scheduler is free to migrate the task between
 * the syscall return and the post-hook, so a re-call would alias every
 * legitimate migration as an oracle hit.  Instead, range-check the
 * values the kernel just wrote against the hard upper bounds it
 * publishes through sysfs:
 *
 *   cpu  < sysconf(_SC_NPROCESSORS_CONF)
 *   node <= max id in /sys/devices/system/node/possible
 *          (fallback: highest nodeN dir under /sys/devices/system/node/)
 *
 * Either bound being violated means the kernel wrote a value that
 * cannot correspond to any CPU/node in the boot-time topology — i.e.
 * a real corruption rather than a benign migration race.
 *
 * Both user slots are snapshotted into local vars BEFORE the sysfs
 * reads so a sibling thread that scribbles the buffer between syscall
 * return and the post hook can't smear the comparison.
 *
 * Per-field bumps with no early-return so simultaneous cpu+node
 * corruption surfaces as two anomalies in the same sample.
 *
 * False-positive sources at ONE_IN(100):
 *   - Scheduler migration mid-syscall: the task is migrated between
 *     syscall return and our snapshot, so cpu_user reflects the
 *     pre-migration CPU.  All CPUs in the task's allowed set are in
 *     nproc_configured by construction, so the range check still
 *     passes; this is fine.
 *   - /sys/devices/system/node/possible read failure (extremely rare):
 *     skip the node check that sample, do not bump anomalies.
 *   - CPU/node hotplug between samples: possible/online sets shift.
 *     Range check uses possible (boot-stable on Meta hosts), so this
 *     only matters on long-uptime VMs that actually unplug CPUs.
 *
 * Corruption shapes this catches:
 *   - copy_to_user mis-write past or before the cpup/nodep slot
 *     (kernel writes to the wrong address).
 *   - 32-on-64 compat path truncation of unsigned int.
 *   - Stale percpu lookup after cpu offline (kernel returns an
 *     offlined-and-removed cpu number).
 *   - Sibling-thread scribble of the user buffer between syscall
 *     return and our post-hook read — caught because the snapshot
 *     happens before the cross-check.
 *
 * Wrapped in #if defined(SYS_getcpu) || defined(__NR_getcpu) for
 * consistency with the rest of the oracle batch; getcpu has been in
 * Linux since 2.6.20 but minimal libcs may omit the macro.
 */
static void post_getcpu(struct syscallrecord *rec)
{
	unsigned int cpu_user, node_user;
	long nproc_configured;
	long max_node;

	if (!ONE_IN(100))
		return;

	if (rec->retval != 0)
		return;
	if (rec->a1 == 0 || rec->a2 == 0)
		return;

	/*
	 * Snapshot both user slots before any cross-check so a sibling
	 * thread can't scribble the buffer between the snapshot and the
	 * sysfs comparison.
	 */
	memcpy(&cpu_user, (const void *)(unsigned long)rec->a1,
	       sizeof(cpu_user));
	memcpy(&node_user, (const void *)(unsigned long)rec->a2,
	       sizeof(node_user));

	nproc_configured = sysconf(_SC_NPROCESSORS_CONF);
	if (nproc_configured > 0 &&
	    cpu_user >= (unsigned int)nproc_configured) {
		output(0, "getcpu oracle: cpu=%u >= _SC_NPROCESSORS_CONF=%ld\n",
		       cpu_user, nproc_configured);
		__atomic_add_fetch(&shm->stats.getcpu_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}

	max_node = parse_sysfs_max("/sys/devices/system/node/possible");
	if (max_node < 0)
		max_node = count_sysfs_nodes();
	if (max_node >= 0 && node_user > (unsigned int)max_node) {
		output(0, "getcpu oracle: node=%u > sysfs max node=%ld\n",
		       node_user, max_node);
		__atomic_add_fetch(&shm->stats.getcpu_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
}
#endif

struct syscallentry syscall_getcpu = {
	.name = "getcpu",
	.num_args = 3,
	.argtype = { [0] = ARG_ADDRESS, [1] = ARG_ADDRESS, [2] = ARG_ADDRESS },
	.argname = { [0] = "cpup", [1] = "nodep", [2] = "unused" },
	.sanitise = sanitise_getcpu,
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_PROCESS,
#if defined(SYS_getcpu) || defined(__NR_getcpu)
	.post = post_getcpu,
#endif
};
