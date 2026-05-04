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
#include "deferred-free.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#if defined(SYS_getcpu) || defined(__NR_getcpu)
#define HAVE_SYS_GETCPU 1
#endif

#ifdef HAVE_SYS_GETCPU
/*
 * Snapshot of the two getcpu input args read by the post oracle, captured
 * at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->aN between the syscall returning and the post
 * handler running cannot redirect the oracle at a foreign cpup / nodep
 * user buffer.  rec->a3 (the deprecated tcache buffer) is not read by the
 * post handler and is therefore not snapshotted.
 */
struct getcpu_post_state {
	unsigned long cpup;
	unsigned long nodep;
};
#endif

static void sanitise_getcpu(struct syscallrecord *rec)
{
#ifdef HAVE_SYS_GETCPU
	struct getcpu_post_state *snap;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;
#endif

	avoid_shared_buffer(&rec->a1, sizeof(unsigned int));
	avoid_shared_buffer(&rec->a2, sizeof(unsigned int));
	avoid_shared_buffer(&rec->a3, page_size);

#ifdef HAVE_SYS_GETCPU
	/*
	 * Snapshot the two input args read by the post oracle.  Without
	 * this the post handler reads rec->a1/a2 at post-time, when a
	 * sibling syscall may have scribbled the slots:
	 * looks_like_corrupted_ptr() cannot tell a real-but-wrong heap
	 * address from the original cpup / nodep user buffer pointers, so
	 * the source memcpy would touch a foreign allocation that the guard
	 * never inspected.  post_state is private to the post handler.
	 * Gated on HAVE_SYS_GETCPU to mirror the .post registration -- on
	 * systems without SYS_getcpu the post handler is not registered and
	 * a snapshot only the post handler can free would leak.
	 */
	snap = zmalloc(sizeof(*snap));
	snap->cpup  = rec->a1;
	snap->nodep = rec->a2;
	rec->post_state = (unsigned long) snap;
#endif
}

#ifdef HAVE_SYS_GETCPU
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
 * Wrapped in HAVE_SYS_GETCPU (defined when SYS_getcpu / __NR_getcpu is
 * visible) for consistency with the rest of the oracle batch; getcpu has
 * been in Linux since 2.6.20 but minimal libcs may omit the macro.
 */
static void post_getcpu(struct syscallrecord *rec)
{
	struct getcpu_post_state *snap =
		(struct getcpu_post_state *) rec->post_state;
	unsigned int cpu_user, node_user;
	long nproc_configured;
	long max_node;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_getcpu: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  snap);
		rec->post_state = 0;
		return;
	}

	if (!ONE_IN(100))
		goto out_free;

	if (rec->retval != 0)
		goto out_free;
	if (snap->cpup == 0 || snap->nodep == 0)
		goto out_free;

	/*
	 * Defense in depth: even with the post_state snapshot, a wholesale
	 * stomp could rewrite the snapshot's inner pointer fields.  Reject
	 * pid-scribbled cpup/nodep before deref.
	 */
	if (looks_like_corrupted_ptr(rec, (void *) snap->cpup) ||
	    looks_like_corrupted_ptr(rec, (void *) snap->nodep)) {
		outputerr("post_getcpu: rejected suspicious cpup=%p nodep=%p (post_state-scribbled?)\n",
			  (void *) snap->cpup, (void *) snap->nodep);
		goto out_free;
	}

	/*
	 * Snapshot both user slots before any cross-check so a sibling
	 * thread can't scribble the buffer between the snapshot and the
	 * sysfs comparison.
	 */
	memcpy(&cpu_user, (const void *) snap->cpup, sizeof(cpu_user));
	memcpy(&node_user, (const void *) snap->nodep, sizeof(node_user));

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

out_free:
	deferred_freeptr(&rec->post_state);
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
#ifdef HAVE_SYS_GETCPU
	.post = post_getcpu,
#endif
};
