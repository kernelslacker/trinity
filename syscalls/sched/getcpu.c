/*
 * SYSCALL_DEFINE3(getcpu, unsigned __user *, cpup, unsigned __user *, nodep,
		 struct getcpu_cache __user *, unused)
 */
#include <dirent.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include "arch.h"
#include "deferred-free.h"
#include "output-poison.h"
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
 * Snapshot of the two getcpu input args plus per-slot poison seeds read
 * by the post oracle, captured at sanitise time and consumed by the post
 * handler.  Lives in rec->post_state, a slot the syscall ABI does not
 * expose, so a sibling syscall scribbling rec->aN between the syscall
 * returning and the post handler running cannot redirect the oracle at
 * a foreign cpup / nodep user buffer or smear a poison check against a
 * heap page that happens to carry a residual pattern from an earlier
 * call.  rec->a3 (the deprecated tcache buffer) is not read by the post
 * handler and is therefore not snapshotted.  A poison_seed of 0 means
 * the sanitise-time writability check refused to stamp poison for that
 * slot (unmapped or NULL) and the post handler must no-op that arm.
 */
#define GETCPU_POST_STATE_MAGIC	0x47435055UL	/* "GCPU" */
struct getcpu_post_state {
	unsigned long magic;
	unsigned long cpup;
	unsigned long nodep;
	uint64_t poison_seed[2];
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

	avoid_shared_buffer_out(&rec->a1, sizeof(unsigned int));
	avoid_shared_buffer_out(&rec->a2, sizeof(unsigned int));
	avoid_shared_buffer_out(&rec->a3, page_size);

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
	 * post_state_install pairs the rec->post_state assign with the
	 * ownership-table register so the observable window between the
	 * two is closed; post_getcpu() will then gate the snap through
	 * post_state_claim_owned() and prove ownership before dereferencing
	 * any field.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = GETCPU_POST_STATE_MAGIC;
	snap->cpup  = rec->a1;
	snap->nodep = rec->a2;
	snap->poison_seed[0] = 0;
	snap->poison_seed[1] = 0;

	/*
	 * Stamp a per-slot poison pattern into each of the cpup / nodep
	 * OUT-buffers the kernel is about to fill.  The post handler feeds
	 * each seed back into check_output_struct(); a byte-identical
	 * poison after a rec->retval == 0 return means the kernel wrote
	 * zero bytes into that unsigned int and left our stamp intact --
	 * getcpu(2) is contracted to overwrite both slots on success when
	 * they are non-NULL.  Each slot is independently nullable, so
	 * skip stamping when the arg draw was 0.  Gate each stamp on
	 * range_readable_user() so a writable-pool draw that
	 * avoid_shared_buffer_out() moved to an address no longer provably
	 * mapped (e.g. sibling munmap between allocation and now) does not
	 * SIGSEGV the sanitiser inside poison_output_struct's byte-walk.
	 * On skip the seed stays 0 and the post handler no-ops that arm
	 * while the existing sysfs range oracle keeps running.  Done after
	 * avoid_shared_buffer_out() so the poison lands on the final
	 * buffer the kernel will see.
	 */
	{
		void *cpup_buf  = (void *)(unsigned long) rec->a1;
		void *nodep_buf = (void *)(unsigned long) rec->a2;

		if (rec->a1 != 0 &&
		    range_readable_user(cpup_buf, sizeof(unsigned int)))
			snap->poison_seed[0] =
				poison_output_struct(cpup_buf,
						     sizeof(unsigned int),
						     0);
		if (rec->a2 != 0 &&
		    range_readable_user(nodep_buf, sizeof(unsigned int)))
			snap->poison_seed[1] =
				poison_output_struct(nodep_buf,
						     sizeof(unsigned int),
						     0);
	}

	post_state_install(rec, snap);
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
	char buf[1024];
	const char *p;
	ssize_t n;
	int fd;
	long max_id = -1;

	/* Raw open/read instead of fopen/fgets/fclose: this is reached from
	 * post_getcpu, which runs in the syscall hot path under fuzz, and
	 * stdio's per-call malloc of FILE struct + IO buffer is heap traffic
	 * we don't need.  The sysfs cpulist/nodelist payload is a single short
	 * line (typically <100 bytes) so one read suffices. */
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return -1;
	buf[n] = '\0';

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
 *     Range check uses possible (boot-stable on typical hosts), so this
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
	struct getcpu_post_state *snap;
	unsigned int cpu_user, node_user;
	long nproc_configured;
	long max_node;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, GETCPU_POST_STATE_MAGIC, __func__);
	if (snap == NULL)
		return;

	if (rec->retval != 0)
		goto out_free;

	/*
	 * Untouched-buffer poison check: sanitise stamped a per-slot
	 * poison pattern into each non-NULL cpup / nodep OUT-buffer.  A
	 * byte-identical match on a slot after a rec->retval == 0 return
	 * means the kernel wrote zero bytes into that unsigned int and
	 * left our stamp intact -- a short-copy or partial copy_to_user()
	 * the sysfs range arm below would not detect at all because a
	 * residual pre-syscall value that already happened to fall inside
	 * the possible-cpu / possible-node bounds would pass the range
	 * check.  Cheap (two 4-byte compares, no re-issue), so runs on
	 * every success sample; the sysfs range arm stays rate-limited
	 * behind ONE_IN(100).  Snapshot each slot into the local cpu_user
	 * / node_user before the compare so a sibling munmap of the
	 * writable-pool page between the deref and here cannot fault
	 * inside a second read.  A seed of 0 means sanitise skipped that
	 * slot (unmapped or NULL) -- skip the check too so "we could not
	 * poison" is not confused with "kernel did not write".  Counts
	 * against the shared post_handler_untouched_out_buf slot.
	 */
	if (snap->cpup != 0 && snap->poison_seed[0] != 0 &&
	    post_snapshot_or_skip(&cpu_user,
				  (const void *) snap->cpup,
				  sizeof(cpu_user)) &&
	    check_output_struct(&cpu_user, sizeof(cpu_user),
				snap->poison_seed[0]))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);
	if (snap->nodep != 0 && snap->poison_seed[1] != 0 &&
	    post_snapshot_or_skip(&node_user,
				  (const void *) snap->nodep,
				  sizeof(node_user)) &&
	    check_output_struct(&node_user, sizeof(node_user),
				snap->poison_seed[1]))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

	if (!ONE_IN(100))
		goto out_free;

	if (snap->cpup == 0 || snap->nodep == 0)
		goto out_free;

	/*
	 * Snapshot both user slots before any cross-check so a sibling
	 * thread can't scribble the buffer between the snapshot and the
	 * sysfs comparison.
	 */
	if (!post_snapshot_or_skip(&cpu_user,
				   (const void *) snap->cpup,
				   sizeof(cpu_user)))
		goto out_free;
	if (!post_snapshot_or_skip(&node_user,
				   (const void *) snap->nodep,
				   sizeof(node_user)))
		goto out_free;

	nproc_configured = sysconf(_SC_NPROCESSORS_CONF);
	if (nproc_configured > 0 &&
	    cpu_user >= (unsigned int)nproc_configured) {
		output(0, "getcpu oracle: cpu=%u >= _SC_NPROCESSORS_CONF=%ld\n",
		       cpu_user, nproc_configured);
		__atomic_add_fetch(&shm->stats.oracle.getcpu_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}

	max_node = parse_sysfs_max("/sys/devices/system/node/possible");
	if (max_node < 0)
		max_node = count_sysfs_nodes();
	if (max_node >= 0 && node_user > (unsigned int)max_node) {
		output(0, "getcpu oracle: node=%u > sysfs max node=%ld\n",
		       node_user, max_node);
		__atomic_add_fetch(&shm->stats.oracle.getcpu_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}

out_free:
	post_state_release(rec, snap);
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
	.flags = REEXEC_SANITISE_OK,
#ifdef HAVE_SYS_GETCPU
	.post = post_getcpu,
#endif
};
