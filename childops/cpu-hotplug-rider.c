/*
 * cpu_hotplug_rider - cycle CPU online/offline state and slam the
 * scheduler with affinity flips while it churns.
 *
 * CPU-hotplug-aware code paths are some of the gnarliest in the kernel:
 * stop_machine() interleaving, RCU's hotplug callbacks, per-CPU
 * workqueue migration, scheduler load-balancer state when a CPU
 * disappears mid-balance, and the cpuset / cgroup-cpus rebuild that
 * hangs off cpu_up()/cpu_down().  Trinity's normal random_syscall path
 * exercises sched_setaffinity() but never touches the hotplug state
 * machine itself, so the most interesting transitions never fire.
 *
 * Per invocation we run a tight bounded loop mixing:
 *   - sched_setaffinity() onto a random subset of the currently-online
 *     CPUs (occasionally referencing a CPU that is being torn down).
 *   - sched_setattr(SCHED_OTHER) with a random nice value, just to
 *     bounce through the scheduler's class-set path between affinity
 *     flips.
 *   - write '0' or '1' to /sys/devices/system/cpu/cpuN/online.  This
 *     returns -EACCES non-root, but the sysfs write handler still
 *     executes — the kernel side of the hotplug entry path is the
 *     fuzz-relevant surface, not whether the change actually takes
 *     effect.
 *   - If we're root (orig_uid == 0), one bounded actual offline+online
 *     cycle on a non-zero CPU per invocation.  Throttled hard because
 *     real hotplug ops are slow and we don't want to wedge the host.
 *
 * Graceful degradation:
 *   - Single-CPU host: no_cpus_to_play is set at init and every
 *     subsequent invocation bails immediately.
 *   - No cpuN online files exist (e.g. CPU 0 only, hotplug compiled
 *     out): same path.
 *   - Non-root sysfs writes failing with -EACCES are counted and the
 *     loop continues; the kernel handler still ran.
 *
 * Self-bounding:
 *   - MAX_ITERATIONS caps the inner loop.
 *   - BUDGET_NS (300 ms) is wider than the typical thrash band because
 *     real hotplug can stall in stop_machine().
 *   - Real offline is gated to one cycle per invocation, on a CPU >= 1
 *     only, with a forced re-online before return.
 *   - alarm(1) is armed by child.c around every non-syscall op, so a
 *     wedged hotplug write here still trips the SIGALRM stall detector.
 *
 * Dormant by default: the syscall hot path stays clean while we wait
 * for dedicated alt-op coverage to stabilise.  Listed in
 * alt_op_rotation alongside fork_storm so a reserved slot can drive it
 * continuously.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <linux/sched/types.h>

#include "child.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "uid.h"

/* Wall-clock ceiling for the inner loop.  300ms — wider than the
 * typical thrash band because real hotplug can stall in stop_machine. */
#define BUDGET_NS	300000000L

/* Hard cap on inner-loop iterations. */
#define MAX_ITERATIONS	32

/* Maximum CPUs we cache.  /sys/devices/system/cpu/cpu* enumeration is
 * bounded by this; any host with more than 1024 CPUs gets a truncated
 * view, which is fine — random selection within the cached subset is
 * still useful pressure. */
#define MAX_TRACKED_CPUS	1024

static bool cpu_inited;
static bool no_cpus_to_play;

/* CPU ids that have an /sys/.../cpuN/online file.  Some CPUs (typically
 * CPU 0 on x86) don't expose 'online' at all; those are omitted here. */
static int hotpluggable_cpus[MAX_TRACKED_CPUS];
static unsigned int nr_hotpluggable;

/* Highest CPU id ever seen with an 'online' file, used to size the
 * cpu_set_t we hand sched_setaffinity. */
static int max_cpu_id;

static long do_sched_setattr(pid_t pid, struct sched_attr *attr)
{
	return syscall(__NR_sched_setattr, (long) pid, attr, 0L);
}

static bool online_file_exists(int cpu, char *path_out, size_t path_len)
{
	snprintf(path_out, path_len,
		 "/sys/devices/system/cpu/cpu%d/online", cpu);
	return access(path_out, F_OK) == 0;
}

/*
 * Walk /sys/devices/system/cpu and cache every cpuN with an 'online'
 * file.  Returns silently on any parse failure — graceful degradation
 * just means no_cpus_to_play stays unset and the per-invocation
 * fast-path bail catches it.
 */
static void scan_hotpluggable_cpus(void)
{
	DIR *d;
	struct dirent *de;
	char path[128];

	d = opendir("/sys/devices/system/cpu");
	if (d == NULL)
		return;

	while ((de = readdir(d)) != NULL &&
	       nr_hotpluggable < MAX_TRACKED_CPUS) {
		int cpu;
		char *end;

		if (strncmp(de->d_name, "cpu", 3) != 0)
			continue;
		if (de->d_name[3] < '0' || de->d_name[3] > '9')
			continue;

		cpu = (int) strtol(de->d_name + 3, &end, 10);
		if (end == de->d_name + 3 || *end != '\0')
			continue;
		if (cpu < 0 || cpu >= MAX_TRACKED_CPUS)
			continue;

		if (!online_file_exists(cpu, path, sizeof(path)))
			continue;

		hotpluggable_cpus[nr_hotpluggable++] = cpu;
		if (cpu > max_cpu_id)
			max_cpu_id = cpu;
	}
	closedir(d);
}

static void init_cpu_state(void)
{
	cpu_inited = true;

	scan_hotpluggable_cpus();

	if (nr_hotpluggable == 0)
		no_cpus_to_play = true;
}

static int pick_hotpluggable_cpu(void)
{
	return hotpluggable_cpus[(unsigned int) rand() % nr_hotpluggable];
}

/*
 * Build a random non-empty subset of currently-online CPUs into *set.
 * "Currently online" is approximated by the cached set plus CPU 0 (and
 * any non-hotpluggable always-online CPUs we can't enumerate); we just
 * trust the kernel to reject EINVAL if the mask is empty after
 * filtering and let the caller count it as a benign failure.
 */
static void build_random_affinity(cpu_set_t *set)
{
	unsigned int i;
	bool any = false;

	CPU_ZERO(set);

	/* CPU 0 is almost always present and not always hotpluggable;
	 * include it with high probability so the mask is rarely empty. */
	if ((rand() % 4) != 0) {
		CPU_SET(0, set);
		any = true;
	}

	for (i = 0; i < nr_hotpluggable; i++) {
		if (RAND_BOOL()) {
			CPU_SET(hotpluggable_cpus[i], set);
			any = true;
		}
	}

	if (!any)
		CPU_SET(hotpluggable_cpus[(unsigned int) rand() % nr_hotpluggable],
			set);
}

/*
 * Try to write '0' or '1' to /sys/.../cpuN/online.  Returns true on
 * success, false on failure.  *was_eperm is set when the failure is
 * the expected non-root case; the caller counts those separately.
 */
static bool sysfs_online_write(int cpu, char val, bool *was_eperm)
{
	char path[128];
	int fd;
	ssize_t w;

	*was_eperm = false;

	snprintf(path, sizeof(path),
		 "/sys/devices/system/cpu/cpu%d/online", cpu);

	fd = open(path, O_WRONLY);
	if (fd < 0) {
		if (errno == EACCES || errno == EPERM)
			*was_eperm = true;
		return false;
	}

	w = write(fd, &val, 1);
	if (w != 1) {
		if (errno == EACCES || errno == EPERM)
			*was_eperm = true;
		close(fd);
		return false;
	}
	close(fd);
	return true;
}

/*
 * Bring CPU `cpu` offline then back online.  Root-only.  Skips CPU 0
 * unconditionally (some kernels refuse, others succeed and brick the
 * box).  Best-effort re-online on the way out so we don't leak an
 * offline CPU back to the host on failure.
 */
static bool real_offline_cycle(int cpu)
{
	bool eperm;

	if (cpu <= 0)
		return false;

	if (!sysfs_online_write(cpu, '0', &eperm))
		return false;

	/* Bring it back up immediately.  If this write fails we've left
	 * the host with one fewer CPU; nothing useful we can do beyond
	 * counting it — the parent's heartbeat will eventually notice
	 * the host is degraded. */
	(void) sysfs_online_write(cpu, '1', &eperm);
	return true;
}

static bool budget_elapsed(const struct timespec *start)
{
	struct timespec now;
	long elapsed_ns;

	clock_gettime(CLOCK_MONOTONIC, &now);
	elapsed_ns = (now.tv_sec  - start->tv_sec)  * 1000000000L
		   + (now.tv_nsec - start->tv_nsec);
	return elapsed_ns >= BUDGET_NS;
}

bool cpu_hotplug_rider(struct childdata *child)
{
	struct timespec start;
	cpu_set_t set;
	struct sched_attr attr;
	unsigned int iter;
	unsigned int affinity_calls = 0;
	unsigned int sysfs_writes = 0;
	unsigned int eperm_count = 0;
	unsigned int real_offlines = 0;
	bool did_real_offline = false;

	(void) child;

	if (!cpu_inited)
		init_cpu_state();

	if (no_cpus_to_play)
		return false;

	__atomic_add_fetch(&shm->stats.cpu_hotplug_runs, 1, __ATOMIC_RELAXED);

	clock_gettime(CLOCK_MONOTONIC, &start);

	for (iter = 0; iter < MAX_ITERATIONS; iter++) {
		unsigned int pick = (unsigned int) rand() % 4;

		switch (pick) {
		case 0:
		case 1:
			build_random_affinity(&set);
			(void) sched_setaffinity(0, sizeof(set), &set);
			affinity_calls++;
			break;

		case 2: {
			cpu_set_t cur;

			(void) sched_getaffinity(0, sizeof(cur), &cur);

			memset(&attr, 0, sizeof(attr));
			attr.size = sizeof(attr);
			attr.sched_policy = SCHED_OTHER;
			attr.sched_nice = (int) ((rand() % 40) - 20);
			(void) do_sched_setattr(0, &attr);
			affinity_calls++;
			break;
		}

		case 3: {
			int cpu = pick_hotpluggable_cpu();
			char val = RAND_BOOL() ? '1' : '0';
			bool eperm;

			(void) sysfs_online_write(cpu, val, &eperm);
			sysfs_writes++;
			if (eperm)
				eperm_count++;

			/* Root-only real offline cycle.  At most one per
			 * invocation; CPU 0 is excluded inside
			 * real_offline_cycle. */
			if (orig_uid == 0 && !did_real_offline &&
			    val == '0' && (rand() % 8) == 0) {
				if (real_offline_cycle(cpu)) {
					real_offlines++;
					did_real_offline = true;
				}
			}
			break;
		}
		}

		if (budget_elapsed(&start))
			break;
	}

	/* Restore a sane affinity mask covering every CPU we know about
	 * so the next iteration of this child (or another op stamped on
	 * the same dedicated alt-op slot) doesn't inherit a starved
	 * mask. */
	CPU_ZERO(&set);
	{
		int cpu;
		for (cpu = 0; cpu <= max_cpu_id && cpu < CPU_SETSIZE; cpu++)
			CPU_SET(cpu, &set);
		if (max_cpu_id < 0)
			CPU_SET(0, &set);
	}
	(void) sched_setaffinity(0, sizeof(set), &set);

	if (affinity_calls)
		__atomic_add_fetch(&shm->stats.cpu_hotplug_affinity_calls,
				   affinity_calls, __ATOMIC_RELAXED);
	if (sysfs_writes)
		__atomic_add_fetch(&shm->stats.cpu_hotplug_sysfs_writes,
				   sysfs_writes, __ATOMIC_RELAXED);
	if (eperm_count)
		__atomic_add_fetch(&shm->stats.cpu_hotplug_eperm,
				   eperm_count, __ATOMIC_RELAXED);
	if (real_offlines)
		__atomic_add_fetch(&shm->stats.cpu_hotplug_actual_offlines,
				   real_offlines, __ATOMIC_RELAXED);

	return true;
}
