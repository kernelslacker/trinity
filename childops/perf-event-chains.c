/*
 * perf_event_chains - exercise perf_event_open() with discovered PMU types.
 *
 * Enumerates hardware PMUs from /sys/bus/event_source/devices/, seeds a
 * catalog of (name, type) pairs, then on each invocation creates an event
 * group — one leader plus zero to two member events — and drives the group
 * through the PERF_EVENT_IOC_* ioctl surface before tearing it down.
 *
 * The perf subsystem's group scheduling, multiplexing, and inheritance paths
 * are only reachable when events are opened in a group relationship (the
 * group_fd argument ties members to the leader).  Trinity's existing
 * perf_event_open syscall path opens events independently; it almost never
 * constructs a leader+members group, so group refcounting and the
 * context-switch multiplexing state machine stay cold.
 *
 * Trinity-todo #2.4.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/perf_event.h>

#include "child.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#define MAX_PMUS		64
#define MAX_GROUP_MEMBERS	3	/* leader + up to 2 members */
#define PMU_NAME_LEN		64

struct pmu_entry {
	char name[PMU_NAME_LEN];
	__u32 type;
};

static struct pmu_entry pmu_catalog[MAX_PMUS];
static unsigned int pmu_count;
static bool pmu_discovery_done;
static bool pmu_warned_unsupported;

static long do_perf_event_open(struct perf_event_attr *attr, pid_t pid,
			       int cpu, int group_fd, unsigned long flags)
{
	return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static void add_pmu(__u32 type, const char *name)
{
	if (pmu_count >= MAX_PMUS)
		return;
	pmu_catalog[pmu_count].type = type;
	{
		size_t namelen = strlen(name);
		if (namelen >= PMU_NAME_LEN)
			namelen = PMU_NAME_LEN - 1;
		memcpy(pmu_catalog[pmu_count].name, name, namelen);
		pmu_catalog[pmu_count].name[namelen] = '\0';
	}
	pmu_count++;
}

/*
 * Read the 'type' pseudo-file from a sysfs PMU device directory and
 * add it to the catalog.  The file contains a decimal integer.
 */
static void probe_sysfs_pmu(const char *devpath, const char *devname)
{
	char typepath[128];
	char buf[32];
	int fd;
	ssize_t n;
	unsigned long type;

	if ((size_t)snprintf(typepath, sizeof(typepath),
			     "%s/type", devpath) >= sizeof(typepath))
		return;

	fd = open(typepath, O_RDONLY);
	if (fd < 0)
		return;

	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return;

	buf[n] = '\0';
	type = strtoul(buf, NULL, 10);
	if (type == 0 || type > 0xffffffff)
		return;

	add_pmu((__u32)type, devname);
}

/*
 * Walk /sys/bus/event_source/devices/ and read the 'type' file from
 * each entry.  Failures are silently skipped — the built-in software
 * PMU added below is always present and sufficient to exercise the
 * group path on any kernel.
 */
static void discover_pmus(void)
{
	static const char dev_root[] = "/sys/bus/event_source/devices";
	DIR *dir;
	struct dirent *de;
	char devpath[128];

	/* Always-available built-ins: keep the catalog non-empty. */
	add_pmu(PERF_TYPE_SOFTWARE, "software");
	add_pmu(PERF_TYPE_HARDWARE, "hardware");

	dir = opendir(dev_root);
	if (dir == NULL)
		return;

	while ((de = readdir(dir)) != NULL) {
		if (de->d_name[0] == '.')
			continue;
		if ((size_t)snprintf(devpath, sizeof(devpath),
				     "%s/%s", dev_root,
				     de->d_name) >= sizeof(devpath))
			continue;
		probe_sysfs_pmu(devpath, de->d_name);
	}

	closedir(dir);
}

static bool ensure_discovery(void)
{
	if (pmu_discovery_done)
		return true;

	discover_pmus();
	pmu_discovery_done = true;

	if (pmu_count == 0) {
		if (!pmu_warned_unsupported) {
			pmu_warned_unsupported = true;
			output(0, "perf_event_chains: no PMUs found, disabling\n");
		}
		return false;
	}

	return true;
}

/*
 * Build a randomised perf_event_attr for the given PMU type.
 * We use pid=0 (measure self) and cpu=-1 (any cpu) — no privileges
 * needed beyond what the kernel's paranoid sysctl allows.
 */
static void fill_attr(struct perf_event_attr *attr, __u32 pmu_type)
{
	memset(attr, 0, sizeof(*attr));
	attr->type = pmu_type;
	attr->size = sizeof(*attr);
	attr->disabled = 1;

	switch (pmu_type) {
	case PERF_TYPE_SOFTWARE:
		/* 1-in-RAND_NEGATIVE_RATIO sub the in-range SW event id for
		 * a curated edge value — exercises perf_event_open's config
		 * range validation against PERF_COUNT_SW_MAX which the
		 * curated 0..MAX-1 mix never reaches. */
		attr->config = (uint64_t)RAND_NEGATIVE_OR(
			rand() % PERF_COUNT_SW_MAX);
		break;
	case PERF_TYPE_HARDWARE:
		attr->config = (uint64_t)(rand() % PERF_COUNT_HW_MAX);
		break;
	default:
		/* Raw event config for hardware PMUs discovered via sysfs. */
		attr->config = rand64();
		break;
	}

	/* Randomly vary the read format to exercise different kernel paths. */
	if (RAND_BOOL())
		attr->read_format |= PERF_FORMAT_TOTAL_TIME_ENABLED;
	if (RAND_BOOL())
		attr->read_format |= PERF_FORMAT_TOTAL_TIME_RUNNING;
	if (RAND_BOOL())
		attr->read_format |= PERF_FORMAT_ID;

	if (RAND_BOOL())
		attr->inherit = 1;
	if (RAND_BOOL())
		attr->exclude_kernel = 1;
	if (RAND_BOOL())
		attr->exclude_hv = 1;
}

/*
 * Apply a random mix of PERF_EVENT_IOC_* operations to an open group.
 * All errors are silently ignored — the goal is to exercise the kernel's
 * ioctl dispatch, not to operate the event correctly.
 */
static void fuzz_group_ioctls(int leader_fd, const int *member_fds,
			      unsigned int nr_members)
{
	uint64_t id;
	unsigned long flag;
	int i;

	/* Enable with and without the group flag. */
	flag = RAND_BOOL() ? PERF_IOC_FLAG_GROUP : 0;
	ioctl(leader_fd, PERF_EVENT_IOC_ENABLE, flag);
	__atomic_add_fetch(&shm->stats.perf_chains_ioctl_ops, 1, __ATOMIC_RELAXED);

	/* Read from leader; catches PERF_FORMAT_GROUP layout bugs. */
	{
		uint64_t buf[16];
		ssize_t ret __unused__;
		ret = read(leader_fd, buf, sizeof(buf));
	}

	/* Reset counters. */
	flag = RAND_BOOL() ? PERF_IOC_FLAG_GROUP : 0;
	ioctl(leader_fd, PERF_EVENT_IOC_RESET, flag);
	__atomic_add_fetch(&shm->stats.perf_chains_ioctl_ops, 1, __ATOMIC_RELAXED);

	/* Fetch the kernel-assigned unique IDs. */
	ioctl(leader_fd, PERF_EVENT_IOC_ID, &id);
	__atomic_add_fetch(&shm->stats.perf_chains_ioctl_ops, 1, __ATOMIC_RELAXED);

	for (i = 0; i < (int)nr_members; i++) {
		ioctl(member_fds[i], PERF_EVENT_IOC_ID, &id);
		__atomic_add_fetch(&shm->stats.perf_chains_ioctl_ops, 1,
				   __ATOMIC_RELAXED);
	}

	/* Redirect overflow output from a member to the leader. */
	if (nr_members > 0 && RAND_BOOL()) {
		ioctl(member_fds[0], PERF_EVENT_IOC_SET_OUTPUT, leader_fd);
		__atomic_add_fetch(&shm->stats.perf_chains_ioctl_ops, 1,
				   __ATOMIC_RELAXED);
	}

	/* REFRESH with a small count — used by sampling, rarely tested. */
	if (RAND_BOOL()) {
		ioctl(leader_fd, PERF_EVENT_IOC_REFRESH, (unsigned long)(rand() % 8 + 1));
		__atomic_add_fetch(&shm->stats.perf_chains_ioctl_ops, 1,
				   __ATOMIC_RELAXED);
	}

	/* Disable the group. */
	flag = RAND_BOOL() ? PERF_IOC_FLAG_GROUP : 0;
	ioctl(leader_fd, PERF_EVENT_IOC_DISABLE, flag);
	__atomic_add_fetch(&shm->stats.perf_chains_ioctl_ops, 1, __ATOMIC_RELAXED);
}

bool perf_event_chains(struct childdata *child)
{
	struct perf_event_attr attr;
	const struct pmu_entry *pmu;
	int leader_fd;
	int member_fds[MAX_GROUP_MEMBERS - 1];
	unsigned int nr_members;
	unsigned int i;

	(void)child;

	if (!ensure_discovery())
		return true;

	__atomic_add_fetch(&shm->stats.perf_chains_runs, 1, __ATOMIC_RELAXED);

	pmu = &pmu_catalog[rand() % pmu_count];

	fill_attr(&attr, pmu->type);

	/* Open the group leader: group_fd=-1 makes this the leader. */
	leader_fd = (int)do_perf_event_open(&attr, 0, -1, -1, 0UL);
	if (leader_fd < 0)
		return true;

	__atomic_add_fetch(&shm->stats.perf_chains_groups_created, 1,
			   __ATOMIC_RELAXED);

	/* Open 0 to MAX_GROUP_MEMBERS-1 member events in this group. */
	nr_members = (unsigned int)(rand() % MAX_GROUP_MEMBERS);
	for (i = 0; i < nr_members; i++) {
		fill_attr(&attr, pmu->type);
		/*
		 * Inherit and pinned are illegal on group members; clearing
		 * them avoids an immediate EINVAL that would leave the member
		 * slot empty and deprive the ioctl phase of interesting fds.
		 */
		attr.inherit = 0;
		attr.pinned = 0;
		member_fds[i] = (int)do_perf_event_open(&attr, 0, -1,
							  leader_fd, 0UL);
		if (member_fds[i] < 0) {
			nr_members = i;
			break;
		}
	}

	fuzz_group_ioctls(leader_fd, member_fds, nr_members);

	for (i = 0; i < nr_members; i++)
		close(member_fds[i]);
	close(leader_fd);

	return true;
}
