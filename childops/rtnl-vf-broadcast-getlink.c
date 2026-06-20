/*
 * rtnl_vf_broadcast_getlink - drive RTM_GETLINK + IFLA_EXT_MASK=
 * RTEXT_FILTER_VF against a netdev that has SR-IOV VFs, so the
 * kernel walks the per-VF info section and emits IFLA_VF_BROADCAST.
 *
 * The bug class this op exists to expose is a stack-info-leak in the
 * rtnetlink IFLA_VF_BROADCAST writer: nla_put_vf_broadcast() copied
 * MAX_ADDR_LEN bytes (32) from an on-stack ifla_vf_broadcast struct
 * whose 6-byte broadcast field was the only thing initialised, leaking
 * the trailing 26 bytes of stack to userspace.  The leak only fires
 * when (a) the netdev has at least one SR-IOV VF and (b) the dump
 * walker is asked to fill the per-VF info section, which requires
 * IFLA_EXT_MASK with RTEXT_FILTER_VF set on the request.  Random
 * rtnetlink fuzzing hits neither condition together: synthetic
 * netdevs the fuzzer creates (dummy, veth, vlan, ...) have no VF
 * table, so the per-VF walker returns immediately.
 *
 * netdevsim implements ndo_set_vf_* and exposes sriov_numvfs via its
 * fake bus, so a private netns + one netdevsim port + a non-zero VF
 * count synthesises the bug-required topology with no PCI hardware.
 *
 * Per child (latched once on first invocation):
 *   - Confirm /sys/bus/netdevsim/new_device is writable.
 *   - unshare(CLONE_NEWNET) into a private netns.
 *   - Write "<bus_id> 1" to new_device to spawn netdevsim<bus_id>
 *     with one port.
 *   - Write "<NUM_VFS>" to .../sriov_numvfs to instantiate VFs.
 *   - Resolve the host-visible netdev name (eni<bus_id>np0 on recent
 *     kernels, eth<bus_id> on legacy) to an ifindex via SIOCGIFINDEX.
 *   - Open a NETLINK_ROUTE socket inside the netns.
 *
 * Per outer iteration (BUDGETED, base 6, cap 32, 200 ms wall cap):
 *   - ONE_IN(8) gate keeps the kernel-side walker cost amortised.
 *   - Build RTM_GETLINK with NLM_F_DUMP + a single IFLA_EXT_MASK
 *     attribute carrying RTEXT_FILTER_VF, then drain the multipart
 *     response via nl_send_recv_dump() until NLMSG_DONE.  We do not
 *     parse the payload - the leak is on the kernel WRITE side; we
 *     just need the dump walker to run.
 *
 * Self-bounding: BUDGETED outer loop with 200 ms CLOCK_MONOTONIC
 * wall cap, recvmsg uses SO_RCVTIMEO=1s, and the netns + sriov_numvfs
 * are torn down by CLONE_NEWNET teardown on child exit.  Loopback
 * only - netdevsim has no path off-host.
 */

#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "child.h"
#include "childops-netlink.h"
#include "jitter.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"

#ifndef RTEXT_FILTER_VF
#define RTEXT_FILTER_VF		(1U << 0)
#endif

#define NETDEVSIM_NEW_DEVICE	"/sys/bus/netdevsim/new_device"
#define VFB_OUTER_BASE		6U
#define VFB_OUTER_CAP		32U
#define VFB_STORM_BUDGET_NS	200000000L
#define VFB_NUM_VFS		3U	/* 2..4 sweet-spot per spec */

static bool ns_unsupported_rtnl_vf_broadcast;
static bool ns_setup_done;
static bool ns_setup_failed_latched;
static struct nl_ctx g_nl = { .fd = -1 };
static int g_port_ifindex;

static bool sysfs_write_str(const char *path, const char *val)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	ssize_t n;

	if (fd < 0)
		return false;
	n = write(fd, val, strlen(val));
	close(fd);
	return n > 0;
}

/*
 * Try the recent and legacy netdevsim host-visible netdev names and
 * return the first ifindex that resolves.  netdevsim names its ports
 * eni<bus_id>np0 on modern kernels and eth<bus_id> on older builds.
 */
static int resolve_port_ifindex(__u32 bus_id)
{
	char name[IFNAMSIZ];
	unsigned int idx;

	snprintf(name, sizeof(name), "eni%unp0", (unsigned int)bus_id);
	idx = if_nametoindex(name);
	if (idx > 0)
		return (int)idx;
	snprintf(name, sizeof(name), "eth%u", (unsigned int)bus_id);
	idx = if_nametoindex(name);
	if (idx > 0)
		return (int)idx;
	return 0;
}

static bool do_setup(void)
{
	struct stat st;
	char path[128];
	char payload[32];
	__u32 bus_id;

	if (stat(NETDEVSIM_NEW_DEVICE, &st) < 0)
		return false;
	if (access(NETDEVSIM_NEW_DEVICE, W_OK) < 0)
		return false;

	if (unshare(CLONE_NEWNET) < 0)
		return false;

	bus_id = rand32() & 0x3fffU;	/* 14-bit bus id avoids collisions */
	snprintf(payload, sizeof(payload), "%u 1", (unsigned int)bus_id);
	if (!sysfs_write_str(NETDEVSIM_NEW_DEVICE, payload))
		return false;

	snprintf(path, sizeof(path),
		 "/sys/bus/netdevsim/devices/netdevsim%u/sriov_numvfs",
		 (unsigned int)bus_id);
	snprintf(payload, sizeof(payload), "%u", VFB_NUM_VFS);
	if (!sysfs_write_str(path, payload))
		return false;

	g_port_ifindex = resolve_port_ifindex(bus_id);
	if (g_port_ifindex <= 0)
		return false;

	{
		struct nl_open_opts opts = {
			.proto = NETLINK_ROUTE,
			.recv_timeo_s = 1,
		};

		if (nl_open(&g_nl, &opts) < 0)
			return false;
	}

	__atomic_add_fetch(&shm->stats.rtnl_vf_broadcast_setup_ok, 1,
			   __ATOMIC_RELAXED);
	return true;
}

/*
 * Build RTM_GETLINK targeted at g_port_ifindex with IFLA_EXT_MASK =
 * RTEXT_FILTER_VF, then drain the multipart response.  We only need
 * to know the dump walker ran; the leak is on the kernel WRITE side.
 */
static bool issue_getlink_with_vf_filter(struct nl_ctx *ctx)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct ifinfomsg *ifi;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_type  = RTM_GETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nlh->nlmsg_seq   = nl_seq_next(ctx);
	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = g_port_ifindex;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));
	off = nla_put_u32(buf, off, sizeof(buf), IFLA_EXT_MASK,
			  RTEXT_FILTER_VF);
	if (!off)
		return false;
	nlh->nlmsg_len = (__u32)off;

	return nl_send_recv_dump(ctx, buf, off) == 0;
}

bool rtnl_vf_broadcast_getlink(struct childdata *child)
{
	struct timespec t0;
	unsigned int iters, i;

	__atomic_add_fetch(&shm->stats.rtnl_vf_broadcast_runs, 1,
			   __ATOMIC_RELAXED);

	if (ns_unsupported_rtnl_vf_broadcast)
		return true;

	if (!ns_setup_done) {
		if (ns_setup_failed_latched || !do_setup()) {
			ns_setup_failed_latched = true;
			ns_unsupported_rtnl_vf_broadcast = true;
			__atomic_store_n(&shm->stats.childop_latch_reason[child->op_type],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
			__atomic_add_fetch(&shm->stats.rtnl_vf_broadcast_setup_failed,
					   1, __ATOMIC_RELAXED);
			return true;
		}
		ns_setup_done = true;
	}

	iters = BUDGETED(CHILD_OP_RTNL_VF_BROADCAST_GETLINK,
			 JITTER_RANGE(VFB_OUTER_BASE));
	if (iters > VFB_OUTER_CAP)
		iters = VFB_OUTER_CAP;

	__atomic_add_fetch(&shm->stats.childop_setup_accepted[child->op_type],
			   1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.childop_data_path[child->op_type],
			   1, __ATOMIC_RELAXED);

	(void)clock_gettime(CLOCK_MONOTONIC, &t0);
	for (i = 0; i < iters; i++) {
		if (ns_since(&t0) >= VFB_STORM_BUDGET_NS)
			break;
		if (!ONE_IN(8))
			continue;
		if (issue_getlink_with_vf_filter(&g_nl))
			__atomic_add_fetch(&shm->stats.rtnl_vf_broadcast_getlink_ok,
					   1, __ATOMIC_RELAXED);
	}

	return true;
}
