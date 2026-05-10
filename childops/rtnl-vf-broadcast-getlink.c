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
 *   - Build RTM_GETLINK with ifi_index = the netdevsim port and a
 *     single IFLA_EXT_MASK attribute carrying RTEXT_FILTER_VF.
 *   - sendmsg, then drain the multipart response with recv() until
 *     NLMSG_DONE / NLMSG_ERROR / EAGAIN.  We do not parse the payload
 *     - the leak is on the kernel WRITE side; we just need the dump
 *     walker to run.
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
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "child.h"
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
static int g_rtnl_fd = -1;
static int g_port_ifindex;
static __u32 g_seq;

static __u32 next_seq(void)
{
	return ++g_seq;
}

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

static int rtnl_open(void)
{
	struct sockaddr_nl sa;
	struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
	int fd;

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (fd < 0)
		return -1;
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(fd);
		return -1;
	}
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	return fd;
}

static size_t nla_put_u32(unsigned char *buf, size_t off, size_t cap,
			  unsigned short type, __u32 val)
{
	struct nlattr *nla;
	size_t total = NLA_HDRLEN + sizeof(val);
	size_t aligned = NLA_ALIGN(total);

	if (off + aligned > cap)
		return 0;
	nla = (struct nlattr *)(buf + off);
	nla->nla_type = type;
	nla->nla_len  = (unsigned short)total;
	memcpy(buf + off + NLA_HDRLEN, &val, sizeof(val));
	if (aligned > total)
		memset(buf + off + total, 0, aligned - total);
	return off + aligned;
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

	g_rtnl_fd = rtnl_open();
	if (g_rtnl_fd < 0)
		return false;

	__atomic_add_fetch(&shm->stats.rtnl_vf_broadcast_setup_ok, 1,
			   __ATOMIC_RELAXED);
	return true;
}

/*
 * Build RTM_GETLINK targeted at g_port_ifindex with IFLA_EXT_MASK =
 * RTEXT_FILTER_VF, then drain the (potentially multipart) response.
 * We only count run/ok; the kernel may send DONE in a separate skb.
 */
static bool issue_getlink_with_vf_filter(int fd)
{
	unsigned char buf[256];
	unsigned char rbuf[4096];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct ifinfomsg *ifi;
	size_t off;
	ssize_t n;
	bool drained = false;

	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_type  = RTM_GETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = next_seq();
	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = g_port_ifindex;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));
	off = nla_put_u32(buf, off, sizeof(buf), IFLA_EXT_MASK,
			  RTEXT_FILTER_VF);
	if (!off)
		return false;
	nlh->nlmsg_len = (__u32)off;

	if (send(fd, buf, off, 0) < 0)
		return false;

	for (;;) {
		n = recv(fd, rbuf, sizeof(rbuf), 0);
		if (n <= 0)
			break;
		drained = true;
		if (n < (ssize_t)NLMSG_HDRLEN)
			break;
		{
			struct nlmsghdr *r = (struct nlmsghdr *)rbuf;

			if (r->nlmsg_type == NLMSG_DONE ||
			    r->nlmsg_type == NLMSG_ERROR ||
			    !(r->nlmsg_flags & NLM_F_MULTI))
				break;
		}
	}
	return drained;
}

static long ns_since(const struct timespec *t0)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		return 0;
	return (now.tv_sec - t0->tv_sec) * 1000000000L +
	       (now.tv_nsec - t0->tv_nsec);
}

bool rtnl_vf_broadcast_getlink(struct childdata *child)
{
	struct timespec t0;
	unsigned int iters, i;

	(void)child;

	__atomic_add_fetch(&shm->stats.rtnl_vf_broadcast_runs, 1,
			   __ATOMIC_RELAXED);

	if (ns_unsupported_rtnl_vf_broadcast)
		return true;

	if (!ns_setup_done) {
		if (ns_setup_failed_latched || !do_setup()) {
			ns_setup_failed_latched = true;
			ns_unsupported_rtnl_vf_broadcast = true;
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

	(void)clock_gettime(CLOCK_MONOTONIC, &t0);
	for (i = 0; i < iters; i++) {
		if (ns_since(&t0) >= VFB_STORM_BUDGET_NS)
			break;
		if (!ONE_IN(8))
			continue;
		if (issue_getlink_with_vf_filter(g_rtnl_fd))
			__atomic_add_fetch(&shm->stats.rtnl_vf_broadcast_getlink_ok,
					   1, __ATOMIC_RELAXED);
	}

	return true;
}
