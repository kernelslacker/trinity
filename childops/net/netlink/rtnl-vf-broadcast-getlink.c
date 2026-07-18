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
 * Per invocation (runs inside a transient grandchild forked by
 * userns_run_in_ns(CLONE_NEWNET); the grandchild's userns + netns are
 * torn down on _exit() so any netdevsim port, VFs and sockets left
 * behind are reaped along with the namespace):
 *   - Confirm /sys/bus/netdevsim/new_device is writable.
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
 * are torn down by CLONE_NEWNET teardown on grandchild exit.  Loopback
 * only - netdevsim has no path off-host.
 */

#include <errno.h>
#include <net/if.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>
#include <unistd.h>

#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "child.h"
#include "childops-netlink.h"
#include "jitter.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "userns-bootstrap.h"

#include "kernel/fcntl.h"
#ifndef RTEXT_FILTER_VF
#define RTEXT_FILTER_VF		(1U << 0)
#endif

#define NETDEVSIM_NEW_DEVICE	"/sys/bus/netdevsim/new_device"
#define NETDEVSIM_DEL_DEVICE	"/sys/bus/netdevsim/del_device"
#define VFB_OUTER_BASE		6U
#define VFB_OUTER_CAP		32U
#define VFB_STORM_BUDGET_NS	200000000L
#define VFB_NUM_VFS		3U	/* 2..4 sweet-spot per spec */

/* Master gate: persistent across iterations in the persistent fuzz
 * child.  Set when userns_run_in_ns() returns -EPERM (hardened userns
 * policy refused CLONE_NEWUSER -- typically user.max_user_namespaces=0
 * or kernel.unprivileged_userns_clone=0) so subsequent invocations
 * short-circuit instead of forking another doomed grandchild. */
static bool ns_unsupported_rtnl_vf_broadcast;

static void warn_once_unsupported_rtnl_vf_broadcast(int err)
{
	static bool warned;

	if (warned)
		return;
	warned = true;
	outputerr("rtnl_vf_broadcast_getlink: userns_run_in_ns(CLONE_NEWNET) failed (errno=%d), latching ns_unsupported_rtnl_vf_broadcast\n",
		  err);
}

/*
 * Per-grandchild iteration state.  Lives on the grandchild's stack and
 * dies when the grandchild _exit()s after the in-ns callback returns;
 * no cross-iteration caching is possible because the netns (and the
 * netdevsim port + VFs + netlink socket inside it) is recreated on
 * every call.
 */
struct rtnl_vf_iter_ctx {
	struct childdata *child;
	struct nl_ctx nl;
	int port_ifindex;
	__u32 bus_id;
	bool bus_id_owned;
};

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

/*
 * Build the netdevsim topology inside the already-entered private
 * netns (userns_run_in_ns() has already done the CLONE_NEWNET unshare
 * inside the grandchild before calling the in-ns callback).  The
 * netdev port lives in the grandchild's netns and is reaped on
 * _exit(); the platform device on /sys/bus/netdevsim is host-global
 * and MUST be explicitly del_device'd in the teardown path (the bus
 * is not netns-scoped, so namespace exit alone leaks it -- and the
 * 14-bit bus_id space saturates fast under per-iteration creation).
 */
static bool do_setup(struct rtnl_vf_iter_ctx *ctx)
{
	char path[128];
	char payload[32];
	struct nl_open_opts opts = {
		.proto = NETLINK_ROUTE,
		.recv_timeo_s = 1,
	};

	ctx->bus_id = rand32() & 0x3fffU;	/* 14-bit bus id avoids collisions */
	snprintf(payload, sizeof(payload), "%u 1", (unsigned int)ctx->bus_id);
	if (!sysfs_write_str(NETDEVSIM_NEW_DEVICE, payload))
		return false;
	ctx->bus_id_owned = true;

	snprintf(path, sizeof(path),
		 "/sys/bus/netdevsim/devices/netdevsim%u/sriov_numvfs",
		 (unsigned int)ctx->bus_id);
	snprintf(payload, sizeof(payload), "%u", VFB_NUM_VFS);
	if (!sysfs_write_str(path, payload))
		return false;

	ctx->port_ifindex = resolve_port_ifindex(ctx->bus_id);
	if (ctx->port_ifindex <= 0)
		return false;

	if (nl_open(&ctx->nl, &opts) < 0)
		return false;

	__atomic_add_fetch(&shm->stats.rtnl_vf_broadcast.setup_ok, 1,
			   __ATOMIC_RELAXED);
	return true;
}

/*
 * Release host-global netdevsim platform-device state acquired by
 * do_setup().  The netdev port and its VFs die with the netns on
 * grandchild _exit(), but the platform device on /sys/bus/netdevsim
 * persists across namespace teardown and must be removed explicitly
 * via /sys/bus/netdevsim/del_device.  Safe to call on any setup
 * exit path -- ctx->bus_id_owned is the latch.
 */
static void do_teardown(struct rtnl_vf_iter_ctx *ctx)
{
	char payload[32];

	nl_close(&ctx->nl);

	if (!ctx->bus_id_owned)
		return;
	snprintf(payload, sizeof(payload), "%u", (unsigned int)ctx->bus_id);
	(void)sysfs_write_str(NETDEVSIM_DEL_DEVICE, payload);
	ctx->bus_id_owned = false;
}

/*
 * Build RTM_GETLINK targeted at ctx->port_ifindex with IFLA_EXT_MASK
 * = RTEXT_FILTER_VF, then drain the multipart response.  We only need
 * to know the dump walker ran; the leak is on the kernel WRITE side.
 */
static bool issue_getlink_with_vf_filter(struct rtnl_vf_iter_ctx *ctx)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct ifinfomsg *ifi;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_type  = RTM_GETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nlh->nlmsg_seq   = nl_seq_next(&ctx->nl);
	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = ctx->port_ifindex;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));
	off = nla_put_u32(buf, off, sizeof(buf), IFLA_EXT_MASK,
			  RTEXT_FILTER_VF);
	if (!off)
		return false;
	nlh->nlmsg_len = (__u32)off;

	return nl_send_recv_dump(&ctx->nl, buf, off) == 0;
}

/*
 * Per-invocation body that runs inside the grandchild's private
 * netns.  userns_run_in_ns() has already entered the netns; this
 * callback builds the netdevsim topology, drives the GETLINK storm
 * and tears down the netlink fd.  Any partially-built state on a
 * setup-failure path is reaped by the grandchild's _exit().  Return
 * value is ignored by the helper -- per-op stats counters carry the
 * outcome.
 */
static int rtnl_vf_broadcast_in_ns(void *arg)
{
	struct rtnl_vf_iter_ctx *ctx = (struct rtnl_vf_iter_ctx *)arg;
	struct childdata *child = ctx->child;
	struct timespec t0;
	unsigned int iters, i;
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (!do_setup(ctx)) {
		__atomic_add_fetch(&shm->stats.rtnl_vf_broadcast.setup_failed,
				   1, __ATOMIC_RELAXED);
		do_teardown(ctx);
		return 0;
	}

	iters = BUDGETED(CHILD_OP_RTNL_VF_BROADCAST_GETLINK,
			 JITTER_RANGE(VFB_OUTER_BASE));
	if (iters > VFB_OUTER_CAP)
		iters = VFB_OUTER_CAP;

	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	}

	(void)clock_gettime(CLOCK_MONOTONIC, &t0);
	for (i = 0; i < iters; i++) {
		if (ns_since(&t0) >= VFB_STORM_BUDGET_NS)
			break;
		if (!ONE_IN(8))
			continue;
		if (issue_getlink_with_vf_filter(ctx))
			__atomic_add_fetch(&shm->stats.rtnl_vf_broadcast.getlink_ok,
					   1, __ATOMIC_RELAXED);
	}

	do_teardown(ctx);
	return 0;
}

bool rtnl_vf_broadcast_getlink(struct childdata *child)
{
	struct rtnl_vf_iter_ctx ctx = {
		.child         = child,
		.nl            = { .fd = -1 },
		.port_ifindex  = 0,
		.bus_id        = 0,
		.bus_id_owned  = false,
	};
	struct stat st;
	int rc;
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op latch slot.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the latch
	 * store entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	__atomic_add_fetch(&shm->stats.rtnl_vf_broadcast.runs, 1,
			   __ATOMIC_RELAXED);

	if (ns_unsupported_rtnl_vf_broadcast)
		return true;

	/* Parent-side fork-elision check.  When /sys/bus/netdevsim is
	 * absent or unwritable the grandchild's do_setup() can only
	 * fail; the in-ns callback's return value is discarded by
	 * userns_run_in_ns() so we would otherwise pay one userns +
	 * netns refork per invocation just to re-discover the same
	 * absent path.  Skip without latching: on CONFIG_NETDEVSIM=m
	 * the module can be loaded mid-run (e.g. by another op's
	 * modprobe path), and a permanent latch here would lose this
	 * op's coverage for the rest of the child's lifetime. */
	if (stat(NETDEVSIM_NEW_DEVICE, &st) < 0 ||
	    access(NETDEVSIM_NEW_DEVICE, W_OK) < 0) {
		__atomic_add_fetch(&shm->stats.rtnl_vf_broadcast.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	rc = userns_run_in_ns(CLONE_NEWNET, rtnl_vf_broadcast_in_ns, &ctx);
	if (rc == -EPERM) {
		ns_unsupported_rtnl_vf_broadcast = true;
		if (valid_op)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		warn_once_unsupported_rtnl_vf_broadcast(EPERM);
		return true;
	}
	if (rc < 0) {
		/* Transient grandchild setup failure (fork, id-map write,
		 * secondary unshare).  Skip this iteration without
		 * latching -- the failure is not policy and may not
		 * recur. */
		__atomic_add_fetch(&shm->stats.rtnl_vf_broadcast.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	return true;
}
