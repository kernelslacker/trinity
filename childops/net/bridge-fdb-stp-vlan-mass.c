/*
 * bridge_fdb_stp - mass-VLAN-add sub-mode.
 *
 * Builds a fresh bridge + veth pair, enslaves + ups the veth, then
 * pushes one RTM_SETLINK whose IFLA_AF_SPEC nest carries up to ~100k
 * IFLA_BRIDGE_VLAN_INFO entries.  Drives the kernel's
 * nbp_vlan_add -> fdb_create -> rhashtable_insert_rehash path, which
 * on rehash can request an 8 MiB+ vmalloc and trip the vmalloc_huge
 * cap in mm/vmalloc.c.
 *
 * Outer-loop budget mirrors the rest of the op: BUDGETED+JITTER
 * around base 4 with a hard cap of 12, and a 200 ms wall-clock cap
 * so a single sub-mode invocation can't outrun the SIGALRM(1s)
 * inherited from child.c even if every sendmsg blocks behind kernel
 * processing.
 */

#include <errno.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>

#include <linux/rtnetlink.h>

#include "child.h"
#include "childops-netlink.h"
#include "jitter.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"

#include "bridge-fdb-stp-internal.h"

static const unsigned int vlan_mass_n_choices[] = {
	100, 1000, 10000, 50000, 100000,
};

/*
 * Build + sendmsg one RTM_SETLINK on `port_ifindex` whose IFLA_AF_SPEC
 * nest holds `n` IFLA_BRIDGE_VLAN_INFO entries.  Returns 0 on send +
 * ack receipt, or -errno (ENOBUFS / EMSGSIZE / EIO) on rejection.  The
 * 1 MiB scratch buffer caps the actual on-wire size; if `n` would
 * overflow we truncate and send what fits.
 *
 * Open-codes the sendmsg here (instead of going through nl_send_recv)
 * because this path uses MSG_DONTWAIT and discards the recv result —
 * a 1 MiB request can face slow kernel processing and we don't want
 * to block past the SIGALRM(1s) child cap waiting for a tx queue slot.
 */
static int build_setlink_vlan_mass(struct nl_ctx *ctx, int port_ifindex,
				   unsigned int n, unsigned int *vid_seed)
{
	unsigned char *buf;
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	struct sockaddr_nl dst;
	struct iovec iov;
	struct msghdr mh;
	struct bridge_vlan_info bvi;
	__u16 br_flags = BRIDGE_FLAGS_MASTER;
	size_t off, af_off, cap = VLAN_MASS_BUF_BYTES;
	unsigned int i;
	unsigned char rbuf[1024];
	ssize_t s;
	int rc = 0;

	buf = malloc(cap);
	if (!buf)
		return -ENOMEM;
	memset(buf, 0, cap);

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_SETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_BRIDGE;
	ifi->ifi_index  = port_ifindex;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	af_off = off;
	off = nla_nest_start(buf, off, cap, IFLA_AF_SPEC | NLA_F_NESTED);
	if (!off) { free(buf); return -EIO; }

	off = nla_put(buf, off, cap, IFLA_BRIDGE_FLAGS,
		      &br_flags, sizeof(br_flags));
	if (!off) { free(buf); return -EIO; }

	for (i = 0; i < n; i++) {
		size_t next;

		bvi.flags = ((i & 7) == 0) ? BRIDGE_VLAN_INFO_MASTER : 0;
		bvi.vid   = (__u16)(((*vid_seed)++ % 4094U) + 1U);
		next = nla_put(buf, off, cap, IFLA_BRIDGE_VLAN_INFO,
			       &bvi, sizeof(bvi));
		if (!next)
			break;	/* buffer full — send what we have */
		off = next;
	}

	nla_nest_end(buf, af_off, off);
	nlh->nlmsg_len = (__u32)off;

	memset(&dst, 0, sizeof(dst));
	dst.nl_family = AF_NETLINK;
	iov.iov_base = buf;
	iov.iov_len  = off;
	memset(&mh, 0, sizeof(mh));
	mh.msg_name    = &dst;
	mh.msg_namelen = sizeof(dst);
	mh.msg_iov     = &iov;
	mh.msg_iovlen  = 1;

	s = sendmsg(ctx->fd, &mh, MSG_DONTWAIT);
	if (s < 0)
		rc = -errno;
	else
		(void)recv(ctx->fd, rbuf, sizeof(rbuf), 0);

	free(buf);
	return rc;
}

/*
 * Mass-VLAN-add sub-mode entry.  Builds a fresh br + veth pair in the
 * (already-unshared) netns, enslaves + ups the veth, then runs the
 * BUDGETED outer loop, each iter picking N from {100,1k,10k,50k,100k}
 * and pushing one bulk SETLINK.  Cleanup deletes the bridge (cascades
 * the veth) plus the surviving veth end on error.
 */
void bridge_vlan_mass_add(struct nl_ctx *ctx)
{
	char br_name[IFNAMSIZ];
	char veth_a[IFNAMSIZ], veth_b[IFNAMSIZ];
	int br_idx = 0, va_idx = 0;
	bool bridge_added = false, veth_added = false;
	struct timespec t0;
	unsigned int rng = (unsigned int)(rand32() & 0xffffu);
	unsigned int iters, i;
	unsigned int vid_seed = 0;

	__atomic_add_fetch(&shm->stats.bridge_fdb_stp.bridge_vlan_mass_runs, 1,
			   __ATOMIC_RELAXED);

	if (ns_unsupported_bridge || ns_unsupported_veth)
		return;

	snprintf(br_name, sizeof(br_name), "trbm%u", rng);
	snprintf(veth_a, sizeof(veth_a), "trbmv%ua", rng);
	snprintf(veth_b, sizeof(veth_b), "trbmv%ub", rng);

	if (bfs_build_bridge_create(ctx, br_name) != 0)
		goto out;
	bridge_added = true;
	br_idx = (int)if_nametoindex(br_name);
	if (br_idx <= 0)
		goto out;

	if (bfs_build_veth_create(ctx, veth_a, veth_b) != 0)
		goto out;
	veth_added = true;
	va_idx = (int)if_nametoindex(veth_a);
	if (va_idx <= 0)
		goto out;

	(void)bfs_build_setlink_master(ctx, va_idx, br_idx);
	(void)rtnl_setlink_up(ctx, br_idx);
	(void)rtnl_setlink_up(ctx, va_idx);

	(void)clock_gettime(CLOCK_MONOTONIC, &t0);
	iters = BUDGETED(CHILD_OP_BRIDGE_FDB_STP,
			 JITTER_RANGE(VLAN_MASS_OUTER_BASE));
	if (iters < 1)
		iters = 1;
	if (iters > VLAN_MASS_OUTER_CAP)
		iters = VLAN_MASS_OUTER_CAP;

	for (i = 0; i < iters; i++) {
		unsigned long want, cur;
		unsigned int n;
		int rc;

		if (ns_since(&t0) >= VLAN_MASS_BUDGET_NS)
			break;

		n = vlan_mass_n_choices[rnd_modulo_u32(
			sizeof(vlan_mass_n_choices) /
			sizeof(vlan_mass_n_choices[0]))];

		rc = build_setlink_vlan_mass(ctx, va_idx, n, &vid_seed);
		if (rc == -ENOBUFS || rc == -EMSGSIZE)
			__atomic_add_fetch(&shm->stats.bridge_fdb_stp.bridge_vlan_mass_enotbufs,
					   1, __ATOMIC_RELAXED);

		want = n;
		cur = __atomic_load_n(&shm->stats.bridge_fdb_stp.bridge_vlan_mass_max_n,
				      __ATOMIC_RELAXED);
		while (want > cur &&
		       !__atomic_compare_exchange_n(&shm->stats.bridge_fdb_stp.bridge_vlan_mass_max_n,
						    &cur, want, false,
						    __ATOMIC_RELAXED,
						    __ATOMIC_RELAXED))
			;
	}

out:
	if (bridge_added && br_idx > 0)
		(void)rtnl_dellink(ctx, br_idx);
	if (veth_added && va_idx > 0)
		(void)rtnl_dellink(ctx, va_idx);
}
