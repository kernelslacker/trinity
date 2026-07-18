/*
 * vlan_filter_churn -- 8021q VLAN filter add/del churn against a veth
 * base device.
 *
 * Target: net/8021q/vlan_core.c (vlan_vid_add, vlan_vid_del,
 * vlan_add_rx_filter_info, vlan_kill_rx_filter_info) and the driver
 * ndo_vlan_rx_add_vid / ndo_vlan_rx_kill_vid callbacks on base devs
 * that advertise NETIF_F_HW_VLAN_CTAG_FILTER.  Every RTM_NEWLINK
 * type=vlan against an IFLA_LINK ifindex drives register_vlan_dev ->
 * vlan_vid_add on the real_dev; the paired RTM_DELLINK cascades
 * unregister_vlan_dev -> vlan_vid_del.  Random per-syscall netlink
 * fuzzing can't chain the pair reliably: create needs a nested
 * IFLA_INFO_DATA IFLA_VLAN_ID at a valid vid on a live IFLA_LINK, and
 * the del must land while the base dev's vlan_info group is still
 * populated for the kill path to see anything to walk.
 *
 * bridge_vlan_churn covers the br_vlan filtering-bridge path
 * (nested IFLA_AF_SPEC IFLA_BRIDGE_VLAN_INFO on an enslaved port);
 * that is a distinct kernel subsystem from the top-level 8021q core.
 * Neither vxlan_encap_churn nor flowtable_encap_vlan reaches
 * vlan_vid_add either -- they build encap tunnels or nf-flow rules,
 * not vlan devices on real_dev.
 *
 * Per outer iteration (BUDGETED+JITTER, 200 ms wall cap, fresh
 * topology) inside a userns_run_in_ns grandchild (identity userns +
 * CLONE_NEWNET, _exit reaps every veth, vlan child, netlink socket):
 * create a veth pair, bring both ends up, then pick one of four
 * churn arms iter%4:
 *   (A) single-vid: RTM_NEWLINK vlan@base vid=base_vid, then
 *       RTM_DELLINK the vlan child.  Minimal add/kill pair.
 *   (B) range: N=4 adjacent RTM_NEWLINK vlan devices at
 *       base_vid..base_vid+3 (each drives another vlan_vid_add on
 *       the same real_dev's vlan_info group), then RTM_DELLINK each
 *       in reverse (repeat vlan_vid_del).
 *   (C) overlap: NEWLINK vid=base_vid, second NEWLINK on the SAME
 *       vid via a differently-named vlan child -- expected -EEXIST
 *       inside vlan_check_real_dev, still walks the shared-vid
 *       validation path.
 *   (D) interleave: NEWLINK vid=base_vid+0, NEWLINK vid=base_vid+1,
 *       DELLINK vid=base_vid+0, NEWLINK vid=base_vid+2, DELLINK
 *       vid=base_vid+1 -- vlan_vid_add and vlan_vid_del interleaved
 *       against a live vlan_info group so the array walk sees mid-
 *       churn holes.
 * vid base rotates {10, 100, 3900} so each iteration hashes into a
 * different vlan_info bucket.  Full DELLINK of the base veth cascades
 * cleanup of any vlan children the arm did not explicitly drop.
 *
 * Brick-safety: everything runs in the grandchild's private netns;
 * host vlan tables never see the op.  No helper processes are forked
 * (all netlink is synchronous from the grandchild), so there is
 * nothing to reap beyond the userns_run_in_ns _exit teardown.  All
 * rtnl I/O has SO_RCVTIMEO=1s and every message is one-shot ACK so
 * the op inherits child.c's SIGALRM(1s) without extra guards.
 *
 * Latches: userns -EPERM permanently gates the op off for this
 * child.  ns_unsupported_vlan_filter_churn additionally short-
 * circuits the rest of an outer loop when the base-veth create OR
 * the first vlan-dev create is rejected with a structural errno
 * (-ENOSYS / -EAFNOSUPPORT / -EOPNOTSUPP / -EPROTONOSUPPORT), the
 * signal a CONFIG_VLAN_8021Q-absent or vlan-kmod-absent kernel
 * emits.  Header-gated by __has_include on <linux/if_link.h>,
 * <linux/if_vlan.h>, <linux/rtnetlink.h> with per-symbol UAPI
 * fallbacks for IFLA_VLAN_ID and VETH_INFO_PEER.
 */

#if __has_include(<linux/if_link.h>) && __has_include(<linux/if_vlan.h>) && __has_include(<linux/rtnetlink.h>)

#include <errno.h>
#include <net/if.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <linux/if_link.h>
#include <linux/if_vlan.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "child.h"
#include "childops-netlink.h"
#include "jitter.h"
#include "kernel/veth.h"
#include "name-pool.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "userns-bootstrap.h"

/* IFLA_VLAN_ID is an enum member (value 1 since the 2.4 8021q merge);
 * on stripped sysroots that predate the enum guard the fallback keeps
 * the build compiling. */
#ifndef IFLA_VLAN_ID
#define IFLA_VLAN_ID			1
#endif

#define VFC_OUTER_BASE			3U
#define VFC_OUTER_FLOOR			6U
#define VFC_OUTER_CAP			12U
#define VFC_WALL_CAP_NS			(200ULL * 1000ULL * 1000ULL)
#define VFC_RTNL_BUF			1024
#define VFC_RANGE_LEN			4U

/* Latched per-child on userns_run_in_ns() -EPERM (hardened policy:
 * user.max_user_namespaces=0 or kernel.unprivileged_userns_clone=0),
 * or inside the grandchild on a structural veth / vlan-dev create
 * rejection (CONFIG_VLAN_8021Q absent, or the vlan/veth kmod is not
 * loadable in this kernel).  Without a private netns we MUST NOT
 * touch the host vlan tables, so the op stays disabled for the
 * remainder of this child's lifetime.  The grandchild write dies
 * with the grandchild's COW copy on _exit(), which only short-
 * circuits the rest of the current invocation's outer loop. */
static bool ns_unsupported_vlan_filter_churn;

static int build_veth_create(struct nl_ctx *ctx, const char *name,
			     const char *peer)
{
	unsigned char buf[VFC_RTNL_BUF];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	struct ifinfomsg *peer_ifi;
	size_t off, li_off, id_off, peer_off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, name);
	if (!off)
		return -EIO;

	li_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_LINKINFO);
	if (!off)
		return -EIO;

	off = nla_put_str(buf, off, sizeof(buf), IFLA_INFO_KIND, "veth");
	if (!off)
		return -EIO;

	id_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_INFO_DATA);
	if (!off)
		return -EIO;

	peer_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), VETH_INFO_PEER);
	if (!off)
		return -EIO;

	if (off + NLMSG_ALIGN(sizeof(*peer_ifi)) > sizeof(buf))
		return -EIO;
	peer_ifi = (struct ifinfomsg *)(buf + off);
	memset(peer_ifi, 0, sizeof(*peer_ifi));
	peer_ifi->ifi_family = AF_UNSPEC;
	off += NLMSG_ALIGN(sizeof(*peer_ifi));

	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, peer);
	if (!off)
		return -EIO;

	nla_nest_end(buf, peer_off, off);
	nla_nest_end(buf, id_off, off);
	nla_nest_end(buf, li_off, off);

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * RTM_NEWLINK type=vlan with IFLA_LINK=base_idx and IFLA_INFO_DATA ->
 * IFLA_VLAN_ID=vid.  On accept, register_vlan_dev calls vlan_vid_add
 * against base_idx's real_dev and the vlan_info group grows by one
 * entry (drives ndo_vlan_rx_add_vid on drivers advertising
 * NETIF_F_HW_VLAN_CTAG_FILTER).  Returns 0 on accept, negated errno
 * on rejection.
 */
static int build_vlan_link(struct nl_ctx *ctx, int base_idx,
			   const char *name, __u16 vid)
{
	unsigned char buf[VFC_RTNL_BUF];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off, li_off, id_off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, name);
	if (!off)
		return -EIO;

	off = nla_put_u32(buf, off, sizeof(buf), IFLA_LINK, (__u32)base_idx);
	if (!off)
		return -EIO;

	li_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_LINKINFO);
	if (!off)
		return -EIO;

	off = nla_put_str(buf, off, sizeof(buf), IFLA_INFO_KIND, "vlan");
	if (!off)
		return -EIO;

	id_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_INFO_DATA);
	if (!off)
		return -EIO;

	off = nla_put_u16(buf, off, sizeof(buf), IFLA_VLAN_ID, vid);
	if (!off)
		return -EIO;

	nla_nest_end(buf, id_off, off);
	nla_nest_end(buf, li_off, off);

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * Per-iteration scratch carried across the setup / churn / teardown
 * helpers.  Lifetime is one iter_one() invocation; nl.fd is the only
 * sentinel-bearing handle (initialised to -1 by the orchestrator).
 * Vlan children indexes are populated as each vlan_link ack lands so
 * teardown can DELLINK them individually; a still-populated slot
 * whose corresponding index is 0 means the create was rejected and
 * cascade teardown of the base veth reaps whatever survived.
 */
struct vlan_filter_iter_ctx {
	struct nl_ctx	nl;
	char		base[IFNAMSIZ];
	char		peer[IFNAMSIZ];
	int		base_idx;
	int		peer_idx;
	int		vlan_idx[VFC_RANGE_LEN];
	bool		veth_added;
	__u16		vid_base;
	unsigned int	rng;
};

/*
 * Open the per-iteration NETLINK_ROUTE socket, name the veth pair
 * from a single random suffix, create the pair, look up ifindexes and
 * bring both ends up.  Picks the iteration's vid_base so later
 * helpers pull it straight off ctx.  Returns 0 on success; on failure
 * bumps setup_failed and (for structural rejections) latches the
 * op off for the remainder of the invocation.
 */
static int vlan_filter_iter_setup(struct vlan_filter_iter_ctx *it,
				  unsigned int iter_idx)
{
	struct nl_open_opts nl_opts = {
		.proto = NETLINK_ROUTE,
		.recv_timeo_s = 1,
	};
	__u16 vid_bases[3] = { 10, 100, 3900 };
	int rc;

	if (nl_open(&it->nl, &nl_opts) < 0) {
		__atomic_add_fetch(&shm->stats.vlan_filter_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}

	it->rng = (unsigned int)(rand32() & 0xffffu);
	snprintf(it->base, sizeof(it->base), "trvf%hu", (unsigned short)it->rng);
	snprintf(it->peer, sizeof(it->peer), "trvp%hu", (unsigned short)it->rng);

	rc = build_veth_create(&it->nl, it->base, it->peer);
	if (rc != 0) {
		if (rc == -EPERM || rc == -ENOSYS ||
		    rc == -EAFNOSUPPORT || rc == -EOPNOTSUPP ||
		    rc == -EPROTONOSUPPORT)
			ns_unsupported_vlan_filter_churn = true;
		__atomic_add_fetch(&shm->stats.vlan_filter_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	it->veth_added = true;
	__atomic_add_fetch(&shm->stats.vlan_filter_churn.veth_create_ok,
			   1, __ATOMIC_RELAXED);

	it->base_idx = (int)if_nametoindex(it->base);
	it->peer_idx = (int)if_nametoindex(it->peer);
	if (it->base_idx <= 0)
		return -1;

	name_pool_record(NAME_KIND_NETDEV, it->base, strlen(it->base));

	(void)rtnl_setlink_up(&it->nl, it->base_idx);
	if (it->peer_idx > 0)
		(void)rtnl_setlink_up(&it->nl, it->peer_idx);

	it->vid_base = vid_bases[iter_idx % 3U];
	return 0;
}

/*
 * Format a per-slot vlan child ifname: trvv<rng>_<slot>.  Slot-indexed
 * rather than vid-indexed so churn arm C (two children on the same
 * vid) gets distinct ifnames the second create can be evaluated
 * against.  Both fields are narrowed to unsigned short so -Wformat-
 * truncation can prove the "trvv" + up-to-5 + "_" + up-to-5 = 15
 * bytes upper bound fits inside IFNAMSIZ.
 */
static void vlan_child_name(const struct vlan_filter_iter_ctx *it,
			    unsigned int slot, char *out, size_t cap)
{
	snprintf(out, cap, "trvv%hu_%hu",
		 (unsigned short)it->rng, (unsigned short)slot);
}

static int vlan_child_add(struct vlan_filter_iter_ctx *it,
			  unsigned int slot, __u16 vid)
{
	char name[IFNAMSIZ];
	int rc;

	vlan_child_name(it, slot, name, sizeof(name));
	rc = build_vlan_link(&it->nl, it->base_idx, name, vid);
	if (rc != 0) {
		if (rc == -ENOSYS || rc == -EAFNOSUPPORT ||
		    rc == -EOPNOTSUPP || rc == -EPROTONOSUPPORT)
			ns_unsupported_vlan_filter_churn = true;
		return rc;
	}
	__atomic_add_fetch(&shm->stats.vlan_filter_churn.vlan_add_ok,
			   1, __ATOMIC_RELAXED);
	if (slot < VFC_RANGE_LEN)
		it->vlan_idx[slot] = (int)if_nametoindex(name);
	return 0;
}

static void vlan_child_del(struct vlan_filter_iter_ctx *it, unsigned int slot)
{
	if (slot >= VFC_RANGE_LEN)
		return;
	if (it->vlan_idx[slot] <= 0)
		return;
	if (rtnl_dellink(&it->nl, it->vlan_idx[slot]) == 0)
		__atomic_add_fetch(&shm->stats.vlan_filter_churn.vlan_del_ok,
				   1, __ATOMIC_RELAXED);
	it->vlan_idx[slot] = 0;
}

/*
 * Churn arm A: create one vlan child, then delete it.  Minimal
 * vlan_vid_add / vlan_vid_del pair against an otherwise-empty
 * vlan_info group on the base veth.
 */
static void vlan_filter_arm_single(struct vlan_filter_iter_ctx *it)
{
	if (vlan_child_add(it, 0, it->vid_base) != 0)
		return;
	vlan_child_del(it, 0);
}

/*
 * Churn arm B: create VFC_RANGE_LEN adjacent vlan children, then
 * delete them in reverse.  Each add extends the base's vlan_info
 * array; each del walks the array to find and drop its entry.
 */
static void vlan_filter_arm_range(struct vlan_filter_iter_ctx *it)
{
	unsigned int i;

	for (i = 0; i < VFC_RANGE_LEN; i++) {
		if (vlan_child_add(it, i, (__u16)(it->vid_base + i)) != 0)
			break;
	}
	for (i = VFC_RANGE_LEN; i > 0; i--)
		vlan_child_del(it, i - 1);
}

/*
 * Churn arm C: create one vlan child, attempt to create a second on
 * the same vid via a differently-named ifname (slot 1).  The second
 * add is expected to be rejected inside vlan_check_real_dev because
 * the vid already lives on base's vlan_info; the walk still runs.
 * Both children (if either survived) are dropped.
 */
static void vlan_filter_arm_overlap(struct vlan_filter_iter_ctx *it)
{
	(void)vlan_child_add(it, 0, it->vid_base);
	(void)vlan_child_add(it, 1, it->vid_base);
	vlan_child_del(it, 1);
	vlan_child_del(it, 0);
}

/*
 * Churn arm D: interleave add and del at neighbouring vids so the
 * vlan_info group has mid-churn holes when the next walk lands.
 *   add slot0 vid+0, add slot1 vid+1, del slot0, add slot2 vid+2,
 *   del slot1, del slot2.
 */
static void vlan_filter_arm_interleave(struct vlan_filter_iter_ctx *it)
{
	if (vlan_child_add(it, 0, it->vid_base) != 0)
		return;
	if (vlan_child_add(it, 1, (__u16)(it->vid_base + 1U)) != 0) {
		vlan_child_del(it, 0);
		return;
	}
	vlan_child_del(it, 0);
	(void)vlan_child_add(it, 2, (__u16)(it->vid_base + 2U));
	vlan_child_del(it, 1);
	vlan_child_del(it, 2);
}

static void vlan_filter_iter_churn(struct vlan_filter_iter_ctx *it,
				   unsigned int iter_idx)
{
	switch (iter_idx & 3U) {
	case 0: vlan_filter_arm_single(it); break;
	case 1: vlan_filter_arm_range(it); break;
	case 2: vlan_filter_arm_overlap(it); break;
	case 3: vlan_filter_arm_interleave(it); break;
	}
}

/*
 * Drop any vlan children still recorded (best-effort; a survivor gets
 * cascade-reaped by the base DELLINK below), then dellink the base
 * veth so unregister_netdev cascades any leftover children the arm
 * couldn't drop.  Only acts on handles the setup helper actually
 * established.
 */
static void vlan_filter_iter_teardown(struct vlan_filter_iter_ctx *it)
{
	unsigned int i;

	for (i = 0; i < VFC_RANGE_LEN; i++)
		vlan_child_del(it, i);

	if (it->veth_added && it->base_idx > 0)
		(void)rtnl_dellink(&it->nl, it->base_idx);
}

static void iter_one(unsigned int iter_idx, const struct timespec *t_outer,
		     struct childdata *child)
{
	struct vlan_filter_iter_ctx it = {
		.nl = { .fd = -1 },
	};
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if ((unsigned long long)ns_since(t_outer) >= VFC_WALL_CAP_NS)
		return;

	if (vlan_filter_iter_setup(&it, iter_idx) != 0)
		goto out;
	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	}

	if ((unsigned long long)ns_since(t_outer) >= VFC_WALL_CAP_NS)
		goto teardown;

	vlan_filter_iter_churn(&it, iter_idx);

teardown:
	vlan_filter_iter_teardown(&it);
out:
	nl_close(&it.nl);
}

struct vlan_filter_churn_ctx {
	struct childdata *child;
};

static int vlan_filter_churn_in_ns(void *arg)
{
	struct vlan_filter_churn_ctx *cctx = arg;
	struct childdata *child = cctx->child;
	struct timespec t_outer;
	unsigned int outer_iters, i;

	if (clock_gettime(CLOCK_MONOTONIC, &t_outer) < 0) {
		t_outer.tv_sec = 0;
		t_outer.tv_nsec = 0;
	}

	outer_iters = BUDGETED(CHILD_OP_VLAN_FILTER_CHURN,
			       JITTER_RANGE(VFC_OUTER_BASE));
	if (outer_iters < VFC_OUTER_FLOOR)
		outer_iters = VFC_OUTER_FLOOR;
	if (outer_iters > VFC_OUTER_CAP)
		outer_iters = VFC_OUTER_CAP;

	for (i = 0; i < outer_iters; i++) {
		if ((unsigned long long)ns_since(&t_outer) >= VFC_WALL_CAP_NS)
			break;

		iter_one(i, &t_outer, child);

		if (ns_unsupported_vlan_filter_churn)
			break;
	}

	return 0;
}

bool vlan_filter_churn(struct childdata *child)
{
	struct vlan_filter_churn_ctx cctx = { .child = child };
	int rc;

	__atomic_add_fetch(&shm->stats.vlan_filter_churn.runs,
			   1, __ATOMIC_RELAXED);

	if (ns_unsupported_vlan_filter_churn) {
		__atomic_add_fetch(&shm->stats.vlan_filter_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	rc = userns_run_in_ns(CLONE_NEWNET, vlan_filter_churn_in_ns, &cctx);
	if (rc == -EPERM) {
		ns_unsupported_vlan_filter_churn = true;
		{
			const enum child_op_type op = child->op_type;
			if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_NS_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		__atomic_add_fetch(&shm->stats.vlan_filter_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}
	if (rc < 0) {
		__atomic_add_fetch(&shm->stats.vlan_filter_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	return true;
}

#else  /* !__has_include(<linux/if_link.h> + <linux/if_vlan.h> + <linux/rtnetlink.h>) */

#include <stdbool.h>
#include "child.h"
#include "shm.h"

bool vlan_filter_churn(struct childdata *child)
{
	(void)child;

	__atomic_add_fetch(&shm->stats.vlan_filter_churn.runs,
			   1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.vlan_filter_churn.setup_failed,
			   1, __ATOMIC_RELAXED);
	return true;
}

#endif
