/*
 * bridge_vlan_churn - bridge VLAN-filtering rule churn vs tagged ingress.
 *
 * Target: net/bridge/br_vlan.c, br_vlan_tunnel.c, br_vlan_options.c,
 * br_mst.c -- specifically br_vlan_get_pvid / br_handle_vlan /
 * br_vlan_tunnel_lookup / br_mst_set_state.  Bug class: vlan-rcu
 * mutation racing an in-flight tagged skb.  Random netlink fuzzing
 * can't assemble the chain: a filtering-on bridge with enslaved ports,
 * a properly-nested IFLA_AF_SPEC/IFLA_BRIDGE_VLAN_INFO add, an
 * AF_PACKET peer pushing 802.1Q frames at a matching vid, plus a
 * concurrent vlan delete / vlan-tunnel mutation / MST topology change.
 *
 * Per outer iteration (BUDGETED+JITTER, 200 ms wall cap, fresh
 * topology), inside a private user+net namespace via userns_run_in_ns
 * (grandchild _exit reaps bridge/veths/vlan-info/sockets/netns): stand
 * up a filtering bridge with two veth pairs (v0a/v0b, v1a/v1b, only
 * the *a ends enslaved), install a vlan range [base..base+10] with
 * PVID base+5, IFF_UP everything, bind an AF_PACKET SOCK_RAW
 * (ETH_P_8021Q) to v0b, send one 802.1Q frame at the PVID, then race
 * one of four variants iter%4: (A) DELLINK VLAN_INFO drop vid base+5,
 * (B) SETLINK VLAN_TUNNEL_INFO add tunnel_id=42 on base+5, (C) SETLINK
 * BRIDGE_MST MSTI=1 STATE=BR_STATE_FORWARDING, (D) VLAN_INFO re-add
 * overlapping range base+3..base+7 (pvid swap).  vid base rotates
 * {10, 100, 4000}.  Full DELLINK teardown.
 *
 * Brick-safety: everything runs in the grandchild's private netns;
 * host bridge/veth/vlan tables never see the op; veth loopback only.
 * Outer loop (base 4/8/16, JITTER, 200 ms) + MSG_DONTWAIT / 100 ms
 * SO_{RCV,SND}TIMEO keep the op inside child.c's SIGALRM(1s).
 *
 * Latches: userns -EPERM permanently gates the op off for this child;
 * -EAGAIN skips.  The intra-invocation ns_unsupported_bridge_vlan_churn
 * short-circuits the rest of an outer loop on the bridge-create probe
 * (-ENOSYS/-EAFNOSUPPORT/-EOPNOTSUPP), dying with the grandchild's
 * COW copy so a CONFIG-absent kernel re-probes once per invocation.
 * Header-gated by __has_include on <linux/if_bridge.h>/if_link.h/
 * rtnetlink.h with per-symbol UAPI-integer fallbacks for
 * IFLA_BR_VLAN_FILTERING / IFLA_BRIDGE_* / BRIDGE_VLAN_INFO_* /
 * IFLA_BRIDGE_MST* / VETH_INFO_PEER.
 */

#if __has_include(<linux/if_bridge.h>) && __has_include(<linux/if_link.h>) && __has_include(<linux/rtnetlink.h>)

#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_packet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "child.h"
#include "childops-netlink.h"
#include "jitter.h"
#include "kernel/if_bridge.h"
#include "kernel/veth.h"
#include "name-pool.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "userns-bootstrap.h"

/* if_link.h on stripped sysroots may omit IFLA_BR_VLAN_FILTERING -- the
 * UAPI integer (7) is stable. */
#ifndef IFLA_BR_VLAN_FILTERING
#define IFLA_BR_VLAN_FILTERING		7
#endif

/* AF_BRIDGE = 7 across glibc / musl / kernel UAPI. */
#ifndef AF_BRIDGE
#define AF_BRIDGE			7
#endif

#define BVC_OUTER_BASE			4U
#define BVC_OUTER_FLOOR			8U
#define BVC_OUTER_CAP			16U
#define BVC_WALL_CAP_NS			(200ULL * 1000ULL * 1000ULL)
#define BVC_RAW_TIMEO_MS		100
#define BVC_RTNL_BUF			2048

/* Latched per-child: userns_run_in_ns() reported -EPERM, meaning the
 * grandchild's unshare(CLONE_NEWUSER) was refused by a hardened
 * policy (user.max_user_namespaces=0 or
 * kernel.unprivileged_userns_clone=0).  Without a private user+net
 * namespace we MUST NOT touch the host bridge / veth / vlan tables,
 * so the op stays disabled for the remainder of this child's
 * lifetime.  Transient helper failures (-EAGAIN) do not set this --
 * they may not recur on the next iteration.  Also set inside the
 * grandchild on a CONFIG-absent bridge create probe; that write dies
 * with the grandchild's COW copy on _exit() and only short-circuits
 * the rest of the current invocation's outer loop. */
static bool ns_unsupported_bridge_vlan_churn;

/*
 * RTM_NEWLINK type=bridge with IFLA_BR_VLAN_FILTERING=1 inside
 * IFLA_LINKINFO -> IFLA_INFO_DATA.  Returns 0 on accept, negated errno
 * on rejection.  Used both as the structural-support probe (first
 * invocation latches ns_unsupported_bridge_vlan_churn) and as the
 * per-iteration bridge create.
 */
static int build_bridge_create(struct nl_ctx *ctx, const char *name)
{
	unsigned char buf[BVC_RTNL_BUF];
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

	li_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_LINKINFO);
	if (!off)
		return -EIO;

	off = nla_put_str(buf, off, sizeof(buf), IFLA_INFO_KIND, "bridge");
	if (!off)
		return -EIO;

	id_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_INFO_DATA);
	if (!off)
		return -EIO;

	off = nla_put_u8(buf, off, sizeof(buf), IFLA_BR_VLAN_FILTERING, 1);
	if (!off)
		return -EIO;

	nla_nest_end(buf, id_off, off);
	nla_nest_end(buf, li_off, off);

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

static int build_veth_create(struct nl_ctx *ctx, const char *name,
			     const char *peer)
{
	unsigned char buf[BVC_RTNL_BUF];
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

static int build_setlink_master(struct nl_ctx *ctx, int ifindex,
				int master_ifindex)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_SETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = ifindex;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));
	off = nla_put_u32(buf, off, sizeof(buf), IFLA_MASTER,
			  (__u32)master_ifindex);
	if (!off)
		return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * Emit RTM_SETLINK / RTM_DELLINK family=AF_BRIDGE on a port (or
 * bridge), with IFLA_AF_SPEC nesting one or more
 * IFLA_BRIDGE_VLAN_INFO entries.  Both the single-vid and the
 * range-begin/range-end shapes route through the same primitive.
 *
 * If pvid is true and is_range is false, emit a single PVID flag bit on
 * the entry.  If is_range is true, emit a range-begin entry at vid, and
 * a range-end entry at vid_end.
 */
static int build_vlan_info(struct nl_ctx *ctx, __u16 nlmsg_type, int port_idx,
			   __u16 vid, __u16 vid_end,
			   bool is_range, bool pvid)
{
	unsigned char buf[512];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	struct bridge_vlan_info bvi;
	size_t off, af_off;
	__u16 br_flags = BRIDGE_FLAGS_MASTER;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = nlmsg_type;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_BRIDGE;
	ifi->ifi_index  = port_idx;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	af_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_AF_SPEC);
	if (!off)
		return -EIO;

	off = nla_put_u16(buf, off, sizeof(buf),
			  IFLA_BRIDGE_FLAGS, br_flags);
	if (!off)
		return -EIO;

	if (is_range) {
		bvi.flags = BRIDGE_VLAN_INFO_RANGE_BEGIN;
		bvi.vid   = vid;
		off = nla_put(buf, off, sizeof(buf),
			      IFLA_BRIDGE_VLAN_INFO, &bvi, sizeof(bvi));
		if (!off)
			return -EIO;

		bvi.flags = BRIDGE_VLAN_INFO_RANGE_END;
		bvi.vid   = vid_end;
		off = nla_put(buf, off, sizeof(buf),
			      IFLA_BRIDGE_VLAN_INFO, &bvi, sizeof(bvi));
		if (!off)
			return -EIO;
	} else {
		bvi.flags = pvid ? (BRIDGE_VLAN_INFO_PVID |
				    BRIDGE_VLAN_INFO_UNTAGGED) : 0;
		bvi.vid   = vid;
		off = nla_put(buf, off, sizeof(buf),
			      IFLA_BRIDGE_VLAN_INFO, &bvi, sizeof(bvi));
		if (!off)
			return -EIO;
	}

	nla_nest_end(buf, af_off, off);

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * RTM_SETLINK family=AF_BRIDGE on a port: IFLA_AF_SPEC ->
 * IFLA_BRIDGE_VLAN_TUNNEL_INFO { TUNNEL_VID, TUNNEL_ID, TUNNEL_FLAGS }.
 * Drives br_vlan_tunnel_info_add via the rarely-walked tunnel-info
 * attribute branch.
 */
static int build_vlan_tunnel_add(struct nl_ctx *ctx, int port_idx,
				 __u16 vid, __u32 tunnel_id)
{
	unsigned char buf[512];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off, af_off, ti_off;
	__u16 br_flags = BRIDGE_FLAGS_MASTER;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_SETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_BRIDGE;
	ifi->ifi_index  = port_idx;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	af_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_AF_SPEC);
	if (!off)
		return -EIO;

	off = nla_put_u16(buf, off, sizeof(buf),
			  IFLA_BRIDGE_FLAGS, br_flags);
	if (!off)
		return -EIO;

	ti_off = off;
	off = nla_nest_start(buf, off, sizeof(buf),
			     IFLA_BRIDGE_VLAN_TUNNEL_INFO);
	if (!off)
		return -EIO;

	off = nla_put_u32(buf, off, sizeof(buf),
			  IFLA_BRIDGE_VLAN_TUNNEL_ID, tunnel_id);
	if (!off)
		return -EIO;

	off = nla_put_u16(buf, off, sizeof(buf),
			  IFLA_BRIDGE_VLAN_TUNNEL_VID, vid);
	if (!off)
		return -EIO;

	off = nla_put_u16(buf, off, sizeof(buf),
			  IFLA_BRIDGE_VLAN_TUNNEL_FLAGS, 0);
	if (!off)
		return -EIO;

	nla_nest_end(buf, ti_off, off);
	nla_nest_end(buf, af_off, off);

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * RTM_SETLINK family=AF_BRIDGE on a port: IFLA_AF_SPEC ->
 * IFLA_BRIDGE_MST -> IFLA_BRIDGE_MST_ENTRY { MSTI, STATE }.
 * br_mst_set_state path; topology change while traffic flows.
 */
static int build_mst_set(struct nl_ctx *ctx, int port_idx,
			 __u16 msti, __u8 state)
{
	unsigned char buf[512];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off, af_off, mst_off, ent_off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_SETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_BRIDGE;
	ifi->ifi_index  = port_idx;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	af_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_AF_SPEC);
	if (!off)
		return -EIO;

	mst_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_BRIDGE_MST);
	if (!off)
		return -EIO;

	ent_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_BRIDGE_MST_ENTRY);
	if (!off)
		return -EIO;

	off = nla_put_u16(buf, off, sizeof(buf),
			  IFLA_BRIDGE_MST_ENTRY_MSTI, msti);
	if (!off)
		return -EIO;

	off = nla_put_u8(buf, off, sizeof(buf),
			 IFLA_BRIDGE_MST_ENTRY_STATE, state);
	if (!off)
		return -EIO;

	nla_nest_end(buf, ent_off, off);
	nla_nest_end(buf, mst_off, off);
	nla_nest_end(buf, af_off, off);

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * Build a synthetic 802.1Q tagged ethernet frame:
 *   dst (6) | src (6) | TPID 0x8100 | TCI (vid in low 12 bits) |
 *   inner ethertype 0x0800 (IPv4) | 32-byte zero payload.
 * Sized at 64 bytes.  Caller passes a buffer >=64 bytes.
 */
static void build_tagged_frame(unsigned char *frame, __u16 vid)
{
	memset(frame, 0xff, 6);              /* broadcast dst */
	frame[6]  = 0x02;                    /* locally-administered src */
	frame[7]  = 0x00; frame[8]  = 0x00;
	frame[9]  = 0x00; frame[10] = 0x00; frame[11] = 0x01;
	frame[12] = 0x81; frame[13] = 0x00;  /* TPID 802.1Q */
	frame[14] = (unsigned char)((vid >> 8) & 0x0f);
	frame[15] = (unsigned char)(vid & 0xff);
	frame[16] = 0x08; frame[17] = 0x00;  /* inner ETH_P_IP */
	memset(frame + 18, 0, 64 - 18);
}

static void apply_raw_timeouts(int s)
{
	struct timeval tv;

	tv.tv_sec  = 0;
	tv.tv_usec = BVC_RAW_TIMEO_MS * 1000;
	(void)setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	(void)setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

/*
 * Per-iteration scratch carried across the setup / load / race /
 * teardown helpers.  Lifetime is one iter_one() invocation; all
 * fields zero-initialised at the top of iter_one except the two
 * sentinel-bearing handles (nl.fd and raw).
 */
struct bridge_vlan_iter_ctx {
	struct nl_ctx	nl;
	char		br_name[IFNAMSIZ];
	char		v0a[IFNAMSIZ];
	char		v0b[IFNAMSIZ];
	char		v1a[IFNAMSIZ];
	char		v1b[IFNAMSIZ];
	int		raw;
	int		br_idx;
	int		v0a_idx;
	int		v0b_idx;
	int		v1a_idx;
	int		v1b_idx;
	bool		bridge_added;
	bool		veth0_added;
	bool		veth1_added;
	__u16		vid_base;
	__u16		pvid;
	__u16		range_end;
};

/*
 * Open the per-iteration NETLINK_ROUTE socket, name the bridge + the
 * two veth pairs from a single random suffix, create the bridge with
 * IFLA_BR_VLAN_FILTERING=1, create both veth pairs, look up their
 * ifindexes, and enslave the v0a / v1a ends to the bridge.  Also
 * picks the iteration's vid_base / pvid / range_end so later helpers
 * can pull them straight off ctx.
 *
 * Returns 0 on success.  Nonzero means the caller should jump
 * straight to the cleanup path: nl_open / bridge create failures get
 * counted as setup_failed here; structurally-unsupported bridge
 * create rejections additionally latch ns_unsupported_bridge_vlan_churn
 * so subsequent invocations short-circuit.
 */
static int bridge_vlan_iter_setup(struct bridge_vlan_iter_ctx *it,
				  unsigned int iter_idx,
				  struct childdata *child)
{
	struct nl_open_opts nl_opts = {
		.proto = NETLINK_ROUTE,
		.recv_timeo_s = 1,
	};
	__u16 vid_bases[3] = { 10, 100, 4000 };
	unsigned int rng;
	int rc;
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * write entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (nl_open(&it->nl, &nl_opts) < 0) {
		__atomic_add_fetch(&shm->stats.bridge_vlan_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}

	rng = (unsigned int)(rand32() & 0xffffu);
	snprintf(it->br_name, sizeof(it->br_name), "trvbr%u", rng);
	snprintf(it->v0a, sizeof(it->v0a), "trvb%ua0", rng);
	snprintf(it->v0b, sizeof(it->v0b), "trvb%ub0", rng);
	snprintf(it->v1a, sizeof(it->v1a), "trvb%ua1", rng);
	snprintf(it->v1b, sizeof(it->v1b), "trvb%ub1", rng);

	rc = build_bridge_create(&it->nl, it->br_name);
	if (rc != 0) {
		if (rc == -EPERM || rc == -ENOSYS ||
		    rc == -EAFNOSUPPORT || rc == -EOPNOTSUPP ||
		    rc == -EPROTONOSUPPORT) {
			ns_unsupported_bridge_vlan_churn = true;
			if (valid_op)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_NS_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		__atomic_add_fetch(&shm->stats.bridge_vlan_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	it->bridge_added = true;
	__atomic_add_fetch(&shm->stats.bridge_vlan_churn.bridge_create_ok,
			   1, __ATOMIC_RELAXED);

	it->br_idx = (int)if_nametoindex(it->br_name);
	if (it->br_idx == 0)
		return -1;

	/* Kernel confirmed it->br_name now names a real bridge; publish it
	 * via the NETDEV name pool so sibling childops (and per-syscall
	 * fuzzers drawing this kind) can collide with it on subsequent
	 * invocations.  Only the bridge master is recorded -- the per-kind
	 * ring is 16 slots so flooding it with the four veth leaves would
	 * thrash the pool. */
	name_pool_record(NAME_KIND_NETDEV, it->br_name, strlen(it->br_name));

	if (build_veth_create(&it->nl, it->v0a, it->v0b) == 0) {
		it->veth0_added = true;
		__atomic_add_fetch(&shm->stats.bridge_vlan_churn.veth_create_ok,
				   1, __ATOMIC_RELAXED);
		it->v0a_idx = (int)if_nametoindex(it->v0a);
		it->v0b_idx = (int)if_nametoindex(it->v0b);
	}
	if (build_veth_create(&it->nl, it->v1a, it->v1b) == 0) {
		it->veth1_added = true;
		__atomic_add_fetch(&shm->stats.bridge_vlan_churn.veth_create_ok,
				   1, __ATOMIC_RELAXED);
		it->v1a_idx = (int)if_nametoindex(it->v1a);
		it->v1b_idx = (int)if_nametoindex(it->v1b);
	}

	if (it->v0a_idx > 0)
		(void)build_setlink_master(&it->nl, it->v0a_idx, it->br_idx);
	if (it->v1a_idx > 0)
		(void)build_setlink_master(&it->nl, it->v1a_idx, it->br_idx);

	it->vid_base  = vid_bases[iter_idx % 3U];
	it->pvid      = (__u16)(it->vid_base + 5U);
	it->range_end = (__u16)(it->vid_base + 10U);

	return 0;
}

/*
 * Stand up the VLAN configuration on v0a: range add covering
 * vid_base..range_end (drives the br_vlan_add range path), then a
 * single PVID add at pvid (the vid the AF_PACKET sender will tag
 * frames with).  Finishes by bringing the bridge and every veth end
 * IFF_UP so ingress can flow through the freshly-populated per-port
 * vlan group.  Best-effort: every netlink is fire-and-forget with
 * its own stats bump on accept, no early-out.
 */
static void bridge_vlan_iter_add_vlan(struct bridge_vlan_iter_ctx *it)
{
	/* Range add of vid_base..range_end on v0a. */
	if (it->v0a_idx > 0) {
		if (build_vlan_info(&it->nl, RTM_SETLINK, it->v0a_idx,
				    it->vid_base, it->range_end,
				    true, false) == 0)
			__atomic_add_fetch(&shm->stats.bridge_vlan_churn.vlan_add_ok,
					   1, __ATOMIC_RELAXED);
		/* Single PVID add at pvid. */
		if (build_vlan_info(&it->nl, RTM_SETLINK, it->v0a_idx,
				    it->pvid, 0, false, true) == 0)
			__atomic_add_fetch(&shm->stats.bridge_vlan_churn.vlan_add_ok,
					   1, __ATOMIC_RELAXED);
	}

	(void)rtnl_setlink_up(&it->nl, it->br_idx);
	if (it->v0a_idx > 0) (void)rtnl_setlink_up(&it->nl, it->v0a_idx);
	if (it->v0b_idx > 0) (void)rtnl_setlink_up(&it->nl, it->v0b_idx);
	if (it->v1a_idx > 0) (void)rtnl_setlink_up(&it->nl, it->v1a_idx);
	if (it->v1b_idx > 0) (void)rtnl_setlink_up(&it->nl, it->v1b_idx);
}

/*
 * Open an AF_PACKET / SOCK_RAW socket on v0b (the free end of the
 * first veth pair), bind it to v0b's ifindex with ETH_P_8021Q, and
 * push one 802.1Q-tagged frame at the configured PVID.  The first
 * send drives br_handle_vlan against the still-fresh per-port vlan
 * group, primed for the race in the next phase.  Socket open / bind
 * failures are swallowed -- the rest of the iteration runs (the
 * second-send half of the race helper just skips on raw < 0).
 */
static void bridge_vlan_iter_open_raw(struct bridge_vlan_iter_ctx *it)
{
	struct sockaddr_ll sll;
	unsigned char frame[64];
	ssize_t n;

	if (it->v0b_idx <= 0)
		return;

	it->raw = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC,
			 htons(ETH_P_8021Q));
	if (it->raw < 0)
		return;

	apply_raw_timeouts(it->raw);
	memset(&sll, 0, sizeof(sll));
	sll.sll_family   = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_8021Q);
	sll.sll_ifindex  = it->v0b_idx;
	(void)bind(it->raw, (struct sockaddr *)&sll, sizeof(sll));

	build_tagged_frame(frame, it->pvid);
	memset(&sll, 0, sizeof(sll));
	sll.sll_family   = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_8021Q);
	sll.sll_ifindex  = it->v0b_idx;
	sll.sll_halen    = 6;
	memset(sll.sll_addr, 0xff, 6);

	n = sendto(it->raw, frame, sizeof(frame), MSG_DONTWAIT,
		   (struct sockaddr *)&sll, sizeof(sll));
	if (n > 0)
		__atomic_add_fetch(&shm->stats.bridge_vlan_churn.raw_send_ok,
				   1, __ATOMIC_RELAXED);
}

/*
 * Race phase: rotate one of four mutations against the in-flight
 * traffic, then push a second tagged frame so the racing op overlaps
 * a live ingress walk.
 *
 *   A (iter%4==0): RTM_DELLINK family=AF_BRIDGE delete vid pvid --
 *                  vlan-rcu vs ingress lookup.
 *   B (iter%4==1): RTM_SETLINK IFLA_BRIDGE_VLAN_TUNNEL_INFO add at
 *                  tunnel_id=42 on pvid -- br_vlan_tunnel parse path.
 *   C (iter%4==2): RTM_SETLINK IFLA_BRIDGE_MST entry STATE=FORWARDING
 *                  -- br_mst_set_state topology change mid-traffic.
 *   D (iter%4==3): re-issue an overlapping range add (base+3..base+7)
 *                  -- pvid swap window inside br_vlan_add range path.
 */
static void bridge_vlan_iter_race(struct bridge_vlan_iter_ctx *it,
				  unsigned int iter_idx)
{
	struct sockaddr_ll sll;
	unsigned char frame[64];
	unsigned int race_letter = iter_idx & 3U;
	ssize_t n;

	switch (race_letter) {
	case 0:
		/* RACE A: delete vid pvid mid-flight. */
		if (it->v0a_idx > 0 &&
		    build_vlan_info(&it->nl, RTM_DELLINK, it->v0a_idx,
				    it->pvid, 0, false, false) == 0)
			__atomic_add_fetch(&shm->stats.bridge_vlan_churn.vlan_del_ok,
					   1, __ATOMIC_RELAXED);
		break;
	case 1:
		/* RACE B: vlan-tunnel add. */
		if (it->v0a_idx > 0 &&
		    build_vlan_tunnel_add(&it->nl, it->v0a_idx,
					  it->pvid, 42U) == 0)
			__atomic_add_fetch(&shm->stats.bridge_vlan_churn.tunnel_add_ok,
					   1, __ATOMIC_RELAXED);
		break;
	case 2:
		/* RACE C: MST topology change on the port. */
		if (it->v0a_idx > 0 &&
		    build_mst_set(&it->nl, it->v0a_idx, 1U,
				  (__u8)BR_STATE_FORWARDING) == 0)
			__atomic_add_fetch(&shm->stats.bridge_vlan_churn.mst_set_ok,
					   1, __ATOMIC_RELAXED);
		break;
	case 3:
		/* RACE D: re-issue overlapping range add. */
		if (it->v0a_idx > 0 &&
		    build_vlan_info(&it->nl, RTM_SETLINK, it->v0a_idx,
				    (__u16)(it->vid_base + 3U),
				    (__u16)(it->vid_base + 7U),
				    true, false) == 0)
			__atomic_add_fetch(&shm->stats.bridge_vlan_churn.vlan_add_ok,
					   1, __ATOMIC_RELAXED);
		break;
	}

	/* Second tagged send while the race is in flight. */
	if (it->raw < 0)
		return;

	build_tagged_frame(frame, it->pvid);
	memset(&sll, 0, sizeof(sll));
	sll.sll_family   = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_8021Q);
	sll.sll_ifindex  = it->v0b_idx;
	sll.sll_halen    = 6;
	memset(sll.sll_addr, 0xff, 6);

	n = sendto(it->raw, frame, sizeof(frame), MSG_DONTWAIT,
		   (struct sockaddr *)&sll, sizeof(sll));
	if (n > 0)
		__atomic_add_fetch(&shm->stats.bridge_vlan_churn.raw_send_ok,
				   1, __ATOMIC_RELAXED);
}

/*
 * Shutdown + close the raw AF_PACKET socket, then dellink the bridge
 * first so br_dev_delete cascades through every enslaved port -- that
 * cascade is the racing teardown half of the iteration: any rx still
 * draining is freed underneath the bridge's port-walk.  Surviving
 * unenslaved veth ends get a follow-up dellink so the netns doesn't
 * accumulate orphans across iterations.  Only acts on handles the
 * setup helper actually established (added flags + ifindex > 0).
 */
static void bridge_vlan_iter_teardown(struct bridge_vlan_iter_ctx *it)
{
	if (it->raw >= 0) {
		(void)shutdown(it->raw, SHUT_RDWR);
		close(it->raw);
		it->raw = -1;
	}

	if (it->bridge_added && it->br_idx > 0)
		(void)rtnl_dellink(&it->nl, it->br_idx);
	if (it->veth0_added && it->v0a_idx > 0)
		(void)rtnl_dellink(&it->nl, it->v0a_idx);
	if (it->veth1_added && it->v1a_idx > 0)
		(void)rtnl_dellink(&it->nl, it->v1a_idx);
}

/*
 * One full create / load / race / teardown cycle on a freshly-named
 * bridge + 2 veth pairs.  Wall-clock cap inherited from the caller.
 * child is threaded through purely for per-childop yield attribution
 * (setup_accepted / data_path / latch_reason) -- the rest of the iter
 * state still lives in the locally zero-initialised bridge_vlan_iter_ctx.
 */
static void iter_one(unsigned int iter_idx, const struct timespec *t_outer,
		     struct childdata *child)
{
	struct bridge_vlan_iter_ctx it = {
		.nl  = { .fd = -1 },
		.raw = -1,
	};
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if ((unsigned long long)ns_since(t_outer) >= BVC_WALL_CAP_NS)
		return;

	if (bridge_vlan_iter_setup(&it, iter_idx, child) != 0)
		goto out;
	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	}
	bridge_vlan_iter_add_vlan(&it);
	bridge_vlan_iter_open_raw(&it);

	if ((unsigned long long)ns_since(t_outer) >= BVC_WALL_CAP_NS)
		goto teardown;

	bridge_vlan_iter_race(&it, iter_idx);

teardown:
	bridge_vlan_iter_teardown(&it);
out:
	if (it.raw >= 0)
		close(it.raw);
	nl_close(&it.nl);
}

/*
 * Per-invocation state handed to the in-ns callback so iter_one's
 * stats writes keep landing against the right childop slot.
 */
struct bridge_vlan_churn_ctx {
	struct childdata *child;
};

/*
 * Per-invocation body that must run inside the private net namespace.
 * Executed in a transient grandchild forked by userns_run_in_ns(); the
 * grandchild's userns + netns are torn down on _exit() so every
 * bridge, veth, vlan-info entry, AF_PACKET socket and netlink socket
 * the BUDGETED outer loop opens is reaped by the kernel along with
 * the namespace.  Return value is ignored by the helper.
 */
static int bridge_vlan_churn_in_ns(void *arg)
{
	struct bridge_vlan_churn_ctx *cctx = arg;
	struct childdata *child = cctx->child;
	struct timespec t_outer;
	unsigned int outer_iters, i;

	if (clock_gettime(CLOCK_MONOTONIC, &t_outer) < 0) {
		t_outer.tv_sec = 0;
		t_outer.tv_nsec = 0;
	}

	outer_iters = BUDGETED(CHILD_OP_BRIDGE_VLAN_CHURN,
			       JITTER_RANGE(BVC_OUTER_BASE));
	if (outer_iters < BVC_OUTER_FLOOR)
		outer_iters = BVC_OUTER_FLOOR;
	if (outer_iters > BVC_OUTER_CAP)
		outer_iters = BVC_OUTER_CAP;

	for (i = 0; i < outer_iters; i++) {
		if ((unsigned long long)ns_since(&t_outer) >=
		    BVC_WALL_CAP_NS)
			break;

		iter_one(i, &t_outer, child);

		if (ns_unsupported_bridge_vlan_churn)
			break;
	}

	return 0;
}

bool bridge_vlan_churn(struct childdata *child)
{
	struct bridge_vlan_churn_ctx cctx = { .child = child };
	int rc;

	__atomic_add_fetch(&shm->stats.bridge_vlan_churn.runs,
			   1, __ATOMIC_RELAXED);

	if (ns_unsupported_bridge_vlan_churn) {
		__atomic_add_fetch(&shm->stats.bridge_vlan_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	rc = userns_run_in_ns(CLONE_NEWNET, bridge_vlan_churn_in_ns, &cctx);
	if (rc == -EPERM) {
		ns_unsupported_bridge_vlan_churn = true;
		/* child->op_type lives in shared memory and can be scribbled
		 * by a poisoned-arena write from a sibling; bounds-check the
		 * snapshot before indexing the NR_CHILD_OP_TYPES-sized stats
		 * array. */
		{
			const enum child_op_type op = child->op_type;
			if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_NS_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		__atomic_add_fetch(&shm->stats.bridge_vlan_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}
	if (rc < 0) {
		/* Transient grandchild setup failure (fork, id-map write,
		 * secondary unshare).  Skip this iteration without latching
		 * -- the failure is not policy and may not recur. */
		__atomic_add_fetch(&shm->stats.bridge_vlan_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	return true;
}

#else  /* !__has_include(<linux/if_bridge.h> + <linux/if_link.h> + <linux/rtnetlink.h>) */

#include <stdbool.h>
#include "child.h"
#include "shm.h"

#include "kernel/socket.h"
bool bridge_vlan_churn(struct childdata *child)
{
	(void)child;

	__atomic_add_fetch(&shm->stats.bridge_vlan_churn.runs,
			   1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.bridge_vlan_churn.setup_failed,
			   1, __ATOMIC_RELAXED);
	return true;
}

#endif
