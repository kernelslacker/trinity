/*
 * flowtable_encap_vlan - nf flowtable inline 802.1Q encap exerciser.
 *
 * Target: net/netfilter/nf_flow_table_offload.c's vlan-push fast path
 * -- inline-encap headroom, checksum, and GSO-resegment (fix bundle
 * for skip-rechecksum-after-vlan-push, reserve-headroom-for-shared-
 * encap, and re-checksum-GSO-segments-after-inline-vlan).  Random
 * netfilter fuzzing can't assemble the shape: two vlan netdevs on a
 * veth, an nft_flow_offload rule on a forward chain whose flowtable
 * references both, a conntrack-tracked flow across both legs, then
 * GSO-large + MTU-borderline + vlan-child teardown racing live traffic.
 *
 * Per outer iteration (BUDGETED+JITTER, 200 ms wall cap), inside a
 * private user+net namespace via userns_run_in_ns (grandchild _exit
 * reaps ifaces/rules/addrs/sockets/netns): create a veth pair with
 * vlan 100 on each leg, disjoint 192.0.2.0/30 addrs, IFF_UP, enable
 * ip_forward, stand up an nft table + flowtable (NF_NETDEV_INGRESS on
 * both vlan devs) + forward chain + flow_offload rule, then burst
 * three traffic shapes: (A) 1400-byte UDP for baseline offload, (B)
 * SYN + a 64KB TCP write to hit the GSO+vlan re-checksum path, (C)
 * 1496-byte UDP for the MTU-borderline shared-encap headroom, with a
 * coin-flip mid-burst RTM_DELLINK on vp_a.100 racing offload-entry
 * expiry.  Full DELRULE/DELCHAIN/DELFLOWTABLE/DELTABLE teardown.
 *
 * Brick-safety: everything runs in the grandchild's private netns;
 * host tables never see this op; veth is loopback only.  Outer loop
 * (base 4/4/16, JITTER, 200 ms) + MSG_DONTWAIT / SO_RCVTIMEO=1s keep
 * the op inside child.c's SIGALRM(1s).
 *
 * Latches: userns -EPERM permanently gates the op off for this child;
 * -EAGAIN skips without latching.  ns_unsupported_flowtable_vlan fires
 * on the first NEWFLOWTABLE EOPNOTSUPP/EAFNOSUPPORT/EPROTONOSUPPORT
 * (CONFIG_NF_FLOW_TABLE absent).  Header-gated by __has_include on
 * <linux/if_link.h>/<linux/netfilter/nf_tables.h>/<nfnetlink.h> with
 * per-symbol UAPI-integer fallbacks for NFT_MSG_NEWFLOWTABLE /
 * NFTA_FLOWTABLE_* / IFLA_VLAN_ID / VETH_INFO_PEER.
 */

#if __has_include(<linux/if_link.h>) && \
    __has_include(<linux/netfilter/nf_tables.h>) && \
    __has_include(<linux/netfilter/nfnetlink.h>)

#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "child.h"
#include "childops-netlink.h"
#include "childops-nfnl.h"
#include "jitter.h"
#include "kernel/nf_tables.h"
#include "name-pool.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "userns-bootstrap.h"

#ifndef IFLA_VLAN_ID
#define IFLA_VLAN_ID			1
#endif
#ifndef NFNL_SUBSYS_NFTABLES
#define NFNL_SUBSYS_NFTABLES		10
#endif

/* NF_INET_FORWARD = 2, NF_NETDEV_INGRESS = 0, NFPROTO_IPV4 = 2 — all
 * stable UAPI integers; redefine if the sysroot strips them. */
#ifndef NF_INET_FORWARD
#define NF_INET_FORWARD			2
#endif
#ifndef NF_NETDEV_INGRESS
#define NF_NETDEV_INGRESS		0
#endif
#ifndef NFPROTO_IPV4
#define NFPROTO_IPV4			2
#endif

#define FEV_OUTER_BASE			4U
#define FEV_OUTER_FLOOR			4U
#define FEV_OUTER_CAP			16U
#define FEV_WALL_CAP_NS			(200ULL * 1000ULL * 1000ULL)
#define FEV_NL_TIMEO_S			1
#define FEV_RTNL_BUF			2048
#define FEV_NFNL_BUF			1024
#define FEV_GSO_PAYLOAD			(64U * 1024U)
#define FEV_MTU_BORDER_PAYLOAD		1496U

/* Latched per-child by two paths:
 *   - userns_run_in_ns() returned -EPERM: the grandchild's
 *     unshare(CLONE_NEWUSER) was refused by a hardened policy
 *     (user.max_user_namespaces=0 or kernel.unprivileged_userns_clone=0).
 *     Set in the wrapper, persists across invocations.  Without a
 *     private netns we MUST NOT touch the host's main flowtable / vlan
 *     / veth tables, so the op stays disabled for the remainder of this
 *     child's lifetime.
 *   - NFT_MSG_NEWFLOWTABLE returned EOPNOTSUPP / EAFNOSUPPORT /
 *     EPROTONOSUPPORT inside the grandchild's iter_install()
 *     (CONFIG_NF_FLOW_TABLE absent at runtime).  Set inside the
 *     grandchild's address space, so the latch short-circuits the rest
 *     of that grandchild's outer loop; the persistent child's copy is
 *     unchanged, and subsequent invocations re-discover the CONFIG-
 *     absent state via one NEWFLOWTABLE round-trip per outer-loop iter.
 * Helper return -EAGAIN (transient grandchild setup failure: fork, id-map
 * write, secondary unshare) does NOT set this latch -- the failure is
 * not policy and may not recur on the next invocation. */
static bool ns_unsupported_flowtable_vlan;
static bool fev_ip_forward_set;

static size_t nla_put_be32(unsigned char *buf, size_t off, size_t cap,
			   unsigned short type, __u32 v)
{
	__u32 be = htonl(v);
	return nla_put(buf, off, cap, type, &be, sizeof(be));
}

static int build_veth_pair(struct nl_ctx *rtnl, const char *name,
			   const char *peer)
{
	unsigned char buf[FEV_RTNL_BUF];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi, *peer_ifi;
	size_t off, li_off, id_off, peer_off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(rtnl);
	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, name);
	if (!off) return -EIO;
	li_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_LINKINFO);
	if (!off) return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), IFLA_INFO_KIND, "veth");
	if (!off) return -EIO;
	id_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_INFO_DATA);
	if (!off) return -EIO;
	peer_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), VETH_INFO_PEER);
	if (!off) return -EIO;
	if (off + NLMSG_ALIGN(sizeof(*peer_ifi)) > sizeof(buf))
		return -EIO;
	peer_ifi = (struct ifinfomsg *)(buf + off);
	memset(peer_ifi, 0, sizeof(*peer_ifi));
	peer_ifi->ifi_family = AF_UNSPEC;
	off += NLMSG_ALIGN(sizeof(*peer_ifi));
	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, peer);
	if (!off) return -EIO;

	nla_nest_end(buf, peer_off, off);
	nla_nest_end(buf, id_off, off);
	nla_nest_end(buf, li_off, off);
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(rtnl, buf, off);
}

static int build_vlan_child(struct nl_ctx *rtnl, const char *name,
			    int link_idx, __u16 vid)
{
	unsigned char buf[FEV_RTNL_BUF];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off, li_off, id_off;
	__u16 v = vid;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(rtnl);
	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	off = nla_put_u32(buf, off, sizeof(buf), IFLA_LINK, (__u32)link_idx);
	if (!off) return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, name);
	if (!off) return -EIO;
	li_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_LINKINFO);
	if (!off) return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), IFLA_INFO_KIND, "vlan");
	if (!off) return -EIO;
	id_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_INFO_DATA);
	if (!off) return -EIO;
	off = nla_put(buf, off, sizeof(buf), IFLA_VLAN_ID, &v, sizeof(v));
	if (!off) return -EIO;

	nla_nest_end(buf, id_off, off);
	nla_nest_end(buf, li_off, off);
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(rtnl, buf, off);
}

static int build_addaddr(struct nl_ctx *rtnl, int ifindex, __u32 addr_be,
			 __u8 plen)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct ifaddrmsg *ifa;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWADDR;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(rtnl);
	ifa = (struct ifaddrmsg *)NLMSG_DATA(nlh);
	ifa->ifa_family    = AF_INET;
	ifa->ifa_prefixlen = plen;
	ifa->ifa_scope     = RT_SCOPE_UNIVERSE;
	ifa->ifa_index     = (unsigned int)ifindex;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifa));
	off = nla_put(buf, off, sizeof(buf), IFA_LOCAL, &addr_be, sizeof(addr_be));
	if (!off) return -EIO;
	off = nla_put(buf, off, sizeof(buf), IFA_ADDRESS, &addr_be, sizeof(addr_be));
	if (!off) return -EIO;
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(rtnl, buf, off);
}

static int build_nft_table(struct nfnl_ctx *nf, const char *table)
{
	unsigned char buf[FEV_NFNL_BUF];
	size_t off;

	memset(buf, 0, sizeof(buf));
	off = nfnl_msg_put(buf, 0, sizeof(buf), nl_seq_next(&nf->nl),
			   NFNL_SUBSYS_NFTABLES, NFT_MSG_NEWTABLE,
			   NLM_F_CREATE | NLM_F_EXCL, NFPROTO_IPV4);
	if (!off) return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), NFTA_TABLE_NAME, table);
	if (!off) return -EIO;
	off = nla_put_be32(buf, off, sizeof(buf), NFTA_TABLE_FLAGS, 0);
	if (!off) return -EIO;
	((struct nlmsghdr *)buf)->nlmsg_len = (__u32)off;
	return nfnl_send_recv(nf, buf, off);
}

static int build_nft_chain_fwd(struct nfnl_ctx *nf, const char *table,
			       const char *chain)
{
	unsigned char buf[FEV_NFNL_BUF];
	size_t off, hk_off;
	__u32 hooknum = htonl(NF_INET_FORWARD);
	__u32 prio    = htonl(0);

	memset(buf, 0, sizeof(buf));
	off = nfnl_msg_put(buf, 0, sizeof(buf), nl_seq_next(&nf->nl),
			   NFNL_SUBSYS_NFTABLES, NFT_MSG_NEWCHAIN,
			   NLM_F_CREATE | NLM_F_EXCL, NFPROTO_IPV4);
	if (!off) return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), NFTA_CHAIN_TABLE, table);
	if (!off) return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), NFTA_CHAIN_NAME, chain);
	if (!off) return -EIO;
	hk_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), NFTA_CHAIN_HOOK);
	if (!off) return -EIO;
	off = nla_put(buf, off, sizeof(buf), NFTA_HOOK_HOOKNUM, &hooknum,
		      sizeof(hooknum));
	if (!off) return -EIO;
	off = nla_put(buf, off, sizeof(buf), NFTA_HOOK_PRIORITY, &prio,
		      sizeof(prio));
	if (!off) return -EIO;
	nla_nest_end(buf, hk_off, off);
	off = nla_put_str(buf, off, sizeof(buf), NFTA_CHAIN_TYPE, "filter");
	if (!off) return -EIO;
	((struct nlmsghdr *)buf)->nlmsg_len = (__u32)off;
	return nfnl_send_recv(nf, buf, off);
}

static int build_nft_flowtable(struct nfnl_ctx *nf, const char *table,
			       const char *ftname,
			       const char *dev_a, const char *dev_b)
{
	unsigned char buf[FEV_NFNL_BUF];
	size_t off, hk_off, devs_off, e1_off, e2_off;
	__u32 hooknum = htonl(NF_NETDEV_INGRESS);
	__u32 prio    = htonl(0);

	memset(buf, 0, sizeof(buf));
	off = nfnl_msg_put(buf, 0, sizeof(buf), nl_seq_next(&nf->nl),
			   NFNL_SUBSYS_NFTABLES, NFT_MSG_NEWFLOWTABLE,
			   NLM_F_CREATE | NLM_F_EXCL, NFPROTO_IPV4);
	if (!off) return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), NFTA_FLOWTABLE_TABLE, table);
	if (!off) return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), NFTA_FLOWTABLE_NAME, ftname);
	if (!off) return -EIO;
	hk_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), NFTA_FLOWTABLE_HOOK);
	if (!off) return -EIO;
	off = nla_put(buf, off, sizeof(buf), NFTA_FLOWTABLE_HOOK_NUM,
		      &hooknum, sizeof(hooknum));
	if (!off) return -EIO;
	off = nla_put(buf, off, sizeof(buf), NFTA_FLOWTABLE_HOOK_PRIORITY,
		      &prio, sizeof(prio));
	if (!off) return -EIO;
	devs_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), NFTA_FLOWTABLE_HOOK_DEVS);
	if (!off) return -EIO;
	e1_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), NFTA_LIST_ELEM);
	if (!off) return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), NFTA_DEVICE_NAME, dev_a);
	if (!off) return -EIO;
	nla_nest_end(buf, e1_off, off);
	e2_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), NFTA_LIST_ELEM);
	if (!off) return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), NFTA_DEVICE_NAME, dev_b);
	if (!off) return -EIO;
	nla_nest_end(buf, e2_off, off);
	nla_nest_end(buf, devs_off, off);
	nla_nest_end(buf, hk_off, off);
	((struct nlmsghdr *)buf)->nlmsg_len = (__u32)off;
	return nfnl_send_recv(nf, buf, off);
}

/*
 * NFT_MSG_NEWRULE on (table, chain) carrying one nft_flow_offload
 * expression.  flow_offload's init validator only checks the chain's
 * family and forward-hook binding — no prior expression dependency —
 * so a bare flow_offload is accepted on any forward chain with the
 * named flowtable in the same table.
 */
static int build_nft_rule_flow_offload(struct nfnl_ctx *nf, const char *table,
				       const char *chain, const char *ftname)
{
	unsigned char buf[FEV_NFNL_BUF];
	size_t off, ex_off, el_off, da_off;

	memset(buf, 0, sizeof(buf));
	off = nfnl_msg_put(buf, 0, sizeof(buf), nl_seq_next(&nf->nl),
			   NFNL_SUBSYS_NFTABLES, NFT_MSG_NEWRULE,
			   NLM_F_CREATE | NLM_F_APPEND, NFPROTO_IPV4);
	if (!off) return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), NFTA_RULE_TABLE, table);
	if (!off) return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), NFTA_RULE_CHAIN, chain);
	if (!off) return -EIO;
	ex_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), NFTA_RULE_EXPRESSIONS);
	if (!off) return -EIO;
	el_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), NFTA_LIST_ELEM);
	if (!off) return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), NFTA_EXPR_NAME, "flow_offload");
	if (!off) return -EIO;
	da_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), NFTA_EXPR_DATA);
	if (!off) return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), NFTA_FLOW_TABLE_NAME, ftname);
	if (!off) return -EIO;
	nla_nest_end(buf, da_off, off);
	nla_nest_end(buf, el_off, off);
	nla_nest_end(buf, ex_off, off);
	((struct nlmsghdr *)buf)->nlmsg_len = (__u32)off;
	return nfnl_send_recv(nf, buf, off);
}

static int build_nft_simple_del(struct nfnl_ctx *nf, __u16 msg_id,
				const char *table,
				const char *named_attr, unsigned short attr_id,
				const char *name)
{
	unsigned char buf[FEV_NFNL_BUF];
	size_t off;

	(void)named_attr;
	memset(buf, 0, sizeof(buf));
	off = nfnl_msg_put(buf, 0, sizeof(buf), nl_seq_next(&nf->nl),
			   NFNL_SUBSYS_NFTABLES, (__u8)msg_id, 0, NFPROTO_IPV4);
	if (!off) return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), NFTA_TABLE_NAME, table);
	if (!off) return -EIO;
	if (name) {
		off = nla_put_str(buf, off, sizeof(buf), attr_id, name);
		if (!off) return -EIO;
	}
	((struct nlmsghdr *)buf)->nlmsg_len = (__u32)off;
	return nfnl_send_recv(nf, buf, off);
}

static void enable_ip_forward(void)
{
	ssize_t n;
	int fd;

	if (fev_ip_forward_set)
		return;
	fd = open("/proc/sys/net/ipv4/ip_forward", O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return;
	n = write(fd, "1\n", 2);
	close(fd);
	if (n > 0)
		fev_ip_forward_set = true;
}

/*
 * Per-iter shared state passed through each phase helper.  Lifetime is
 * one iter_one() call; not part of any persistent API.
 */
struct flowtable_vlan_iter_ctx {
	char vp_a[IFNAMSIZ], vp_b[IFNAMSIZ];
	char vla[IFNAMSIZ], vlb[IFNAMSIZ];
	char tab[64], ft[64];
	const char *chain;
	int vp_a_idx, vp_b_idx;
	int vla_idx, vlb_idx;
	__u32 a_addr, b_addr;
	bool veth_added, vla_added, vlb_added;
	bool table_added, ft_added, chain_added;
};

/*
 * Fill @out (capacity @cap) with the nft table name for this iter.
 * Minority arm (ONE_IN(4)) draws a previously-recorded name from
 * the per-kind NAME_KIND_NETLINK_TABLE pool, optionally mutated
 * (1-byte flip / truncate / case-flip / suffix-near-max) so a
 * later netlink op in this or a sibling iteration can collide
 * with an earlier op's NFTA_TABLE_NAME and reach past the
 * kernel's "no such table" reject into the real commit/lookup
 * handler path.  Majority arm generates a fresh "ftv<rng>" --
 * preserving fresh-random diversity is the dominant arm; over-
 * narrowing to all-pool would delete the reject-path warmth.
 * Either way the chosen name is recorded into the pool so a
 * sibling iteration (or a per-syscall fuzzer drawing the same
 * kind) can collide with it.  The buffer is always NUL-
 * terminated.
 */
static void fill_tab_name(char *out, size_t cap, unsigned int rng)
{
	int wrote;
	size_t len;

	if (cap < 2) {
		if (cap > 0)
			out[0] = '\0';
		return;
	}

	if (ONE_IN(4)) {
		size_t got = name_pool_draw_mutated(NAME_KIND_NETLINK_TABLE,
						    out, cap);

		if (got > 0) {
			if (got >= cap)
				got = cap - 1;
			out[got] = '\0';
			name_pool_record(NAME_KIND_NETLINK_TABLE, out, got);
			return;
		}
		/* empty pool -- fall through to fresh generation */
	}

	wrote = snprintf(out, cap, "ftv%u", rng);
	if (wrote <= 0) {
		out[0] = '\0';
		return;
	}
	len = (size_t)wrote;
	if (len >= cap)
		len = cap - 1;
	name_pool_record(NAME_KIND_NETLINK_TABLE, out, len);
}

/*
 * Phase 1: open the per-iter topology — veth pair, vlan children,
 * addresses, links up, and ip_forward.  Returns 0 on success.  On
 * partial failure the *_added / *_idx fields are still set so the
 * orchestrator teardown cleans up whatever made it onto the host.
 */
static int flowtable_vlan_iter_setup(struct nl_ctx *rtnl,
				     struct flowtable_vlan_iter_ctx *c)
{
	unsigned int rng;

	rng = (unsigned int)(rand32() & 0xffffu);
	snprintf(c->vp_a, sizeof(c->vp_a), "tfv%ua", rng);
	snprintf(c->vp_b, sizeof(c->vp_b), "tfv%ub", rng);
	snprintf(c->vla,  sizeof(c->vla),  "tfv%ua.100", rng);
	snprintf(c->vlb,  sizeof(c->vlb),  "tfv%ub.100", rng);
	fill_tab_name(c->tab, sizeof(c->tab), rng);
	snprintf(c->ft,   sizeof(c->ft),   "ft%u",  rng);

	if (build_veth_pair(rtnl, c->vp_a, c->vp_b) != 0) {
		__atomic_add_fetch(&shm->stats.flowtable_vlan.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	c->veth_added = true;
	c->vp_a_idx = (int)if_nametoindex(c->vp_a);
	c->vp_b_idx = (int)if_nametoindex(c->vp_b);
	if (c->vp_a_idx <= 0 || c->vp_b_idx <= 0)
		return -1;

	/* Kernel confirmed c->vp_a names a real device; publish it via the
	 * NETDEV name pool so sibling childops and per-syscall fuzzers
	 * drawing this kind can land a HIT on dev_get_by_name /
	 * SO_BINDTODEVICE instead of always-fresh-random ENODEV.  Record
	 * only the veth master -- the per-kind ring is 16 slots and
	 * recording the peer + both vlan leaves would thrash it. */
	name_pool_record(NAME_KIND_NETDEV, c->vp_a, strlen(c->vp_a));

	if (build_vlan_child(rtnl, c->vla, c->vp_a_idx, 100) == 0) {
		c->vla_added = true;
		c->vla_idx = (int)if_nametoindex(c->vla);
	}
	if (build_vlan_child(rtnl, c->vlb, c->vp_b_idx, 100) == 0) {
		c->vlb_added = true;
		c->vlb_idx = (int)if_nametoindex(c->vlb);
	}
	if (c->vla_idx <= 0 || c->vlb_idx <= 0)
		return -1;

	c->a_addr = htonl(0xc0000201u);	/* 192.0.2.1 */
	c->b_addr = htonl(0xc0000205u);	/* 192.0.2.5 */
	(void)build_addaddr(rtnl, c->vla_idx, c->a_addr, 30);
	(void)build_addaddr(rtnl, c->vlb_idx, c->b_addr, 30);

	(void)rtnl_setlink_up(rtnl, c->vp_a_idx);
	(void)rtnl_setlink_up(rtnl, c->vp_b_idx);
	(void)rtnl_setlink_up(rtnl, c->vla_idx);
	(void)rtnl_setlink_up(rtnl, c->vlb_idx);

	enable_ip_forward();
	return 0;
}

/*
 * Phase 2: install the nft objects — table, flowtable, forward chain,
 * flow_offload rule.  Latches ns_unsupported_flowtable_vlan when the
 * NEWFLOWTABLE step returns EOPNOTSUPP / EAFNOSUPPORT / EPROTONOSUPPORT
 * (CONFIG_NF_FLOW_TABLE absent at runtime).  Bumps setup_ok on full
 * success.  Returns 0 on success, -1 on any failure; ctx *_added flags
 * reflect partial state for orchestrator teardown.
 */
static int flowtable_vlan_iter_install(struct nfnl_ctx *nf,
				       struct flowtable_vlan_iter_ctx *c)
{
	int rc;

	if (build_nft_table(nf, c->tab) != 0) {
		__atomic_add_fetch(&shm->stats.flowtable_vlan.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	c->table_added = true;

	rc = build_nft_flowtable(nf, c->tab, c->ft, c->vla, c->vlb);
	if (rc != 0) {
		if (rc == -EOPNOTSUPP || rc == -EAFNOSUPPORT ||
		    rc == -EPROTONOSUPPORT)
			ns_unsupported_flowtable_vlan = true;
		__atomic_add_fetch(&shm->stats.flowtable_vlan.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	c->ft_added = true;

	if (build_nft_chain_fwd(nf, c->tab, c->chain) != 0)
		return -1;
	c->chain_added = true;

	if (build_nft_rule_flow_offload(nf, c->tab, c->chain, c->ft) != 0)
		return -1;

	__atomic_add_fetch(&shm->stats.flowtable_vlan.setup_ok, 1,
			   __ATOMIC_RELAXED);
	return 0;
}

/*
 * Phase 3: drive the three traffic shapes — small UDP burst (slow path
 * then offload fast path), TCP connect-no-listener (SYN forward + RST
 * return + a GSO-large blind send on a second socket), and an
 * MTU-borderline UDP send — exercising the inline vlan-encap headroom,
 * GSO re-checksum, and offload-entry paths.  All sends are
 * MSG_DONTWAIT / MSG_NOSIGNAL so nothing blocks.
 */
static void flowtable_vlan_iter_churn(const struct flowtable_vlan_iter_ctx *c)
{
	struct sockaddr_in src_a, dst_b;
	int udp_fd, tcp_fd, gso_fd;
	ssize_t n;

	memset(&src_a, 0, sizeof(src_a));
	src_a.sin_family = AF_INET;
	src_a.sin_addr.s_addr = c->a_addr;

	memset(&dst_b, 0, sizeof(dst_b));
	dst_b.sin_family = AF_INET;
	dst_b.sin_addr.s_addr = c->b_addr;

	/* Shape A: small UDP burst.  First few packets go through the
	 * slow path; once the 5-tuple is offloaded the rest traverse
	 * the inline-vlan-encap fast path. */
	udp_fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (udp_fd >= 0) {
		static const char pad[1400];
		unsigned int j;

		(void)bind(udp_fd, (struct sockaddr *)&src_a,
			   sizeof(src_a));
		dst_b.sin_port = htons(9090);
		for (j = 0; j < 8; j++) {
			n = sendto(udp_fd, pad, sizeof(pad),
				   MSG_DONTWAIT,
				   (struct sockaddr *)&dst_b,
				   sizeof(dst_b));
			if (n > 0)
				__atomic_add_fetch(
					&shm->stats.flowtable_vlan.offloaded_pkts,
					1, __ATOMIC_RELAXED);
		}
		close(udp_fd);
	}

	/* Shape B: TCP connect (no listener) — SYN drives forward, RST
	 * drives the reverse leg.  Then a GSO-large blind send on a
	 * second socket targets the inline GSO re-checksum path that
	 * a177ae30f786 fixes. */
	tcp_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK |
			SOCK_CLOEXEC, 0);
	if (tcp_fd >= 0) {
		(void)bind(tcp_fd, (struct sockaddr *)&src_a,
			   sizeof(src_a));
		dst_b.sin_port = htons(8080);
		(void)connect(tcp_fd, (struct sockaddr *)&dst_b,
			      sizeof(dst_b));
		close(tcp_fd);
	}

	gso_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK |
			SOCK_CLOEXEC, 0);
	if (gso_fd >= 0) {
		static unsigned char gso_buf[FEV_GSO_PAYLOAD];
		int one = 0;

		(void)setsockopt(gso_fd, IPPROTO_TCP, TCP_NODELAY,
				 &one, sizeof(one));
		(void)bind(gso_fd, (struct sockaddr *)&src_a,
			   sizeof(src_a));
		dst_b.sin_port = htons(9091);
		(void)connect(gso_fd, (struct sockaddr *)&dst_b,
			      sizeof(dst_b));
		n = send(gso_fd, gso_buf, FEV_GSO_PAYLOAD,
			 MSG_DONTWAIT | MSG_NOSIGNAL);
		if (n > 0)
			__atomic_add_fetch(
				&shm->stats.flowtable_vlan.gso_sends,
				1, __ATOMIC_RELAXED);
		close(gso_fd);
	}

	/* Shape C: MTU-borderline UDP — payload sized to the vlan MTU
	 * edge so headroom math is exercised on the encap-needed path
	 * that 69c54f80f407 fixes. */
	udp_fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (udp_fd >= 0) {
		static unsigned char border[FEV_MTU_BORDER_PAYLOAD];

		(void)bind(udp_fd, (struct sockaddr *)&src_a,
			   sizeof(src_a));
		dst_b.sin_port = htons(9092);
		n = sendto(udp_fd, border, sizeof(border),
			   MSG_DONTWAIT,
			   (struct sockaddr *)&dst_b,
			   sizeof(dst_b));
		if (n > 0)
			__atomic_add_fetch(
				&shm->stats.flowtable_vlan.offloaded_pkts,
				1, __ATOMIC_RELAXED);
		close(udp_fd);
	}
}

/*
 * Phase 4: coin-flip teardown race — on odd iters, drop one vlan child
 * mid-burst so the offload-entry expiry path runs concurrently with
 * the in-flight forward.  The next outer iter rebuilds the topology
 * fresh.
 */
static void flowtable_vlan_iter_race(unsigned int iter_idx,
				     struct nl_ctx *rtnl,
				     struct flowtable_vlan_iter_ctx *c)
{
	if ((iter_idx & 1U) && c->vla_added && c->vla_idx > 0) {
		if (rtnl_dellink(rtnl, c->vla_idx) == 0) {
			__atomic_add_fetch(&shm->stats.flowtable_vlan.vlan_teardown_races,
					   1, __ATOMIC_RELAXED);
			c->vla_added = false;
		}
	}
}

/*
 * Phase 5: per-iter teardown.  Reverses install() then setup() within
 * the partial-state limits indicated by ctx flags, so any goto teardown
 * along the way cleans up exactly what was created.
 */
static void
flowtable_vlan_iter_teardown(struct nfnl_ctx *nf, struct nl_ctx *rtnl,
			     const struct flowtable_vlan_iter_ctx *c)
{
	if (c->table_added) {
		if (c->chain_added)
			(void)build_nft_simple_del(nf, NFT_MSG_DELRULE, c->tab,
						   "chain", NFTA_RULE_CHAIN,
						   c->chain);
		if (c->chain_added)
			(void)build_nft_simple_del(nf, NFT_MSG_DELCHAIN, c->tab,
						   "chain", NFTA_CHAIN_NAME,
						   c->chain);
		if (c->ft_added)
			(void)build_nft_simple_del(nf, NFT_MSG_DELFLOWTABLE,
						   c->tab, "ft",
						   NFTA_FLOWTABLE_NAME, c->ft);
		(void)build_nft_simple_del(nf, NFT_MSG_DELTABLE, c->tab,
					   NULL, 0, NULL);
	}
	if (c->vla_added && c->vla_idx > 0)
		(void)rtnl_dellink(rtnl, c->vla_idx);
	if (c->vlb_added && c->vlb_idx > 0)
		(void)rtnl_dellink(rtnl, c->vlb_idx);
	if (c->veth_added && c->vp_a_idx > 0)
		(void)rtnl_dellink(rtnl, c->vp_a_idx);
}

/*
 * One full create / drive / race / teardown cycle.  Wall cap inherited
 * from the caller — every step short-circuits if FEV_WALL_CAP_NS has
 * been exceeded.
 */
static void iter_one(unsigned int iter_idx, const struct timespec *t_outer)
{
	struct flowtable_vlan_iter_ctx c = { .chain = "fwd" };
	struct nl_ctx rtnl = { .fd = -1 };
	struct nfnl_ctx nf = { .nl = { .fd = -1 } };
	struct nl_open_opts rtnl_opts = {
		.proto         = NETLINK_ROUTE,
		.recv_timeo_s  = FEV_NL_TIMEO_S,
	};
	struct nfnl_open_opts nf_opts = {
		.recv_timeo_s  = FEV_NL_TIMEO_S,
	};

	if ((unsigned long long)ns_since(t_outer) >= FEV_WALL_CAP_NS)
		return;

	if (nl_open(&rtnl, &rtnl_opts) < 0 ||
	    nfnl_open(&nf, &nf_opts) < 0) {
		__atomic_add_fetch(&shm->stats.flowtable_vlan.setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}

	if (flowtable_vlan_iter_setup(&rtnl, &c) != 0)
		goto teardown;

	if (flowtable_vlan_iter_install(&nf, &c) != 0)
		goto teardown;

	if ((unsigned long long)ns_since(t_outer) >= FEV_WALL_CAP_NS)
		goto teardown;

	flowtable_vlan_iter_churn(&c);

	flowtable_vlan_iter_race(iter_idx, &rtnl, &c);

teardown:
	flowtable_vlan_iter_teardown(&nf, &rtnl, &c);

out:
	nfnl_close(&nf);
	nl_close(&rtnl);
}

/*
 * Per-invocation state handed to the in-ns callback so it can keep
 * accounting against the right childop slot.
 */
struct flowtable_encap_vlan_ctx {
	struct childdata *child;
};

/*
 * Per-invocation body that must run inside the private net namespace.
 * Executed in a transient grandchild forked by userns_run_in_ns(); the
 * grandchild's userns + netns are torn down on _exit() so any links,
 * addrs, nft objects or sockets left behind are reaped by the kernel
 * along with the namespace.  Return value is ignored by the helper.
 */
static int flowtable_encap_vlan_in_ns(void *arg)
{
	struct flowtable_encap_vlan_ctx *cctx =
		(struct flowtable_encap_vlan_ctx *)arg;
	struct childdata *child = cctx->child;
	struct timespec t_outer;
	unsigned int outer_iters, i;
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	if (clock_gettime(CLOCK_MONOTONIC, &t_outer) < 0) {
		t_outer.tv_sec = 0;
		t_outer.tv_nsec = 0;
	}

	outer_iters = BUDGETED(CHILD_OP_FLOWTABLE_ENCAP_VLAN,
			       JITTER_RANGE(FEV_OUTER_BASE));
	if (outer_iters < FEV_OUTER_FLOOR)
		outer_iters = FEV_OUTER_FLOOR;
	if (outer_iters > FEV_OUTER_CAP)
		outer_iters = FEV_OUTER_CAP;

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	for (i = 0; i < outer_iters; i++) {
		if ((unsigned long long)ns_since(&t_outer) >= FEV_WALL_CAP_NS)
			break;
		iter_one(i, &t_outer);
		if (ns_unsupported_flowtable_vlan) {
			if (valid_op)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_UNSUPPORTED,
						 __ATOMIC_RELAXED);
			break;
		}
	}

	return 0;
}

bool flowtable_encap_vlan(struct childdata *child)
{
	struct flowtable_encap_vlan_ctx cctx = { .child = child };
	int rc;
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * write entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	__atomic_add_fetch(&shm->stats.flowtable_vlan.runs, 1,
			   __ATOMIC_RELAXED);

	if (ns_unsupported_flowtable_vlan) {
		__atomic_add_fetch(&shm->stats.flowtable_vlan.unsupported_latched,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	rc = userns_run_in_ns(CLONE_NEWNET, flowtable_encap_vlan_in_ns, &cctx);
	if (rc == -EPERM) {
		ns_unsupported_flowtable_vlan = true;
		if (valid_op)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.flowtable_vlan.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}
	if (rc < 0) {
		/* Transient grandchild setup failure (fork, id-map write,
		 * secondary unshare).  Skip this iteration without latching
		 * -- the failure is not policy and may not recur. */
		__atomic_add_fetch(&shm->stats.flowtable_vlan.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	return true;
}

#else  /* !__has_include(<linux/if_link.h> + nf_tables.h + nfnetlink.h) */

#include <stdbool.h>
#include "child.h"
#include "shm.h"

#include "kernel/fcntl.h"
#include "kernel/socket.h"
bool flowtable_encap_vlan(struct childdata *child)
{
	(void)child;

	__atomic_add_fetch(&shm->stats.flowtable_vlan.runs, 1,
			   __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.flowtable_vlan.setup_failed, 1,
			   __ATOMIC_RELAXED);
	return true;
}

#endif
