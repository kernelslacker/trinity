/*
 * flowtable_encap_vlan - nf flowtable inline 802.1Q encap exerciser.
 *
 * Random netfilter / netlink fuzzing rarely assembles the chain that
 * drives net/netfilter/nf_flow_table_offload.c's vlan-push fast path.
 * Reaching it needs (a) two vlan netdevs stacked on a veth pair, (b) an
 * nft_flow_offload rule on a forward chain whose flowtable hook
 * references both vlan netdevs, (c) a real conntrack-tracked flow that
 * traverses both legs so the kernel offloads it, then (d) a GSO-large
 * send + an MTU-borderline send + a vlan-child teardown racing live
 * traffic.  Without that combination the inline-encap headroom /
 * checksum / GSO-resegment paths stay cold.
 *
 * Targets the upstream rc-window fix bundle:
 *   baa3c65435fb  flowtable: skip rechecksum after vlan push
 *   69c54f80f407  flowtable: reserve headroom for shared encap
 *   a177ae30f786  flowtable: re-checksum GSO segments after inline vlan
 *
 * Sequence (per BUDGETED + JITTER outer iteration, 200 ms wall cap,
 * fresh netns + topology per iteration):
 *
 *   1.  unshare(CLONE_NEWNET) (one-time per child).  EPERM falls through
 *       to the host netns; the cap-gate latches on the first NEWFLOWTABLE
 *       rejection if structural support is missing.
 *   2.  Open NETLINK_ROUTE and NETLINK_NETFILTER sockets, both
 *       SO_RCVTIMEO 1s.
 *   3.  RTM_NEWLINK type=veth pair vp_a / vp_b.
 *   4.  RTM_NEWLINK type=vlan IFLA_VLAN_ID=100 over each leg
 *       (vp_a.100, vp_b.100).
 *   5.  RTM_NEWADDR ipv4 /30 on each vlan netdev (192.0.2.1 and
 *       192.0.2.5 on disjoint /30s so the netns acts as the router
 *       between them).
 *   6.  RTM_SETLINK IFF_UP on every device.
 *   7.  Write "1" to /proc/sys/net/ipv4/ip_forward so FORWARD hook
 *       fires on cross-leg traffic.
 *   8.  NFT_MSG_NEWTABLE family=NFPROTO_IPV4 name="ftvlan_<rng>".
 *   9.  NFT_MSG_NEWFLOWTABLE on that table, hook NF_NETDEV_INGRESS,
 *       priority 0, NFTA_FLOWTABLE_HOOK_DEVS = { vp_a.100, vp_b.100 }.
 *       First-invocation EOPNOTSUPP latches ns_unsupported_flowtable_vlan.
 *  10.  NFT_MSG_NEWCHAIN family=NFPROTO_IPV4 name="fwd",
 *       hook NF_INET_FORWARD priority 0 type "filter".
 *  11.  NFT_MSG_NEWRULE on (table, "fwd") carrying one
 *       nft_flow_offload expression (NFTA_EXPR_NAME="flow_offload",
 *       NFTA_FLOW_TABLE_NAME=<flowtable name>).  flow_offload's
 *       init validator only requires family in {ipv4,ipv6,inet} and a
 *       forward-hook chain; no prior expression dependency.
 *  12.  Per-iter traffic burst, three shapes:
 *         A: SOCK_DGRAM connect+send 1400-byte UDP at 192.0.2.5:9090,
 *            source bound to 192.0.2.1.  Forwards through the chain;
 *            after the 5-tuple is offloaded the next packets traverse
 *            the inline-encap fast path.
 *         B: SOCK_STREAM connect to 192.0.2.5:8080 (no listener — the
 *            SYN drives a single forward, ECONNREFUSED reply does the
 *            return leg; both edges hit the encap path).  After the
 *            handshake-or-rst, do a TCP_NODELAY=0 + write(64KB) on a
 *            second socket targeting 192.0.2.5:9091 with the kernel
 *            already in offload state for the connect SYN — drives the
 *            GSO-with-vlan-encap re-checksum path that a177ae30f786
 *            fixes.
 *         C: One sendto() of an MTU-borderline 1496-byte UDP payload
 *            (ip-mtu 1500 - 4 vlan hdr = 1496) — exercises the shared
 *            encap headroom path that 69c54f80f407 fixes.
 *  13.  Coin-flip: RTM_DELLINK vp_a.100 mid-burst — vlan-child teardown
 *       racing the offload entry expiry path.
 *  14.  NFT_MSG_DELRULE / DELCHAIN / DELFLOWTABLE / DELTABLE for the
 *       per-iteration nft objects, then RTM_DELLINK on the veth pair.
 *
 * Cap-gate latch: ns_unsupported_flowtable_vlan fires on EOPNOTSUPP /
 * EAFNOSUPPORT / EPROTONOSUPPORT from NFT_MSG_NEWFLOWTABLE on the first
 * invocation (means CONFIG_NF_FLOW_TABLE absent at runtime).  Once
 * latched, every subsequent invocation just bumps runs+setup_failed and
 * returns.  Mirrors the bridge_vlan_churn / vsock_transport_churn shape.
 *
 * Brick-safety:
 *   - All work happens inside a private netns; the host flowtable /
 *     vlan / veth tables never see this op.
 *   - BUDGETED outer loop (base 4 / floor 4 / cap 16) with JITTER and
 *     200 ms wall-cap; every send/recv uses MSG_DONTWAIT or carries a
 *     1s SO_RCVTIMEO so an unresponsive kernel can't wedge the child
 *     past the SIGALRM(1s) cap inherited from child.c.
 *   - veth stays in loopback only; no underlying physical device.
 *
 * Header gates: __has_include(<linux/if_link.h>) /
 * <linux/netfilter/nf_tables.h> / <linux/netfilter/nfnetlink.h>.
 * NFT_MSG_NEWFLOWTABLE / NFTA_FLOWTABLE_* / NFTA_FLOW_TABLE_NAME /
 * IFLA_VLAN_ID / VETH_INFO_PEER are #define-fallback-supplied at
 * their stable UAPI integer values when absent.
 */

#if __has_include(<linux/if_link.h>) && \
    __has_include(<linux/netfilter/nf_tables.h>) && \
    __has_include(<linux/netfilter/nfnetlink.h>)

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "child.h"
#include "childops-netlink.h"
#include "childops-nfnl.h"
#include "jitter.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"

#ifndef IFLA_VLAN_ID
#define IFLA_VLAN_ID			1
#endif
#ifndef VETH_INFO_PEER
#define VETH_INFO_PEER			1
#endif
#ifndef NFNL_SUBSYS_NFTABLES
#define NFNL_SUBSYS_NFTABLES		10
#endif
#ifndef NFNETLINK_V0
#define NFNETLINK_V0			0
#endif

#ifndef NFT_MSG_NEWTABLE
#define NFT_MSG_NEWTABLE		0
#define NFT_MSG_DELTABLE		2
#define NFT_MSG_NEWCHAIN		3
#define NFT_MSG_DELCHAIN		5
#define NFT_MSG_NEWRULE			6
#define NFT_MSG_DELRULE			8
#endif
#ifndef NFT_MSG_NEWFLOWTABLE
#define NFT_MSG_NEWFLOWTABLE		22
#define NFT_MSG_DELFLOWTABLE		24
#endif

#ifndef NFTA_TABLE_NAME
#define NFTA_TABLE_NAME			1
#define NFTA_TABLE_FLAGS		2
#endif
#ifndef NFTA_CHAIN_TABLE
#define NFTA_CHAIN_TABLE		1
#define NFTA_CHAIN_NAME			3
#define NFTA_CHAIN_HOOK			4
#define NFTA_CHAIN_TYPE			7
#endif
#ifndef NFTA_HOOK_HOOKNUM
#define NFTA_HOOK_HOOKNUM		1
#define NFTA_HOOK_PRIORITY		2
#define NFTA_HOOK_DEV			3
#define NFTA_HOOK_DEVS			4
#endif
#ifndef NFTA_RULE_TABLE
#define NFTA_RULE_TABLE			1
#define NFTA_RULE_CHAIN			2
#define NFTA_RULE_EXPRESSIONS		4
#endif
#ifndef NFTA_LIST_ELEM
#define NFTA_LIST_ELEM			1
#endif
#ifndef NFTA_EXPR_NAME
#define NFTA_EXPR_NAME			1
#define NFTA_EXPR_DATA			2
#endif
#ifndef NFTA_FLOWTABLE_TABLE
#define NFTA_FLOWTABLE_TABLE		1
#define NFTA_FLOWTABLE_NAME		2
#define NFTA_FLOWTABLE_HOOK		3
#endif
#ifndef NFTA_FLOWTABLE_HOOK_NUM
#define NFTA_FLOWTABLE_HOOK_NUM		1
#define NFTA_FLOWTABLE_HOOK_PRIORITY	2
#define NFTA_FLOWTABLE_HOOK_DEVS	3
#endif
#ifndef NFTA_DEVICE_NAME
#define NFTA_DEVICE_NAME		1
#endif
#ifndef NFTA_FLOW_TABLE_NAME
#define NFTA_FLOW_TABLE_NAME		1
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

static bool ns_unsupported_flowtable_vlan;
static bool fev_unshared;
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

static int build_setlink_up(struct nl_ctx *rtnl, int ifindex)
{
	unsigned char buf[128];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_SETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(rtnl);
	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = ifindex;
	ifi->ifi_flags  = IFF_UP;
	ifi->ifi_change = IFF_UP;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(rtnl, buf, off);
}

static int build_dellink(struct nl_ctx *rtnl, int ifindex)
{
	unsigned char buf[128];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_DELLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(rtnl);
	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = ifindex;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));
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
	snprintf(c->tab,  sizeof(c->tab),  "ftv%u", rng);
	snprintf(c->ft,   sizeof(c->ft),   "ft%u",  rng);

	if (build_veth_pair(rtnl, c->vp_a, c->vp_b) != 0) {
		__atomic_add_fetch(&shm->stats.flowtable_vlan_setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	c->veth_added = true;
	c->vp_a_idx = (int)if_nametoindex(c->vp_a);
	c->vp_b_idx = (int)if_nametoindex(c->vp_b);
	if (c->vp_a_idx <= 0 || c->vp_b_idx <= 0)
		return -1;

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

	(void)build_setlink_up(rtnl, c->vp_a_idx);
	(void)build_setlink_up(rtnl, c->vp_b_idx);
	(void)build_setlink_up(rtnl, c->vla_idx);
	(void)build_setlink_up(rtnl, c->vlb_idx);

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
		__atomic_add_fetch(&shm->stats.flowtable_vlan_setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	c->table_added = true;

	rc = build_nft_flowtable(nf, c->tab, c->ft, c->vla, c->vlb);
	if (rc != 0) {
		if (rc == -EOPNOTSUPP || rc == -EAFNOSUPPORT ||
		    rc == -EPROTONOSUPPORT)
			ns_unsupported_flowtable_vlan = true;
		__atomic_add_fetch(&shm->stats.flowtable_vlan_setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	c->ft_added = true;

	if (build_nft_chain_fwd(nf, c->tab, c->chain) != 0)
		return -1;
	c->chain_added = true;

	if (build_nft_rule_flow_offload(nf, c->tab, c->chain, c->ft) != 0)
		return -1;

	__atomic_add_fetch(&shm->stats.flowtable_vlan_setup_ok, 1,
			   __ATOMIC_RELAXED);
	return 0;
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
		__atomic_add_fetch(&shm->stats.flowtable_vlan_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}

	if (flowtable_vlan_iter_setup(&rtnl, &c) != 0)
		goto teardown;

	if (flowtable_vlan_iter_install(&nf, &c) != 0)
		goto teardown;

	if ((unsigned long long)ns_since(t_outer) >= FEV_WALL_CAP_NS)
		goto teardown;

	{
		struct sockaddr_in src_a, dst_b;
		int udp_fd, tcp_fd, gso_fd;
		ssize_t n;
		unsigned char *gso_buf;

		memset(&src_a, 0, sizeof(src_a));
		src_a.sin_family = AF_INET;
		src_a.sin_addr.s_addr = c.a_addr;

		memset(&dst_b, 0, sizeof(dst_b));
		dst_b.sin_family = AF_INET;
		dst_b.sin_addr.s_addr = c.b_addr;

		/* Shape A: small UDP burst.  First few packets go through
		 * the slow path; once the 5-tuple is offloaded the rest
		 * traverse the inline-vlan-encap fast path. */
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
						&shm->stats.flowtable_vlan_offloaded_pkts,
						1, __ATOMIC_RELAXED);
			}
			close(udp_fd);
		}

		/* Shape B: TCP connect (no listener) — SYN drives forward,
		 * RST drives the reverse leg.  Then a GSO-large blind send
		 * on a second socket targets the inline GSO re-checksum
		 * path that a177ae30f786 fixes. */
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
			int one = 0;
			(void)setsockopt(gso_fd, IPPROTO_TCP, TCP_NODELAY,
					 &one, sizeof(one));
			(void)bind(gso_fd, (struct sockaddr *)&src_a,
				   sizeof(src_a));
			dst_b.sin_port = htons(9091);
			(void)connect(gso_fd, (struct sockaddr *)&dst_b,
				      sizeof(dst_b));
			gso_buf = calloc(1, FEV_GSO_PAYLOAD);
			if (gso_buf) {
				n = send(gso_fd, gso_buf, FEV_GSO_PAYLOAD,
					 MSG_DONTWAIT | MSG_NOSIGNAL);
				if (n > 0)
					__atomic_add_fetch(
						&shm->stats.flowtable_vlan_gso_sends,
						1, __ATOMIC_RELAXED);
				free(gso_buf);
			}
			close(gso_fd);
		}

		/* Shape C: MTU-borderline UDP — payload sized to the vlan
		 * MTU edge so headroom math is exercised on the encap-needed
		 * path that 69c54f80f407 fixes. */
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
					&shm->stats.flowtable_vlan_offloaded_pkts,
					1, __ATOMIC_RELAXED);
			close(udp_fd);
		}
	}

	/* Coin-flip teardown race: drop one vlan child mid-burst so the
	 * offload-entry expiry path runs concurrently with the in-flight
	 * forward.  Re-creating in the next outer iter rebuilds the
	 * topology fresh. */
	if ((iter_idx & 1U) && c.vla_added && c.vla_idx > 0) {
		if (build_dellink(&rtnl, c.vla_idx) == 0) {
			__atomic_add_fetch(&shm->stats.flowtable_vlan_vlan_teardown_races,
					   1, __ATOMIC_RELAXED);
			c.vla_added = false;
		}
	}

teardown:
	if (c.table_added) {
		if (c.chain_added)
			(void)build_nft_simple_del(&nf, NFT_MSG_DELRULE, c.tab,
						   "chain", NFTA_RULE_CHAIN,
						   c.chain);
		if (c.chain_added)
			(void)build_nft_simple_del(&nf, NFT_MSG_DELCHAIN, c.tab,
						   "chain", NFTA_CHAIN_NAME,
						   c.chain);
		if (c.ft_added)
			(void)build_nft_simple_del(&nf, NFT_MSG_DELFLOWTABLE,
						   c.tab, "ft",
						   NFTA_FLOWTABLE_NAME, c.ft);
		(void)build_nft_simple_del(&nf, NFT_MSG_DELTABLE, c.tab,
					   NULL, 0, NULL);
	}
	if (c.vla_added && c.vla_idx > 0)
		(void)build_dellink(&rtnl, c.vla_idx);
	if (c.vlb_added && c.vlb_idx > 0)
		(void)build_dellink(&rtnl, c.vlb_idx);
	if (c.veth_added && c.vp_a_idx > 0)
		(void)build_dellink(&rtnl, c.vp_a_idx);

out:
	nfnl_close(&nf);
	nl_close(&rtnl);
}

bool flowtable_encap_vlan(struct childdata *child)
{
	struct timespec t_outer;
	unsigned int outer_iters, i;

	(void)child;

	__atomic_add_fetch(&shm->stats.flowtable_vlan_runs, 1,
			   __ATOMIC_RELAXED);

	if (ns_unsupported_flowtable_vlan) {
		__atomic_add_fetch(&shm->stats.flowtable_vlan_unsupported_latched,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (!fev_unshared) {
		if (unshare(CLONE_NEWNET) < 0) {
			if (errno != EPERM) {
				ns_unsupported_flowtable_vlan = true;
				__atomic_add_fetch(&shm->stats.flowtable_vlan_setup_failed,
						   1, __ATOMIC_RELAXED);
				return true;
			}
		}
		fev_unshared = true;
	}

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

	for (i = 0; i < outer_iters; i++) {
		if ((unsigned long long)ns_since(&t_outer) >= FEV_WALL_CAP_NS)
			break;
		iter_one(i, &t_outer);
		if (ns_unsupported_flowtable_vlan)
			break;
	}

	return true;
}

#else  /* !__has_include(<linux/if_link.h> + nf_tables.h + nfnetlink.h) */

#include <stdbool.h>
#include "child.h"
#include "shm.h"

bool flowtable_encap_vlan(struct childdata *child)
{
	(void)child;

	__atomic_add_fetch(&shm->stats.flowtable_vlan_runs, 1,
			   __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.flowtable_vlan_setup_failed, 1,
			   __ATOMIC_RELAXED);
	return true;
}

#endif
