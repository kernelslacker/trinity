/*
 * bridge_ip6_refrag_fraggap - push fragmented IPv6 frames through a
 * bridge that has conntrack-defrag on ingress, so the ct hook
 * reassembles and the bridge refrag helper (br_ip6_fragment in
 * net/bridge/netfilter/nf_conntrack_bridge.c) rebuilds fresh
 * fragments on egress.  Between the defrag reassembly and the refrag
 * output, the pskb points at a linear buffer whose ipv6 extension
 * chain no longer matches the wire layout of the original fragments:
 * the fragment header is stripped and the "previous header" (prevhdr)
 * pointer that ip6_find_1stfragopt / ip6_fraglist_init uses to walk
 * the reassembled chain is derived at refrag time from the newly
 * constructed linear buffer.  If that walk hits a truncated / short
 * header or a nexthdr chain whose byte layout has drifted from what
 * refrag expects (fragment gap - "fraggap" in ip6_output.c), the
 * prevhdr pointer aims at bytes that no longer describe a valid
 * extension header slot, and the copy_from_kernel into the new
 * per-fragment IPv6 header lands with a stale template.
 *
 * Reachability requires the exact sandwich:
 *   1. bridge with IPv6 forwarding on and bridge-netfilter routing
 *      IPv6 through the conntrack pre/post hooks
 *      (net.bridge.bridge-nf-call-ip6tables=1)
 *   2. nf_conntrack registered on NFPROTO_BRIDGE via a base nft chain
 *      that references the ct expression (drives
 *      nf_conntrack_bridge_init hooks)
 *   3. incoming fragmented IPv6 frames whose reassembled length
 *      exceeds the egress interface MTU, so refrag has to happen
 *   4. an extension-header chain (HbH, DstOpt) between the IPv6 header
 *      and the Fragment header that varies per burst so the prevhdr
 *      offset ip6_fraglist_prepare picks up drifts across the pool
 *
 * Per invocation (driven by userns_run_in_ns(CLONE_NEWNET) grandchild):
 *   - Bring lo up.  Create bridge br0, veth pair v0/v1, enslave v0 to
 *     br0.  Up the bridge and both veth ends.  Assign IPv6 addresses:
 *     bridge fd00::1/64, v1 fd00::2/64.  Set the bridge MTU per
 *     invocation from {1280, 1400, 1500, 9000} so the refrag boundary
 *     shifts across bursts.
 *   - Enable IPv6 forwarding (net.ipv6.conf.all.forwarding=1) and the
 *     bridge-nf hook for IPv6 (net.bridge.bridge-nf-call-ip6tables=1).
 *     Both writes are best-effort; if the bridge-nf write fails
 *     (module absent, sysctl not present), latch off — without the
 *     hook the refrag path is unreachable and the burst is pure noise.
 *   - Install an nft NEWTABLE/NEWCHAIN/NEWRULE on family=NFPROTO_BRIDGE
 *     with a base chain hooked at NF_BR_PRE_ROUTING carrying a single
 *     ct expression (drives nf_conntrack registration on the bridge
 *     family, matching bridge_conntrack_churn).
 *   - AF_PACKET raw socket bound to v1.  In a bounded burst, emit
 *     multi-fragment IPv6 datagrams whose payload total exceeds the
 *     bridge MTU: churn per-fragment size, first-fragment offset,
 *     nexthdr chain (0/1/2 HbH+DstOpt options ahead of the Fragment
 *     header), and short/stale prevhdr byte counts (walking past the
 *     first ext hdr into what would be Fragment header territory but
 *     with an intentionally truncated ext-hdr len byte).
 *
 * Setup is heavy (bridge + veth + nft + sysctls + userns bootstrap),
 * so a ONE_IN(16) gate at dispatch keeps the amortised cost low.
 * Self-bounding: the outer packet burst is BUDGETED(base 4, cap 12)
 * with a 200 ms wall cap; every send is MSG_DONTWAIT; the rtnl / nfnl
 * ack sockets carry SO_RCVTIMEO = 1s so a wedged netlink can't
 * outlive child.c's inherited SIGALRM(1s) cap.  Grandchild _exit()
 * reaps the entire netns (links, addrs, hooks, sockets) so no host
 * state leaks between invocations.
 *
 * Latches (probe-once-and-stick):
 *   ns_unsupported            -EPERM from userns_run_in_ns (policy)
 *   ns_unsupported_bridge     RTM_NEWLINK bridge rejected
 *   ns_unsupported_nf_tables  NEWTABLE/NEWCHAIN rejected
 *   ns_unsupported_brnf       bridge-nf-call-ip6tables sysctl absent
 *
 * Loopback + private netns only.  No host state is touched.
 */

#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <linux/if_addr.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_packet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "child.h"
#include "childops-netlink.h"
#include "childops-nfnl.h"
#include "jitter.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "userns-bootstrap.h"

#include "kernel/socket.h"

#ifndef NFPROTO_BRIDGE
#define NFPROTO_BRIDGE			7
#endif
#ifndef NF_BR_PRE_ROUTING
#define NF_BR_PRE_ROUTING		0
#endif
#ifndef NF_BR_PRI_CT_PRE
#define NF_BR_PRI_CT_PRE		(-200)
#endif
#ifndef NFNL_SUBSYS_NFTABLES
#define NFNL_SUBSYS_NFTABLES		10
#endif

/* nf_tables UAPI subset - kept local so a stripped sysroot still
 * builds; values match include/uapi/linux/netfilter/nf_tables.h. */
#define BIF_NFT_MSG_NEWTABLE		0
#define BIF_NFT_MSG_NEWCHAIN		3
#define BIF_NFT_MSG_NEWRULE		6
#define BIF_NFTA_TABLE_NAME		1
#define BIF_NFTA_CHAIN_TABLE		1
#define BIF_NFTA_CHAIN_NAME		3
#define BIF_NFTA_CHAIN_HOOK		4
#define BIF_NFTA_CHAIN_TYPE		7
#define BIF_NFTA_HOOK_HOOKNUM		1
#define BIF_NFTA_HOOK_PRIORITY		2
#define BIF_NFTA_RULE_TABLE		1
#define BIF_NFTA_RULE_CHAIN		2
#define BIF_NFTA_RULE_EXPRESSIONS	4
#define BIF_NFTA_LIST_ELEM		1
#define BIF_NFTA_EXPR_NAME		1
#define BIF_NFTA_EXPR_DATA		2
#define BIF_NFTA_CT_DREG		1
#define BIF_NFTA_CT_KEY			2
#define BIF_NFT_CT_STATE		0
#define BIF_NFT_REG_1			8

#define BIF_OUTER_BASE			4U
#define BIF_OUTER_CAP			12U
#define BIF_BUDGET_NS			200000000LL
#define BIF_RTNL_BUF_BYTES		2048
#define BIF_NFT_BUF_BYTES		1024
#define BIF_FRAME_BYTES			2048
#define BIF_ETH_HLEN			14
#define BIF_IP6_HLEN			40
#define BIF_FRAG_HLEN			8

static const uint32_t bif_mtus[] = { 1280, 1400, 1500, 9000 };

/* Latched per-child; see file header for the semantics. */
static bool ns_unsupported;
static bool ns_unsupported_bridge;
static bool ns_unsupported_nf_tables;
static bool ns_unsupported_brnf;

/* Per-invocation state handed to the in-ns callback. */
struct bridge_ip6_refrag_fraggap_ctx {
	struct childdata *child;
};

static size_t bif_nla_put_be32(unsigned char *buf, size_t off, size_t cap,
			       unsigned short type, __u32 v)
{
	__u32 be = htonl(v);

	return nla_put(buf, off, cap, type, &be, sizeof(be));
}

static bool bif_sysfs_write_one(const char *path, const char *val)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	ssize_t n;

	if (fd < 0)
		return false;
	n = write(fd, val, strlen(val));
	close(fd);
	return n > 0;
}

static int bif_rtnl_create_bridge(struct nl_ctx *rtnl, const char *name)
{
	unsigned char buf[BIF_RTNL_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off, li_off;

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
	if (!off)
		return -EIO;
	li_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_LINKINFO);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), IFLA_INFO_KIND, "bridge");
	if (!off)
		return -EIO;
	nla_nest_end(buf, li_off, off);
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(rtnl, buf, off);
}

static int bif_rtnl_create_veth(struct nl_ctx *rtnl, const char *a,
				const char *b)
{
	unsigned char buf[BIF_RTNL_BUF_BYTES];
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

	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, a);
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
	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, b);
	if (!off)
		return -EIO;
	nla_nest_end(buf, peer_off, off);
	nla_nest_end(buf, id_off, off);
	nla_nest_end(buf, li_off, off);
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(rtnl, buf, off);
}

static int bif_rtnl_setlink_master(struct nl_ctx *rtnl, int idx, int master)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct ifinfomsg *ifi;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_type  = RTM_SETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(rtnl);
	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = idx;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));
	off = nla_put_u32(buf, off, sizeof(buf), IFLA_MASTER, (__u32)master);
	if (!off)
		return -EIO;
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(rtnl, buf, off);
}

static int bif_rtnl_set_mtu(struct nl_ctx *rtnl, int idx, __u32 mtu)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct ifinfomsg *ifi;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(rtnl);
	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = idx;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));
	off = nla_put_u32(buf, off, sizeof(buf), IFLA_MTU, mtu);
	if (!off)
		return -EIO;
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(rtnl, buf, off);
}

static int bif_rtnl_addr_add_v6(struct nl_ctx *rtnl, int idx,
				const struct in6_addr *addr, __u8 prefix)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct ifaddrmsg *ifa;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_type  = RTM_NEWADDR;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(rtnl);
	ifa = (struct ifaddrmsg *)NLMSG_DATA(nlh);
	ifa->ifa_family    = AF_INET6;
	ifa->ifa_prefixlen = prefix;
	ifa->ifa_flags     = 0;
	ifa->ifa_scope     = RT_SCOPE_UNIVERSE;
	ifa->ifa_index     = (unsigned int)idx;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifa));
	off = nla_put(buf, off, sizeof(buf), IFA_LOCAL, addr, sizeof(*addr));
	if (!off)
		return -EIO;
	off = nla_put(buf, off, sizeof(buf), IFA_ADDRESS, addr, sizeof(*addr));
	if (!off)
		return -EIO;
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(rtnl, buf, off);
}

/*
 * Install a bridge-family nft table + base chain + one ct expression
 * rule.  The ct reference is what drives nf_conntrack registration on
 * NFPROTO_BRIDGE — same shape bridge_conntrack_churn uses.  Returns 0
 * on clean batch end, -errno on the first rejection.
 */
static int bif_nft_install_bridge_ct(struct nfnl_ctx *nf, const char *table,
				     const char *chain)
{
	unsigned char buf[BIF_NFT_BUF_BYTES];
	size_t off = 0, hook_off, exprs_off, elem_off, expr_data_off;
	__u8 family = NFPROTO_BRIDGE;
	__u32 prio = (__u32)(NF_BR_PRI_CT_PRE - 1);

	memset(buf, 0, sizeof(buf));

	off = nfnl_batch_begin(buf, off, sizeof(buf),
			       nl_seq_next(&nf->nl), NFNL_SUBSYS_NFTABLES);
	if (!off)
		return -EIO;

	{
		size_t msg_off = off;

		off = nfnl_msg_put(buf, off, sizeof(buf), nl_seq_next(&nf->nl),
				   NFNL_SUBSYS_NFTABLES, BIF_NFT_MSG_NEWTABLE,
				   NLM_F_CREATE, family);
		if (!off)
			return -EIO;
		off = nla_put_str(buf, off, sizeof(buf),
				  BIF_NFTA_TABLE_NAME, table);
		if (!off)
			return -EIO;
		((struct nlmsghdr *)(buf + msg_off))->nlmsg_len =
			(__u32)(off - msg_off);
	}

	{
		size_t msg_off = off;

		off = nfnl_msg_put(buf, off, sizeof(buf), nl_seq_next(&nf->nl),
				   NFNL_SUBSYS_NFTABLES, BIF_NFT_MSG_NEWCHAIN,
				   NLM_F_CREATE, family);
		if (!off)
			return -EIO;
		off = nla_put_str(buf, off, sizeof(buf),
				  BIF_NFTA_CHAIN_TABLE, table);
		off = nla_put_str(buf, off, sizeof(buf),
				  BIF_NFTA_CHAIN_NAME, chain);
		if (!off)
			return -EIO;
		hook_off = off;
		off = nla_nest_start(buf, off, sizeof(buf),
				     BIF_NFTA_CHAIN_HOOK | NLA_F_NESTED);
		if (!off)
			return -EIO;
		off = bif_nla_put_be32(buf, off, sizeof(buf),
				       BIF_NFTA_HOOK_HOOKNUM,
				       NF_BR_PRE_ROUTING);
		off = bif_nla_put_be32(buf, off, sizeof(buf),
				       BIF_NFTA_HOOK_PRIORITY, prio);
		if (!off)
			return -EIO;
		nla_nest_end(buf, hook_off, off);
		off = nla_put_str(buf, off, sizeof(buf),
				  BIF_NFTA_CHAIN_TYPE, "filter");
		if (!off)
			return -EIO;
		((struct nlmsghdr *)(buf + msg_off))->nlmsg_len =
			(__u32)(off - msg_off);
	}

	{
		size_t msg_off = off;

		off = nfnl_msg_put(buf, off, sizeof(buf), nl_seq_next(&nf->nl),
				   NFNL_SUBSYS_NFTABLES, BIF_NFT_MSG_NEWRULE,
				   NLM_F_CREATE | NLM_F_APPEND, family);
		if (!off)
			return -EIO;
		off = nla_put_str(buf, off, sizeof(buf),
				  BIF_NFTA_RULE_TABLE, table);
		off = nla_put_str(buf, off, sizeof(buf),
				  BIF_NFTA_RULE_CHAIN, chain);
		if (!off)
			return -EIO;
		exprs_off = off;
		off = nla_nest_start(buf, off, sizeof(buf),
				     BIF_NFTA_RULE_EXPRESSIONS | NLA_F_NESTED);
		if (!off)
			return -EIO;
		elem_off = off;
		off = nla_nest_start(buf, off, sizeof(buf),
				     BIF_NFTA_LIST_ELEM | NLA_F_NESTED);
		off = nla_put_str(buf, off, sizeof(buf),
				  BIF_NFTA_EXPR_NAME, "ct");
		expr_data_off = off;
		off = nla_nest_start(buf, off, sizeof(buf),
				     BIF_NFTA_EXPR_DATA | NLA_F_NESTED);
		off = bif_nla_put_be32(buf, off, sizeof(buf),
				       BIF_NFTA_CT_KEY, BIF_NFT_CT_STATE);
		off = bif_nla_put_be32(buf, off, sizeof(buf),
				       BIF_NFTA_CT_DREG, BIF_NFT_REG_1);
		if (!off)
			return -EIO;
		nla_nest_end(buf, expr_data_off, off);
		nla_nest_end(buf, elem_off, off);
		nla_nest_end(buf, exprs_off, off);
		((struct nlmsghdr *)(buf + msg_off))->nlmsg_len =
			(__u32)(off - msg_off);
	}

	off = nfnl_batch_end(buf, off, sizeof(buf),
			     nl_seq_next(&nf->nl), NFNL_SUBSYS_NFTABLES);
	if (!off)
		return -EIO;

	return nfnl_send_recv_batched(nf, buf, off);
}

/*
 * Build one IPv6 fragment on the wire, ready to sendto() through the
 * AF_PACKET raw socket bound to v1.  Layout:
 *
 *   [ether:14][ipv6:40][opt_hdrs:opt_len][frag:8][payload:payload_len]
 *
 * opt_hdrs is an optional chain of HbH / DstOpt options with PadN
 * fillers whose byte length varies per burst so the prevhdr walk that
 * br_ip6_fragment / ip6_fraglist_prepare performs on the refrag path
 * hits a different offset each time.  A short_opt_len (>0) truncates
 * the extension-header length byte to a value that stops the chain
 * walk mid-option -- the "stale prevhdr" arm from the task brief.
 *
 * Returns the total on-wire frame length, or 0 if the requested
 * layout would overflow the fixed frame buffer.
 */
static size_t bif_build_fragment_frame(unsigned char *frame, size_t cap,
				       const unsigned char *dst_mac,
				       const unsigned char *src_mac,
				       const struct in6_addr *src,
				       const struct in6_addr *dst,
				       unsigned int nr_opts,
				       unsigned int opt_pad_units,
				       unsigned int short_opt_len,
				       uint32_t frag_id, uint16_t frag_off,
				       bool more_frags, uint8_t inner_nxt,
				       const unsigned char *payload,
				       size_t payload_len)
{
	struct ip6_hdr *ip6;
	struct ip6_frag *frag;
	unsigned char *p;
	size_t total, opt_len = 0;
	unsigned int i;
	uint8_t chain_nxt = IPPROTO_FRAGMENT;
	uint8_t first_nxt;

	if (nr_opts > 2)
		nr_opts = 2;
	if (opt_pad_units > 6)
		opt_pad_units = 6;

	/* Each opt chunk is (2 + PadN option(2+6*units)) rounded to 8. */
	for (i = 0; i < nr_opts; i++) {
		unsigned int chunk;

		chunk = 2 + 2 + opt_pad_units * 6;
		chunk = (chunk + 7U) & ~7U;
		opt_len += chunk;
	}

	total = BIF_ETH_HLEN + BIF_IP6_HLEN + opt_len + BIF_FRAG_HLEN +
		payload_len;
	if (total > cap)
		return 0;

	memset(frame, 0, total);

	memcpy(frame + 0, dst_mac, 6);
	memcpy(frame + 6, src_mac, 6);
	frame[12] = 0x86;
	frame[13] = 0xdd;

	ip6 = (struct ip6_hdr *)(frame + BIF_ETH_HLEN);
	ip6->ip6_flow = htonl(0x60000000U);
	ip6->ip6_plen = htons((uint16_t)(opt_len + BIF_FRAG_HLEN +
					 payload_len));
	ip6->ip6_hlim = 64;
	memcpy(&ip6->ip6_src, src, sizeof(*src));
	memcpy(&ip6->ip6_dst, dst, sizeof(*dst));

	/* First ext-hdr nxt: HbH(0) if we have >=1 opt, else Fragment. */
	first_nxt = (nr_opts >= 1) ? IPPROTO_HOPOPTS : IPPROTO_FRAGMENT;
	ip6->ip6_nxt = first_nxt;

	p = frame + BIF_ETH_HLEN + BIF_IP6_HLEN;
	for (i = 0; i < nr_opts; i++) {
		unsigned int chunk;
		uint8_t next_hdr;

		chunk = 2 + 2 + opt_pad_units * 6;
		chunk = (chunk + 7U) & ~7U;

		next_hdr = (i + 1 < nr_opts) ? IPPROTO_DSTOPTS : chain_nxt;
		p[0] = next_hdr;
		/* Length in 8-byte units minus 1. */
		if (i == 0 && short_opt_len)
			p[1] = (uint8_t)short_opt_len;
		else
			p[1] = (uint8_t)((chunk / 8U) - 1U);

		if (opt_pad_units == 0) {
			p[2] = 0;	/* Pad1 */
			p[3] = 0;
			p[4] = 0;
			p[5] = 0;
		} else {
			p[2] = 1;	/* PadN */
			p[3] = (uint8_t)(opt_pad_units * 6);
			/* remainder already zeroed */
		}
		p += chunk;
	}

	frag = (struct ip6_frag *)p;
	frag->ip6f_nxt = inner_nxt;
	frag->ip6f_reserved = 0;
	frag->ip6f_offlg = htons((uint16_t)((frag_off & IP6F_OFF_MASK) |
					    (more_frags ?
					     ntohs(IP6F_MORE_FRAG) : 0)));
	frag->ip6f_ident = htonl(frag_id);
	p += BIF_FRAG_HLEN;

	if (payload_len && payload)
		memcpy(p, payload, payload_len);

	return total;
}

/*
 * Emit one fragmented IPv6 datagram (two fragments) at the picked
 * variant.  The payload total exceeds the bridge MTU so refrag must
 * run on egress.  frag_id is per-burst so successive iterations
 * exercise different reassembly buckets.
 */
static void bif_emit_frag_pair(int raw, int ifindex,
			       const unsigned char *dst_mac,
			       const unsigned char *src_mac,
			       const struct in6_addr *src,
			       const struct in6_addr *dst,
			       unsigned int variant, uint32_t frag_id)
{
	unsigned char frame[BIF_FRAME_BYTES];
	unsigned char payload1[512];
	unsigned char payload2[512];
	struct sockaddr_ll sll;
	size_t frame_len;
	size_t p1_len = 256;
	size_t p2_len = 256;
	unsigned int nr_opts, opt_pad;
	unsigned int short_opt = 0;

	/* Variant fan: 0..15 -> distinct (opt-chain, size, prevhdr) combos. */
	nr_opts = variant & 0x3U;
	if (nr_opts > 2)
		nr_opts = 2;
	opt_pad = (variant >> 2) & 0x3U;
	if ((variant & 0xfU) == 0xfU)
		short_opt = 1;	/* stale prevhdr: short ext-hdr len byte */

	/* Nudge fragment sizes off 8-aligned defaults so refrag has to
	 * roll the boundary at different points. */
	p1_len = 240 + ((variant & 0x7U) * 8U);
	p2_len = 200 + (((variant >> 3) & 0x3U) * 16U);

	memset(payload1, (int)(0xa5 ^ variant), p1_len);
	memset(payload2, (int)(0x5a ^ variant), p2_len);

	memset(&sll, 0, sizeof(sll));
	sll.sll_family   = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_IPV6);
	sll.sll_ifindex  = ifindex;
	sll.sll_halen    = 6;
	memcpy(sll.sll_addr, dst_mac, 6);

	/* First fragment: MF=1, offset=0. */
	frame_len = bif_build_fragment_frame(frame, sizeof(frame),
					     dst_mac, src_mac, src, dst,
					     nr_opts, opt_pad, short_opt,
					     frag_id, 0, true,
					     IPPROTO_UDP, payload1, p1_len);
	if (frame_len &&
	    sendto(raw, frame, frame_len, MSG_DONTWAIT,
		   (struct sockaddr *)&sll, sizeof(sll)) > 0)
		__atomic_add_fetch(&shm->stats.bridge_ip6_refrag_fraggap_frags_sent,
				   1, __ATOMIC_RELAXED);

	/* Second fragment: MF=0, offset = payload1 rounded to 8-byte units. */
	frame_len = bif_build_fragment_frame(frame, sizeof(frame),
					     dst_mac, src_mac, src, dst,
					     nr_opts, opt_pad, short_opt,
					     frag_id,
					     (uint16_t)((p1_len + 7U) & ~7U),
					     false, IPPROTO_UDP,
					     payload2, p2_len);
	if (frame_len &&
	    sendto(raw, frame, frame_len, MSG_DONTWAIT,
		   (struct sockaddr *)&sll, sizeof(sll)) > 0)
		__atomic_add_fetch(&shm->stats.bridge_ip6_refrag_fraggap_frags_sent,
				   1, __ATOMIC_RELAXED);
}

/*
 * Enable IPv6 forwarding + bridge-nf-call-ip6tables.  The latter is
 * what routes bridged IPv6 through the conntrack pre/post hooks; if
 * it fails (module absent, sysctl not present) latch off — the refrag
 * path is unreachable and the burst degrades to inert traffic.
 * Returns 0 on success, -1 to signal the caller should skip cleanly.
 */
static int bif_enable_bridge_nf(void)
{
	(void)bif_sysfs_write_one("/proc/sys/net/ipv6/conf/all/forwarding", "1");
	if (!bif_sysfs_write_one(
		    "/proc/sys/net/bridge/bridge-nf-call-ip6tables", "1"))
		return -1;
	(void)bif_sysfs_write_one(
		"/proc/sys/net/bridge/bridge-nf-filter-vlan-tagged", "0");
	return 0;
}

/*
 * Per-invocation body that must run inside the private net namespace.
 * The transient grandchild's _exit() reaps every fd, addr, link and
 * hook installed here, so no host state leaks even if a phase bails
 * mid-setup.  Return value is ignored by the helper.
 */
static int bridge_ip6_refrag_fraggap_in_ns(void *arg)
{
	struct bridge_ip6_refrag_fraggap_ctx *cctx =
		(struct bridge_ip6_refrag_fraggap_ctx *)arg;
	struct childdata *child = cctx->child;
	struct nl_ctx rtnl = { .fd = -1 };
	struct nfnl_ctx nfnl_nft = { .nl = { .fd = -1 } };
	struct nl_open_opts rtnl_opts = {
		.proto        = NETLINK_ROUTE,
		.recv_timeo_s = 1,
	};
	struct nfnl_open_opts nfnl_opts = {
		.recv_timeo_s = 1,
	};
	char br_name[IFNAMSIZ];
	char veth_a[IFNAMSIZ];
	char veth_b[IFNAMSIZ];
	struct in6_addr br_addr;
	struct in6_addr v1_addr;
	struct in6_addr src_addr;
	struct in6_addr dst_addr;
	unsigned char dst_mac[6];
	unsigned char src_mac[6];
	struct timespec t_burst;
	int br_idx = 0, va_idx = 0, vb_idx = 0;
	int raw = -1;
	int rc;
	uint32_t mtu;
	uint32_t frag_id_base;
	unsigned int iters, i;
	unsigned int rng;
	bool bridge_added = false, veth_added = false;

	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (nl_open(&rtnl, &rtnl_opts) < 0)
		return 0;
	rtnl_bring_lo_up(&rtnl);

	rng = (unsigned int)(rand32() & 0xffffu);
	snprintf(br_name, sizeof(br_name), "trbf%u", rng);
	snprintf(veth_a,  sizeof(veth_a),  "trbfv%ua", rng);
	snprintf(veth_b,  sizeof(veth_b),  "trbfv%ub", rng);

	rc = bif_rtnl_create_bridge(&rtnl, br_name);
	if (rc != 0) {
		if (rc == -EAFNOSUPPORT || rc == -EOPNOTSUPP ||
		    rc == -ENOTSUP || rc == -EPROTONOSUPPORT) {
			ns_unsupported_bridge = true;
			if (valid_op)
				__atomic_store_n(
					&shm->stats.childop.latch_reason[op],
					CHILDOP_LATCH_NS_UNSUPPORTED,
					__ATOMIC_RELAXED);
		}
		goto out;
	}
	bridge_added = true;
	br_idx = (int)if_nametoindex(br_name);
	if (br_idx <= 0)
		goto out;

	if (bif_rtnl_create_veth(&rtnl, veth_a, veth_b) != 0)
		goto out;
	veth_added = true;
	va_idx = (int)if_nametoindex(veth_a);
	vb_idx = (int)if_nametoindex(veth_b);
	if (va_idx <= 0 || vb_idx <= 0)
		goto out;

	(void)bif_rtnl_setlink_master(&rtnl, va_idx, br_idx);

	mtu = RAND_ARRAY(bif_mtus);
	(void)bif_rtnl_set_mtu(&rtnl, br_idx, mtu);
	(void)bif_rtnl_set_mtu(&rtnl, va_idx, mtu);
	(void)bif_rtnl_set_mtu(&rtnl, vb_idx, mtu);

	(void)rtnl_setlink_up(&rtnl, br_idx);
	(void)rtnl_setlink_up(&rtnl, va_idx);
	(void)rtnl_setlink_up(&rtnl, vb_idx);

	memset(&br_addr, 0, sizeof(br_addr));
	br_addr.s6_addr[0]  = 0xfd; br_addr.s6_addr[15] = 0x01;
	memset(&v1_addr, 0, sizeof(v1_addr));
	v1_addr.s6_addr[0]  = 0xfd; v1_addr.s6_addr[15] = 0x02;
	(void)bif_rtnl_addr_add_v6(&rtnl, br_idx, &br_addr, 64);
	(void)bif_rtnl_addr_add_v6(&rtnl, vb_idx, &v1_addr, 64);

	if (bif_enable_bridge_nf() != 0) {
		ns_unsupported_brnf = true;
		if (valid_op)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		goto out;
	}
	__atomic_add_fetch(&shm->stats.bridge_ip6_refrag_fraggap_brnf_enabled,
			   1, __ATOMIC_RELAXED);

	if (nfnl_open(&nfnl_nft, &nfnl_opts) < 0)
		goto out;
	rc = bif_nft_install_bridge_ct(&nfnl_nft, "br_ip6_frag", "in");
	if (rc == -EAFNOSUPPORT || rc == -EPROTONOSUPPORT ||
	    rc == -EOPNOTSUPP || rc == -ENOTSUP) {
		ns_unsupported_nf_tables = true;
		if (valid_op)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		goto out;
	}

	raw = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_IPV6));
	if (raw < 0)
		goto out;
	{
		struct sockaddr_ll bind_sll;

		memset(&bind_sll, 0, sizeof(bind_sll));
		bind_sll.sll_family   = AF_PACKET;
		bind_sll.sll_protocol = htons(ETH_P_IPV6);
		bind_sll.sll_ifindex  = vb_idx;
		(void)bind(raw, (struct sockaddr *)&bind_sll,
			   sizeof(bind_sll));
	}

	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	}

	/* Source MAC locally-administered unicast; destination broadcast
	 * so the bridge floods (we don't cheaply know v0's MAC). */
	memset(dst_mac, 0xff, sizeof(dst_mac));
	generate_rand_bytes(src_mac, sizeof(src_mac));
	src_mac[0] = (unsigned char)((src_mac[0] & 0xfc) | 0x02);

	memcpy(&src_addr, &v1_addr, sizeof(src_addr));
	memcpy(&dst_addr, &br_addr, sizeof(dst_addr));

	if (clock_gettime(CLOCK_MONOTONIC, &t_burst) < 0) {
		t_burst.tv_sec = 0;
		t_burst.tv_nsec = 0;
	}
	frag_id_base = rand32();

	iters = BUDGETED(CHILD_OP_BRIDGE_IP6_REFRAG_FRAGGAP,
			 JITTER_RANGE(BIF_OUTER_BASE));
	if (iters < 1)
		iters = 1;
	if (iters > BIF_OUTER_CAP)
		iters = BIF_OUTER_CAP;

	for (i = 0; i < iters; i++) {
		if (ns_since(&t_burst) >= BIF_BUDGET_NS)
			break;
		bif_emit_frag_pair(raw, vb_idx, dst_mac, src_mac,
				   &src_addr, &dst_addr, i,
				   frag_id_base + i);
		__atomic_add_fetch(&shm->stats.bridge_ip6_refrag_fraggap_bursts,
				   1, __ATOMIC_RELAXED);
	}

	{
		unsigned char drain[512];

		while (recv(raw, drain, sizeof(drain), MSG_DONTWAIT) > 0)
			;
	}

out:
	if (raw >= 0)
		close(raw);
	nfnl_close(&nfnl_nft);
	if (rtnl.fd >= 0) {
		if (bridge_added && br_idx > 0)
			(void)rtnl_dellink(&rtnl, br_idx);
		if (veth_added && vb_idx > 0)
			(void)rtnl_dellink(&rtnl, vb_idx);
		nl_close(&rtnl);
	}
	return 0;
}

bool bridge_ip6_refrag_fraggap(struct childdata *child)
{
	struct bridge_ip6_refrag_fraggap_ctx cctx = { .child = child };
	int rc;

	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	__atomic_add_fetch(&shm->stats.bridge_ip6_refrag_fraggap_runs,
			   1, __ATOMIC_RELAXED);

	if (ns_unsupported || ns_unsupported_bridge ||
	    ns_unsupported_nf_tables || ns_unsupported_brnf)
		return true;

	if (!ONE_IN(16))
		return true;

	rc = userns_run_in_ns(CLONE_NEWNET,
			      bridge_ip6_refrag_fraggap_in_ns, &cctx);
	if (rc == -EPERM) {
		ns_unsupported = true;
		if (valid_op)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		return true;
	}
	if (rc < 0) {
		/* Transient grandchild setup failure (fork, id-map write,
		 * secondary unshare).  Skip this iteration without
		 * latching — the failure is not policy and may not
		 * recur. */
		return true;
	}

	return true;
}
