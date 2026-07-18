/*
 * bridge_ip6frag_refrag - drive IPv6 fragments through the bridge
 * netfilter defrag / refrag path.
 *
 * Targets the IPv6 defrag-then-refrag surface reached only when a
 * bridge has nf_conntrack_bridge active: incoming IPv6 fragments hit
 * the bridge pre-routing hook, nf_ct_frag6_gather() reassembles them
 * into one skb, conntrack sees the reassembled tuple, and on egress
 * br_ip6_fragment() re-fragments the skb if it exceeds the outbound
 * port's MTU.  The reassembly path tracks a `prev_nexthdr` pointer
 * into the pre-fragment extension-header chain; the refragmentation
 * path walks that chain again to stamp the next-header field on each
 * emitted fragment.  Mismatches between the chain the reassembler
 * remembered and the chain the refragmenter walks are the historical
 * bug shape in this area (see e.g. Kconfig NF_DEFRAG_IPV6 changelog
 * and the br_ip6_fragment fixups landed for RFC 8200 truncated
 * chains).  Random syscall fuzzing never reaches this surface: it
 * needs a bridge with an nf_tables "ct" expression on the bridge
 * family to load nf_conntrack_bridge, plus IPv6 fragment frames
 * injected on a bridge port at line rate, with a small egress MTU
 * so the refrag path fires.
 *
 * Per invocation (driven by userns_run_in_ns, CLONE_NEWNET):
 *   - Enter a private user + net namespace via a transient grandchild
 *     so the persistent fuzz child never changes its own credentials
 *     or namespace stack (see include/userns-bootstrap.h rationale).
 *   - Bring lo up.  RTM_NEWLINK bridge br0.  RTM_NEWLINK veth pair
 *     v0/v0p; enslave v0 to br0; set v0's MTU to IPV6_MIN_MTU (1280)
 *     so any reassembled datagram > 1232 payload bytes forces
 *     br_ip6_fragment on egress.  Bring all three up.
 *   - nf_tables transaction: NEWTABLE family=NFPROTO_BRIDGE
 *     "br_ip6ct"; NEWCHAIN base, hook=NF_BR_PRE_ROUTING; NEWRULE
 *     with one nft_ct expression (NFTA_CT_KEY=NFT_CT_STATE,
 *     NFTA_CT_DREG=NFT_REG_1) — the expression's verdict path is
 *     unused; it exists to force nf_conntrack_bridge registration.
 *   - AF_PACKET raw socket bound to v0p; inject a bounded burst of
 *     crafted IPv6 fragmented UDP frames addressed to broadcast MAC
 *     so the bridge floods them out v0.  Each frame carries either a
 *     zero-length HOP-BY-HOP / DESTINATION option immediately before
 *     the fragment header (so the "prev_nexthdr" the reassembler
 *     remembers points into an extension header, not the base IPv6
 *     header), or no pre-frag extension at all.  A fraction of frames
 *     stamp a deliberately truncated hdr_ext_len (0 with a full
 *     8-byte body, or 1 with only 8 bytes present) on the option
 *     immediately preceding the fragment header — the "stale / short
 *     previous-header" the refrag walker must tolerate without
 *     dereferencing past the recorded chain.  Fragment sizes,
 *     offsets, next-header pick, identification counter and payload
 *     length are churned by JITTER_RANGE / BUDGETED across the burst.
 *
 * Config-gated / degrade-to-noop:
 *   ns_unsupported            userns_run_in_ns() -EPERM (hardened
 *                             userns policy) — latch off for the
 *                             remainder of this child's lifetime.
 *   ns_unsupported_bridge     RTM_NEWLINK "bridge" rejected with
 *                             EAFNOSUPPORT / EPROTONOSUPPORT /
 *                             ENOTSUP / EOPNOTSUPP (kernel built
 *                             without CONFIG_BRIDGE).
 *   ns_unsupported_nf_tables  NEWTABLE/NEWCHAIN/NEWRULE rejected with
 *                             those same codes (no NF_TABLES_BRIDGE /
 *                             NF_CONNTRACK_BRIDGE).
 *   ns_unsupported_af_packet  AF_PACKET socket() refused (kernel
 *                             built without CONFIG_PACKET).
 * All three latches probe once and stick; ONE_IN(8) gate keeps the
 * per-iteration cost low.  All I/O is MSG_DONTWAIT; nfnl/rtnl
 * contexts carry SO_RCVTIMEO=1s so an unresponsive kernel cannot
 * wedge us past child.c's SIGALRM(1s).  Loopback only (private netns).
 */

#include <errno.h>
#include <net/if.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

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
 * builds; values are stable in include/uapi/linux/netfilter/nf_tables.h. */
#define B6R_NFT_MSG_NEWTABLE		0
#define B6R_NFT_MSG_NEWCHAIN		3
#define B6R_NFT_MSG_NEWRULE		6
#define B6R_NFTA_TABLE_NAME		1
#define B6R_NFTA_CHAIN_TABLE		1
#define B6R_NFTA_CHAIN_NAME		3
#define B6R_NFTA_CHAIN_HOOK		4
#define B6R_NFTA_CHAIN_TYPE		7
#define B6R_NFTA_HOOK_HOOKNUM		1
#define B6R_NFTA_HOOK_PRIORITY		2
#define B6R_NFTA_RULE_TABLE		1
#define B6R_NFTA_RULE_CHAIN		2
#define B6R_NFTA_RULE_EXPRESSIONS	4
#define B6R_NFTA_LIST_ELEM		1
#define B6R_NFTA_EXPR_NAME		1
#define B6R_NFTA_EXPR_DATA		2
#define B6R_NFTA_CT_DREG		1
#define B6R_NFTA_CT_KEY			2
#define B6R_NFT_CT_STATE		0
#define B6R_NFT_REG_1			8

/* IPv6 header bits kept local so we do not tie the build to whichever
 * of <netinet/ip6.h> / <linux/ipv6.h> the sysroot ships. */
#define B6R_NEXTHDR_HOP			0
#define B6R_NEXTHDR_ROUTING		43
#define B6R_NEXTHDR_FRAGMENT		44
#define B6R_NEXTHDR_DEST		60
#define B6R_NEXTHDR_UDP			17
#define B6R_IPV6_MIN_MTU		1280U
#define B6R_IP6_MF			0x0001U		/* wire order, low bit of frag_off */
#define B6R_IP6HDR_LEN			40U
#define B6R_FRAGHDR_LEN			8U
#define B6R_EXTHDR_UNIT			8U		/* ext header length granularity */

#define B6R_BURST_BASE			6U
#define B6R_BURST_CAP			24U
#define B6R_BUDGET_NS			(220ULL * 1000ULL * 1000ULL)
#define B6R_RTNL_BUF_BYTES		2048
#define B6R_NFT_BUF_BYTES		1024
#define B6R_FRAME_CAP			1600U		/* MTU (1500) + eth + slop */

static bool ns_unsupported;
static bool ns_unsupported_bridge;
static bool ns_unsupported_nf_tables;
static bool ns_unsupported_af_packet;
static bool lo_up_done;

static uint32_t b6r_ident_counter;

static size_t nla_put_be32(unsigned char *buf, size_t off, size_t cap,
			   unsigned short type, __u32 v)
{
	__u32 be = htonl(v);

	return nla_put(buf, off, cap, type, &be, sizeof(be));
}

/*
 * RTM_NEWLINK "bridge" — matches bridge-conntrack-churn's helper.
 * Kept local because the sibling's version is file-static.
 */
static int b6r_rtnl_create_bridge(struct nl_ctx *rtnl, const char *name)
{
	unsigned char buf[B6R_RTNL_BUF_BYTES];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct ifinfomsg *ifi;
	size_t off, li_off;

	memset(buf, 0, sizeof(buf));
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
	off = nla_put_str(buf, off, sizeof(buf), IFLA_INFO_KIND, "bridge");
	if (!off) return -EIO;
	nla_nest_end(buf, li_off, off);
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(rtnl, buf, off);
}

/*
 * RTM_NEWLINK veth pair — same shape as bridge-conntrack-churn's
 * helper; independent copy so the two sibling ops do not share
 * translation-unit state.
 */
static int b6r_rtnl_create_veth(struct nl_ctx *rtnl, const char *a,
				const char *b)
{
	unsigned char buf[B6R_RTNL_BUF_BYTES];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct ifinfomsg *ifi, *peer_ifi;
	size_t off, li_off, id_off, peer_off;

	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(rtnl);
	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, a);
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
	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, b);
	if (!off) return -EIO;
	nla_nest_end(buf, peer_off, off);
	nla_nest_end(buf, id_off, off);
	nla_nest_end(buf, li_off, off);
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(rtnl, buf, off);
}

static int b6r_rtnl_setlink_master(struct nl_ctx *rtnl, int idx, int master)
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
	if (!off) return -EIO;
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(rtnl, buf, off);
}

/* Set an interface's MTU via RTM_SETLINK + IFLA_MTU.  Best-effort:
 * caller ignores the return code because a rejected MTU (e.g. kernel
 * clamped below IPV6_MIN_MTU) still leaves the port usable — just
 * without the small-MTU forcing that maximises refrag coverage. */
static int b6r_rtnl_setlink_mtu(struct nl_ctx *rtnl, int idx, unsigned int mtu)
{
	unsigned char buf[128];
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
	off = nla_put_u32(buf, off, sizeof(buf), IFLA_MTU, (__u32)mtu);
	if (!off) return -EIO;
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(rtnl, buf, off);
}

/*
 * Build the full BATCH_BEGIN / NEWTABLE / NEWCHAIN / NEWRULE / BATCH_END
 * transaction for a bridge-family "ct" rule and ship it as one sendmsg.
 * The rule's verdict path is unused; installing it is what forces
 * nf_conntrack_bridge registration, which is the precondition for the
 * kernel to run nf_ct_frag6_gather on bridged IPv6 fragments.  Returns
 * 0 on clean end-of-batch, negated errno on the first rejection.
 */
static int b6r_nft_install_bridge_ct(struct nfnl_ctx *nf, const char *table,
				     const char *chain)
{
	unsigned char buf[B6R_NFT_BUF_BYTES];
	size_t off = 0, hook_off, exprs_off, elem_off, expr_data_off;
	__u8 family = NFPROTO_BRIDGE;
	__u32 prio = (__u32)(NF_BR_PRI_CT_PRE - 1);
	size_t msg_off;

	memset(buf, 0, sizeof(buf));

	off = nfnl_batch_begin(buf, off, sizeof(buf),
			       nl_seq_next(&nf->nl), NFNL_SUBSYS_NFTABLES);
	if (!off) return -EIO;

	msg_off = off;
	off = nfnl_msg_put(buf, off, sizeof(buf), nl_seq_next(&nf->nl),
			   NFNL_SUBSYS_NFTABLES, B6R_NFT_MSG_NEWTABLE,
			   NLM_F_CREATE, family);
	if (!off) return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), B6R_NFTA_TABLE_NAME, table);
	if (!off) return -EIO;
	((struct nlmsghdr *)(buf + msg_off))->nlmsg_len = (__u32)(off - msg_off);

	msg_off = off;
	off = nfnl_msg_put(buf, off, sizeof(buf), nl_seq_next(&nf->nl),
			   NFNL_SUBSYS_NFTABLES, B6R_NFT_MSG_NEWCHAIN,
			   NLM_F_CREATE, family);
	if (!off) return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), B6R_NFTA_CHAIN_TABLE, table);
	off = nla_put_str(buf, off, sizeof(buf), B6R_NFTA_CHAIN_NAME, chain);
	if (!off) return -EIO;
	hook_off = off;
	off = nla_nest_start(buf, off, sizeof(buf),
			     B6R_NFTA_CHAIN_HOOK | NLA_F_NESTED);
	if (!off) return -EIO;
	off = nla_put_be32(buf, off, sizeof(buf),
			   B6R_NFTA_HOOK_HOOKNUM, NF_BR_PRE_ROUTING);
	off = nla_put_be32(buf, off, sizeof(buf),
			   B6R_NFTA_HOOK_PRIORITY, prio);
	if (!off) return -EIO;
	nla_nest_end(buf, hook_off, off);
	off = nla_put_str(buf, off, sizeof(buf),
			  B6R_NFTA_CHAIN_TYPE, "filter");
	if (!off) return -EIO;
	((struct nlmsghdr *)(buf + msg_off))->nlmsg_len = (__u32)(off - msg_off);

	msg_off = off;
	off = nfnl_msg_put(buf, off, sizeof(buf), nl_seq_next(&nf->nl),
			   NFNL_SUBSYS_NFTABLES, B6R_NFT_MSG_NEWRULE,
			   NLM_F_CREATE | NLM_F_APPEND, family);
	if (!off) return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), B6R_NFTA_RULE_TABLE, table);
	off = nla_put_str(buf, off, sizeof(buf), B6R_NFTA_RULE_CHAIN, chain);
	if (!off) return -EIO;
	exprs_off = off;
	off = nla_nest_start(buf, off, sizeof(buf),
			     B6R_NFTA_RULE_EXPRESSIONS | NLA_F_NESTED);
	if (!off) return -EIO;
	elem_off = off;
	off = nla_nest_start(buf, off, sizeof(buf),
			     B6R_NFTA_LIST_ELEM | NLA_F_NESTED);
	off = nla_put_str(buf, off, sizeof(buf), B6R_NFTA_EXPR_NAME, "ct");
	expr_data_off = off;
	off = nla_nest_start(buf, off, sizeof(buf),
			     B6R_NFTA_EXPR_DATA | NLA_F_NESTED);
	off = nla_put_be32(buf, off, sizeof(buf),
			   B6R_NFTA_CT_KEY, B6R_NFT_CT_STATE);
	off = nla_put_be32(buf, off, sizeof(buf),
			   B6R_NFTA_CT_DREG, B6R_NFT_REG_1);
	if (!off) return -EIO;
	nla_nest_end(buf, expr_data_off, off);
	nla_nest_end(buf, elem_off, off);
	nla_nest_end(buf, exprs_off, off);
	((struct nlmsghdr *)(buf + msg_off))->nlmsg_len = (__u32)(off - msg_off);

	off = nfnl_batch_end(buf, off, sizeof(buf),
			     nl_seq_next(&nf->nl), NFNL_SUBSYS_NFTABLES);
	if (!off) return -EIO;

	return nfnl_send_recv_batched(nf, buf, off);
}

/*
 * Craft one IPv6 fragment.  Layout stamped into `frame` (starting
 * from the ethernet header):
 *
 *   [eth][ipv6][optional pre-frag ext hdr][frag hdr][payload]
 *
 * `ext_kind` picks the pre-fragment header:
 *   0  no extension     — ipv6->nexthdr = FRAGMENT
 *   1  DEST-OPT stub    — 8-byte DEST option, then FRAGMENT
 *   2  HOP-BY-HOP stub  — 8-byte HOP option, then FRAGMENT
 *   3  DEST-OPT stub with hdr_ext_len = 1 but only 8 bytes present
 *                      — the "short prev-header" the refrag walker
 *                        must tolerate: reassembler recorded the
 *                        actual chain, refragmenter re-derives it
 *                        from hdr_ext_len and may over-read past
 *                        the recorded chain.
 *
 * Returns the total frame length in bytes.
 */
static size_t b6r_build_frag_frame(unsigned char *frame, size_t cap,
				   const unsigned char *dst_mac,
				   const unsigned char *src_mac,
				   unsigned int ext_kind,
				   uint32_t ident, uint16_t frag_off_he,
				   bool more_frags,
				   const unsigned char *payload,
				   size_t payload_len)
{
	size_t off = 0;
	size_t ip6_off, payload_off;
	size_t ext_len = 0;
	uint8_t first_nexthdr;
	uint16_t payload_field;
	uint16_t frag_off_word;

	if (cap < 14U + B6R_IP6HDR_LEN + B6R_EXTHDR_UNIT +
		  B6R_FRAGHDR_LEN + payload_len)
		return 0;

	memcpy(frame + off, dst_mac, 6); off += 6;
	memcpy(frame + off, src_mac, 6); off += 6;
	frame[off++] = 0x86; frame[off++] = 0xdd;	/* ETH_P_IPV6 */

	ip6_off = off;
	memset(frame + ip6_off, 0, B6R_IP6HDR_LEN);
	frame[ip6_off + 0] = 0x60;			/* version=6, tc=0 */
	frame[ip6_off + 6] = 64;			/* nexthdr placeholder */
	frame[ip6_off + 7] = 64;			/* hop limit */
	/* fe80::5a5a:1 -> fe80::a5a5:1 */
	frame[ip6_off +  8] = 0xfe; frame[ip6_off +  9] = 0x80;
	frame[ip6_off + 20] = 0x5a; frame[ip6_off + 21] = 0x5a;
	frame[ip6_off + 23] = 0x01;
	frame[ip6_off + 24] = 0xfe; frame[ip6_off + 25] = 0x80;
	frame[ip6_off + 36] = 0xa5; frame[ip6_off + 37] = 0xa5;
	frame[ip6_off + 39] = 0x01;
	off = ip6_off + B6R_IP6HDR_LEN;

	first_nexthdr = B6R_NEXTHDR_FRAGMENT;
	if (ext_kind == 1 || ext_kind == 3)
		first_nexthdr = B6R_NEXTHDR_DEST;
	else if (ext_kind == 2)
		first_nexthdr = B6R_NEXTHDR_HOP;
	frame[ip6_off + 6] = first_nexthdr;

	if (ext_kind != 0) {
		frame[off + 0] = B6R_NEXTHDR_FRAGMENT;	/* next-hdr */
		/* hdr_ext_len is (total-8)/8; 0 == 8 total.  ext_kind 3
		 * stamps 1 (claim 16 total) while only 8 bytes are
		 * written, so the walker over-reads past the recorded
		 * chain into the fragment header. */
		frame[off + 1] = (ext_kind == 3) ? 1 : 0;
		/* PadN of type=0x01, len=4 to fill the 8-byte unit */
		frame[off + 2] = 0x01; frame[off + 3] = 0x04;
		memset(frame + off + 4, 0, 4);
		ext_len = B6R_EXTHDR_UNIT;
		off += ext_len;
	}

	frame[off + 0] = B6R_NEXTHDR_UDP;		/* frag: next-hdr */
	frame[off + 1] = 0;				/* reserved */
	frag_off_word = (uint16_t)(frag_off_he & 0xfff8U);
	if (more_frags)
		frag_off_word |= B6R_IP6_MF;
	frame[off + 2] = (unsigned char)(frag_off_word >> 8);
	frame[off + 3] = (unsigned char)(frag_off_word & 0xff);
	frame[off + 4] = (unsigned char)(ident >> 24);
	frame[off + 5] = (unsigned char)(ident >> 16);
	frame[off + 6] = (unsigned char)(ident >>  8);
	frame[off + 7] = (unsigned char)(ident      );
	off += B6R_FRAGHDR_LEN;

	payload_off = off;
	if (payload && payload_len)
		memcpy(frame + payload_off, payload, payload_len);
	off += payload_len;

	payload_field = (uint16_t)(ext_len + B6R_FRAGHDR_LEN + payload_len);
	frame[ip6_off + 4] = (unsigned char)(payload_field >> 8);
	frame[ip6_off + 5] = (unsigned char)(payload_field & 0xff);

	return off;
}

/*
 * Send one two-fragment pair.  Both fragments share `ident`.  The
 * first frag carries the majority of the payload with MF set at
 * offset 0; the second carries a small tail with MF clear at the
 * offset dictated by the first frag's payload size.  Fragment size,
 * pre-frag extension shape and total datagram size are picked from
 * `rnd_hi` so the burst sweeps distinct (ident, ext, len) triples.
 */
static void b6r_send_frag_pair(int raw_fd, int ifindex,
			       const unsigned char *dst_mac,
			       const unsigned char *src_mac,
			       uint32_t ident, uint32_t rnd_hi)
{
	unsigned char frame[B6R_FRAME_CAP];
	unsigned char payload[1400];
	unsigned int ext_kind    = rnd_hi & 0x3U;
	unsigned int frag1_pick  = (rnd_hi >> 2) & 0x7U;
	unsigned int total_pick  = (rnd_hi >> 5) & 0x7U;
	size_t frag1_len         = 64U + frag1_pick * 128U;
	size_t total_len         = frag1_len + 40U + total_pick * 96U;
	size_t frame_len;
	struct sockaddr_ll sll;

	if (total_len > sizeof(payload))
		total_len = sizeof(payload);
	if (frag1_len > total_len - 8U)
		frag1_len = total_len - 8U;
	frag1_len &= ~((size_t)7U);
	if (frag1_len < 8U)
		frag1_len = 8U;

	memset(payload, (unsigned char)(0xa0 | (rnd_hi & 0xfU)), total_len);

	memset(&sll, 0, sizeof(sll));
	sll.sll_family   = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_IPV6);
	sll.sll_ifindex  = ifindex;
	sll.sll_halen    = 6;
	memcpy(sll.sll_addr, dst_mac, 6);

	frame_len = b6r_build_frag_frame(frame, sizeof(frame),
					 dst_mac, src_mac, ext_kind,
					 ident, 0U, true,
					 payload, frag1_len);
	if (frame_len &&
	    sendto(raw_fd, frame, frame_len, MSG_DONTWAIT,
		   (struct sockaddr *)&sll, sizeof(sll)) > 0)
		__atomic_add_fetch(&shm->stats.bridge_ip6frag.frames_sent,
				   1, __ATOMIC_RELAXED);

	frame_len = b6r_build_frag_frame(frame, sizeof(frame),
					 dst_mac, src_mac, ext_kind,
					 ident, (uint16_t)frag1_len, false,
					 payload + frag1_len,
					 total_len - frag1_len);
	if (frame_len &&
	    sendto(raw_fd, frame, frame_len, MSG_DONTWAIT,
		   (struct sockaddr *)&sll, sizeof(sll)) > 0)
		__atomic_add_fetch(&shm->stats.bridge_ip6frag.frames_sent,
				   1, __ATOMIC_RELAXED);
}

/* Per-invocation state carried across the extracted phase helpers.
 * fd fields default to -1 via the orchestrator's designated
 * initialiser so the teardown helper can close them unconditionally
 * regardless of which earlier phase bailed. */
struct b6r_iter_ctx {
	char			br_name[IFNAMSIZ];
	char			veth_a[IFNAMSIZ];
	char			veth_b[IFNAMSIZ];
	struct nl_ctx		rtnl;
	struct nfnl_ctx		nfnl_nft;
	int			raw;
	int			br_idx;
	int			va_idx;
	int			vb_idx;
	bool			bridge_added;
	bool			veth_added;
	struct childdata	*child;
};

/*
 * Phase 1: pick per-invocation interface names + open the rtnl
 * socket.  lo is brought up once per process via the lo_up_done
 * latch.  Names derive from a single 16-bit random suffix so the
 * three interfaces share a stable in-netns correlator.
 */
static int b6r_iter_setup_names(struct b6r_iter_ctx *ctx)
{
	struct nl_open_opts rtnl_opts = {
		.proto         = NETLINK_ROUTE,
		.recv_timeo_s  = 1,
	};
	unsigned int rng;

	if (nl_open(&ctx->rtnl, &rtnl_opts) < 0)
		return -1;
	if (!lo_up_done) {
		rtnl_bring_lo_up(&ctx->rtnl);
		lo_up_done = true;
	}

	rng = (unsigned int)(rand32() & 0xffffu);
	snprintf(ctx->br_name, sizeof(ctx->br_name), "tr6r%u",  rng);
	snprintf(ctx->veth_a,  sizeof(ctx->veth_a),  "tr6r%ua", rng);
	snprintf(ctx->veth_b,  sizeof(ctx->veth_b),  "tr6r%ub", rng);
	return 0;
}

/*
 * Phase 2: create bridge + veth pair, enslave v0 to br, set v0's MTU
 * to IPV6_MIN_MTU (1280) so any reassembled datagram > 1232 bytes of
 * payload forces br_ip6_fragment.  RTM_NEWLINK bridge-side latches
 * ns_unsupported_bridge on the family/proto rejection codes so
 * siblings stop probing when CONFIG_BRIDGE is absent.
 */
static int b6r_iter_bridge_and_veth(struct b6r_iter_ctx *ctx)
{
	const enum child_op_type op = ctx->child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);
	int rc;

	rc = b6r_rtnl_create_bridge(&ctx->rtnl, ctx->br_name);
	if (rc != 0) {
		if (rc == -EAFNOSUPPORT || rc == -EOPNOTSUPP ||
		    rc == -ENOTSUP || rc == -EPROTONOSUPPORT) {
			ns_unsupported_bridge = true;
			if (valid_op)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_NS_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		return -1;
	}
	ctx->bridge_added = true;
	ctx->br_idx = (int)if_nametoindex(ctx->br_name);
	if (ctx->br_idx <= 0)
		return -1;

	if (b6r_rtnl_create_veth(&ctx->rtnl, ctx->veth_a, ctx->veth_b) != 0)
		return -1;
	ctx->veth_added = true;
	ctx->va_idx = (int)if_nametoindex(ctx->veth_a);
	ctx->vb_idx = (int)if_nametoindex(ctx->veth_b);
	if (ctx->va_idx <= 0 || ctx->vb_idx <= 0)
		return -1;

	(void)b6r_rtnl_setlink_master(&ctx->rtnl, ctx->va_idx, ctx->br_idx);
	(void)b6r_rtnl_setlink_mtu(&ctx->rtnl, ctx->va_idx, B6R_IPV6_MIN_MTU);
	(void)rtnl_setlink_up(&ctx->rtnl, ctx->br_idx);
	(void)rtnl_setlink_up(&ctx->rtnl, ctx->va_idx);
	(void)rtnl_setlink_up(&ctx->rtnl, ctx->vb_idx);
	return 0;
}

/*
 * Phase 3: open the nf_tables nfnl socket and install the
 * bridge-family ct table / chain / rule transaction.  Installing the
 * "ct" expression is what forces nf_conntrack_bridge registration and
 * therefore the IPv6 defrag hook we are here to exercise.  Latches
 * ns_unsupported_nf_tables on family/proto rejection.  A local
 * nfnl_open failure is treated as iteration-fatal because without
 * the ct rule the traffic burst degenerates into a plain bridge flood
 * that never touches the defrag path.
 */
static int b6r_iter_nft_setup(struct b6r_iter_ctx *ctx)
{
	struct nfnl_open_opts nfnl_opts = { .recv_timeo_s = 1 };
	const enum child_op_type op = ctx->child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);
	int rc;

	if (nfnl_open(&ctx->nfnl_nft, &nfnl_opts) < 0)
		return -1;
	rc = b6r_nft_install_bridge_ct(&ctx->nfnl_nft, "br_ip6ct", "in");
	if (rc == -EAFNOSUPPORT || rc == -EPROTONOSUPPORT ||
	    rc == -EOPNOTSUPP || rc == -ENOTSUP) {
		ns_unsupported_nf_tables = true;
		if (valid_op)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		return -1;
	}
	return 0;
}

/*
 * Phase 4: open the AF_PACKET raw socket on v0p, bind, then inject
 * the bounded IPv6-fragment burst.  Broadcast destination MAC so the
 * bridge floods each frame out v0 — the reassembly + refrag happens
 * on that egress path.  All sends are MSG_DONTWAIT; the local
 * BUDGETED loop plus the B6R_BUDGET_NS wall cap keep the burst under
 * child.c's SIGALRM(1s).
 */
static void b6r_iter_packet_burst(struct b6r_iter_ctx *ctx)
{
	const enum child_op_type op = ctx->child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);
	unsigned char dst_mac[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	unsigned char src_mac[6];
	struct sockaddr_ll bind_sll;
	struct timespec t0;
	unsigned int iters, i;

	ctx->raw = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC,
			  htons(ETH_P_IPV6));
	if (ctx->raw < 0) {
		if (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT) {
			ns_unsupported_af_packet = true;
			if (valid_op)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_NS_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		return;
	}

	memset(&bind_sll, 0, sizeof(bind_sll));
	bind_sll.sll_family   = AF_PACKET;
	bind_sll.sll_protocol = htons(ETH_P_IPV6);
	bind_sll.sll_ifindex  = ctx->vb_idx;
	(void)bind(ctx->raw, (struct sockaddr *)&bind_sll, sizeof(bind_sll));

	generate_rand_bytes(src_mac, 6);
	src_mac[0] = (unsigned char)((src_mac[0] & 0xfc) | 0x02);

	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	}

	if (clock_gettime(CLOCK_MONOTONIC, &t0) < 0) {
		t0.tv_sec = 0;
		t0.tv_nsec = 0;
	}
	iters = BUDGETED(CHILD_OP_BRIDGE_IP6FRAG_REFRAG,
			 JITTER_RANGE(B6R_BURST_BASE));
	if (iters < 1)
		iters = 1;
	if (iters > B6R_BURST_CAP)
		iters = B6R_BURST_CAP;

	for (i = 0; i < iters; i++) {
		uint32_t rnd_hi;

		if ((unsigned long long)ns_since(&t0) >= B6R_BUDGET_NS)
			break;

		rnd_hi = rand32();
		b6r_send_frag_pair(ctx->raw, ctx->vb_idx,
				   dst_mac, src_mac,
				   b6r_ident_counter, rnd_hi);
		b6r_ident_counter++;
		__atomic_add_fetch(&shm->stats.bridge_ip6frag.pairs_sent,
				   1, __ATOMIC_RELAXED);
	}
}

/*
 * Phase 5: close whichever resources we managed to open.  Order
 * matches bridge-conntrack-churn's teardown: drain the raw fd first,
 * close the nfnl context, then RTM_DELLINK the survivors before
 * closing rtnl.  br0 dellink cascades v0; v0p (the survivor) is
 * removed explicitly.
 */
static void b6r_iter_teardown(struct b6r_iter_ctx *ctx)
{
	if (ctx->raw >= 0) {
		unsigned char drain[256];

		while (recv(ctx->raw, drain, sizeof(drain), MSG_DONTWAIT) > 0)
			;
		close(ctx->raw);
	}
	nfnl_close(&ctx->nfnl_nft);
	if (ctx->rtnl.fd >= 0) {
		if (ctx->bridge_added && ctx->br_idx > 0)
			(void)rtnl_dellink(&ctx->rtnl, ctx->br_idx);
		if (ctx->veth_added && ctx->vb_idx > 0)
			(void)rtnl_dellink(&ctx->rtnl, ctx->vb_idx);
		nl_close(&ctx->rtnl);
	}
}

struct b6r_ctx {
	struct childdata *child;
};

/*
 * Per-invocation body that must run inside the private net namespace.
 * Executed in a transient grandchild forked by userns_run_in_ns(); the
 * grandchild's userns + netns are torn down on _exit() so every link,
 * hook, address and socket left behind is reaped along with the
 * namespace.  Return value is ignored by the helper.
 */
static int bridge_ip6frag_refrag_in_ns(void *arg)
{
	struct b6r_ctx *cctx = (struct b6r_ctx *)arg;
	struct b6r_iter_ctx ctx = {
		.rtnl     = { .fd = -1 },
		.nfnl_nft = { .nl = { .fd = -1 } },
		.raw      = -1,
		.child    = cctx->child,
	};

	if (b6r_iter_setup_names(&ctx) != 0)
		goto out;
	if (b6r_iter_bridge_and_veth(&ctx) != 0)
		goto out;
	if (b6r_iter_nft_setup(&ctx) != 0)
		goto out;
	b6r_iter_packet_burst(&ctx);

out:
	b6r_iter_teardown(&ctx);
	return 0;
}

bool bridge_ip6frag_refrag(struct childdata *child)
{
	struct b6r_ctx cctx = { .child = child };
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);
	int rc;

	__atomic_add_fetch(&shm->stats.bridge_ip6frag.runs, 1,
			   __ATOMIC_RELAXED);

	if (ns_unsupported || ns_unsupported_bridge ||
	    ns_unsupported_nf_tables || ns_unsupported_af_packet)
		return true;

	if (!ONE_IN(8))
		return true;

	rc = userns_run_in_ns(CLONE_NEWNET, bridge_ip6frag_refrag_in_ns, &cctx);
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
		 * secondary unshare).  Skip this iteration without latching
		 * -- the failure is not policy and may not recur. */
		return true;
	}

	return true;
}
