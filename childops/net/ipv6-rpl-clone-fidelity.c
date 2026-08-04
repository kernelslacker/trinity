/*
 * ipv6_rpl_clone_fidelity -- packet-fidelity oracle for the RPL SRH
 * receive path.
 *
 * Background: ip6_protocol_deliver_rcu() at line 427 calls
 * raw6_local_deliver() with nexthdr==43 (IPPROTO_ROUTING) BEFORE the
 * routing extension-header handler runs.  raw6_local_deliver() hands a
 * skb_clone() of the incoming skb to any matching raw socket.  The
 * clone shares the same data buffer as the original.  ipv6_rpl_srh_rcv()
 * then runs on the original and modifies the Routing Header in-place --
 * decrementing segments_left and memmove-ing the compressed address list
 * -- without calling skb_make_writable() to break sharing first.  Because
 * the clone and the original share a data buffer, the modification bleeds
 * into the clone; by the time user space calls recvfrom() on the raw
 * socket, the SRH bytes reflect the post-handler state rather than the
 * original transmitted state.
 *
 * Oracle shape: differential packet fidelity.  We transmit a frame with
 * a known segments_left and known IPv6 daddr, then compare what each of
 * two independent listeners received against those known values.
 *
 *   Primary listener   socket(AF_INET6, SOCK_RAW, IPPROTO_ROUTING/43)
 *                      Sees the raw6 clone; receives at transport-layer
 *                      offset (SRH byte 0 == routing_type, byte 3 ==
 *                      segments_left).  Checks SRH[3] vs transmitted.
 *
 *   Secondary listener socket(AF_PACKET, SOCK_RAW, ETH_P_IPV6) on the
 *                      RX-side veth (non-mmap, plain recvfrom()).
 *                      Sees the full Ethernet frame including the IPv6
 *                      header; checks daddr (bytes 38..53 of the frame)
 *                      vs transmitted fd00::1.
 *
 * Divergence in segments_left or daddr == BUG; logged with offset and
 * hex windows, bumped into shm->stats.rpl_clone_fidelity.
 *
 * Setup per invocation (inside a userns_run_in_ns CLONE_NEWNET grandchild
 * -- private netns, all per-net sysctl writes are isolated, _exit reaps):
 *   1. Open NETLINK_ROUTE socket; bring lo up.
 *   2. RTM_NEWLINK veth pair "trplv0" / "trplv1"; IFF_UP both.
 *   3. RTM_NEWADDR fd00::1/64 on trplv1 (receive side) with
 *      IFA_F_NODAD | IFA_F_PERMANENT so the address is immediately
 *      usable.
 *   4. Write net.ipv6.conf.all.rpl_seg_enabled = 1 (covers both veth
 *      ends) and net.ipv6.conf.trplv0.rpl_seg_enabled = 1 (spec: inject
 *      dev).
 *   5. Open primary listener (raw6 IPPROTO_ROUTING), set SO_RCVTIMEO
 *      100 ms.
 *   6. Open secondary listener (AF_PACKET trplv1), set SO_RCVTIMEO
 *      100 ms.
 *   7. Open injection socket (AF_PACKET trplv0).
 *   8. Build and send the frame; recvfrom() both listeners; compare.
 *
 * Brick-safety: all operations are inside a private CLONE_NEWNET netns.
 * Sysctl writes are per-net; the host IPv6 config is untouched.  All
 * sends/recvs are MSG_DONTWAIT / SO_RCVTIMEO-bounded.  Netns teardown
 * on grandchild _exit() reaps all sockets, veth devices, and the per-net
 * sysctl state.
 *
 * Injection note: plain recvfrom() is used, NOT PACKET_RX_RING /
 * TPACKET.  TPACKET copies into the ring at enqueue time (before the
 * routing handler mutates the data) and would suppress the post-mutation
 * visibility that is the point of this oracle.
 *
 * Latches: ns_unsupported_ipv6_rpl_clone_fidelity on
 * userns_run_in_ns() -EPERM (unprivileged userns disabled or
 * user.max_user_namespaces=0).
 */

#include <errno.h>
#include <fcntl.h>
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
#include <unistd.h>

#include <linux/if_ether.h>
#include <linux/if_addr.h>
#include <linux/if_link.h>
#include <linux/if_packet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "child.h"
#include "childop-outcome.h"
#include "childops-netlink.h"
#include "childops-util.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"
#include "userns-bootstrap.h"

#include "kernel/socket.h"

/*
 * UAPI fallbacks.  IPPROTO_ROUTING is stable since POSIX; IFA_F_NODAD
 * and IFA_F_PERMANENT are defined in <linux/if_addr.h> (included above).
 */
#ifndef IPPROTO_ROUTING
# define IPPROTO_ROUTING		43
#endif
#ifndef VETH_INFO_PEER
# define VETH_INFO_PEER			1
#endif

/*
 * Frame geometry.  RPL SRH type 3, RFC 9008:
 *   nsegments = 3 → hdrlen = 2*nsegments = 6
 *   SRH total  = 8 + 16*3 = 56 bytes
 *   segments_left = 3 → 2 after decrement (spec: ≥ 2 after decrement)
 */
#define RPL_CF_NSEG		3U
#define RPL_CF_SRH_BYTES	(8U + 16U * RPL_CF_NSEG)	/* 56 */
#define RPL_CF_HDRLEN		((RPL_CF_SRH_BYTES / 8U) - 1U)	/* 6  */
#define RPL_CF_SEGL_TX		3U
#define RPL_CF_ETH_LEN		14U
#define RPL_CF_IP6_LEN		40U
#define RPL_CF_FRAME_LEN	(RPL_CF_ETH_LEN + RPL_CF_IP6_LEN + RPL_CF_SRH_BYTES)

/* veth names (private netns, no conflict risk). */
#define RPL_CF_VETH0		"trplv0"	/* injection side */
#define RPL_CF_VETH1		"trplv1"	/* receive side   */

/* SO_RCVTIMEO for oracle sockets: 100 ms gives the routing handler time
 * to run on any core before user space reads the (possibly mutated) data.*/
#define RPL_CF_RCV_TIMEO_USEC	100000U

/* RTNL buffer size (generous, covers veth RTM_NEWLINK + RTM_NEWADDR). */
#define RPL_CF_RTNL_BUF		512U

/*
 * fd00::1  -- the IPv6 address we assign to veth1 (daddr in injected
 * frame, and the "expected daddr" the oracle checks for).
 */
static const uint8_t rpl_cf_veth_addr[16] = {
	0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
};

/*
 * Per-child master latch.  Set by the wrapper on userns_run_in_ns()
 * returning -EPERM (unprivileged userns disabled).  Without a private
 * netns we must not inject RPL frames on the host, so the op stays
 * disabled for the remainder of this child's lifetime.
 */
static bool ns_unsupported_ipv6_rpl_clone_fidelity;

/* -------------------------------------------------------------------------
 * Helpers
 * ---------------------------------------------------------------------- */

static void rpl_cf_set_rcvtimeo(int fd, unsigned long *calls)
{
	struct timeval tv = { 0, RPL_CF_RCV_TIMEO_USEC };

	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	(*calls)++;
}

/*
 * Write "1\n" to /proc/sys/net/ipv6/conf/<dev>/rpl_seg_enabled.
 * Best-effort; a failure here means the running kernel predates the knob
 * (added with the rpl_seg_enabled sysctl in the unconditional ipv6-y
 * build list -- rpl.o carries no CONFIG_IPV6_RPL_LWTUNNEL guard).
 * If the write fails we skip silently; ipv6_rpl_srh_rcv() will gate
 * every packet and the oracle times out on recvfrom() harmlessly.
 */
static void rpl_cf_enable_seg(const char *dev, unsigned long *calls)
{
	char path[128];
	int fd;
	ssize_t n;

	snprintf(path, sizeof(path),
		 "/proc/sys/net/ipv6/conf/%s/rpl_seg_enabled", dev);
	fd = open(path, O_WRONLY | O_CLOEXEC);
	(*calls)++;
	if (fd < 0)
		return;
	n = write(fd, "1", 1);
	(*calls)++;
	(void)n;
	close(fd);
	(*calls)++;
}

/*
 * RTM_NEWLINK veth pair <a>/<b> inside the current netns.
 * Returns 0 on success, negated errno on rejection, -EIO on local failure.
 */
static int rpl_cf_create_veth(struct nl_ctx *ctx, const char *a, const char *b)
{
	unsigned char buf[RPL_CF_RTNL_BUF];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi, *peer_ifi;
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
	return nl_send_recv(ctx, buf, off);
}

/*
 * RTM_NEWADDR fd00::1/64 on <ifindex> with IFA_F_NODAD | IFA_F_PERMANENT.
 * The NODAD flag skips the Duplicate Address Detection delay so the
 * address is immediately usable without a ~1-second wait.
 */
static int rpl_cf_add_v6_addr(struct nl_ctx *ctx, int ifindex)
{
	unsigned char buf[RPL_CF_RTNL_BUF];
	struct nlmsghdr *nlh;
	struct ifaddrmsg *ifa;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWADDR;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifa = (struct ifaddrmsg *)NLMSG_DATA(nlh);
	ifa->ifa_family    = AF_INET6;
	ifa->ifa_prefixlen = 64;
	ifa->ifa_flags     = IFA_F_NODAD | IFA_F_PERMANENT;
	ifa->ifa_scope     = RT_SCOPE_UNIVERSE;
	ifa->ifa_index     = (unsigned int)ifindex;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifa));
	off = nla_put(buf, off, sizeof(buf), IFA_LOCAL,
		      rpl_cf_veth_addr, sizeof(rpl_cf_veth_addr));
	if (!off)
		return -EIO;
	off = nla_put(buf, off, sizeof(buf), IFA_ADDRESS,
		      rpl_cf_veth_addr, sizeof(rpl_cf_veth_addr));
	if (!off)
		return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * Build the Ether/IPv6(nh=43)/RPL-SRH frame into buf.
 * Frame layout (RPL_CF_FRAME_LEN = 110 bytes):
 *   [  0..13] Ethernet: dst=bcast, src=local-admin, type=0x86dd
 *   [ 14..53] IPv6: nh=43, hop_limit=64, src=fd00::2, dst=fd00::1
 *   [ 54..109] RPL SRH type 3: routing_type=3, segments_left=3,
 *              hdrlen=6, cmpri=cmpre=pad=0, Addresses[0..2]=::1
 *
 * The SRH's next-header field (byte 54) is IPPROTO_NONE(=59) so no
 * inner protocol parsing is needed after decap.
 */
static void rpl_cf_build_frame(uint8_t *buf)
{
	static const uint8_t bcast_mac[6] = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	};
	/* fd00::2 as source (arbitrary non-local ULA) */
	static const uint8_t src_addr[16] = {
		0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
	};
	uint16_t payload_len = (uint16_t)RPL_CF_SRH_BYTES;
	unsigned int off = 0;
	unsigned int i;

	memset(buf, 0, RPL_CF_FRAME_LEN);

	/* Ethernet header. */
	memcpy(buf + off, bcast_mac, 6);	off += 6;
	buf[off] = 0x02;			/* locally-administered src */
	off += 6;
	buf[off + 0] = 0x86;			/* EtherType IPv6 = 0x86dd */
	buf[off + 1] = 0xdd;
	off += 2;				/* off = 14 */

	/* IPv6 header. */
	buf[off + 0] = 0x60;			/* version=6, TC=0, FL=0   */
	buf[off + 4] = (uint8_t)(payload_len >> 8);
	buf[off + 5] = (uint8_t)(payload_len & 0xffU);
	buf[off + 6] = IPPROTO_ROUTING;		/* next-header = 43        */
	buf[off + 7] = 64U;			/* hop_limit               */
	memcpy(buf + off + 8,  src_addr,       16);	/* saddr = fd00::2         */
	memcpy(buf + off + 24, rpl_cf_veth_addr, 16);	/* daddr = fd00::1         */
	off += 40;				/* off = 54 */

	/* RPL SRH (routing type 3, RFC 9008). */
	buf[off + 0] = 59U;			/* next-header = IPPROTO_NONE */
	buf[off + 1] = RPL_CF_HDRLEN;		/* hdr_ext_len = 6            */
	buf[off + 2] = 3U;			/* routing_type = RPL SRH     */
	buf[off + 3] = RPL_CF_SEGL_TX;		/* segments_left = 3          */
	/* buf[off+4] = (cmpri<<4)|cmpre = 0: no prefix compression */
	/* buf[off+5] = (pad<<4)|0 = 0: no pad bytes                */
	/* buf[off+6..7] reserved = 0                               */
	/* Addresses[0..2] = ::1 (loopback) so daddr rewrite lands
	 * on loopback; all other bytes are already zero from memset. */
	for (i = 0; i < RPL_CF_NSEG; i++)
		buf[off + 8 + 16 * i + 15] = 0x01U;
	/* off += RPL_CF_SRH_BYTES; -- not needed, frame is complete */
}

/* -------------------------------------------------------------------------
 * Oracle comparison helpers
 * ---------------------------------------------------------------------- */

static void rpl_cf_log_srh_divergence(uint8_t rx_segl, uint8_t tx_segl)
{
	outputerr("ipv6_rpl_clone_fidelity: BUG -- " /* check-static: child-output-ok */
		  "SRH segments_left mutated in raw6 clone: "
		  "transmitted=%u received=%u (expected no change)\n",
		  (unsigned)tx_segl, (unsigned)rx_segl);
	__atomic_add_fetch(&shm->stats.rpl_clone_fidelity.srh_mutated,
			   1, __ATOMIC_RELAXED);
}

static void rpl_cf_log_daddr_divergence(const uint8_t *rx_daddr,
					const uint8_t *tx_daddr)
{
	char rx_hex[49], tx_hex[49];
	unsigned int i;

	for (i = 0; i < 16; i++) {
		snprintf(rx_hex + i * 3, 4, "%02x ", rx_daddr[i]);
		snprintf(tx_hex + i * 3, 4, "%02x ", tx_daddr[i]);
	}
	outputerr("ipv6_rpl_clone_fidelity: BUG -- " /* check-static: child-output-ok */
		  "IPv6 daddr mutated in AF_PACKET clone:\n"
		  "  transmitted: %s\n  received:    %s\n",
		  tx_hex, rx_hex);
	__atomic_add_fetch(&shm->stats.rpl_clone_fidelity.daddr_mutated,
			   1, __ATOMIC_RELAXED);
}

/* -------------------------------------------------------------------------
 * Grandchild context
 * ---------------------------------------------------------------------- */

struct rpl_cf_in_ns_ctx {
	struct childdata *child;
};

struct rpl_cf_iter_ctx {
	struct nl_ctx		nl;
	int			raw6;		/* AF_INET6 SOCK_RAW IPPROTO_ROUTING */
	int			pkt_obs;	/* AF_PACKET on veth1 (observer)     */
	int			pkt_tx;		/* AF_PACKET on veth0 (injector)     */
	int			veth0_idx;
	int			veth1_idx;
	bool			nl_opened;
	bool			veth_created;
	struct childdata	*child;
	unsigned long		direct_calls;
};

/*
 * Open the rtnl context and bring lo up.
 */
static int rpl_cf_open_nl(struct rpl_cf_iter_ctx *ctx)
{
	struct nl_open_opts opts = {
		.proto        = NETLINK_ROUTE,
		.recv_timeo_s = 1,
	};

	if (nl_open(&ctx->nl, &opts) < 0)
		return -1;
	ctx->nl_opened = true;
	rtnl_bring_lo_up(&ctx->nl);
	return 0;
}

/*
 * Create veth pair, bring both ends up, add fd00::1/64 to the receive
 * side (veth1), and enable rpl_seg_enabled on "all" and the inject dev.
 */
static int rpl_cf_setup_net(struct rpl_cf_iter_ctx *ctx)
{
	if (rpl_cf_create_veth(&ctx->nl, RPL_CF_VETH0, RPL_CF_VETH1) != 0)
		return -1;
	ctx->veth_created = true;

	ctx->veth0_idx = (int)if_nametoindex(RPL_CF_VETH0);
	ctx->veth1_idx = (int)if_nametoindex(RPL_CF_VETH1);
	if (ctx->veth0_idx <= 0 || ctx->veth1_idx <= 0)
		return -1;

	/* Bring both veth ends up so IPv6 link-local autoconfiguration
	 * starts; our explicit fd00::1/64 address bypasses the liveness
	 * wait via IFA_F_NODAD. */
	if (rtnl_setlink_up(&ctx->nl, ctx->veth0_idx) < 0 ||
	    rtnl_setlink_up(&ctx->nl, ctx->veth1_idx) < 0)
		return -1;

	/* Assign fd00::1/64 to the receive side (veth1) with NODAD so
	 * the address is immediately active.  The injected frame's daddr
	 * matches this, causing local delivery through veth1's RX path. */
	if (rpl_cf_add_v6_addr(&ctx->nl, ctx->veth1_idx) != 0)
		return -1;

	/* Enable RPL SRH processing for this netns.
	 *
	 * ipv6_rpl_srh_rcv() gates on:
	 *   min(net->ipv6.devconf_all->rpl_seg_enabled,
	 *       idev->cnf.rpl_seg_enabled)           -- idev == skb->dev
	 * where skb->dev for a frame injected on trplv0 is its veth peer
	 * trplv1 (the receive side).  The "all" knob satisfies the
	 * devconf_all side of the min(); the per-device write on the
	 * *receive* veth (VETH1) satisfies the per-idev side.  Omitting
	 * the VETH1 write leaves cnf.rpl_seg_enabled==0 on the receive
	 * device so min(1,0)==0 and every injected packet is dropped. */
	rpl_cf_enable_seg("all",        &ctx->direct_calls);
	rpl_cf_enable_seg(RPL_CF_VETH0, &ctx->direct_calls);
	rpl_cf_enable_seg(RPL_CF_VETH1, &ctx->direct_calls);

	return 0;
}

/*
 * Open the three sockets used by the oracle:
 *   raw6   -- AF_INET6/SOCK_RAW/IPPROTO_ROUTING, receives the SRH clone
 *   pkt_obs-- AF_PACKET/SOCK_RAW/ETH_P_IPV6 bound to veth1 (observer)
 *   pkt_tx -- AF_PACKET/SOCK_RAW/ETH_P_IPV6 bound to veth0 (injector)
 */
static int rpl_cf_open_sockets(struct rpl_cf_iter_ctx *ctx)
{
	struct sockaddr_ll sll;

	/* Primary: raw6 clone receiver.  Unbound -- receives from any
	 * interface on nexthdr==43. */
	ctx->raw6 = socket(AF_INET6, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ROUTING);
	ctx->direct_calls++;
	if (ctx->raw6 < 0)
		return -1;
	rpl_cf_set_rcvtimeo(ctx->raw6, &ctx->direct_calls);

	/* Secondary: AF_PACKET frame observer on veth1 (receive side). */
	ctx->pkt_obs = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC,
			      htons(ETH_P_IPV6));
	ctx->direct_calls++;
	if (ctx->pkt_obs < 0)
		return -1;
	memset(&sll, 0, sizeof(sll));
	sll.sll_family   = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_IPV6);
	sll.sll_ifindex  = ctx->veth1_idx;
	if (bind(ctx->pkt_obs, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		ctx->direct_calls++;
		return -1;
	}
	ctx->direct_calls++;
	rpl_cf_set_rcvtimeo(ctx->pkt_obs, &ctx->direct_calls);

	/* Injection: AF_PACKET socket on veth0 (transmit side).
	 * TX on veth0 → RX arrives on veth1. */
	ctx->pkt_tx = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC,
			     htons(ETH_P_IPV6));
	ctx->direct_calls++;
	if (ctx->pkt_tx < 0)
		return -1;
	memset(&sll, 0, sizeof(sll));
	sll.sll_family   = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_IPV6);
	sll.sll_ifindex  = ctx->veth0_idx;
	if (bind(ctx->pkt_tx, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		ctx->direct_calls++;
		return -1;
	}
	ctx->direct_calls++;
	return 0;
}

/*
 * Send the frame, then receive from both oracle sockets and compare.
 * Any divergence is logged and counted.
 */
static void rpl_cf_run_oracle(struct rpl_cf_iter_ctx *ctx)
{
	uint8_t frame[RPL_CF_FRAME_LEN];
	/* Raw6 recv buffer: large enough for the SRH (56 bytes) plus any
	 * preceding headers that recvmsg may include.  512 is generous. */
	uint8_t raw6_buf[512];
	/* AF_PACKET recv buffer: full Ethernet frame. */
	uint8_t pkt_buf[RPL_CF_FRAME_LEN + 64];
	struct sockaddr_ll dst;
	ssize_t raw6_n, pkt_n;

	rpl_cf_build_frame(frame);

	/* Inject via AF_PACKET on veth0. */
	memset(&dst, 0, sizeof(dst));
	dst.sll_family   = AF_PACKET;
	dst.sll_protocol = htons(ETH_P_IPV6);
	dst.sll_ifindex  = ctx->veth0_idx;
	dst.sll_halen    = 6;
	memset(dst.sll_addr, 0xff, 6);

	(void)sendto(ctx->pkt_tx, frame, sizeof(frame), MSG_DONTWAIT,
		     (struct sockaddr *)&dst, sizeof(dst));
	ctx->direct_calls++;

	/* Receive from primary listener (raw6 clone). */
	raw6_n = recvfrom(ctx->raw6, raw6_buf, sizeof(raw6_buf), 0,
			  NULL, NULL);
	ctx->direct_calls++;

	/* Receive from secondary listener (AF_PACKET full-frame). */
	pkt_n = recvfrom(ctx->pkt_obs, pkt_buf, sizeof(pkt_buf), 0,
			 NULL, NULL);
	ctx->direct_calls++;

	/*
	 * Primary oracle: check SRH[3] (segments_left).
	 *
	 * raw6 recvfrom() delivers starting at the transport header
	 * (nexthdr=43, which IS the SRH).  Byte 3 of the SRH is
	 * segments_left.  In a correct kernel this equals RPL_CF_SEGL_TX
	 * (3); in a buggy kernel ipv6_rpl_srh_rcv() has decremented it
	 * in-place on the shared clone data → value is RPL_CF_SEGL_TX - 1.
	 */
	if (raw6_n >= 4) {
		uint8_t rx_segl = raw6_buf[3];

		if (rx_segl != RPL_CF_SEGL_TX)
			rpl_cf_log_srh_divergence(rx_segl, RPL_CF_SEGL_TX);
	}

	/*
	 * Secondary oracle: check IPv6 daddr in the full Ethernet frame.
	 *
	 * Frame layout: Ethernet(14) + IPv6(40) + SRH(56).
	 * IPv6 daddr is at offset 24 within the IPv6 header → offset
	 * 14 + 24 = 38 from the start of the frame.
	 * In a correct kernel daddr == fd00::1; in a buggy kernel
	 * ipv6_rpl_srh_rcv() has swapped it to Addresses[0] = ::1.
	 */
	if (pkt_n >= (ssize_t)(RPL_CF_ETH_LEN + RPL_CF_IP6_LEN)) {
		const uint8_t *rx_daddr = pkt_buf + RPL_CF_ETH_LEN + 24U;

		if (memcmp(rx_daddr, rpl_cf_veth_addr, 16) != 0)
			rpl_cf_log_daddr_divergence(rx_daddr, rpl_cf_veth_addr);
	}
}

static void rpl_cf_teardown(struct rpl_cf_iter_ctx *ctx)
{
	if (ctx->pkt_tx >= 0)
		close(ctx->pkt_tx);
	if (ctx->pkt_obs >= 0)
		close(ctx->pkt_obs);
	if (ctx->raw6 >= 0)
		close(ctx->raw6);

	/* Netns teardown on grandchild _exit() catches anything left behind,
	 * including veth devices and per-net sysctls.  Explicit cleanup is a
	 * belt-and-braces defence in case the grandchild outlives the op. */
	if (!ctx->nl_opened)
		return;
	if (ctx->veth_created && ctx->veth0_idx > 0)
		(void)rtnl_dellink(&ctx->nl, ctx->veth0_idx);
	nl_close(&ctx->nl);
}

/*
 * Per-invocation body executed inside the private net namespace by
 * userns_run_in_ns().  The grandchild's userns + netns are torn down on
 * _exit() so all network state created here is reaped automatically.
 */
static int rpl_cf_in_ns(void *arg)
{
	struct rpl_cf_in_ns_ctx *cctx = (struct rpl_cf_in_ns_ctx *)arg;
	struct rpl_cf_iter_ctx ctx = {
		.nl      = NL_CTX_INIT,
		.raw6    = -1,
		.pkt_obs = -1,
		.pkt_tx  = -1,
		.child   = cctx->child,
	};
	const enum child_op_type op  = cctx->child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (rpl_cf_open_nl(&ctx) != 0)
		goto out;

	if (rpl_cf_setup_net(&ctx) != 0)
		goto out;

	if (rpl_cf_open_sockets(&ctx) != 0)
		goto out;

	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	}

	rpl_cf_run_oracle(&ctx);

out:
	rpl_cf_teardown(&ctx);
	if (valid_op)
		childop_direct_syscalls_add(op, ctx.direct_calls);
	return 0;
}

/*
 * Entry point.  Spawns a transient grandchild in an identity userns +
 * private netns, runs the oracle body, then returns to caller.
 */
bool ipv6_rpl_clone_fidelity(struct childdata *child)
{
	struct rpl_cf_in_ns_ctx cctx = { .child = child };
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);
	int rc;

	if (ns_unsupported_ipv6_rpl_clone_fidelity)
		return true;

	rc = userns_run_in_ns(CLONE_NEWNET, rpl_cf_in_ns, &cctx);
	if (rc == -EPERM) {
		ns_unsupported_ipv6_rpl_clone_fidelity = true;
		if (valid_op)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
	}
	return true;
}
