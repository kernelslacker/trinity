/*
 * bridge_vlan_churn - bridge VLAN-filtering rule churn vs tagged ingress.
 *
 * Random netlink fuzzing rarely assembles the chain that drives
 * net/bridge/br_vlan.c, br_vlan_tunnel.c, br_vlan_options.c and
 * br_mst.c.  Reaching those files needs a bridge with VLAN filtering
 * enabled, ports enslaved into it, a VLAN add carrying the right nested
 * IFLA_AF_SPEC -> IFLA_BRIDGE_VLAN_INFO encoding, an AF_PACKET
 * SOCK_RAW peer pushing 802.1Q tagged frames at the port matching
 * a configured vid, and a concurrent vlan delete / vlan-tunnel mutation
 * / MST topology-change racing the in-flight skb.  Without all of those
 * the br_vlan_get_pvid / br_handle_vlan / br_vlan_tunnel_lookup /
 * br_mst_set_state windows never co-fire.
 *
 * Sequence (per BUDGETED + JITTER iteration, 200 ms wall cap, fresh
 * topology per iteration):
 *
 *   1.  unshare(CLONE_NEWNET) (one-time per child; failure latches the
 *       op off, EPERM is not fatal -- the cap-gate handles it).
 *   2.  Open a NETLINK_ROUTE socket; first invocation probes
 *       RTM_NEWLINK type=bridge with IFLA_BR_VLAN_FILTERING=1.  If the
 *       kernel returns -EPERM / -ENOSYS / -EAFNOSUPPORT / -EOPNOTSUPP,
 *       latch ns_unsupported_bridge_vlan_churn and short-circuit every
 *       subsequent invocation.
 *   3.  RTM_NEWLINK type=veth twice (two pairs: v0a/v0b and v1a/v1b).
 *   4.  RTM_SETLINK IFLA_MASTER on v0a and v1a to enslave them to the
 *       bridge.  v0b and v1b stay free so they can carry the AF_PACKET
 *       traffic into the bridge ports.
 *   5.  RTM_SETLINK family=AF_BRIDGE on v0a with IFLA_AF_SPEC
 *       containing IFLA_BRIDGE_VLAN_INFO range begin/end (vid base ..
 *       base+10) plus a PVID at vid base+5.  Range encoding hits the
 *       br_vlan_add range path.
 *   6.  RTM_SETLINK IFF_UP on bridge + every veth end.
 *   7.  socket(AF_PACKET, SOCK_RAW, htons(ETH_P_8021Q)); bind to v0b's
 *       ifindex; SO_RCVTIMEO/SO_SNDTIMEO 100 ms.  Skip on EPERM.
 *   8.  Send one 802.1Q tagged frame at vid base+5 (PVID vid).  The
 *       bridge ingress runs br_handle_vlan against the still-fresh
 *       per-port vlan group.
 *   9.  RACE per iteration -- variant rotates through:
 *         A: RTM_DELLINK family=AF_BRIDGE IFLA_BRIDGE_VLAN_INFO del
 *            single vid base+5 mid-traffic (vlan-rcu vs ingress lookup);
 *         B: RTM_SETLINK family=AF_BRIDGE IFLA_BRIDGE_VLAN_TUNNEL_INFO
 *            add tunnel_id=42 on vid base+5 (br_vlan_tunnel parse path,
 *            the IFLA_BRIDGE_VLAN_TUNNEL_INFO attribute is essentially
 *            unfuzzed by random netlink walks);
 *         C: RTM_SETLINK family=AF_BRIDGE on the bridge dev with
 *            IFLA_BRIDGE_MST nested IFLA_BRIDGE_MST_ENTRY MSTI=1
 *            STATE=BR_STATE_FORWARDING (br_mst_set_state topology
 *            change while the port carries traffic);
 *         D: re-issue the IFLA_BRIDGE_VLAN_INFO add with an overlapping
 *            range (base+3 .. base+7) mid-traffic -- pvid swap window.
 *  10.  shutdown / close raw socket, RTM_DELLINK bridge + veths.
 *
 *   Additional knobs per iteration: vid base rotates in {10, 100, 4000}
 *   so all three vid magnitudes get exercise; the RACE letter that
 *   fires first rotates iter % 4 so no single race predominates.
 *
 * Per-process cap-gate latch: ns_unsupported_bridge_vlan_churn fires
 * on -EPERM / -ENOSYS / -EAFNOSUPPORT / -EOPNOTSUPP from the first
 * RTM_NEWLINK type=bridge probe.  Once latched, every subsequent
 * invocation just bumps runs+setup_failed and returns.  Mirrors the
 * other CHURN childops (vsock_transport_churn / msg_zerocopy_churn /
 * netns_teardown_churn).
 *
 * Brick-safety:
 *   - All work happens inside a private netns -- the host bridge /
 *     veth / vlan tables never see this op.
 *   - BUDGETED outer loop (base 4 / floor 8 / cap 16) with JITTER and
 *     200 ms wall-cap; every send/recv uses MSG_DONTWAIT or carries a
 *     100 ms SO_RCVTIMEO/SO_SNDTIMEO so an unresponsive netlink can't
 *     wedge us past the SIGALRM(1s) cap inherited from child.c.
 *   - veth remains in loopback only; no underlying physical device is
 *     touched.
 *
 * Header gates: __has_include(<linux/if_bridge.h>) /
 * <linux/if_link.h> / <linux/rtnetlink.h>.  IFLA_BR_VLAN_FILTERING,
 * IFLA_BRIDGE_*, BRIDGE_VLAN_INFO_*, BRIDGE_FLAGS_*, IFLA_BRIDGE_MST*,
 * VETH_INFO_PEER are #define-fallback-supplied at their stable UAPI
 * integer values when absent on the build host -- the kernel returns
 * EINVAL/ENOPROTOOPT and the cap-gate latches.
 */

#if __has_include(<linux/if_bridge.h>) && __has_include(<linux/if_link.h>) && __has_include(<linux/rtnetlink.h>)

#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <linux/if_bridge.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_packet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "child.h"
#include "jitter.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"

/* if_link.h on stripped sysroots may omit IFLA_BR_VLAN_FILTERING -- the
 * UAPI integer (7) is stable. */
#ifndef IFLA_BR_VLAN_FILTERING
#define IFLA_BR_VLAN_FILTERING		7
#endif

/* if_bridge.h IFLA_BRIDGE_* enum members and BRIDGE_VLAN_INFO_* /
 * BRIDGE_FLAGS_* may be missing on older sysroots; redefine to the
 * stable UAPI integers. */
#ifndef IFLA_BRIDGE_FLAGS
#define IFLA_BRIDGE_FLAGS		0
#endif
#ifndef IFLA_BRIDGE_MODE
#define IFLA_BRIDGE_MODE		1
#endif
#ifndef IFLA_BRIDGE_VLAN_INFO
#define IFLA_BRIDGE_VLAN_INFO		2
#endif
#ifndef IFLA_BRIDGE_VLAN_TUNNEL_INFO
#define IFLA_BRIDGE_VLAN_TUNNEL_INFO	3
#endif
#ifndef IFLA_BRIDGE_MST
#define IFLA_BRIDGE_MST			6
#endif

#ifndef BRIDGE_FLAGS_MASTER
#define BRIDGE_FLAGS_MASTER		1
#endif
#ifndef BRIDGE_FLAGS_SELF
#define BRIDGE_FLAGS_SELF		2
#endif

#ifndef BRIDGE_VLAN_INFO_PVID
#define BRIDGE_VLAN_INFO_PVID		(1 << 1)
#endif
#ifndef BRIDGE_VLAN_INFO_UNTAGGED
#define BRIDGE_VLAN_INFO_UNTAGGED	(1 << 2)
#endif
#ifndef BRIDGE_VLAN_INFO_RANGE_BEGIN
#define BRIDGE_VLAN_INFO_RANGE_BEGIN	(1 << 3)
#endif
#ifndef BRIDGE_VLAN_INFO_RANGE_END
#define BRIDGE_VLAN_INFO_RANGE_END	(1 << 4)
#endif

#ifndef IFLA_BRIDGE_VLAN_TUNNEL_ID
#define IFLA_BRIDGE_VLAN_TUNNEL_ID	1
#endif
#ifndef IFLA_BRIDGE_VLAN_TUNNEL_VID
#define IFLA_BRIDGE_VLAN_TUNNEL_VID	2
#endif
#ifndef IFLA_BRIDGE_VLAN_TUNNEL_FLAGS
#define IFLA_BRIDGE_VLAN_TUNNEL_FLAGS	3
#endif

#ifndef IFLA_BRIDGE_MST_ENTRY
#define IFLA_BRIDGE_MST_ENTRY		1
#endif
#ifndef IFLA_BRIDGE_MST_ENTRY_MSTI
#define IFLA_BRIDGE_MST_ENTRY_MSTI	1
#endif
#ifndef IFLA_BRIDGE_MST_ENTRY_STATE
#define IFLA_BRIDGE_MST_ENTRY_STATE	2
#endif

#ifndef VETH_INFO_PEER
#define VETH_INFO_PEER			1
#endif

/* BR_STATE_FORWARDING (3) is stable since the bridge UAPI shipped. */
#ifndef BR_STATE_FORWARDING
#define BR_STATE_FORWARDING		3
#endif

/* AF_BRIDGE = 7 across glibc / musl / kernel UAPI. */
#ifndef AF_BRIDGE
#define AF_BRIDGE			7
#endif

#define BVC_OUTER_BASE			4U
#define BVC_OUTER_FLOOR			8U
#define BVC_OUTER_CAP			16U
#define BVC_WALL_CAP_NS			(200ULL * 1000ULL * 1000ULL)
#define BVC_NL_RECV_TIMEO_S		1
#define BVC_RAW_TIMEO_MS		100
#define BVC_RTNL_BUF			2048

static bool ns_unsupported_bridge_vlan_churn;
static bool bvc_unshared;

static __u32 g_seq;

static __u32 next_seq(void)
{
	return ++g_seq;
}

static long long ns_since(const struct timespec *t0)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		return 0;
	return (long long)(now.tv_sec - t0->tv_sec) * 1000000000LL +
	       (long long)(now.tv_nsec - t0->tv_nsec);
}

static int rtnl_open(void)
{
	struct sockaddr_nl sa;
	struct timeval tv;
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

	tv.tv_sec  = BVC_NL_RECV_TIMEO_S;
	tv.tv_usec = 0;
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	return fd;
}

static size_t nla_put(unsigned char *buf, size_t off, size_t cap,
		      unsigned short type, const void *data, size_t len)
{
	struct nlattr *nla;
	size_t total = NLA_HDRLEN + len;
	size_t aligned = NLA_ALIGN(total);

	if (off + aligned > cap)
		return 0;

	nla = (struct nlattr *)(buf + off);
	nla->nla_type = type;
	nla->nla_len  = (unsigned short)total;
	if (len)
		memcpy(buf + off + NLA_HDRLEN, data, len);
	if (aligned > total)
		memset(buf + off + total, 0, aligned - total);
	return off + aligned;
}

static size_t nla_put_u8(unsigned char *buf, size_t off, size_t cap,
			 unsigned short type, __u8 v)
{
	return nla_put(buf, off, cap, type, &v, sizeof(v));
}

static size_t nla_put_u16(unsigned char *buf, size_t off, size_t cap,
			  unsigned short type, __u16 v)
{
	return nla_put(buf, off, cap, type, &v, sizeof(v));
}

static size_t nla_put_u32(unsigned char *buf, size_t off, size_t cap,
			  unsigned short type, __u32 v)
{
	return nla_put(buf, off, cap, type, &v, sizeof(v));
}

static size_t nla_put_str(unsigned char *buf, size_t off, size_t cap,
			  unsigned short type, const char *s)
{
	return nla_put(buf, off, cap, type, s, strlen(s) + 1);
}

static int rtnl_send_recv(int fd, void *msg, size_t len)
{
	struct sockaddr_nl dst;
	struct iovec iov;
	struct msghdr mh;
	unsigned char rbuf[1024];
	struct nlmsghdr *nlh;
	ssize_t n;

	memset(&dst, 0, sizeof(dst));
	dst.nl_family = AF_NETLINK;

	iov.iov_base = msg;
	iov.iov_len  = len;

	memset(&mh, 0, sizeof(mh));
	mh.msg_name    = &dst;
	mh.msg_namelen = sizeof(dst);
	mh.msg_iov     = &iov;
	mh.msg_iovlen  = 1;

	if (sendmsg(fd, &mh, 0) < 0)
		return -EIO;

	n = recv(fd, rbuf, sizeof(rbuf), 0);
	if (n < 0)
		return -EIO;
	if ((size_t)n < NLMSG_HDRLEN)
		return -EIO;

	nlh = (struct nlmsghdr *)rbuf;
	if (nlh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh);
		return err->error;
	}
	return -EIO;
}

/*
 * RTM_NEWLINK type=bridge with IFLA_BR_VLAN_FILTERING=1 inside
 * IFLA_LINKINFO -> IFLA_INFO_DATA.  Returns 0 on accept, negated errno
 * on rejection.  Used both as the structural-support probe (first
 * invocation latches ns_unsupported_bridge_vlan_churn) and as the
 * per-iteration bridge create.
 */
static int build_bridge_create(int fd, const char *name)
{
	unsigned char buf[BVC_RTNL_BUF];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	struct nlattr *linkinfo;
	struct nlattr *infodata;
	size_t off, li_off, id_off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = next_seq();

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, name);
	if (!off)
		return -EIO;

	li_off = off;
	off = nla_put(buf, off, sizeof(buf), IFLA_LINKINFO, NULL, 0);
	if (!off)
		return -EIO;

	off = nla_put_str(buf, off, sizeof(buf), IFLA_INFO_KIND, "bridge");
	if (!off)
		return -EIO;

	id_off = off;
	off = nla_put(buf, off, sizeof(buf), IFLA_INFO_DATA, NULL, 0);
	if (!off)
		return -EIO;

	off = nla_put_u8(buf, off, sizeof(buf), IFLA_BR_VLAN_FILTERING, 1);
	if (!off)
		return -EIO;

	infodata = (struct nlattr *)(buf + id_off);
	infodata->nla_len = (unsigned short)(off - id_off);

	linkinfo = (struct nlattr *)(buf + li_off);
	linkinfo->nla_len = (unsigned short)(off - li_off);

	nlh->nlmsg_len = (__u32)off;
	return rtnl_send_recv(fd, buf, off);
}

static int build_veth_create(int fd, const char *name, const char *peer)
{
	unsigned char buf[BVC_RTNL_BUF];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	struct ifinfomsg *peer_ifi;
	struct nlattr *linkinfo;
	struct nlattr *infodata;
	struct nlattr *peer_attr;
	size_t off, li_off, id_off, peer_off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = next_seq();

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, name);
	if (!off)
		return -EIO;

	li_off = off;
	off = nla_put(buf, off, sizeof(buf), IFLA_LINKINFO, NULL, 0);
	if (!off)
		return -EIO;

	off = nla_put_str(buf, off, sizeof(buf), IFLA_INFO_KIND, "veth");
	if (!off)
		return -EIO;

	id_off = off;
	off = nla_put(buf, off, sizeof(buf), IFLA_INFO_DATA, NULL, 0);
	if (!off)
		return -EIO;

	peer_off = off;
	off = nla_put(buf, off, sizeof(buf), VETH_INFO_PEER, NULL, 0);
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

	peer_attr = (struct nlattr *)(buf + peer_off);
	peer_attr->nla_len = (unsigned short)(off - peer_off);

	infodata = (struct nlattr *)(buf + id_off);
	infodata->nla_len = (unsigned short)(off - id_off);

	linkinfo = (struct nlattr *)(buf + li_off);
	linkinfo->nla_len = (unsigned short)(off - li_off);

	nlh->nlmsg_len = (__u32)off;
	return rtnl_send_recv(fd, buf, off);
}

static int build_setlink_master(int fd, int ifindex, int master_ifindex)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_SETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = next_seq();

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = ifindex;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));
	off = nla_put_u32(buf, off, sizeof(buf), IFLA_MASTER,
			  (__u32)master_ifindex);
	if (!off)
		return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return rtnl_send_recv(fd, buf, off);
}

static int build_setlink_up(int fd, int ifindex)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_SETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = next_seq();

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = ifindex;
	ifi->ifi_flags  = IFF_UP;
	ifi->ifi_change = IFF_UP;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));
	nlh->nlmsg_len = (__u32)off;
	return rtnl_send_recv(fd, buf, off);
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
static int build_vlan_info(int fd, __u16 nlmsg_type, int port_idx,
			   __u16 vid, __u16 vid_end,
			   bool is_range, bool pvid)
{
	unsigned char buf[512];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	struct nlattr *afspec;
	struct bridge_vlan_info bvi;
	size_t off, af_off;
	__u16 br_flags = BRIDGE_FLAGS_MASTER;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = nlmsg_type;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = next_seq();

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_BRIDGE;
	ifi->ifi_index  = port_idx;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	af_off = off;
	off = nla_put(buf, off, sizeof(buf),
		      IFLA_AF_SPEC, NULL, 0);
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

	afspec = (struct nlattr *)(buf + af_off);
	afspec->nla_len = (unsigned short)(off - af_off);

	nlh->nlmsg_len = (__u32)off;
	return rtnl_send_recv(fd, buf, off);
}

/*
 * RTM_SETLINK family=AF_BRIDGE on a port: IFLA_AF_SPEC ->
 * IFLA_BRIDGE_VLAN_TUNNEL_INFO { TUNNEL_VID, TUNNEL_ID, TUNNEL_FLAGS }.
 * Drives br_vlan_tunnel_info_add via the rarely-walked tunnel-info
 * attribute branch.
 */
static int build_vlan_tunnel_add(int fd, int port_idx,
				 __u16 vid, __u32 tunnel_id)
{
	unsigned char buf[512];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	struct nlattr *afspec;
	struct nlattr *tinfo;
	size_t off, af_off, ti_off;
	__u16 br_flags = BRIDGE_FLAGS_MASTER;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_SETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = next_seq();

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_BRIDGE;
	ifi->ifi_index  = port_idx;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	af_off = off;
	off = nla_put(buf, off, sizeof(buf),
		      IFLA_AF_SPEC, NULL, 0);
	if (!off)
		return -EIO;

	off = nla_put_u16(buf, off, sizeof(buf),
			  IFLA_BRIDGE_FLAGS, br_flags);
	if (!off)
		return -EIO;

	ti_off = off;
	off = nla_put(buf, off, sizeof(buf),
		      IFLA_BRIDGE_VLAN_TUNNEL_INFO, NULL, 0);
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

	tinfo = (struct nlattr *)(buf + ti_off);
	tinfo->nla_len = (unsigned short)(off - ti_off);

	afspec = (struct nlattr *)(buf + af_off);
	afspec->nla_len = (unsigned short)(off - af_off);

	nlh->nlmsg_len = (__u32)off;
	return rtnl_send_recv(fd, buf, off);
}

/*
 * RTM_SETLINK family=AF_BRIDGE on a port: IFLA_AF_SPEC ->
 * IFLA_BRIDGE_MST -> IFLA_BRIDGE_MST_ENTRY { MSTI, STATE }.
 * br_mst_set_state path; topology change while traffic flows.
 */
static int build_mst_set(int fd, int port_idx,
			 __u16 msti, __u8 state)
{
	unsigned char buf[512];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	struct nlattr *afspec;
	struct nlattr *mst;
	struct nlattr *entry;
	size_t off, af_off, mst_off, ent_off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_SETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = next_seq();

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_BRIDGE;
	ifi->ifi_index  = port_idx;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	af_off = off;
	off = nla_put(buf, off, sizeof(buf),
		      IFLA_AF_SPEC, NULL, 0);
	if (!off)
		return -EIO;

	mst_off = off;
	off = nla_put(buf, off, sizeof(buf),
		      IFLA_BRIDGE_MST, NULL, 0);
	if (!off)
		return -EIO;

	ent_off = off;
	off = nla_put(buf, off, sizeof(buf),
		      IFLA_BRIDGE_MST_ENTRY, NULL, 0);
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

	entry = (struct nlattr *)(buf + ent_off);
	entry->nla_len = (unsigned short)(off - ent_off);

	mst = (struct nlattr *)(buf + mst_off);
	mst->nla_len = (unsigned short)(off - mst_off);

	afspec = (struct nlattr *)(buf + af_off);
	afspec->nla_len = (unsigned short)(off - af_off);

	nlh->nlmsg_len = (__u32)off;
	return rtnl_send_recv(fd, buf, off);
}

static int build_dellink(int fd, int ifindex)
{
	unsigned char buf[128];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_DELLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = next_seq();

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = ifindex;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));
	nlh->nlmsg_len = (__u32)off;
	return rtnl_send_recv(fd, buf, off);
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
 * One full create / load / race / teardown cycle on a freshly-named
 * bridge + 2 veth pairs.  Wall-clock cap inherited from the caller.
 */
static void iter_one(unsigned int iter_idx, const struct timespec *t_outer)
{
	char br_name[IFNAMSIZ];
	char v0a[IFNAMSIZ], v0b[IFNAMSIZ];
	char v1a[IFNAMSIZ], v1b[IFNAMSIZ];
	int rtnl = -1;
	int raw = -1;
	int br_idx = 0;
	int v0a_idx = 0, v0b_idx = 0, v1a_idx = 0, v1b_idx = 0;
	bool bridge_added = false;
	bool veth0_added = false;
	bool veth1_added = false;
	unsigned int rng;
	__u16 vid_bases[3] = { 10, 100, 4000 };
	__u16 vid_base, pvid, range_end;
	int rc;
	unsigned char frame[64];
	struct sockaddr_ll sll;
	unsigned int race_letter = iter_idx & 3U;

	if ((unsigned long long)ns_since(t_outer) >= BVC_WALL_CAP_NS)
		return;

	rtnl = rtnl_open();
	if (rtnl < 0) {
		__atomic_add_fetch(&shm->stats.bridge_vlan_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return;
	}

	rng = (unsigned int)(rand32() & 0xffffu);
	snprintf(br_name, sizeof(br_name), "trvbr%u", rng);
	snprintf(v0a, sizeof(v0a), "trvb%ua0", rng);
	snprintf(v0b, sizeof(v0b), "trvb%ub0", rng);
	snprintf(v1a, sizeof(v1a), "trvb%ua1", rng);
	snprintf(v1b, sizeof(v1b), "trvb%ub1", rng);

	rc = build_bridge_create(rtnl, br_name);
	if (rc != 0) {
		if (rc == -EPERM || rc == -ENOSYS ||
		    rc == -EAFNOSUPPORT || rc == -EOPNOTSUPP ||
		    rc == -EPROTONOSUPPORT)
			ns_unsupported_bridge_vlan_churn = true;
		__atomic_add_fetch(&shm->stats.bridge_vlan_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}
	bridge_added = true;
	__atomic_add_fetch(&shm->stats.bridge_vlan_churn_bridge_create_ok,
			   1, __ATOMIC_RELAXED);

	br_idx = (int)if_nametoindex(br_name);
	if (br_idx == 0)
		goto out;

	if (build_veth_create(rtnl, v0a, v0b) == 0) {
		veth0_added = true;
		__atomic_add_fetch(&shm->stats.bridge_vlan_churn_veth_create_ok,
				   1, __ATOMIC_RELAXED);
		v0a_idx = (int)if_nametoindex(v0a);
		v0b_idx = (int)if_nametoindex(v0b);
	}
	if (build_veth_create(rtnl, v1a, v1b) == 0) {
		veth1_added = true;
		__atomic_add_fetch(&shm->stats.bridge_vlan_churn_veth_create_ok,
				   1, __ATOMIC_RELAXED);
		v1a_idx = (int)if_nametoindex(v1a);
		v1b_idx = (int)if_nametoindex(v1b);
	}

	if (v0a_idx > 0)
		(void)build_setlink_master(rtnl, v0a_idx, br_idx);
	if (v1a_idx > 0)
		(void)build_setlink_master(rtnl, v1a_idx, br_idx);

	vid_base  = vid_bases[iter_idx % 3U];
	pvid      = (__u16)(vid_base + 5U);
	range_end = (__u16)(vid_base + 10U);

	/* Range add of vid_base..range_end on v0a. */
	if (v0a_idx > 0) {
		if (build_vlan_info(rtnl, RTM_SETLINK, v0a_idx,
				    vid_base, range_end, true, false) == 0)
			__atomic_add_fetch(&shm->stats.bridge_vlan_churn_vlan_add_ok,
					   1, __ATOMIC_RELAXED);
		/* Single PVID add at pvid. */
		if (build_vlan_info(rtnl, RTM_SETLINK, v0a_idx,
				    pvid, 0, false, true) == 0)
			__atomic_add_fetch(&shm->stats.bridge_vlan_churn_vlan_add_ok,
					   1, __ATOMIC_RELAXED);
	}

	(void)build_setlink_up(rtnl, br_idx);
	if (v0a_idx > 0) (void)build_setlink_up(rtnl, v0a_idx);
	if (v0b_idx > 0) (void)build_setlink_up(rtnl, v0b_idx);
	if (v1a_idx > 0) (void)build_setlink_up(rtnl, v1a_idx);
	if (v1b_idx > 0) (void)build_setlink_up(rtnl, v1b_idx);

	if (v0b_idx > 0) {
		raw = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC,
			     htons(ETH_P_8021Q));
		if (raw >= 0) {
			apply_raw_timeouts(raw);
			memset(&sll, 0, sizeof(sll));
			sll.sll_family   = AF_PACKET;
			sll.sll_protocol = htons(ETH_P_8021Q);
			sll.sll_ifindex  = v0b_idx;
			(void)bind(raw, (struct sockaddr *)&sll, sizeof(sll));
		}
	}

	if (raw >= 0) {
		ssize_t n;

		build_tagged_frame(frame, pvid);
		memset(&sll, 0, sizeof(sll));
		sll.sll_family   = AF_PACKET;
		sll.sll_protocol = htons(ETH_P_8021Q);
		sll.sll_ifindex  = v0b_idx;
		sll.sll_halen    = 6;
		memset(sll.sll_addr, 0xff, 6);

		n = sendto(raw, frame, sizeof(frame), MSG_DONTWAIT,
			   (struct sockaddr *)&sll, sizeof(sll));
		if (n > 0)
			__atomic_add_fetch(&shm->stats.bridge_vlan_churn_raw_send_ok,
					   1, __ATOMIC_RELAXED);
	}

	if ((unsigned long long)ns_since(t_outer) >= BVC_WALL_CAP_NS)
		goto teardown;

	/* RACE A/B/C/D dispatch.  Each iteration fires one race kind so
	 * the four shapes get balanced exposure across the BUDGETED
	 * outer loop. */
	switch (race_letter) {
	case 0:
		/* RACE A: delete vid pvid mid-flight. */
		if (v0a_idx > 0 &&
		    build_vlan_info(rtnl, RTM_DELLINK, v0a_idx,
				    pvid, 0, false, false) == 0)
			__atomic_add_fetch(&shm->stats.bridge_vlan_churn_vlan_del_ok,
					   1, __ATOMIC_RELAXED);
		break;
	case 1:
		/* RACE B: vlan-tunnel add. */
		if (v0a_idx > 0 &&
		    build_vlan_tunnel_add(rtnl, v0a_idx, pvid, 42U) == 0)
			__atomic_add_fetch(&shm->stats.bridge_vlan_churn_tunnel_add_ok,
					   1, __ATOMIC_RELAXED);
		break;
	case 2:
		/* RACE C: MST topology change on the port. */
		if (v0a_idx > 0 &&
		    build_mst_set(rtnl, v0a_idx, 1U,
				  (__u8)BR_STATE_FORWARDING) == 0)
			__atomic_add_fetch(&shm->stats.bridge_vlan_churn_mst_set_ok,
					   1, __ATOMIC_RELAXED);
		break;
	case 3:
		/* RACE D: re-issue overlapping range add. */
		if (v0a_idx > 0 &&
		    build_vlan_info(rtnl, RTM_SETLINK, v0a_idx,
				    (__u16)(vid_base + 3U),
				    (__u16)(vid_base + 7U),
				    true, false) == 0)
			__atomic_add_fetch(&shm->stats.bridge_vlan_churn_vlan_add_ok,
					   1, __ATOMIC_RELAXED);
		break;
	}

	/* Second tagged send while the race is in flight. */
	if (raw >= 0) {
		ssize_t n;

		build_tagged_frame(frame, pvid);
		memset(&sll, 0, sizeof(sll));
		sll.sll_family   = AF_PACKET;
		sll.sll_protocol = htons(ETH_P_8021Q);
		sll.sll_ifindex  = v0b_idx;
		sll.sll_halen    = 6;
		memset(sll.sll_addr, 0xff, 6);

		n = sendto(raw, frame, sizeof(frame), MSG_DONTWAIT,
			   (struct sockaddr *)&sll, sizeof(sll));
		if (n > 0)
			__atomic_add_fetch(&shm->stats.bridge_vlan_churn_raw_send_ok,
					   1, __ATOMIC_RELAXED);
	}

teardown:
	if (raw >= 0) {
		(void)shutdown(raw, SHUT_RDWR);
		close(raw);
		raw = -1;
	}

	/* DELLINK the bridge first; cascades to enslaved veths via
	 * br_dev_delete and races any in-flight rx still draining. */
	if (bridge_added && br_idx > 0)
		(void)build_dellink(rtnl, br_idx);
	if (veth0_added && v0a_idx > 0)
		(void)build_dellink(rtnl, v0a_idx);
	if (veth1_added && v1a_idx > 0)
		(void)build_dellink(rtnl, v1a_idx);

out:
	if (raw >= 0)
		close(raw);
	if (rtnl >= 0)
		close(rtnl);
}

bool bridge_vlan_churn(struct childdata *child)
{
	struct timespec t_outer;
	unsigned int outer_iters, i;

	(void)child;

	__atomic_add_fetch(&shm->stats.bridge_vlan_churn_runs,
			   1, __ATOMIC_RELAXED);

	if (ns_unsupported_bridge_vlan_churn) {
		__atomic_add_fetch(&shm->stats.bridge_vlan_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (!bvc_unshared) {
		if (unshare(CLONE_NEWNET) < 0) {
			if (errno != EPERM) {
				ns_unsupported_bridge_vlan_churn = true;
				__atomic_add_fetch(&shm->stats.bridge_vlan_churn_setup_failed,
						   1, __ATOMIC_RELAXED);
				return true;
			}
			/* EPERM: keep going in the host netns -- the cap
			 * gate on the first bridge create will catch any
			 * remaining structural unsupported case. */
		}
		bvc_unshared = true;
	}

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

		iter_one(i, &t_outer);

		if (ns_unsupported_bridge_vlan_churn)
			break;
	}

	return true;
}

#else  /* !__has_include(<linux/if_bridge.h> + <linux/if_link.h> + <linux/rtnetlink.h>) */

#include <stdbool.h>
#include "child.h"
#include "shm.h"

bool bridge_vlan_churn(struct childdata *child)
{
	(void)child;

	__atomic_add_fetch(&shm->stats.bridge_vlan_churn_runs,
			   1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.bridge_vlan_churn_setup_failed,
			   1, __ATOMIC_RELAXED);
	return true;
}

#endif
