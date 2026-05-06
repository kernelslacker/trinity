/*
 * bridge_fdb_stp - bridge fdb learn vs delete vs STP topology race.
 *
 * Random netlink fuzzing rarely assembles the full chain that the
 * software bridge needs to enter its learning + topology-change paths
 * simultaneously: a bridge dev must exist, at least one port must be
 * enslaved to it, the port must be UP and have BR_LEARNING armed,
 * traffic must arrive on the port (driving br_fdb_update via the
 * receive path rather than via RTM_NEWNEIGH NTF_MASTER), and the STP
 * state machine must be live so a topology-change can race with the
 * learning-driven fdb mutation.  Without all of those the
 * br_fdb_update / br_fdb_delete / br_stp_change_bridge_id windows
 * never co-fire and the lockdep / refcount edges between
 * net/bridge/br_fdb.c and net/bridge/br_stp_*.c stay cold.
 *
 * Sequence (per invocation):
 *   1. unshare(CLONE_NEWNET) once per child into a private net
 *      namespace so no host bridge / fdb table is touched.  Failure
 *      latches the whole op off.
 *   2. Bring lo up inside the netns (one-time).
 *   3. RTM_NEWLINK type=bridge to create a bridge dev.  Failure of
 *      this first NEWLINK latches ns_unsupported_bridge — a kernel
 *      without CONFIG_BRIDGE pays the EOPNOTSUPP once.
 *   4. RTM_NEWLINK type=veth twice, with VETH_INFO_PEER carrying the
 *      peer's IFLA_IFNAME so each pair has distinct peer names.
 *      Failure latches ns_unsupported_veth.
 *   5. RTM_SETLINK IFLA_MASTER=bridge_ifindex on each of the four
 *      veth ends to enslave them to the bridge.
 *   6. RTM_SETLINK IFF_UP for the bridge and all four veth ends
 *      (5 ifaces total).
 *   7. RTM_SETLINK family=AF_BRIDGE with IFLA_PROTINFO containing
 *      IFLA_BRPORT_LEARNING=1 on each veth port — arms BR_LEARNING.
 *   8. socket(AF_PACKET, SOCK_RAW); bind to one of the veth port
 *      ifindices.  sendto() 50 ethernet frames with random
 *      locally-administered unicast src MACs so each receive at the
 *      bridge port drives br_fdb_update with a fresh source.  This
 *      is the learning path we want — not RTM_NEWNEIGH NTF_MASTER,
 *      which calls br_fdb_add directly and skips the receive-path
 *      window.
 *   9. Toggle STP via /sys/class/net/<br>/bridge/stp_state — write
 *      "1" then "0".  open+write+close per toggle; EROFS / EACCES
 *      latches ns_unsupported_sysfs_stp.  STP toggle drives
 *      br_stp_start / br_stp_stop and the topology-change timer
 *      arm / disarm sequences.
 *  10. RTM_DELNEIGH on one of the just-learned fdb entries (using
 *      one of the random macs we sent), racing the receive-path
 *      learning that may re-add the same entry.  This is the
 *      learn-vs-delete window the op exists to open.
 *  11. RTM_DELLINK on the bridge — kernel cascades the cleanup to
 *      the enslaved veths via br_dev_delete, racing any in-flight
 *      receive from step 8 still draining through softirq.
 *
 * CVE class: br_fdb_delete_by_port lineage (use-after-free on enslaved
 * port teardown vs concurrent br_fdb_update from rx softirq), STP
 * topology-change timer races (br_stp_change_bridge_id vs port-state
 * transition), CVE-2024-26982 br_multicast hash teardown vs add (same
 * structural shape: per-port hash table mutation racing dellink-driven
 * cleanup).  Subsystems reached: net/bridge/br_fdb.c,
 * net/bridge/br_stp.c, net/bridge/br_stp_if.c, net/bridge/br_input.c,
 * net/bridge/br_if.c, net/core/dev.c (rx path), drivers/net/veth.c.
 *
 * Self-bounding: one full create/destroy cycle per invocation, packet
 * burst count BUDGETED+JITTER around base 3 with a STORM_BUDGET_NS
 * 200 ms wall-clock cap on the inner send loop.  All I/O is
 * MSG_DONTWAIT, SO_RCVTIMEO=1s on the rtnl ack socket, so an
 * unresponsive netlink can't wedge us past the SIGALRM(1s) cap
 * inherited from child.c.  Loopback only (private netns).  Three
 * latches so a kernel without CONFIG_BRIDGE / CONFIG_VETH / sysfs-
 * writable bridge knobs pays the EFAIL once and skips that part
 * permanently.
 */

#if __has_include(<linux/if_bridge.h>)
#include <linux/if_bridge.h>
#endif
#if __has_include(<linux/veth.h>)
#include <linux/veth.h>
#endif

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

#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_packet.h>
#include <linux/neighbour.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "child.h"
#include "jitter.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"

/* if_bridge.h on stripped sysroots may not have BRIDGE_FLAGS_* / the
 * IFLA_BRIDGE_* enum.  These IDs are stable in the UAPI; redefine the
 * minimal subset we emit if the header didn't supply them. */
#ifndef BRIDGE_FLAGS_MASTER
#define BRIDGE_FLAGS_MASTER	1
#endif
#ifndef BRIDGE_FLAGS_SELF
#define BRIDGE_FLAGS_SELF	2
#endif
#ifndef IFLA_BRIDGE_FLAGS
#define IFLA_BRIDGE_FLAGS	0
#define IFLA_BRIDGE_MODE	1
#endif

/* IFLA_BRPORT_LEARNING value 8 from net/bridge UAPI; redefine if the
 * if_link.h on this sysroot is too old to expose it. */
#ifndef IFLA_BRPORT_LEARNING
#define IFLA_BRPORT_LEARNING	8
#endif

/* IFLA_PROTINFO is the legacy per-port nested attribute slot used by
 * br_setlink for IFLA_BRPORT_*. */
#ifndef IFLA_PROTINFO
#define IFLA_PROTINFO		12
#endif

/* veth UAPI: VETH_INFO_PEER carries an ifinfomsg + IFLA_IFNAME for the
 * peer end of the pair inside IFLA_INFO_DATA. */
#ifndef VETH_INFO_PEER
#define VETH_INFO_PEER		1
#endif

#ifndef NDA_DST
#define NDA_DST			1
#endif
#ifndef NDA_LLADDR
#define NDA_LLADDR		2
#endif
#ifndef NDA_MASTER
#define NDA_MASTER		9
#endif

#ifndef NUD_PERMANENT
#define NUD_PERMANENT		0x80
#endif
#ifndef NUD_REACHABLE
#define NUD_REACHABLE		0x02
#endif

#ifndef NTF_MASTER
#define NTF_MASTER		(1 << 2)
#endif

/* Reasonable ceiling on a single rtnl message + payload.  A bridge or
 * veth NEWLINK with IFLA_LINKINFO + IFLA_INFO_DATA + nested peer
 * ifinfomsg fits well under 1 KiB; 2 KiB leaves headroom. */
#define RTNL_BUF_BYTES		2048
#define RTNL_RECV_TIMEO_S	1

/* Per-iteration packet burst base.  BUDGETED+JITTER scales it: a
 * productive run grows to ~iter*4 sends, an unproductive one shrinks
 * to floor.  Sends are MSG_DONTWAIT; the inner loop also clamps to
 * STORM_BUDGET_NS wall-clock so even an unbounded burst can't stall
 * the iteration past the SIGALRM(1s) cap. */
#define BRIDGE_PACKET_BASE	3U
#define BRIDGE_PACKET_FLOOR	8U	/* always send at least this many */
#define BRIDGE_PACKET_CAP	64U	/* upper clamp on per-iter burst */
#define STORM_BUDGET_NS		200000000L	/* 200 ms */

/* Per-child latched gates.  Set on the first failure of the
 * corresponding subsystem and never cleared — kernel module / config
 * presence is static for the child's lifetime, so we pay the EFAIL
 * once and skip the path on subsequent invocations. */
static bool ns_unsupported_bridge;
static bool ns_unsupported_veth;
static bool ns_unsupported_sysfs_stp;

static bool ns_unshared;
static bool ns_setup_failed;
static bool lo_brought_up;

static __u32 g_seq;

static __u32 next_seq(void)
{
	return ++g_seq;
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

	tv.tv_sec  = RTNL_RECV_TIMEO_S;
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

static size_t nla_put_u32(unsigned char *buf, size_t off, size_t cap,
			  unsigned short type, __u32 v)
{
	return nla_put(buf, off, cap, type, &v, sizeof(v));
}

static size_t nla_put_u8(unsigned char *buf, size_t off, size_t cap,
			 unsigned short type, __u8 v)
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
 * Bring lo up inside the private netns.  A freshly-unshared netns has
 * lo present but DOWN; some bridge / fdb code paths short-circuit on
 * the upper-layer carrier state, so flip lo up once-per-child.
 * Failures are ignored — they latch through the rest of the sequence
 * naturally.
 */
static void bring_lo_up(int rtnl)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	int lo_idx = (int)if_nametoindex("lo");

	if (lo_idx <= 0)
		return;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = next_seq();

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = lo_idx;
	ifi->ifi_flags  = IFF_UP;
	ifi->ifi_change = IFF_UP;

	nlh->nlmsg_len = (__u32)(NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi)));
	(void)rtnl_send_recv(rtnl, buf, nlh->nlmsg_len);
}

/*
 * RTM_NEWLINK type=bridge with the supplied dev name.  No
 * IFLA_INFO_DATA — defaults are fine for our purposes (STP off,
 * default ageing, default forward delay).  STP gets toggled later
 * via sysfs.  Returns 0 on accept, negated errno on rejection,
 * -EIO on local failure.
 */
static int build_bridge_create(int fd, const char *name)
{
	unsigned char buf[RTNL_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	struct nlattr *linkinfo;
	size_t off;
	size_t li_off;

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

	linkinfo = (struct nlattr *)(buf + li_off);
	linkinfo->nla_len = (unsigned short)(off - li_off);

	nlh->nlmsg_len = (__u32)off;
	return rtnl_send_recv(fd, buf, off);
}

/*
 * RTM_NEWLINK type=veth with VETH_INFO_PEER carrying the peer's
 * ifinfomsg + IFLA_IFNAME.  Distinct peer names per pair so the four
 * veth ends in this op are unambiguously addressable by name.
 */
static int build_veth_create(int fd, const char *name, const char *peer_name)
{
	unsigned char buf[RTNL_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	struct ifinfomsg *peer_ifi;
	struct nlattr *linkinfo;
	struct nlattr *infodata;
	struct nlattr *peer_attr;
	size_t off;
	size_t li_off, id_off, peer_off;

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

	/* VETH_INFO_PEER's payload starts with an ifinfomsg, then
	 * regular IFLA attributes (IFLA_IFNAME for the peer name). */
	if (off + NLMSG_ALIGN(sizeof(*peer_ifi)) > sizeof(buf))
		return -EIO;
	peer_ifi = (struct ifinfomsg *)(buf + off);
	memset(peer_ifi, 0, sizeof(*peer_ifi));
	peer_ifi->ifi_family = AF_UNSPEC;
	off += NLMSG_ALIGN(sizeof(*peer_ifi));

	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, peer_name);
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

/*
 * RTM_SETLINK with IFLA_MASTER=master_ifindex on ifindex.  Enslaves
 * the veth end to the bridge.
 */
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
 * RTM_SETLINK family=AF_BRIDGE with IFLA_PROTINFO containing
 * IFLA_BRPORT_LEARNING=1 — arms BR_LEARNING on the port.  This is
 * what makes the receive-path frame ingress drive br_fdb_update
 * (the rx-driven learning path the op exists to exercise).
 */
static int build_setlink_brport_learning(int fd, int ifindex)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	struct nlattr *protinfo;
	size_t off, pi_off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_SETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = next_seq();

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_BRIDGE;
	ifi->ifi_index  = ifindex;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	pi_off = off;
	off = nla_put(buf, off, sizeof(buf),
		      IFLA_PROTINFO | NLA_F_NESTED, NULL, 0);
	if (!off)
		return -EIO;

	off = nla_put_u8(buf, off, sizeof(buf), IFLA_BRPORT_LEARNING, 1);
	if (!off)
		return -EIO;

	protinfo = (struct nlattr *)(buf + pi_off);
	protinfo->nla_len = (unsigned short)(off - pi_off);

	nlh->nlmsg_len = (__u32)off;
	return rtnl_send_recv(fd, buf, off);
}

/*
 * RTM_DELNEIGH for a fdb entry: family=AF_BRIDGE, ndm_ifindex=port,
 * NDA_LLADDR=mac.  Races the receive-path learning that may be
 * re-installing the same entry concurrently — the targeted
 * learn-vs-delete window.
 */
static int build_fdb_del(int fd, int port_ifindex, const unsigned char *mac)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct ndmsg *ndm;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_DELNEIGH;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = next_seq();

	ndm = (struct ndmsg *)NLMSG_DATA(nlh);
	ndm->ndm_family  = AF_BRIDGE;
	ndm->ndm_ifindex = port_ifindex;
	ndm->ndm_state   = NUD_REACHABLE;
	ndm->ndm_flags   = NTF_MASTER;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ndm));
	off = nla_put(buf, off, sizeof(buf), NDA_LLADDR, mac, 6);
	if (!off)
		return -EIO;

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
 * Toggle STP via /sys/class/net/<br>/bridge/stp_state.  Open + write
 * + close per call.  EROFS / EACCES / ENOENT all latch
 * ns_unsupported_sysfs_stp — those are the failure modes for a
 * kernel without sysfs writeable bridge knobs (read-only bind mount,
 * lockdown=integrity, missing CONFIG_SYSFS).
 */
static bool sysfs_stp_write(const char *brname, char val)
{
	char path[64];
	int fd;
	ssize_t n;

	if (snprintf(path, sizeof(path),
		     "/sys/class/net/%s/bridge/stp_state", brname) >= (int)sizeof(path))
		return false;

	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0) {
		if (errno == EROFS || errno == EACCES || errno == ENOENT)
			ns_unsupported_sysfs_stp = true;
		return false;
	}

	n = write(fd, &val, 1);
	close(fd);
	return n == 1;
}

/*
 * Generate a random unicast, locally-administered MAC.  Bit 0 of the
 * first byte is the multicast bit (must be 0); bit 1 is the
 * locally-administered bit (set so we don't collide with any host
 * OUI).  br_fdb_update accepts any unicast lladdr.
 */
static void random_unicast_lla(unsigned char *mac)
{
	generate_rand_bytes(mac, 6);
	mac[0] = (unsigned char)((mac[0] & 0xfc) | 0x02);
}

static long ns_since(const struct timespec *t0)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		return 0;
	return (now.tv_sec - t0->tv_sec) * 1000000000L +
	       (now.tv_nsec - t0->tv_nsec);
}

bool bridge_fdb_stp(struct childdata *child)
{
	char br_name[IFNAMSIZ];
	char veth0a[IFNAMSIZ], veth0b[IFNAMSIZ];
	char veth1a[IFNAMSIZ], veth1b[IFNAMSIZ];
	const char *port_names[4];
	int port_idx[4] = { 0, 0, 0, 0 };
	int rtnl = -1;
	int raw = -1;
	int br_idx = 0;
	bool bridge_added = false;
	bool veth0_added = false;
	bool veth1_added = false;
	unsigned char last_src_mac[6] = { 0 };
	bool have_last_mac = false;
	struct timespec t0;
	unsigned int iters;
	unsigned int i;
	unsigned int rng;
	int rc;

	(void)child;

	__atomic_add_fetch(&shm->stats.bridge_fdb_stp_runs, 1,
			   __ATOMIC_RELAXED);

	if (ns_setup_failed || ns_unsupported_bridge)
		return true;

	if (!ns_unshared) {
		if (unshare(CLONE_NEWNET) < 0) {
			ns_setup_failed = true;
			__atomic_add_fetch(&shm->stats.bridge_fdb_stp_setup_failed,
					   1, __ATOMIC_RELAXED);
			return true;
		}
		ns_unshared = true;
	}

	rtnl = rtnl_open();
	if (rtnl < 0) {
		__atomic_add_fetch(&shm->stats.bridge_fdb_stp_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (!lo_brought_up) {
		bring_lo_up(rtnl);
		lo_brought_up = true;
	}

	rng = (unsigned int)(rand32() & 0xffffu);
	snprintf(br_name, sizeof(br_name), "trbr%u", rng);
	snprintf(veth0a, sizeof(veth0a), "trbv%ua0", rng);
	snprintf(veth0b, sizeof(veth0b), "trbv%ub0", rng);
	snprintf(veth1a, sizeof(veth1a), "trbv%ua1", rng);
	snprintf(veth1b, sizeof(veth1b), "trbv%ub1", rng);

	rc = build_bridge_create(rtnl, br_name);
	if (rc != 0) {
		/* Latch only on the structural-unsupported errnos —
		 * EBUSY / EEXIST from a stale name leave the latch
		 * alone so the next iteration retries with fresh rng. */
		if (rc == -EAFNOSUPPORT || rc == -EOPNOTSUPP ||
		    rc == -ENOTSUP || rc == -ENOENT || rc == -EPROTONOSUPPORT)
			ns_unsupported_bridge = true;
		goto out;
	}
	bridge_added = true;
	__atomic_add_fetch(&shm->stats.bridge_fdb_stp_bridge_create_ok,
			   1, __ATOMIC_RELAXED);

	br_idx = (int)if_nametoindex(br_name);
	if (br_idx == 0)
		goto out;

	/* veth pair 0 */
	if (!ns_unsupported_veth) {
		rc = build_veth_create(rtnl, veth0a, veth0b);
		if (rc != 0) {
			if (rc == -EAFNOSUPPORT || rc == -EOPNOTSUPP ||
			    rc == -ENOTSUP || rc == -ENOENT)
				ns_unsupported_veth = true;
		} else {
			veth0_added = true;
			__atomic_add_fetch(&shm->stats.bridge_fdb_stp_veth_create_ok,
					   1, __ATOMIC_RELAXED);
		}
	}

	/* veth pair 1 */
	if (!ns_unsupported_veth) {
		rc = build_veth_create(rtnl, veth1a, veth1b);
		if (rc == 0) {
			veth1_added = true;
			__atomic_add_fetch(&shm->stats.bridge_fdb_stp_veth_create_ok,
					   1, __ATOMIC_RELAXED);
		}
	}

	port_names[0] = veth0_added ? veth0a : NULL;
	port_names[1] = veth0_added ? veth0b : NULL;
	port_names[2] = veth1_added ? veth1a : NULL;
	port_names[3] = veth1_added ? veth1b : NULL;

	for (i = 0; i < 4; i++) {
		if (!port_names[i])
			continue;
		port_idx[i] = (int)if_nametoindex(port_names[i]);
		if (port_idx[i] > 0)
			(void)build_setlink_master(rtnl, port_idx[i], br_idx);
	}

	(void)build_setlink_up(rtnl, br_idx);
	for (i = 0; i < 4; i++) {
		if (port_idx[i] > 0)
			(void)build_setlink_up(rtnl, port_idx[i]);
	}

	for (i = 0; i < 4; i++) {
		if (port_idx[i] > 0)
			(void)build_setlink_brport_learning(rtnl, port_idx[i]);
	}

	/* AF_PACKET sender bound to one of the ports — drives the
	 * receive-path learning at the bridge ingress.  Pick port 0
	 * (veth0a) preferentially; fall back to whichever port_idx
	 * survived. */
	{
		int tx_port_idx = 0;
		unsigned int j;

		for (j = 0; j < 4; j++) {
			if (port_idx[j] > 0) {
				tx_port_idx = port_idx[j];
				break;
			}
		}

		if (tx_port_idx > 0) {
			raw = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC,
				     htons(ETH_P_ALL));
			if (raw >= 0) {
				struct sockaddr_ll sll;

				memset(&sll, 0, sizeof(sll));
				sll.sll_family   = AF_PACKET;
				sll.sll_protocol = htons(ETH_P_ALL);
				sll.sll_ifindex  = tx_port_idx;
				(void)bind(raw, (struct sockaddr *)&sll,
					   sizeof(sll));
			}

			if (raw >= 0) {
				(void)clock_gettime(CLOCK_MONOTONIC, &t0);
				iters = BUDGETED(CHILD_OP_BRIDGE_FDB_STP,
						 JITTER_RANGE(BRIDGE_PACKET_BASE));
				if (iters < BRIDGE_PACKET_FLOOR)
					iters = BRIDGE_PACKET_FLOOR;
				if (iters > BRIDGE_PACKET_CAP)
					iters = BRIDGE_PACKET_CAP;

				for (i = 0; i < iters; i++) {
					struct sockaddr_ll sll;
					unsigned char frame[64];
					unsigned char dst_mac[6];
					unsigned char src_mac[6];
					ssize_t n;

					if (ns_since(&t0) >= STORM_BUDGET_NS)
						break;

					/* Random locally-administered unicast
					 * src; deterministic broadcast dst so
					 * the bridge floods the frame and the
					 * src triggers br_fdb_update on
					 * ingress. */
					random_unicast_lla(src_mac);
					memset(dst_mac, 0xff, sizeof(dst_mac));

					memset(frame, 0, sizeof(frame));
					memcpy(frame + 0, dst_mac, 6);
					memcpy(frame + 6, src_mac, 6);
					frame[12] = 0x08;	/* ETH_P_IP */
					frame[13] = 0x00;
					/* payload is zeros — the bridge
					 * doesn't parse upper layers for the
					 * learning-on-rx path. */

					memset(&sll, 0, sizeof(sll));
					sll.sll_family   = AF_PACKET;
					sll.sll_protocol = htons(ETH_P_ALL);
					sll.sll_ifindex  = tx_port_idx;
					sll.sll_halen    = 6;
					memcpy(sll.sll_addr, dst_mac, 6);

					n = sendto(raw, frame, sizeof(frame),
						   MSG_DONTWAIT,
						   (struct sockaddr *)&sll,
						   sizeof(sll));
					if (n > 0) {
						__atomic_add_fetch(&shm->stats.bridge_fdb_stp_raw_send_ok,
								   1, __ATOMIC_RELAXED);
						memcpy(last_src_mac, src_mac,
						       sizeof(last_src_mac));
						have_last_mac = true;
					}
				}
			}

			/* fdb DELNEIGH on the most-recently-sent src mac
			 * races the rx-driven learning that may be
			 * re-installing it.  Use the same port we sent on. */
			if (have_last_mac) {
				if (build_fdb_del(rtnl, tx_port_idx,
						  last_src_mac) == 0)
					__atomic_add_fetch(&shm->stats.bridge_fdb_stp_fdb_del_ok,
							   1, __ATOMIC_RELAXED);
			}
		}
	}

	if (!ns_unsupported_sysfs_stp) {
		if (sysfs_stp_write(br_name, '1'))
			__atomic_add_fetch(&shm->stats.bridge_fdb_stp_stp_toggle_ok,
					   1, __ATOMIC_RELAXED);
		if (sysfs_stp_write(br_name, '0'))
			__atomic_add_fetch(&shm->stats.bridge_fdb_stp_stp_toggle_ok,
					   1, __ATOMIC_RELAXED);
	}

out:
	if (raw >= 0)
		close(raw);

	if (rtnl >= 0) {
		/* Deleting the bridge cascades to the enslaved veths via
		 * br_dev_delete — that's the targeted teardown-vs-rx
		 * window.  Don't pre-DELLINK the veths individually. */
		if (bridge_added && br_idx > 0) {
			if (build_dellink(rtnl, br_idx) == 0)
				__atomic_add_fetch(&shm->stats.bridge_fdb_stp_link_del_ok,
						   1, __ATOMIC_RELAXED);
		}
		/* Veths whose bridge enslave failed are still around;
		 * mop them up so a long-lived child doesn't accumulate
		 * orphan veths in its private netns. */
		if (veth0_added && port_idx[0] > 0)
			(void)build_dellink(rtnl, port_idx[0]);
		if (veth1_added && port_idx[2] > 0)
			(void)build_dellink(rtnl, port_idx[2]);
		close(rtnl);
	}

	return true;
}
