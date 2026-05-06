/*
 * vxlan_encap_churn - VXLAN / GRE / GENEVE encap setup + packet inject.
 *
 * Flat netlink fuzzing rarely assembles the full chain that an
 * overlay-tunnel needs to reach its decap / encap fast paths: the
 * link must be created with a kind-specific IFLA_INFO_DATA payload
 * (vni for vxlan/geneve, ikey/okey for gre), at least one peer must
 * be installed (NTF_SELF fdb entry on vxlan, or the unicast remote
 * baked into IFLA_*_REMOTE), the link must be brought up, and an
 * AF_PACKET SOCK_RAW peer must push frames at the tunnel device so
 * the encap-tx path actually runs.  Without any one of those the
 * vxlan_xmit_one / geneve_xmit / ipgre_xmit code paths never trigger,
 * and the destroy edge (RTM_DELLINK racing an in-flight skb on the
 * tx queue) never opens its window.
 *
 * Sequence (per invocation):
 *   1. unshare(CLONE_NEWNET) once per child into a private net
 *      namespace so the host's main routing table never sees any of
 *      this.  Failure latches the kind-specific gates off.
 *   2. Best-effort modprobe vxlan / ip_gre / geneve and bring lo up
 *      (one-time, latched after first success).
 *   3. Pick a kind (vxlan / gre / geneve) at random; if its latch is
 *      already tripped, fall through to the next kind.  All-tripped
 *      means every kind is structurally unsupported, return cheaply.
 *   4. RTM_NEWLINK with type = picked kind.  Payload has random vni
 *      (vxlan/geneve) or ikey+okey (gre); local/remote pinned to
 *      127.0.0.1 / 127.0.0.2 so packets stay loopback-bound and the
 *      tunnel resolves against `lo` as the underlay.
 *   5. RTM_NEWLINK setlink to bring the tunnel dev up.
 *   6. RTM_NEWNEIGH NTF_SELF (vxlan only): add a permanent fdb entry
 *      pointing inner-mac at peer remote 127.0.0.2.  This drives
 *      vxlan_fdb_add and arms the static-fdb decap path that the
 *      vxlan_remcsum UAF history hangs off.
 *   7. socket(AF_PACKET, SOCK_RAW); bind to the tunnel dev's ifindex.
 *      sendto() a small synthetic IPv4 frame with random length so
 *      the encap-tx path runs once.  BUDGETED+JITTER around base 3
 *      for the per-iteration burst count; each send is MSG_DONTWAIT.
 *   8. RTM_DELLINK the tunnel dev WHILE the raw socket is still open
 *      and any sends from step 7 are still draining.  The teardown-
 *      vs-in-flight-rx race is the targeted window.
 *
 * CVE class: CVE-2023-52454 nvmet-tcp shift family (oob), CVE-2022-2588
 * cls_route+tunnel UAFs, vxlan_remcsum UAF history (commit 6db924687fd1
 * lineage and re-occurrences).  Subsystems reached: drivers/net/vxlan/,
 * net/ipv4/ip_gre.c, net/ipv6/ip6_gre.c, drivers/net/geneve.c,
 * net/core/lwtunnel.c (encap path inside ip_route_output_tunnel).
 *
 * Self-bounding: one full create/destroy cycle per invocation, packet
 * burst count bounded by BUDGETED+JITTER around base 3, all I/O
 * non-blocking, SO_RCVTIMEO=1s on the netlink ack socket so an
 * unresponsive rtnl can't wedge us past the SIGALRM(1s) cap inherited
 * from child.c.  Loopback only (peer addr 127.0.0.2 inside the
 * private netns).  Three latches (one per kind) so a kernel without a
 * given module pays the EFAIL once and skips that kind permanently.
 */

#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
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

/* if_link.h on stripped sysroots may not have the full VXLAN/GENEVE/GRE
 * attribute enums.  Provide the minimal subset we actually emit: the
 * IDs are stable in the UAPI, so re-defining as a fallback is safe.
 * We test the canonical anchor for each family (IFLA_VXLAN_ID,
 * IFLA_GENEVE_ID, IFLA_GRE_LINK) and fall back wholesale if any one
 * of them is missing rather than per-symbol — keeps the gate simple. */
#ifndef IFLA_VXLAN_ID
#define IFLA_VXLAN_ID		1
#define IFLA_VXLAN_GROUP	2
#define IFLA_VXLAN_LINK		3
#define IFLA_VXLAN_LOCAL	4
#define IFLA_VXLAN_PORT		15
#endif

#ifndef IFLA_GENEVE_ID
#define IFLA_GENEVE_ID		1
#define IFLA_GENEVE_REMOTE	2
#endif

#ifndef IFLA_GRE_LINK
#define IFLA_GRE_LINK		1
#define IFLA_GRE_IKEY		3
#define IFLA_GRE_OKEY		4
#define IFLA_GRE_LOCAL		5
#define IFLA_GRE_REMOTE		6
#endif

#ifndef NDA_DST
#define NDA_DST			1
#define NDA_LLADDR		2
#endif

#ifndef NTF_SELF
#define NTF_SELF		(1 << 1)
#endif

#ifndef NUD_PERMANENT
#define NUD_PERMANENT		0x80
#endif

/* Reasonable ceiling on a single rtnl message + payload.  vxlan link
 * create with all attributes set fits in well under 1 KiB; 2 KiB
 * leaves headroom for any future attribute additions. */
#define RTNL_BUF_BYTES		2048
#define RTNL_RECV_TIMEO_S	1

/* Per-iteration packet burst base.  BUDGETED+JITTER scales it: a
 * productive run grows to ~iter*4 sends, an unproductive one shrinks
 * to floor.  Sends are MSG_DONTWAIT so even an unlimited burst can't
 * stall the iteration past the inherited SIGALRM(1s) cap. */
#define VXLAN_PACKET_BASE	3U

/* VXLAN VNI is 24-bit; mask to that width so we never emit values the
 * kernel will reject as malformed.  GRE keys are 32-bit u32 and accept
 * any value, so they get the raw rand32(). */
#define VNI_MASK		0x00ffffffU

/* UDP destination port for sent test packets.  Loopback-only — the
 * value doesn't matter functionally; pinning it to a fixed
 * non-privileged port keeps any escaped packet trivially identifiable
 * in tcpdump traces during triage. */
#define INNER_DST_PORT		34567

/* Latched per-child gates.  None of these flip during a child's
 * lifetime (kernel module presence is static), so once we've paid the
 * EFAIL we stop probing the kind on subsequent invocations and just
 * bump the runs+setup_failed pair. */
static bool ns_unsupported_vxlan;
static bool ns_unsupported_gre;
static bool ns_unsupported_geneve;

/* Latched once a successful unshare puts us in a private netns.  The
 * trinity child is long-lived; we only need to unshare once and
 * inherit the namespace across subsequent invocations.  Re-unsharing
 * each call would just leak namespaces. */
static bool ns_unshared;
static bool ns_setup_failed;
static bool lo_brought_up;

static __u32 g_seq;

enum tun_kind {
	TUN_VXLAN = 0,
	TUN_GRE,
	TUN_GENEVE,
	TUN_NR,
};

static const char *kind_name(enum tun_kind k)
{
	switch (k) {
	case TUN_VXLAN:		return "vxlan";
	case TUN_GRE:		return "gre";
	case TUN_GENEVE:	return "geneve";
	case TUN_NR:		break;
	}
	return "unknown";
}

static bool *kind_latch(enum tun_kind k)
{
	switch (k) {
	case TUN_VXLAN:		return &ns_unsupported_vxlan;
	case TUN_GRE:		return &ns_unsupported_gre;
	case TUN_GENEVE:	return &ns_unsupported_geneve;
	case TUN_NR:		break;
	}
	return NULL;
}

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

static size_t nla_put_u16(unsigned char *buf, size_t off, size_t cap,
			  unsigned short type, __u16 v)
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
 * Best-effort modprobe.  fork+execvp; child redirects stdio to /dev/null
 * so any module-load chatter doesn't pollute trinity's output.  Ignore
 * the exit status — modprobe failures (no module, no permission, no
 * /sbin/modprobe at all) are exactly the cases the kind latch will
 * catch on the subsequent RTM_NEWLINK probe.
 */
static void try_modprobe(const char *mod)
{
	pid_t pid = fork();
	int status;

	if (pid < 0)
		return;
	if (pid == 0) {
		int devnull = open("/dev/null", O_RDWR | O_CLOEXEC);
		if (devnull >= 0) {
			(void)dup2(devnull, 0);
			(void)dup2(devnull, 1);
			(void)dup2(devnull, 2);
			close(devnull);
		}
		execlp("modprobe", "modprobe", "-q", mod, (char *)NULL);
		_exit(127);
	}
	(void)waitpid(pid, &status, 0);
}

/*
 * Bring lo up inside the private netns.  Newly created netns has lo
 * present but DOWN; AF_PACKET sendto on a tunnel whose underlay is
 * lo silently drops if lo is down, defeating the encap-tx coverage.
 * Setlink errors are ignored — a kernel that refuses lo up is also
 * one where the rest of the sequence will fail visibly.
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
 * Build & send RTM_NEWLINK creating a tunnel of the requested kind.
 * Local pinned to 127.0.0.1, remote to 127.0.0.2.  vni / keys are
 * randomised so each iteration hashes into a different hash-table
 * bucket on the kernel side.  Returns 0 on accept, negated errno on
 * rejection, -EIO on local failure.
 */
static int build_tunnel_link(int fd, enum tun_kind kind, const char *name,
			     __u32 vni_or_key)
{
	unsigned char buf[RTNL_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	struct nlattr *linkinfo;
	struct nlattr *infodata;
	__u32 local_addr;
	__u32 remote_addr;
	size_t off;
	size_t li_off, id_off;

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

	off = nla_put_str(buf, off, sizeof(buf), IFLA_INFO_KIND,
			  kind_name(kind));
	if (!off)
		return -EIO;

	id_off = off;
	off = nla_put(buf, off, sizeof(buf), IFLA_INFO_DATA, NULL, 0);
	if (!off)
		return -EIO;

	local_addr  = htonl(0x7f000001U);	/* 127.0.0.1 */
	remote_addr = htonl(0x7f000002U);	/* 127.0.0.2 */

	switch (kind) {
	case TUN_VXLAN:
		off = nla_put_u32(buf, off, sizeof(buf), IFLA_VXLAN_ID,
				  vni_or_key & VNI_MASK);
		if (!off)
			return -EIO;
		off = nla_put(buf, off, sizeof(buf), IFLA_VXLAN_LOCAL,
			      &local_addr, sizeof(local_addr));
		if (!off)
			return -EIO;
		off = nla_put(buf, off, sizeof(buf), IFLA_VXLAN_GROUP,
			      &remote_addr, sizeof(remote_addr));
		if (!off)
			return -EIO;
		/* IFLA_VXLAN_PORT is __be16; htons keeps it network-order
		 * regardless of the nla_put_u16 helper's host-order intent. */
		off = nla_put_u16(buf, off, sizeof(buf), IFLA_VXLAN_PORT,
				  htons(4789));
		if (!off)
			return -EIO;
		break;
	case TUN_GRE:
		off = nla_put_u32(buf, off, sizeof(buf), IFLA_GRE_IKEY,
				  htonl(vni_or_key));
		if (!off)
			return -EIO;
		off = nla_put_u32(buf, off, sizeof(buf), IFLA_GRE_OKEY,
				  htonl(vni_or_key));
		if (!off)
			return -EIO;
		off = nla_put(buf, off, sizeof(buf), IFLA_GRE_LOCAL,
			      &local_addr, sizeof(local_addr));
		if (!off)
			return -EIO;
		off = nla_put(buf, off, sizeof(buf), IFLA_GRE_REMOTE,
			      &remote_addr, sizeof(remote_addr));
		if (!off)
			return -EIO;
		break;
	case TUN_GENEVE:
		off = nla_put_u32(buf, off, sizeof(buf), IFLA_GENEVE_ID,
				  vni_or_key & VNI_MASK);
		if (!off)
			return -EIO;
		off = nla_put(buf, off, sizeof(buf), IFLA_GENEVE_REMOTE,
			      &remote_addr, sizeof(remote_addr));
		if (!off)
			return -EIO;
		break;
	case TUN_NR:
		return -EIO;
	}

	infodata = (struct nlattr *)(buf + id_off);
	infodata->nla_len = (unsigned short)(off - id_off);

	linkinfo = (struct nlattr *)(buf + li_off);
	linkinfo->nla_len = (unsigned short)(off - li_off);

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
	nlh->nlmsg_type  = RTM_NEWLINK;
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
 * Build & send RTM_NEWNEIGH NTF_SELF for the vxlan fdb.  Adds a
 * permanent entry mapping a random inner mac to peer remote
 * 127.0.0.2.  Drives vxlan_fdb_add and the static-fdb path that the
 * vxlan_remcsum UAF history hangs off.
 */
static int build_fdb_add(int fd, int ifindex)
{
	unsigned char buf[256];
	unsigned char mac[6];
	struct nlmsghdr *nlh;
	struct ndmsg *ndm;
	__u32 dst;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWNEIGH;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = next_seq();

	ndm = (struct ndmsg *)NLMSG_DATA(nlh);
	ndm->ndm_family  = AF_BRIDGE;
	ndm->ndm_ifindex = ifindex;
	ndm->ndm_state   = NUD_PERMANENT;
	ndm->ndm_flags   = NTF_SELF;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ndm));

	/* Random unicast mac (clear the multicast bit, set locally-
	 * administered).  vxlan_fdb_add insists on a unicast lladdr for
	 * NTF_SELF entries so colliding with an actual host mac is not
	 * a concern inside the private netns. */
	generate_rand_bytes(mac, sizeof(mac));
	mac[0] = (unsigned char)((mac[0] & 0xfe) | 0x02);

	off = nla_put(buf, off, sizeof(buf), NDA_LLADDR, mac, sizeof(mac));
	if (!off)
		return -EIO;

	dst = htonl(0x7f000002U);	/* 127.0.0.2 — peer remote */
	off = nla_put(buf, off, sizeof(buf), NDA_DST, &dst, sizeof(dst));
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
 * Pick a starting kind that isn't latched off.  Returns TUN_NR if
 * every kind's latch is tripped — caller treats that as "all kinds
 * structurally unsupported, return cheaply".
 */
static enum tun_kind pick_kind(void)
{
	enum tun_kind start = (enum tun_kind)(rand32() % TUN_NR);
	unsigned int i;

	for (i = 0; i < TUN_NR; i++) {
		enum tun_kind k = (enum tun_kind)((start + i) % TUN_NR);
		if (!*kind_latch(k))
			return k;
	}
	return TUN_NR;
}

bool vxlan_encap_churn(struct childdata *child)
{
	char ifname[IFNAMSIZ];
	enum tun_kind kind;
	int rtnl = -1;
	int raw = -1;
	int ifindex = 0;
	__u32 vni_or_key;
	bool link_added = false;
	unsigned int iters;
	unsigned int i;
	int rc;

	(void)child;

	__atomic_add_fetch(&shm->stats.vxlan_encap_churn_runs, 1,
			   __ATOMIC_RELAXED);

	if (ns_setup_failed)
		return true;

	if (!ns_unshared) {
		if (unshare(CLONE_NEWNET) < 0) {
			ns_setup_failed = true;
			__atomic_add_fetch(&shm->stats.vxlan_encap_churn_setup_failed,
					   1, __ATOMIC_RELAXED);
			return true;
		}
		ns_unshared = true;
		/* Best-effort module loads; failures latch via the
		 * subsequent NEWLINK probe rather than here. */
		try_modprobe("vxlan");
		try_modprobe("ip_gre");
		try_modprobe("geneve");
	}

	kind = pick_kind();
	if (kind == TUN_NR)
		return true;

	rtnl = rtnl_open();
	if (rtnl < 0) {
		__atomic_add_fetch(&shm->stats.vxlan_encap_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (!lo_brought_up) {
		bring_lo_up(rtnl);
		lo_brought_up = true;
	}

	snprintf(ifname, sizeof(ifname), "trtun%u",
		 (unsigned int)(rand32() & 0xffffu));
	vni_or_key = rand32();

	rc = build_tunnel_link(rtnl, kind, ifname, vni_or_key);
	if (rc != 0) {
		/* EAFNOSUPPORT / EOPNOTSUPP / ENOTSUPP / ENOENT all mean
		 * "this rtnl_link_ops is not registered" — the kind's
		 * module isn't built or loadable, so latch and skip on
		 * future invocations.  Other rejections (EBUSY, EEXIST
		 * from a stale name collision) leave the latch alone so
		 * the next iteration retries with a fresh ifname. */
		if (rc == -EAFNOSUPPORT || rc == -EOPNOTSUPP ||
		    rc == -ENOTSUP || rc == -ENOENT || rc == -EPROTONOSUPPORT)
			*kind_latch(kind) = true;
		goto out;
	}
	link_added = true;
	__atomic_add_fetch(&shm->stats.vxlan_encap_churn_link_create_ok,
			   1, __ATOMIC_RELAXED);

	ifindex = (int)if_nametoindex(ifname);
	if (ifindex == 0)
		goto out;

	if (kind == TUN_VXLAN) {
		if (build_fdb_add(rtnl, ifindex) == 0)
			__atomic_add_fetch(&shm->stats.vxlan_encap_churn_fdb_add_ok,
					   1, __ATOMIC_RELAXED);
	}

	if (build_setlink_up(rtnl, ifindex) == 0)
		__atomic_add_fetch(&shm->stats.vxlan_encap_churn_link_up_ok,
				   1, __ATOMIC_RELAXED);

	raw = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_IP));
	if (raw < 0)
		goto out;

	{
		struct sockaddr_ll sll;

		memset(&sll, 0, sizeof(sll));
		sll.sll_family   = AF_PACKET;
		sll.sll_protocol = htons(ETH_P_IP);
		sll.sll_ifindex  = ifindex;
		(void)bind(raw, (struct sockaddr *)&sll, sizeof(sll));
	}

	/* Per-iteration packet burst.  Each send drives one trip
	 * through the encap-tx path (vxlan_xmit_one / geneve_xmit /
	 * ipgre_xmit, depending on kind).  The DELLINK below races
	 * against in-flight sends from the tail of this loop — that's
	 * the targeted teardown-vs-tx window. */
	iters = BUDGETED(CHILD_OP_VXLAN_ENCAP_CHURN,
			 JITTER_RANGE(VXLAN_PACKET_BASE));
	for (i = 0; i < iters; i++) {
		struct sockaddr_ll sll;
		unsigned char pkt[128];
		struct iphdr *iph;
		ssize_t n;
		size_t pkt_len;

		/* Random length in [40, sizeof(pkt)] so the encap path
		 * sees small / medium / fragmenting candidates instead of
		 * one fixed shape.  Minimum sized to fit the iphdr we
		 * stamp; maximum sized to fit the buffer. */
		pkt_len = 40U + (rand32() % (sizeof(pkt) - 40U));

		memset(pkt, 0, sizeof(pkt));
		iph = (struct iphdr *)pkt;
		iph->version  = 4;
		iph->ihl      = 5;
		iph->tot_len  = htons((__u16)pkt_len);
		iph->ttl      = 64;
		iph->protocol = IPPROTO_UDP;
		iph->saddr    = htonl(0x7f000001U);
		iph->daddr    = htonl(0x7f000002U);

		memset(&sll, 0, sizeof(sll));
		sll.sll_family   = AF_PACKET;
		sll.sll_protocol = htons(ETH_P_IP);
		sll.sll_ifindex  = ifindex;
		sll.sll_halen    = 6;

		n = sendto(raw, pkt, pkt_len, MSG_DONTWAIT,
			   (struct sockaddr *)&sll, sizeof(sll));
		if (n > 0)
			__atomic_add_fetch(&shm->stats.vxlan_encap_churn_packet_sent_ok,
					   1, __ATOMIC_RELAXED);
	}

out:
	if (raw >= 0)
		close(raw);

	if (rtnl >= 0) {
		if (link_added && ifindex > 0) {
			if (build_dellink(rtnl, ifindex) == 0)
				__atomic_add_fetch(&shm->stats.vxlan_encap_churn_link_del_ok,
						   1, __ATOMIC_RELAXED);
		}
		close(rtnl);
	}

	return true;
}
