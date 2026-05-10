/*
 * ip6erspan_netns_migrate - exercise rtnl_link_ops ->changelink across a
 * net-ns migration.  The kind we care most about is "ip6erspan": the
 * upstream rcv-side ip6erspan changelink path looked up its tunnel net via
 * t->net rather than dev_net(dev), so after RTM_SETLINK + IFLA_NET_NS_FD
 * moved the device into a sibling ns the very next NLM_F_REPLACE issued
 * against the post-migration tunnel walked the wrong netns hash.  Random
 * isolated syscall fuzzing essentially never assembles (a) a virtual
 * netdev created with kind X, (b) RTM_SETLINK IFLA_NET_NS_FD pointing at
 * a freshly-unshare()d sibling netns, (c) RTM_NEWLINK NLM_F_REPLACE with
 * mutated link params issued in the *target* ns, and (d) clean teardown,
 * all in a single child's lifetime.  This childop drives that sequence
 * deterministically and rotates over a small kind table so all
 * rtnl_link_ops with a ->changelink op (gre/gretap/ip6gre/ip6erspan/
 * erspan/vxlan/geneve) get the same shape exercised.
 *
 * Per iteration:
 *   (a) unshare(CLONE_NEWNET) once per child for the original ns.  EPERM
 *       latches the whole op off.
 *   (b) Open AF_NETLINK NETLINK_ROUTE socket; bind.
 *   (c) RTM_NEWLINK creating a link of the rolled kind: nested
 *       IFLA_LINKINFO with IFLA_INFO_KIND=<kind>; nested IFLA_INFO_DATA
 *       holding a small kind-specific attr blob (IFLA_GRE_LOCAL/REMOTE/
 *       LINK + ERSPAN_VER/INDEX for GRE family, IFLA_VXLAN_ID for vxlan,
 *       IFLA_GENEVE_ID for geneve).  EPERM/EOPNOTSUPP/EAFNOSUPPORT/
 *       ENOENT latch ns_unsupported_ip6erspan -- typically a kernel
 *       missing the corresponding tunnel module / erspan ver bits.
 *   (d) unshare(CLONE_NEWNET) again to obtain a fresh sibling
 *       ("target") netns; keep an FD on it via /proc/self/ns/net opened
 *       before re-entering the original.  setns() back to the original
 *       ns so the rtnetlink socket still talks to the link's current ns.
 *   (e) RTM_SETLINK on the link with IFLA_NET_NS_FD pointing at the
 *       target ns FD -- migrates the link to the sibling ns.
 *   (f) setns() into the target ns; open a fresh rtnetlink socket there
 *       and issue RTM_NEWLINK NLM_F_REPLACE with mutated changelink
 *       params (rolled IFLA_GRE_REMOTE / IFLA_GRE_ERSPAN_INDEX /
 *       IFLA_GRE_ERSPAN_HWID for GRE family, mutated IFLA_VXLAN_ID for
 *       vxlan, mutated IFLA_GENEVE_ID for geneve).  This walks the
 *       kind's ->changelink op with the device's post-migration
 *       dev_net(); a kernel using t->net instead of dev_net() reaches
 *       into the wrong tunnel hash here.
 *   (g) Force teardown: RTM_DELLINK in the target ns; close target
 *       rtnetlink + ns FD; setns() back to the original ns.
 *
 * Latches:
 *   ns_unsupported_ip6erspan -- master gate; set on first ENOENT/
 *                               EAFNOSUPPORT/EPROTONOSUPPORT/EOPNOTSUPP
 *                               from create or from setns/unshare; one
 *                               warn_once_unsupported line then skip.
 *   ns_unsupported_changelink -- secondary gate; set when NLM_F_REPLACE
 *                                returns -EOPNOTSUPP for any kind so a
 *                                missing changelink op doesn't kill the
 *                                whole childop -- create + migrate +
 *                                teardown still walk.
 *
 * Self-bounding: one create + migrate + changelink + teardown cycle per
 * invocation; no inner loops over kinds (one kind per outer iter, rolled
 * uniformly).  All rtnetlink I/O carries SO_RCVTIMEO.  Loopback-class
 * activity stays inside private netns FDs.
 */

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
#include <unistd.h>

#include <linux/if_link.h>
#include <linux/if_tunnel.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "child.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/*
 * UAPI fallbacks.  linux/if_link.h and linux/if_tunnel.h are present on
 * every sysroot trinity targets, but if a stripped build host lacks any
 * of these enum tags the numeric values match the upstream UAPI.  Inline
 * shims rather than a topic-specific compat-iftunnel.h: ~6 LOC total
 * across 2 consumers (this file + the test build), well under the
 * ~30 LOC / 3 consumer threshold for a dedicated compat header.
 */
#ifndef IFLA_NET_NS_FD
#define IFLA_NET_NS_FD			28
#endif

#ifndef IFLA_GRE_LINK
#define IFLA_GRE_LINK			1
#define IFLA_GRE_LOCAL			5
#define IFLA_GRE_REMOTE			6
#endif

#ifndef IFLA_GRE_ERSPAN_INDEX
#define IFLA_GRE_ERSPAN_INDEX		16
#define IFLA_GRE_ERSPAN_VER		17
#define IFLA_GRE_ERSPAN_DIR		18
#define IFLA_GRE_ERSPAN_HWID		19
#endif

#ifndef IFLA_VXLAN_ID
#define IFLA_VXLAN_ID			1
#endif

#ifndef IFLA_GENEVE_ID
#define IFLA_GENEVE_ID			1
#endif

#define INM_BUF				1024
#define INM_RECV_TIMEO_S		1

enum inm_kind {
	INM_KIND_GRE,
	INM_KIND_GRETAP,
	INM_KIND_IP6GRE,
	INM_KIND_IP6ERSPAN,
	INM_KIND_ERSPAN,
	INM_KIND_VXLAN,
	INM_KIND_GENEVE,
	INM_KIND_NR,
};

static const char * const inm_kind_names[INM_KIND_NR] = {
	[INM_KIND_GRE]		= "gre",
	[INM_KIND_GRETAP]	= "gretap",
	[INM_KIND_IP6GRE]	= "ip6gre",
	[INM_KIND_IP6ERSPAN]	= "ip6erspan",
	[INM_KIND_ERSPAN]	= "erspan",
	[INM_KIND_VXLAN]	= "vxlan",
	[INM_KIND_GENEVE]	= "geneve",
};

/* True for the GRE-family kinds that take IFLA_GRE_* attrs in their
 * IFLA_INFO_DATA blob.  vxlan / geneve have their own per-kind attrs. */
static bool inm_kind_is_gre_family(enum inm_kind k)
{
	switch (k) {
	case INM_KIND_GRE:
	case INM_KIND_GRETAP:
	case INM_KIND_IP6GRE:
	case INM_KIND_IP6ERSPAN:
	case INM_KIND_ERSPAN:
		return true;
	default:
		return false;
	}
}

/* ip6erspan and ip6gre travel over IPv6.  Loopback-class addresses for
 * the link's local/remote endpoints; the changelink path walks
 * dev_net(dev) without ever putting traffic on the wire. */
static bool inm_kind_is_v6(enum inm_kind k)
{
	return k == INM_KIND_IP6GRE || k == INM_KIND_IP6ERSPAN;
}

static const __u8 inm_v6_local[16] = {
	0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1,	/* ::1 */
};
static const __u8 inm_v6_remote[16] = {
	0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,2,	/* ::2 */
};

static bool ns_unsupported_ip6erspan;
static bool ns_unsupported_changelink;
static bool inm_unshared_orig;
static int  inm_orig_ns_fd = -1;
static __u32 g_seq;
static __u32 g_iter;
static unsigned int g_warned_kinds;	/* bitmask of kinds that latched off */

static __u32 next_seq(void)
{
	return ++g_seq;
}

static void warn_once_unsupported(const char *reason, int err)
{
	if (ns_unsupported_ip6erspan)
		return;
	ns_unsupported_ip6erspan = true;
	outputerr("ip6erspan_netns_migrate: %s failed (errno=%d), latching unsupported_ip6erspan\n",
		  reason, err);
}

static int inm_rtnl_open(void)
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

	tv.tv_sec  = INM_RECV_TIMEO_S;
	tv.tv_usec = 0;
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	return fd;
}

static int inm_send_recv(int fd, void *msg, size_t len)
{
	struct sockaddr_nl dst;
	struct iovec iov;
	struct msghdr mh;
	unsigned char rbuf[512];
	struct nlmsghdr *r;
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
	if (n < 0 || (size_t)n < NLMSG_HDRLEN)
		return -EIO;
	r = (struct nlmsghdr *)rbuf;
	if (r->nlmsg_type == NLMSG_ERROR)
		return ((struct nlmsgerr *)NLMSG_DATA(r))->error;
	return 0;
}

static size_t inm_nla(unsigned char *buf, size_t off, size_t cap,
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

static size_t inm_nla_u32(unsigned char *buf, size_t off, size_t cap,
			  unsigned short type, __u32 v)
{
	return inm_nla(buf, off, cap, type, &v, sizeof(v));
}

static size_t inm_nla_u8(unsigned char *buf, size_t off, size_t cap,
			 unsigned short type, __u8 v)
{
	return inm_nla(buf, off, cap, type, &v, sizeof(v));
}

static size_t inm_nla_str(unsigned char *buf, size_t off, size_t cap,
			  unsigned short type, const char *s)
{
	return inm_nla(buf, off, cap, type, s, strlen(s) + 1);
}

/*
 * Append the per-kind IFLA_INFO_DATA blob.  GRE family takes a small
 * IFLA_GRE_* envelope with kind-specific extra (ERSPAN_VER/INDEX/HWID
 * for the erspan variants); vxlan / geneve take a single ID attr.  Same
 * envelope across kinds at the call site -- caller wraps this in
 * IFLA_INFO_DATA and the surrounding IFLA_LINKINFO nest.
 */
static size_t append_kind_info_data(unsigned char *buf, size_t off, size_t cap,
				    enum inm_kind k)
{
	if (inm_kind_is_gre_family(k)) {
		off = inm_nla_u32(buf, off, cap, IFLA_GRE_LINK, 0);
		if (!off) return 0;
		if (inm_kind_is_v6(k)) {
			off = inm_nla(buf, off, cap, IFLA_GRE_LOCAL,
				      inm_v6_local, sizeof(inm_v6_local));
			if (!off) return 0;
			off = inm_nla(buf, off, cap, IFLA_GRE_REMOTE,
				      inm_v6_remote, sizeof(inm_v6_remote));
			if (!off) return 0;
		} else {
			__u32 local  = htonl(0x7f000001U);
			__u32 remote = htonl(0x7f000002U);
			off = inm_nla(buf, off, cap, IFLA_GRE_LOCAL,
				      &local, sizeof(local));
			if (!off) return 0;
			off = inm_nla(buf, off, cap, IFLA_GRE_REMOTE,
				      &remote, sizeof(remote));
			if (!off) return 0;
		}
		if (k == INM_KIND_IP6ERSPAN || k == INM_KIND_ERSPAN) {
			__u8  ver   = (rand32() & 1U) ? 2 : 1;
			__u32 index = (rand32() & 0xfffU) + 1U;
			off = inm_nla_u8(buf, off, cap,
					 IFLA_GRE_ERSPAN_VER, ver);
			if (!off) return 0;
			off = inm_nla_u32(buf, off, cap,
					  IFLA_GRE_ERSPAN_INDEX, index);
			if (!off) return 0;
			if (ver == 2) {
				__u8 hwid = (__u8)(rand32() & 0x3fU);
				off = inm_nla_u8(buf, off, cap,
						 IFLA_GRE_ERSPAN_HWID, hwid);
				if (!off) return 0;
				off = inm_nla_u8(buf, off, cap,
						 IFLA_GRE_ERSPAN_DIR, 0);
				if (!off) return 0;
			}
		}
		return off;
	}

	if (k == INM_KIND_VXLAN) {
		off = inm_nla_u32(buf, off, cap, IFLA_VXLAN_ID,
				  (rand32() & 0xfffffU) + 1U);
		return off;
	}

	if (k == INM_KIND_GENEVE) {
		off = inm_nla_u32(buf, off, cap, IFLA_GENEVE_ID,
				  (rand32() & 0xfffffU) + 1U);
		return off;
	}

	return off;
}

/*
 * RTM_NEWLINK creating a link of @kind named @ifname with the per-kind
 * IFLA_INFO_DATA blob.  Optional NLM_F_REPLACE for the post-migration
 * changelink invocation; same envelope so we don't fork the message
 * builder per call site.
 */
static int inm_create_or_replace(int fd, const char *ifname, enum inm_kind k,
				 bool replace)
{
	unsigned char buf[INM_BUF];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	struct nlattr *li, *id;
	size_t off, li_off, id_off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   (replace ? NLM_F_REPLACE
				    : (NLM_F_CREATE | NLM_F_EXCL));
	nlh->nlmsg_seq   = next_seq();

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	off = inm_nla_str(buf, off, sizeof(buf), IFLA_IFNAME, ifname);
	if (!off) return -EIO;

	li_off = off;
	off = inm_nla(buf, off, sizeof(buf), IFLA_LINKINFO, NULL, 0);
	if (!off) return -EIO;
	off = inm_nla_str(buf, off, sizeof(buf), IFLA_INFO_KIND,
			  inm_kind_names[k]);
	if (!off) return -EIO;
	id_off = off;
	off = inm_nla(buf, off, sizeof(buf), IFLA_INFO_DATA, NULL, 0);
	if (!off) return -EIO;

	off = append_kind_info_data(buf, off, sizeof(buf), k);
	if (!off) return -EIO;

	id = (struct nlattr *)(buf + id_off);
	id->nla_len = (unsigned short)(off - id_off);
	li = (struct nlattr *)(buf + li_off);
	li->nla_len = (unsigned short)(off - li_off);

	nlh->nlmsg_len = (__u32)off;
	return inm_send_recv(fd, buf, off);
}

/*
 * RTM_SETLINK on @ifindex with IFLA_NET_NS_FD = @ns_fd.  Migrates the
 * link into the ns referred to by @ns_fd.  This is the trigger for the
 * dev_net change the upstream commit was about: subsequent changelink
 * messages issued in the target ns must use dev_net(dev) rather than a
 * stale t->net captured at create time.
 */
static int inm_setlink_netns(int fd, int ifindex, int ns_fd)
{
	unsigned char buf[128];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off;
	__u32 fdval = (__u32)ns_fd;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_SETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = next_seq();

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = ifindex;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));
	off = inm_nla(buf, off, sizeof(buf), IFLA_NET_NS_FD,
		      &fdval, sizeof(fdval));
	if (!off) return -EIO;
	nlh->nlmsg_len = (__u32)off;
	return inm_send_recv(fd, buf, off);
}

static int inm_dellink(int fd, int ifindex)
{
	unsigned char buf[64];
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
	return inm_send_recv(fd, buf, off);
}

/*
 * Snapshot the current net ns FD for setns()-back use.  Returned FD is
 * owned by the caller and must be closed.  -1 on failure.
 */
static int inm_open_self_netns(void)
{
	return open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
}

/*
 * Per-process one-shot: enter a fresh net ns for the original side and
 * cache its FD so we can setns() back to it after sibling unshare().
 * Returns true on success.  False latches ns_unsupported_ip6erspan via
 * warn_once_unsupported.
 */
static bool inm_enter_orig_ns(void)
{
	if (inm_unshared_orig)
		return true;
	if (unshare(CLONE_NEWNET) < 0) {
		warn_once_unsupported("unshare(CLONE_NEWNET)", errno);
		return false;
	}
	inm_orig_ns_fd = inm_open_self_netns();
	if (inm_orig_ns_fd < 0) {
		warn_once_unsupported("open(/proc/self/ns/net)", errno);
		return false;
	}
	inm_unshared_orig = true;
	return true;
}

bool ip6erspan_netns_migrate(struct childdata *child)
{
	int rtnl = -1, target_rtnl = -1, target_ns_fd = -1;
	enum inm_kind k;
	int ifindex = 0;
	int rc;
	char ifname[IFNAMSIZ];

	(void)child;

	__atomic_add_fetch(&shm->stats.inm_iters, 1, __ATOMIC_RELAXED);

	if (ns_unsupported_ip6erspan)
		return true;

	if (!inm_enter_orig_ns()) {
		__atomic_add_fetch(&shm->stats.inm_eperm, 1, __ATOMIC_RELAXED);
		return true;
	}

	k = (enum inm_kind)(rand32() % (unsigned int)INM_KIND_NR);

	rtnl = inm_rtnl_open();
	if (rtnl < 0)
		goto out;

	g_iter++;
	snprintf(ifname, sizeof(ifname), "inm%u", g_iter & 0xffffU);

	rc = inm_create_or_replace(rtnl, ifname, k, false);
	if (rc != 0) {
		if (rc == -EPERM) {
			__atomic_add_fetch(&shm->stats.inm_eperm,
					   1, __ATOMIC_RELAXED);
			ns_unsupported_ip6erspan = true;
			outputerr("ip6erspan_netns_migrate: NEWLINK %s -EPERM, latching unsupported_ip6erspan\n",
				  inm_kind_names[k]);
		} else if (rc == -ENOENT || rc == -EAFNOSUPPORT ||
			   rc == -EPROTONOSUPPORT || rc == -EOPNOTSUPP) {
			unsigned int bit = 1U << k;
			__atomic_add_fetch(&shm->stats.inm_unsupported,
					   1, __ATOMIC_RELAXED);
			/* Per-kind one-shot warn so a kernel missing
			 * just (e.g.) ip6erspan doesn't suppress the
			 * other kinds. */
			if (!(g_warned_kinds & bit)) {
				g_warned_kinds |= bit;
				outputerr("ip6erspan_netns_migrate: NEWLINK kind=%s rejected (rc=%d), skipping kind\n",
					  inm_kind_names[k], rc);
			}
		}
		goto out;
	}
	__atomic_add_fetch(&shm->stats.inm_link_create_ok, 1, __ATOMIC_RELAXED);

	ifindex = (int)if_nametoindex(ifname);
	if (ifindex <= 0)
		goto out;

	/* Step (d): unshare into a sibling ns; capture its FD; setns()
	 * back to the original ns so the rtnetlink socket above (which
	 * lives in the original ns) still talks to the link. */
	if (unshare(CLONE_NEWNET) < 0) {
		warn_once_unsupported("unshare(target)", errno);
		goto teardown_orig;
	}
	target_ns_fd = inm_open_self_netns();
	if (target_ns_fd < 0) {
		warn_once_unsupported("open(target ns)", errno);
		(void)setns(inm_orig_ns_fd, CLONE_NEWNET);
		goto teardown_orig;
	}
	if (setns(inm_orig_ns_fd, CLONE_NEWNET) < 0) {
		warn_once_unsupported("setns(orig)", errno);
		close(target_ns_fd);
		target_ns_fd = -1;
		goto teardown_orig;
	}

	/* Step (e): migrate link into the target ns. */
	rc = inm_setlink_netns(rtnl, ifindex, target_ns_fd);
	if (rc != 0)
		goto teardown_orig;
	__atomic_add_fetch(&shm->stats.inm_netns_migrate_ok,
			   1, __ATOMIC_RELAXED);

	/* The link no longer lives in the original ns -- the rtnl socket
	 * above is now useless for it.  Hop into the target ns, open a
	 * fresh rtnetlink socket there, and issue NLM_F_REPLACE.  This
	 * is the call that walks the kind's ->changelink op against the
	 * post-migration dev_net(dev). */
	if (setns(target_ns_fd, CLONE_NEWNET) < 0) {
		warn_once_unsupported("setns(target)", errno);
		goto restore_orig;
	}
	target_rtnl = inm_rtnl_open();
	if (target_rtnl < 0)
		goto restore_orig;

	rc = inm_create_or_replace(target_rtnl, ifname, k, true);
	if (rc == 0) {
		__atomic_add_fetch(&shm->stats.inm_changelink_ok,
				   1, __ATOMIC_RELAXED);
	} else if (rc == -EOPNOTSUPP && !ns_unsupported_changelink) {
		ns_unsupported_changelink = true;
		outputerr("ip6erspan_netns_migrate: NLM_F_REPLACE kind=%s -EOPNOTSUPP, latching unsupported_changelink\n",
			  inm_kind_names[k]);
	}

	(void)inm_dellink(target_rtnl, ifindex);

restore_orig:
	(void)setns(inm_orig_ns_fd, CLONE_NEWNET);
	if (target_rtnl >= 0) {
		close(target_rtnl);
		target_rtnl = -1;
	}
	if (target_ns_fd >= 0) {
		close(target_ns_fd);
		target_ns_fd = -1;
	}
	/* Link lives in the now-orphaned target ns; closing the last FD
	 * on that ns triggers cleanup_net which drops the link.  Nothing
	 * more for us to do in the original ns. */
	goto out;

teardown_orig:
	if (ifindex > 0 && rtnl >= 0)
		(void)inm_dellink(rtnl, ifindex);
	if (target_rtnl >= 0)
		close(target_rtnl);
	if (target_ns_fd >= 0)
		close(target_ns_fd);
out:
	if (rtnl >= 0)
		close(rtnl);
	return true;
}
