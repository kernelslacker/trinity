/*
 * nf_conntrack_helper_churn - attach/detach in-kernel conntrack helpers and
 * rotate zones underneath a live flow.
 *
 * The bug class is the conntrack-helper lifecycle: helpers
 * (nf_conntrack_ftp, nf_conntrack_sip, nf_conntrack_h323,
 * nf_conntrack_pptp, nf_conntrack_tftp, ...) attach to an existing
 * struct nf_conn through the CTA_HELP attribute on CTNETLINK CT_NEW
 * messages, allocate a per-conntrack helper extension via
 * nf_ct_helper_ext_add(), and register expectation policies that the
 * data-path matches in nf_ct_helper().  Userspace can attach, detach
 * (CT_NEW NLM_F_REPLACE without CTA_HELP), or delete the parent
 * conntrack while the in-kernel helper is mid-walk over its
 * expectations -- expectation_register / expectation_evict /
 * helper_destroy_rcu / __nf_conntrack_helper_unregister all share the
 * net->expect_lock and the per-helper expectation lists, and the
 * RCU-deferred destroy of struct nf_conntrack_helper has historically
 * raced both the expectation-walk path (CVE-2023-39189-class
 * helper-extension UAFs) and the conntrack-extend reallocation that
 * runs when a helper extension is added after the entry has already
 * been confirmed (CVE-2024-26625-class out-of-bounds on the extend
 * region).  Conntrack zones make this materially worse: a flow whose
 * tuple lives in zone Z but whose expectation injects a child tuple
 * in a different zone exercises the per-zone hash split in
 * __nf_conntrack_find_get() under the same locks the helper
 * registration touches, and zone churn under traffic is exactly the
 * shape that surfaced the h323 expectation-refcount imbalance
 * (CVE-2025-21756-class) -- expectation lookup walks the global
 * expect-hash but the parent conntrack is keyed by zone, so a stale
 * expectation matched against a zone-rotated parent puts the helper
 * into a state the per-helper ->help() callback was never written to
 * tolerate.
 *
 * Sequence (per BUDGETED inner-loop iteration):
 *   1.  Choose a zone Z = rand() % NF_ZONE_SPREAD and an L4 protocol
 *       (TCP / UDP) and a helper name from the runtime-available mask.
 *   2.  IPCTNL_MSG_CT_NEW: insert a synthetic tuple in zone Z over
 *       loopback (src/dst ports randomised), CTA_PROTOINFO_TCP_STATE
 *       set to ESTABLISHED for TCP so the conntrack is taken seriously
 *       by the input path.  The CTA_HELP attribute carries the chosen
 *       helper name -- this is the slot that drives
 *       __nf_ct_try_assign_helper() and nf_ct_helper_ext_add().
 *   3.  IPCTNL_MSG_EXP_NEW: manually inject an expectation in zone Z'
 *       (Z' = (Z + 1) % NF_ZONE_SPREAD with low probability, otherwise
 *       Z) with CTA_EXPECT_HELP_NAME set -- exercises the
 *       expectation_insert path under net->expect_lock and the
 *       per-helper expectation list.
 *   4.  AF_INET socket; setsockopt SO_MARK = (zone-derived skb mark);
 *       sendto loopback to drive nf_conntrack_in() over the just-
 *       inserted tuple.  Error returns are benign coverage -- the
 *       conntrack lookup + helper ->help() callback already ran.
 *   5.  Race burst (also BUDGETED):
 *         a) IPCTNL_MSG_CT_DELETE on the tuple in zone Z -- races the
 *            helper expectation walk.
 *         b) setsockopt SO_MARK to a different zone-derived value and
 *            send again -- forces nf_conntrack_in() to re-resolve in
 *            a different zone slot.
 *         c) IPCTNL_MSG_CT_NEW NLM_F_REPLACE without CTA_HELP -- the
 *            mid-flow helper-detach shape.  Drives
 *            __nf_ct_helper_destroy() while the expectation list may
 *            still have an entry pointing at the helper extension.
 *   6.  close all fds.
 *
 * Brick-safety: nfnetlink + AF_INET on loopback only.  No module
 * load, no sysfs writes, no persistent state outside per-process
 * socket fds.  Synthetic conntrack entries are GC'd by the kernel's
 * timeout (we set CTA_TIMEOUT to a small value so the kernel cleans
 * up even if we fail to send the CT_DELETE).  All netlink sends
 * MSG_DONTWAIT, all recvs SO_RCVTIMEO=1s so a stuck controller
 * cannot pin past child.c's SIGALRM(1s).
 *
 * Cap-gate latch behaviour: the first invocation per process probes
 * NETLINK_NETFILTER socket open, then sends a minimal IPCTNL_MSG_CT_NEW
 * to verify the kernel exposes CTNETLINK at all.  If the probe yields
 * -EPROTONOSUPPORT / -EOPNOTSUPP (CONFIG_NF_CONNTRACK_NETLINK=n) the
 * latch fires and every subsequent invocation just bumps setup_failed
 * and returns -- mirrors the g_handshake_resolved pattern from
 * handshake-req-abort.  Helper availability is probed lazily via the
 * first attach attempt for each helper name; helpers absent from the
 * kernel's helper table return -EOPNOTSUPP and the per-name bit in
 * helper_available_mask stays clear for the rest of the child's
 * lifetime.
 *
 * Header gating: <linux/netfilter/nfnetlink.h> +
 * <linux/netfilter/nfnetlink_conntrack.h> via __has_include().  Older
 * sysroots without either fall to a stub that bumps runs +
 * setup_failed -- same shape as handshake-req-abort and mptcp-pm-churn.
 *
 * Failure modes treated as benign coverage:
 *   - CTNETLINK absent: latched, every subsequent call short-circuits.
 *   - EOPNOTSUPP on CTA_HELP: helper module not loaded.  Per-name bit
 *     cleared and we skip that helper.  Other helpers may still work.
 *   - EEXIST on CT_NEW: the synthetic tuple already exists from a
 *     prior iteration in the same zone.  Counted as insert_ok because
 *     the lookup + collision-detection path ran end-to-end.
 *   - ENOENT on CT_DELETE / EXP_NEW: the parent conntrack was already
 *     reaped or the expectation tuple doesn't match any pending
 *     master.  The lookup ran -- benign.
 *   - EPERM on any nfnl op: insufficient capabilities in this netns.
 *     The validation path still ran on the front door.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "child.h"
#include "shm.h"
#include "trinity.h"

#if __has_include(<linux/netfilter/nfnetlink.h>) && \
    __has_include(<linux/netfilter/nfnetlink_conntrack.h>)

#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>

#include "jitter.h"
#include "random.h"

/*
 * UAPI fallbacks.  Older sysroots may have nfnetlink.h but be missing
 * a few of these constants; keep us building cleanly.  IDs come from
 * the in-tree UAPI and have been stable for many years.
 */
#ifndef NFNETLINK_V0
#define NFNETLINK_V0			0
#endif
#ifndef NFNL_SUBSYS_CTNETLINK
#define NFNL_SUBSYS_CTNETLINK		1
#endif
#ifndef NFNL_SUBSYS_CTNETLINK_EXP
#define NFNL_SUBSYS_CTNETLINK_EXP	2
#endif
#ifndef NLA_F_NESTED
#define NLA_F_NESTED			(1 << 15)
#endif
#ifndef NLA_F_NET_BYTEORDER
#define NLA_F_NET_BYTEORDER		(1 << 14)
#endif

/* IPS_* status bits used in the synthetic CT entry.  Values from
 * include/uapi/linux/netfilter/nf_conntrack_common.h. */
#ifndef IPS_CONFIRMED
#define IPS_CONFIRMED			(1U << 3)
#endif
#ifndef IPS_ASSURED
#define IPS_ASSURED			(1U << 2)
#endif

/* TCP conntrack state used in CTA_PROTOINFO_TCP_STATE.  Value from
 * include/uapi/linux/netfilter/nf_conntrack_tcp.h. */
#ifndef TCP_CONNTRACK_ESTABLISHED
#define TCP_CONNTRACK_ESTABLISHED	3
#endif

/* Per-process latched gate: CTNETLINK probe failed (kernel was built
 * without CONFIG_NF_CONNTRACK_NETLINK, or the netfilter module set
 * isn't loaded).  Once latched, every subsequent invocation just
 * bumps setup_failed and returns. */
static bool ns_unsupported_nf_conntrack_helper;

/* Per-process probe-once latch.  False until the first invocation has
 * confirmed (or rejected) CTNETLINK availability via a minimal CT_NEW
 * round-trip.  Kept independent of the unsupported flag so the probe
 * cost is paid exactly once. */
static bool ctnetlink_probed;

/* Per-process running netlink seq.  Each child has its own socket so
 * cross-process seq overlap is harmless; the kernel doesn't dedupe
 * across sockets. */
static __u32 g_nfct_seq;

/* Helper names we know about.  Order matches helper_available_mask
 * bit positions.  Each name corresponds to an in-kernel helper module
 * (nf_conntrack_ftp.ko / nf_conntrack_sip.ko / etc).  Names are ASCIIZ
 * and bounded by NF_CT_HELPER_NAME_LEN (16) on the kernel side.
 *
 * "ftp" is the canonical TCP helper, "sip"/"tftp" the canonical UDP
 * helpers; "h323"/"pptp" round out the set with their own protocol
 * shapes.  The CV class includes h323 specifically because its
 * expectation refcount path was the most recent to surface a UAF. */
static const char * const helper_names[] = {
	"ftp",
	"sip",
	"pptp",
	"tftp",
	"h323",
};
#define NUM_HELPERS	(sizeof(helper_names) / sizeof(helper_names[0]))

/* L4 proto each helper expects on its master tuple.  ftp/h323/pptp are
 * TCP-bound; sip/tftp are UDP-bound.  Mismatching the L4 proto here
 * just makes the kernel reject the helper attach with -EINVAL, which
 * is benign coverage but wastes the iteration. */
static const __u8 helper_l4proto[NUM_HELPERS] = {
	IPPROTO_TCP,	/* ftp  */
	IPPROTO_UDP,	/* sip  */
	IPPROTO_TCP,	/* pptp */
	IPPROTO_UDP,	/* tftp */
	IPPROTO_TCP,	/* h323 */
};

/* Bitmask of helpers known to be available on this kernel.  Bit N is
 * set after the first successful CT_NEW with CTA_HELP=helper_names[N];
 * cleared on -EOPNOTSUPP / -EINVAL (helper module not loaded).  Both
 * states stick for the rest of the child's lifetime -- module load
 * state is static.  Initial value: all bits set (probe optimistically
 * on the first iteration through each helper). */
static unsigned int helper_available_mask = (1U << NUM_HELPERS) - 1U;

/* Per-helper exhaustion latch: set once we've definitively seen the
 * kernel reject this helper with EOPNOTSUPP/EPROTONOSUPPORT.  Used to
 * stop bumping the available bit back on -- a single attach failure
 * with one of those errnos is the canonical "module not loaded"
 * signal. */
static unsigned int helper_unavailable_mask;

#define NF_ZONE_SPREAD			8U	/* zones rotated through */
#define NFCT_BUF_BYTES			1024
#define NFCT_RECV_TIMEO_S		1
#define NFCT_LOOP_BUDGET		16U
#define NFCT_LOOP_ITERS_BASE		2U
#define NFCT_RACE_BUDGET		16U
#define NFCT_RACE_ITERS_BASE		2U
#define NFCT_DEFAULT_TIMEOUT		10	/* seconds; kernel GC backstop */

/* Loopback target; the per-iter src/dst port are randomised inside
 * iter_one().  127.0.0.1 keeps every escaped packet trivially
 * identifiable in tcpdump during triage. */
#define NFCT_LOOPBACK_ADDR		0x7f000001U

static __u32 next_seq(void)
{
	return ++g_nfct_seq;
}

static int nfnl_open(void)
{
	struct sockaddr_nl sa;
	struct timeval tv;
	int fd;

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER);
	if (fd < 0)
		return -1;

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(fd);
		return -1;
	}

	tv.tv_sec  = NFCT_RECV_TIMEO_S;
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

static size_t nla_put_be16(unsigned char *buf, size_t off, size_t cap,
			   unsigned short type, __u16 v)
{
	__u16 be = htons(v);

	return nla_put(buf, off, cap,
		       type | NLA_F_NET_BYTEORDER, &be, sizeof(be));
}

static size_t nla_put_be32(unsigned char *buf, size_t off, size_t cap,
			   unsigned short type, __u32 v)
{
	__u32 be = htonl(v);

	return nla_put(buf, off, cap,
		       type | NLA_F_NET_BYTEORDER, &be, sizeof(be));
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

/*
 * nfnetlink message header skeleton: nlmsghdr (with type encoded as
 * (subsys << 8) | msg_id) followed by an nfgenmsg carrying the family
 * and version.  The res_id field carries CTA_ZONE for messages that
 * scope to a zone (CT_NEW / CT_DELETE).  Caller fills attrs after
 * the returned offset.
 */
struct nfgenmsg_local {
	__u8  nfgen_family;
	__u8  version;
	__u16 res_id;	/* network byte order */
};

static size_t nfnl_hdr(unsigned char *buf, __u8 subsys, __u16 msg_id,
		       __u16 flags, __u8 family, __u16 res_id)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct nfgenmsg_local *nfg;

	nlh->nlmsg_type  = (__u16)((subsys << 8) | (msg_id & 0xff));
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | flags;
	nlh->nlmsg_seq   = next_seq();

	nfg = (struct nfgenmsg_local *)NLMSG_DATA(nlh);
	nfg->nfgen_family = family;
	nfg->version      = NFNETLINK_V0;
	nfg->res_id       = htons(res_id);

	return NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*nfg));
}

static void nfnl_finalize(unsigned char *buf, size_t off)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;

	nlh->nlmsg_len = (__u32)off;
}

/*
 * Send and consume one ack.  Returns 0 on positive ack, the negated
 * kernel errno on rejection, or -EIO on local sendmsg/recv failure.
 */
static int nfnl_send_recv(int fd, void *msg, size_t len)
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

	if (sendmsg(fd, &mh, MSG_DONTWAIT) < 0)
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
	return 0;
}

/*
 * Append a CTA_TUPLE_{ORIG,REPLY,MASTER} nested attribute carrying the
 * (saddr, daddr, l4proto, sport, dport) tuple.  All four-tuple fields
 * are big-endian on the wire.  Returns the new offset or 0 on overflow.
 */
static size_t put_tuple(unsigned char *buf, size_t off, size_t cap,
			unsigned short tuple_type,
			__u32 saddr, __u32 daddr,
			__u8 l4proto, __u16 sport, __u16 dport)
{
	struct nlattr *outer, *ip, *proto;
	size_t outer_off, ip_off, proto_off;

	outer_off = off;
	off = nla_put(buf, off, cap, tuple_type | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	/* CTA_TUPLE_IP nested */
	ip_off = off;
	off = nla_put(buf, off, cap, CTA_TUPLE_IP | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, CTA_IP_V4_SRC, saddr);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, CTA_IP_V4_DST, daddr);
	if (!off)
		return 0;
	ip = (struct nlattr *)(buf + ip_off);
	ip->nla_len = (unsigned short)(off - ip_off);

	/* CTA_TUPLE_PROTO nested */
	proto_off = off;
	off = nla_put(buf, off, cap, CTA_TUPLE_PROTO | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;
	off = nla_put_u8(buf, off, cap, CTA_PROTO_NUM, l4proto);
	if (!off)
		return 0;
	if (l4proto == IPPROTO_TCP || l4proto == IPPROTO_UDP) {
		off = nla_put_be16(buf, off, cap, CTA_PROTO_SRC_PORT, sport);
		if (!off)
			return 0;
		off = nla_put_be16(buf, off, cap, CTA_PROTO_DST_PORT, dport);
		if (!off)
			return 0;
	}
	proto = (struct nlattr *)(buf + proto_off);
	proto->nla_len = (unsigned short)(off - proto_off);

	outer = (struct nlattr *)(buf + outer_off);
	outer->nla_len = (unsigned short)(off - outer_off);
	return off;
}

/*
 * Append a CTA_HELP nested attribute carrying CTA_HELP_NAME=name.
 * Drives __nf_ct_try_assign_helper() / nf_ct_helper_ext_add() on the
 * receiving conntrack.  Returns the new offset or 0 on overflow.
 */
static size_t put_help(unsigned char *buf, size_t off, size_t cap,
		       const char *helper_name)
{
	struct nlattr *outer;
	size_t outer_off;

	outer_off = off;
	off = nla_put(buf, off, cap, CTA_HELP | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;
	off = nla_put_str(buf, off, cap, CTA_HELP_NAME, helper_name);
	if (!off)
		return 0;
	outer = (struct nlattr *)(buf + outer_off);
	outer->nla_len = (unsigned short)(off - outer_off);
	return off;
}

/*
 * Append a CTA_PROTOINFO_TCP nested attribute fixing the conntrack
 * TCP state to ESTABLISHED.  Without this the kernel may reject a
 * synthetic CT_NEW for a TCP tuple that doesn't carry plausible state.
 */
static size_t put_protoinfo_tcp_established(unsigned char *buf, size_t off,
					    size_t cap)
{
	struct nlattr *outer, *tcp;
	size_t outer_off, tcp_off;

	outer_off = off;
	off = nla_put(buf, off, cap, CTA_PROTOINFO | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	tcp_off = off;
	off = nla_put(buf, off, cap,
		      CTA_PROTOINFO_TCP | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;
	off = nla_put_u8(buf, off, cap,
			 CTA_PROTOINFO_TCP_STATE, TCP_CONNTRACK_ESTABLISHED);
	if (!off)
		return 0;
	tcp = (struct nlattr *)(buf + tcp_off);
	tcp->nla_len = (unsigned short)(off - tcp_off);

	outer = (struct nlattr *)(buf + outer_off);
	outer->nla_len = (unsigned short)(off - outer_off);
	return off;
}

/*
 * Build & send IPCTNL_MSG_CT_NEW carrying CTA_TUPLE_ORIG +
 * CTA_TUPLE_REPLY + CTA_ZONE + CTA_TIMEOUT + (optionally) CTA_HELP +
 * (TCP only) CTA_PROTOINFO.  helper_name == NULL omits CTA_HELP --
 * combined with NLM_F_REPLACE this is the helper-detach shape.
 */
static int build_ct_new(int fd, __u16 zone, __u8 l4proto,
			__u16 sport, __u16 dport,
			const char *helper_name, __u16 extra_flags)
{
	unsigned char buf[NFCT_BUF_BYTES];
	__u32 timeout_be;
	__u32 status_be;
	size_t off;

	memset(buf, 0, sizeof(buf));
	off = nfnl_hdr(buf, NFNL_SUBSYS_CTNETLINK, IPCTNL_MSG_CT_NEW,
		       NLM_F_CREATE | extra_flags, AF_INET, zone);

	off = put_tuple(buf, off, sizeof(buf), CTA_TUPLE_ORIG,
			NFCT_LOOPBACK_ADDR, NFCT_LOOPBACK_ADDR,
			l4proto, sport, dport);
	if (!off)
		return -EIO;
	off = put_tuple(buf, off, sizeof(buf), CTA_TUPLE_REPLY,
			NFCT_LOOPBACK_ADDR, NFCT_LOOPBACK_ADDR,
			l4proto, dport, sport);
	if (!off)
		return -EIO;

	off = nla_put_be16(buf, off, sizeof(buf), CTA_ZONE, zone);
	if (!off)
		return -EIO;

	timeout_be = htonl((__u32)NFCT_DEFAULT_TIMEOUT);
	off = nla_put(buf, off, sizeof(buf),
		      CTA_TIMEOUT | NLA_F_NET_BYTEORDER,
		      &timeout_be, sizeof(timeout_be));
	if (!off)
		return -EIO;

	status_be = htonl(IPS_CONFIRMED | IPS_ASSURED);
	off = nla_put(buf, off, sizeof(buf),
		      CTA_STATUS | NLA_F_NET_BYTEORDER,
		      &status_be, sizeof(status_be));
	if (!off)
		return -EIO;

	if (l4proto == IPPROTO_TCP) {
		off = put_protoinfo_tcp_established(buf, off, sizeof(buf));
		if (!off)
			return -EIO;
	}

	if (helper_name) {
		off = put_help(buf, off, sizeof(buf), helper_name);
		if (!off)
			return -EIO;
	}

	nfnl_finalize(buf, off);
	return nfnl_send_recv(fd, buf, off);
}

/*
 * Build & send IPCTNL_MSG_CT_DELETE on (zone, l4proto, sport, dport).
 * The kernel walks the zone-scoped conntrack hash for a tuple match
 * and tears it down; ENOENT is the bulk case when the tuple has
 * already been GC'd.
 */
static int build_ct_delete(int fd, __u16 zone, __u8 l4proto,
			   __u16 sport, __u16 dport)
{
	unsigned char buf[NFCT_BUF_BYTES];
	size_t off;

	memset(buf, 0, sizeof(buf));
	off = nfnl_hdr(buf, NFNL_SUBSYS_CTNETLINK, IPCTNL_MSG_CT_DELETE,
		       0, AF_INET, zone);

	off = put_tuple(buf, off, sizeof(buf), CTA_TUPLE_ORIG,
			NFCT_LOOPBACK_ADDR, NFCT_LOOPBACK_ADDR,
			l4proto, sport, dport);
	if (!off)
		return -EIO;

	off = nla_put_be16(buf, off, sizeof(buf), CTA_ZONE, zone);
	if (!off)
		return -EIO;

	nfnl_finalize(buf, off);
	return nfnl_send_recv(fd, buf, off);
}

/*
 * Build & send IPCTNL_MSG_EXP_NEW manually injecting an expectation
 * keyed on (master_zone, master tuple) with the expected child tuple
 * in (exp_zone, child tuple).  The CTA_EXPECT_HELP_NAME ties the
 * expectation to the named helper.  Drives nf_ct_expect_insert()
 * under net->expect_lock and the per-helper expectation list.
 */
static int build_exp_new(int fd, __u16 master_zone, __u16 exp_zone,
			 __u8 l4proto, __u16 master_sport, __u16 master_dport,
			 __u16 child_sport, __u16 child_dport,
			 const char *helper_name)
{
	unsigned char buf[NFCT_BUF_BYTES];
	__u32 timeout_be;
	__u32 flags_be;
	size_t off;

	memset(buf, 0, sizeof(buf));
	off = nfnl_hdr(buf, NFNL_SUBSYS_CTNETLINK_EXP, IPCTNL_MSG_EXP_NEW,
		       NLM_F_CREATE, AF_INET, exp_zone);

	off = put_tuple(buf, off, sizeof(buf), CTA_EXPECT_TUPLE,
			NFCT_LOOPBACK_ADDR, NFCT_LOOPBACK_ADDR,
			l4proto, child_sport, child_dport);
	if (!off)
		return -EIO;

	/* Mask: all-ones for the address fields; tells the kernel to
	 * match the full 5-tuple on the expected child. */
	off = put_tuple(buf, off, sizeof(buf), CTA_EXPECT_MASK,
			0xffffffffU, 0xffffffffU,
			l4proto, 0xffff, 0xffff);
	if (!off)
		return -EIO;

	off = put_tuple(buf, off, sizeof(buf), CTA_EXPECT_MASTER,
			NFCT_LOOPBACK_ADDR, NFCT_LOOPBACK_ADDR,
			l4proto, master_sport, master_dport);
	if (!off)
		return -EIO;

	timeout_be = htonl((__u32)NFCT_DEFAULT_TIMEOUT);
	off = nla_put(buf, off, sizeof(buf),
		      CTA_EXPECT_TIMEOUT | NLA_F_NET_BYTEORDER,
		      &timeout_be, sizeof(timeout_be));
	if (!off)
		return -EIO;

	flags_be = htonl(0);
	off = nla_put(buf, off, sizeof(buf),
		      CTA_EXPECT_FLAGS | NLA_F_NET_BYTEORDER,
		      &flags_be, sizeof(flags_be));
	if (!off)
		return -EIO;

	off = nla_put_str(buf, off, sizeof(buf),
			  CTA_EXPECT_HELP_NAME, helper_name);
	if (!off)
		return -EIO;

	off = nla_put_be16(buf, off, sizeof(buf), CTA_EXPECT_ZONE, exp_zone);
	if (!off)
		return -EIO;

	(void)master_zone;	/* master tuple is keyed by its own zone via
				 * the existing parent conntrack lookup;
				 * exp_zone is what scopes the expectation. */

	nfnl_finalize(buf, off);
	return nfnl_send_recv(fd, buf, off);
}

/*
 * One-time CTNETLINK availability probe.  Sends a minimal CT_NEW for a
 * disposable tuple in zone 0 and inspects the ack: anything other than
 * EPROTONOSUPPORT/EOPNOTSUPP is treated as "kernel has CTNETLINK".
 * Sets ns_unsupported_nf_conntrack_helper on hard absence so subsequent
 * invocations short-circuit.
 */
static void probe_ctnetlink(int fd)
{
	int rc;

	rc = build_ct_new(fd, 0, IPPROTO_UDP,
			  (__u16)(40000 + (rand32() & 0x3ff)),
			  (__u16)(50000 + (rand32() & 0x3ff)),
			  NULL, 0);
	ctnetlink_probed = true;

	if (rc == -EPROTONOSUPPORT || rc == -EOPNOTSUPP || rc == -EAFNOSUPPORT)
		ns_unsupported_nf_conntrack_helper = true;
}

/*
 * Open a loopback AF_INET socket of the given proto and best-effort
 * sendto a small payload at (NFCT_LOOPBACK_ADDR, dport).  SO_MARK is
 * set to the zone-derived value so packets land in the right
 * conntrack zone via the kernel's mark-based zone classifier.  Returns
 * the socket fd (already used) so the caller can close it; a negative
 * return means socket() failed.
 */
static int loopback_drive(__u8 l4proto, __u16 dport, __u32 mark)
{
	struct sockaddr_in dst;
	const char payload[] = "trinity-nfct-helper-churn-payload";
	int fd;
	int sotype = (l4proto == IPPROTO_TCP) ? SOCK_STREAM : SOCK_DGRAM;

	fd = socket(AF_INET, sotype | SOCK_CLOEXEC, l4proto);
	if (fd < 0)
		return -1;

	(void)fcntl(fd, F_SETFL, O_NONBLOCK);
	(void)setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));

	memset(&dst, 0, sizeof(dst));
	dst.sin_family = AF_INET;
	dst.sin_addr.s_addr = htonl(NFCT_LOOPBACK_ADDR);
	dst.sin_port = htons(dport);

	if (l4proto == IPPROTO_TCP)
		(void)connect(fd, (struct sockaddr *)&dst, sizeof(dst));

	(void)sendto(fd, payload, sizeof(payload) - 1, MSG_DONTWAIT,
		     (struct sockaddr *)&dst, sizeof(dst));
	return fd;
}

/*
 * Pick an available helper index, or -1 if the runtime mask is empty.
 * Random pick over the set bits keeps the rotation roughly even
 * across helpers without the bias a modulo over NUM_HELPERS would
 * introduce when only a few helpers are loaded.
 */
static int pick_helper(void)
{
	unsigned int mask = helper_available_mask & ~helper_unavailable_mask;
	unsigned int popcount = (unsigned int)__builtin_popcount(mask);
	unsigned int pick;
	unsigned int i;
	unsigned int seen = 0;

	if (popcount == 0)
		return -1;

	pick = rand32() % popcount;
	for (i = 0; i < NUM_HELPERS; i++) {
		if (!(mask & (1U << i)))
			continue;
		if (seen == pick)
			return (int)i;
		seen++;
	}
	return -1;
}

/*
 * Fold a CT_NEW ack into the per-helper availability mask.  Treat
 * EOPNOTSUPP / EPROTONOSUPPORT / EINVAL as "this helper isn't
 * registered with the kernel" and latch the unavailable bit; treat
 * any other ack (including success, EEXIST, EPERM) as "the helper
 * exists; some other validation failed".
 */
static void update_helper_mask(int helper_idx, int rc)
{
	if (helper_idx < 0)
		return;
	if (rc == -EOPNOTSUPP || rc == -EPROTONOSUPPORT || rc == -EINVAL) {
		helper_unavailable_mask |= (1U << (unsigned)helper_idx);
		helper_available_mask &= ~(1U << (unsigned)helper_idx);
	}
}

/*
 * One outer iteration: pick zone + helper, insert master conntrack +
 * expectation, drive a packet through, then run a small race burst
 * (delete / zone-swap / detach).  Returns true on every path; the
 * stats counters carry the per-step success signal.
 */
static void iter_one(int fd)
{
	__u16 zone, alt_zone;
	__u16 sport, dport;
	__u16 child_sport, child_dport;
	int helper_idx;
	const char *helper_name;
	__u8 l4proto;
	int rc;
	int drive_fd;
	unsigned int races, r;

	helper_idx = pick_helper();
	if (helper_idx < 0) {
		__atomic_add_fetch(&shm->stats.nf_conntrack_helper_churn_no_helper,
				   1, __ATOMIC_RELAXED);
		return;
	}
	helper_name = helper_names[helper_idx];
	l4proto = helper_l4proto[helper_idx];

	zone     = (__u16)(rand32() % NF_ZONE_SPREAD);
	alt_zone = (__u16)((zone + 1U + (rand32() % (NF_ZONE_SPREAD - 1U)))
			   % NF_ZONE_SPREAD);

	sport = (__u16)(20000 + (rand32() & 0x1fff));
	dport = (__u16)(40000 + (rand32() & 0x1fff));
	child_sport = (__u16)(30000 + (rand32() & 0x1fff));
	child_dport = (__u16)(50000 + (rand32() & 0x1fff));

	/* 2) CT_NEW with CTA_HELP -- the helper-attach path.  EEXIST is
	 *    benign coverage (lookup + collision-detection ran).  */
	rc = build_ct_new(fd, zone, l4proto, sport, dport, helper_name, 0);
	update_helper_mask(helper_idx, rc);
	if (rc == 0 || rc == -EEXIST) {
		__atomic_add_fetch(&shm->stats.nf_conntrack_helper_churn_attach_ok,
				   1, __ATOMIC_RELAXED);
	} else {
		__atomic_add_fetch(&shm->stats.nf_conntrack_helper_churn_attach_fail,
				   1, __ATOMIC_RELAXED);
	}

	/* 3) EXP_NEW -- expectation injection.  Half the time put the
	 *    child in a different zone than the master to exercise the
	 *    cross-zone expectation-vs-conntrack split. */
	{
		__u16 exp_zone = (rand32() & 1U) ? alt_zone : zone;

		rc = build_exp_new(fd, zone, exp_zone, l4proto,
				   sport, dport, child_sport, child_dport,
				   helper_name);
		if (rc == 0) {
			__atomic_add_fetch(&shm->stats.nf_conntrack_helper_churn_exp_ok,
					   1, __ATOMIC_RELAXED);
		}
	}

	/* 4) Drive a packet through loopback to fire nf_conntrack_in()
	 *    and the helper's ->help() callback. */
	drive_fd = loopback_drive(l4proto, dport,
				  0xc0de0000U | (__u32)zone);
	if (drive_fd >= 0) {
		__atomic_add_fetch(&shm->stats.nf_conntrack_helper_churn_packet_sent,
				   1, __ATOMIC_RELAXED);
		close(drive_fd);
	}

	/* 5) Race burst: BUDGETED inner loop alternating delete /
	 *    zone-swap / mid-flow detach.  Each step targets a distinct
	 *    helper-lifecycle race window. */
	races = BUDGETED(CHILD_OP_NF_CONNTRACK_HELPER, NFCT_RACE_ITERS_BASE);
	if (races > NFCT_RACE_BUDGET)
		races = NFCT_RACE_BUDGET;
	if (races == 0U)
		races = 1U;

	for (r = 0; r < races; r++) {
		/* a) CT_DELETE in the master's zone -- races the helper's
		 *    expectation walk. */
		rc = build_ct_delete(fd, zone, l4proto, sport, dport);
		if (rc == 0)
			__atomic_add_fetch(&shm->stats.nf_conntrack_helper_churn_delete_ok,
					   1, __ATOMIC_RELAXED);

		/* b) Zone-swap drive: re-send into a different zone via
		 *    SO_MARK.  Forces a re-resolve in alt_zone's hash slot
		 *    while the prior delete may still be in-flight on the
		 *    RCU grace period. */
		drive_fd = loopback_drive(l4proto, dport,
					  0xc0de0000U | (__u32)alt_zone);
		if (drive_fd >= 0) {
			__atomic_add_fetch(&shm->stats.nf_conntrack_helper_churn_zone_swap,
					   1, __ATOMIC_RELAXED);
			close(drive_fd);
		}

		/* c) Mid-flow helper detach: CT_NEW with NLM_F_REPLACE,
		 *    no CTA_HELP.  Drives __nf_ct_helper_destroy() while
		 *    the expectation list may still hold an entry. */
		rc = build_ct_new(fd, zone, l4proto, sport, dport,
				  NULL, NLM_F_REPLACE);
		if (rc == 0)
			__atomic_add_fetch(&shm->stats.nf_conntrack_helper_churn_detach_ok,
					   1, __ATOMIC_RELAXED);
	}
}

bool nf_conntrack_helper_churn(struct childdata *child)
{
	int nfnl_fd;
	unsigned int outer_iters, i;

	(void)child;

	__atomic_add_fetch(&shm->stats.nf_conntrack_helper_churn_runs,
			   1, __ATOMIC_RELAXED);

	if (ns_unsupported_nf_conntrack_helper) {
		__atomic_add_fetch(&shm->stats.nf_conntrack_helper_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	nfnl_fd = nfnl_open();
	if (nfnl_fd < 0) {
		__atomic_add_fetch(&shm->stats.nf_conntrack_helper_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (!ctnetlink_probed) {
		probe_ctnetlink(nfnl_fd);
		if (ns_unsupported_nf_conntrack_helper) {
			__atomic_add_fetch(&shm->stats.nf_conntrack_helper_churn_setup_failed,
					   1, __ATOMIC_RELAXED);
			close(nfnl_fd);
			return true;
		}
	}

	outer_iters = BUDGETED(CHILD_OP_NF_CONNTRACK_HELPER,
			       JITTER_RANGE(NFCT_LOOP_ITERS_BASE));
	if (outer_iters > NFCT_LOOP_BUDGET)
		outer_iters = NFCT_LOOP_BUDGET;
	if (outer_iters == 0U)
		outer_iters = 1U;

	for (i = 0; i < outer_iters; i++)
		iter_one(nfnl_fd);

	close(nfnl_fd);
	return true;
}

#else  /* !__has_include(<linux/netfilter/nfnetlink_conntrack.h>) */

bool nf_conntrack_helper_churn(struct childdata *child)
{
	(void)child;
	__atomic_add_fetch(&shm->stats.nf_conntrack_helper_churn_runs,
			   1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.nf_conntrack_helper_churn_setup_failed,
			   1, __ATOMIC_RELAXED);
	return true;
}

#endif /* __has_include(<linux/netfilter/nfnetlink_conntrack.h>) */
