/*
 * nf_conntrack_helper_churn - attach/detach in-kernel conntrack helpers and
 * rotate zones underneath a live flow.
 *
 * Bug class: the conntrack-helper lifecycle in net/netfilter/nf_conntrack_*.
 * Helpers attach via CTA_HELP on CTNETLINK CT_NEW, allocate a per-nf_conn
 * extension via nf_ct_helper_ext_add(), and register expectation policies.
 * expectation_register / evict / helper_destroy_rcu /
 * __nf_conntrack_helper_unregister share net->expect_lock and the
 * per-helper expect lists, and the RCU-deferred helper destroy has raced
 * both the expectation walker (CVE-2023-39189 helper-ext UAFs) and the
 * conntrack-extend realloc that runs when a helper extension is added
 * post-confirm (CVE-2024-26625 OOB).  Conntrack zones sharpen it: expect
 * lookup walks the global expect-hash but the parent nf_conn is zone-keyed,
 * so a stale expectation against a zone-rotated parent puts the helper in
 * a state ->help() was never written to tolerate (CVE-2025-21756 h323 refct
 * imbalance shape).
 *
 * Per BUDGETED iteration: pick zone Z in [0, NF_ZONE_SPREAD), an L4 proto,
 * and a helper name from the runtime-available mask; CT_NEW inserts a
 * synthetic tuple in Z with CTA_HELP (drives __nf_ct_try_assign_helper +
 * nf_ct_helper_ext_add); EXP_NEW injects an expectation in Z' (usually Z,
 * occasionally (Z+1)%SPREAD) with CTA_EXPECT_HELP_NAME; AF_INET sendto with
 * a zone-derived SO_MARK drives nf_conntrack_in over the tuple.  Race burst:
 * CT_DELETE the tuple, flip SO_MARK to force re-resolve in a different zone
 * slot, then CT_NEW NLM_F_REPLACE without CTA_HELP (mid-flow helper detach:
 * __nf_ct_helper_destroy while the expect list may still point at the
 * helper extension).
 *
 * Brick-safety: nfnetlink + AF_INET on loopback only; no modprobe, no
 * sysfs, no persistent state outside process fds.  CTA_TIMEOUT is set small
 * so the kernel GC reaps synthetic entries even if CT_DELETE never sends.
 * All netlink sends MSG_DONTWAIT, recvs SO_RCVTIMEO=1s so a stuck
 * controller can't pin past child.c's SIGALRM(1s).
 *
 * Latches (per-process): probe latches on NETLINK_NETFILTER + minimal
 * IPCTNL_MSG_CT_NEW returning -EPROTONOSUPPORT / -EOPNOTSUPP
 * (CONFIG_NF_CONNTRACK_NETLINK=n); subsequent invocations bump setup_failed
 * and return.  helper_available_mask is a per-name bit cleared lazily on
 * first -EOPNOTSUPP for that helper name (module not loaded); other
 * helpers keep working.  EPERM / ENOENT / EEXIST are counted as benign
 * coverage -- the validation path ran.
 *
 * Header-gated by __has_include() on linux/netfilter/nfnetlink.h and
 * linux/netfilter/nfnetlink_conntrack.h; missing headers fall to a stub.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#include "child.h"
#include "shm.h"
#include "trinity.h"

#if __has_include(<linux/netfilter/nfnetlink.h>) && \
    __has_include(<linux/netfilter/nfnetlink_conntrack.h>)

#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>

#include "childops-netlink.h"
#include "childops-nfnl.h"
#include "jitter.h"
#include "random.h"

#include "kernel/socket.h"
/*
 * UAPI fallbacks.  Older sysroots may have nfnetlink.h but be missing
 * a few of these constants; keep us building cleanly.  IDs come from
 * the in-tree UAPI and have been stable for many years.
 */
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
	size_t outer_off, ip_off, proto_off;

	outer_off = off;
	off = nla_nest_start(buf, off, cap, tuple_type | NLA_F_NESTED);
	if (!off)
		return 0;

	/* CTA_TUPLE_IP nested */
	ip_off = off;
	off = nla_nest_start(buf, off, cap, CTA_TUPLE_IP | NLA_F_NESTED);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, CTA_IP_V4_SRC, saddr);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, CTA_IP_V4_DST, daddr);
	if (!off)
		return 0;
	nla_nest_end(buf, ip_off, off);

	/* CTA_TUPLE_PROTO nested */
	proto_off = off;
	off = nla_nest_start(buf, off, cap, CTA_TUPLE_PROTO | NLA_F_NESTED);
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
	nla_nest_end(buf, proto_off, off);
	nla_nest_end(buf, outer_off, off);
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
	size_t outer_off;

	outer_off = off;
	off = nla_nest_start(buf, off, cap, CTA_HELP | NLA_F_NESTED);
	if (!off)
		return 0;
	off = nla_put_str(buf, off, cap, CTA_HELP_NAME, helper_name);
	if (!off)
		return 0;
	nla_nest_end(buf, outer_off, off);
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
	size_t outer_off, tcp_off;

	outer_off = off;
	off = nla_nest_start(buf, off, cap, CTA_PROTOINFO | NLA_F_NESTED);
	if (!off)
		return 0;

	tcp_off = off;
	off = nla_nest_start(buf, off, cap,
			     CTA_PROTOINFO_TCP | NLA_F_NESTED);
	if (!off)
		return 0;
	off = nla_put_u8(buf, off, cap,
			 CTA_PROTOINFO_TCP_STATE, TCP_CONNTRACK_ESTABLISHED);
	if (!off)
		return 0;
	nla_nest_end(buf, tcp_off, off);
	nla_nest_end(buf, outer_off, off);
	return off;
}

/*
 * Build & send IPCTNL_MSG_CT_NEW carrying CTA_TUPLE_ORIG +
 * CTA_TUPLE_REPLY + CTA_ZONE + CTA_TIMEOUT + (optionally) CTA_HELP +
 * (TCP only) CTA_PROTOINFO.  helper_name == NULL omits CTA_HELP --
 * combined with NLM_F_REPLACE this is the helper-detach shape.
 */
static int build_ct_new(struct nfnl_ctx *ctx, __u16 zone, __u8 l4proto,
			__u16 sport, __u16 dport,
			const char *helper_name, __u16 extra_flags)
{
	unsigned char buf[NFCT_BUF_BYTES];
	__u32 timeout_be;
	__u32 status_be;
	size_t off;

	memset(buf, 0, sizeof(buf));
	off = nfnl_msg_put(buf, 0, sizeof(buf), nl_seq_next(&ctx->nl),
			   NFNL_SUBSYS_CTNETLINK, IPCTNL_MSG_CT_NEW,
			   NLM_F_CREATE | extra_flags, AF_INET);
	if (!off)
		return -EIO;

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

	((struct nlmsghdr *)buf)->nlmsg_len = (__u32)off;
	return nfnl_send_recv(ctx, buf, off);
}

/*
 * Build & send IPCTNL_MSG_CT_DELETE on (zone, l4proto, sport, dport).
 * The kernel walks the zone-scoped conntrack hash for a tuple match
 * and tears it down; ENOENT is the bulk case when the tuple has
 * already been GC'd.
 */
static int build_ct_delete(struct nfnl_ctx *ctx, __u16 zone, __u8 l4proto,
			   __u16 sport, __u16 dport)
{
	unsigned char buf[NFCT_BUF_BYTES];
	size_t off;

	memset(buf, 0, sizeof(buf));
	off = nfnl_msg_put(buf, 0, sizeof(buf), nl_seq_next(&ctx->nl),
			   NFNL_SUBSYS_CTNETLINK, IPCTNL_MSG_CT_DELETE,
			   0, AF_INET);
	if (!off)
		return -EIO;

	off = put_tuple(buf, off, sizeof(buf), CTA_TUPLE_ORIG,
			NFCT_LOOPBACK_ADDR, NFCT_LOOPBACK_ADDR,
			l4proto, sport, dport);
	if (!off)
		return -EIO;

	off = nla_put_be16(buf, off, sizeof(buf), CTA_ZONE, zone);
	if (!off)
		return -EIO;

	((struct nlmsghdr *)buf)->nlmsg_len = (__u32)off;
	return nfnl_send_recv(ctx, buf, off);
}

/*
 * Build & send IPCTNL_MSG_EXP_NEW manually injecting an expectation
 * keyed on (master_zone, master tuple) with the expected child tuple
 * in (exp_zone, child tuple).  The CTA_EXPECT_HELP_NAME ties the
 * expectation to the named helper.  Drives nf_ct_expect_insert()
 * under net->expect_lock and the per-helper expectation list.
 */
static int build_exp_new(struct nfnl_ctx *ctx, __u16 master_zone, __u16 exp_zone,
			 __u8 l4proto, __u16 master_sport, __u16 master_dport,
			 __u16 child_sport, __u16 child_dport,
			 const char *helper_name)
{
	unsigned char buf[NFCT_BUF_BYTES];
	__u32 timeout_be;
	__u32 flags_be;
	size_t off;

	memset(buf, 0, sizeof(buf));
	off = nfnl_msg_put(buf, 0, sizeof(buf), nl_seq_next(&ctx->nl),
			   NFNL_SUBSYS_CTNETLINK_EXP, IPCTNL_MSG_EXP_NEW,
			   NLM_F_CREATE, AF_INET);
	if (!off)
		return -EIO;

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

	((struct nlmsghdr *)buf)->nlmsg_len = (__u32)off;
	return nfnl_send_recv(ctx, buf, off);
}

/*
 * One-time CTNETLINK availability probe.  Sends a minimal CT_NEW for a
 * disposable tuple in zone 0 and inspects the ack: anything other than
 * EPROTONOSUPPORT/EOPNOTSUPP is treated as "kernel has CTNETLINK".
 * Sets ns_unsupported_nf_conntrack_helper on hard absence so subsequent
 * invocations short-circuit.
 */
static void probe_ctnetlink(struct nfnl_ctx *ctx)
{
	int rc;

	rc = build_ct_new(ctx, 0, IPPROTO_UDP,
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

	pick = rnd_modulo_u32(popcount);
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
 * Per-iteration context shared across the iter_one phase helpers.
 * `ctx` is the caller-owned nfnetlink socket; the remaining fields are
 * rolled fresh each outer iteration by nfct_helper_iter_pick and read by
 * the attach/expect/drive/race phases.
 */
struct nfct_helper_iter_ctx {
	struct nfnl_ctx	*ctx;
	int		helper_idx;
	const char	*helper_name;
	__u8		l4proto;
	__u16		zone;
	__u16		alt_zone;
	__u16		sport;
	__u16		dport;
	__u16		child_sport;
	__u16		child_dport;
};

/*
 * Phase: roll per-iteration identifiers -- pick an available helper, the
 * zone pair, and the master/child port quads.  Returns 0 on success;
 * -1 means no helper is currently available (caller bumps the no_helper
 * stat and bails -- the attach/expect/drive/race phases have nothing to
 * anchor on).
 */
static int nfct_helper_iter_pick(struct nfct_helper_iter_ctx *ictx)
{
	ictx->helper_idx = pick_helper();
	if (ictx->helper_idx < 0) {
		__atomic_add_fetch(&shm->stats.nf_conntrack_helper_churn.no_helper,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	ictx->helper_name = helper_names[ictx->helper_idx];
	ictx->l4proto = helper_l4proto[ictx->helper_idx];

	ictx->zone     = (__u16)(rand32() % NF_ZONE_SPREAD);
	ictx->alt_zone = (__u16)((ictx->zone + 1U +
				  (rand32() % (NF_ZONE_SPREAD - 1U)))
				 % NF_ZONE_SPREAD);

	ictx->sport       = (__u16)(20000 + (rand32() & 0x1fff));
	ictx->dport       = (__u16)(40000 + (rand32() & 0x1fff));
	ictx->child_sport = (__u16)(30000 + (rand32() & 0x1fff));
	ictx->child_dport = (__u16)(50000 + (rand32() & 0x1fff));

	return 0;
}

/*
 * Phase: CT_NEW with CTA_HELP -- the helper-attach path.  Folds the ack
 * into the per-helper availability mask and bumps the attach_ok /
 * attach_fail stats accordingly.  EEXIST is benign coverage (the lookup
 * + collision-detection path ran end-to-end).
 */
static void nfct_helper_iter_attach(struct nfct_helper_iter_ctx *ictx)
{
	int rc;

	rc = build_ct_new(ictx->ctx, ictx->zone, ictx->l4proto,
			  ictx->sport, ictx->dport, ictx->helper_name, 0);
	update_helper_mask(ictx->helper_idx, rc);
	if (rc == 0 || rc == -EEXIST) {
		__atomic_add_fetch(&shm->stats.nf_conntrack_helper_churn.attach_ok,
				   1, __ATOMIC_RELAXED);
	} else {
		__atomic_add_fetch(&shm->stats.nf_conntrack_helper_churn.attach_fail,
				   1, __ATOMIC_RELAXED);
	}
}

/*
 * Phase: EXP_NEW -- expectation injection.  Half the time the child
 * lands in alt_zone instead of the master's zone, exercising the
 * cross-zone expectation-vs-conntrack split under the same net->
 * expect_lock the per-helper expectation list takes.
 */
static void nfct_helper_iter_expect(struct nfct_helper_iter_ctx *ictx)
{
	__u16 exp_zone = (rand32() & 1U) ? ictx->alt_zone : ictx->zone;
	int rc;

	rc = build_exp_new(ictx->ctx, ictx->zone, exp_zone, ictx->l4proto,
			   ictx->sport, ictx->dport,
			   ictx->child_sport, ictx->child_dport,
			   ictx->helper_name);
	if (rc == 0) {
		__atomic_add_fetch(&shm->stats.nf_conntrack_helper_churn.exp_ok,
				   1, __ATOMIC_RELAXED);
	}
}

/*
 * Phase: drive a single loopback packet at the master tuple's zone via
 * SO_MARK so nf_conntrack_in() fires the just-installed helper's
 * ->help() callback.  Send failures are benign coverage -- the
 * conntrack lookup already ran by the time sendto returns.
 */
static void nfct_helper_iter_drive(struct nfct_helper_iter_ctx *ictx)
{
	int drive_fd;

	drive_fd = loopback_drive(ictx->l4proto, ictx->dport,
				  0xc0de0000U | (__u32)ictx->zone);
	if (drive_fd >= 0) {
		__atomic_add_fetch(&shm->stats.nf_conntrack_helper_churn.packet_sent,
				   1, __ATOMIC_RELAXED);
		close(drive_fd);
	}
}

/*
 * Phase: race burst.  BUDGETED inner loop alternating CT_DELETE in the
 * master's zone, a zone-swap drive into alt_zone via SO_MARK, and a
 * mid-flow helper detach (CT_NEW NLM_F_REPLACE without CTA_HELP).  Each
 * step targets a distinct helper-lifecycle race window -- expectation
 * walk vs delete, zone re-resolve under an in-flight RCU grace period,
 * and __nf_ct_helper_destroy() while the expectation list may still
 * hold an entry pointing at the helper extension.
 */
static void nfct_helper_iter_race(struct nfct_helper_iter_ctx *ictx)
{
	unsigned int races, r;
	int drive_fd;
	int rc;

	races = BUDGETED(CHILD_OP_NF_CONNTRACK_HELPER, NFCT_RACE_ITERS_BASE);
	if (races > NFCT_RACE_BUDGET)
		races = NFCT_RACE_BUDGET;
	if (races == 0U)
		races = 1U;

	for (r = 0; r < races; r++) {
		/* a) CT_DELETE in the master's zone -- races the helper's
		 *    expectation walk. */
		rc = build_ct_delete(ictx->ctx, ictx->zone, ictx->l4proto,
				     ictx->sport, ictx->dport);
		if (rc == 0)
			__atomic_add_fetch(&shm->stats.nf_conntrack_helper_churn.delete_ok,
					   1, __ATOMIC_RELAXED);

		/* b) Zone-swap drive: re-send into a different zone via
		 *    SO_MARK.  Forces a re-resolve in alt_zone's hash slot
		 *    while the prior delete may still be in-flight on the
		 *    RCU grace period. */
		drive_fd = loopback_drive(ictx->l4proto, ictx->dport,
					  0xc0de0000U | (__u32)ictx->alt_zone);
		if (drive_fd >= 0) {
			__atomic_add_fetch(&shm->stats.nf_conntrack_helper_churn.zone_swap,
					   1, __ATOMIC_RELAXED);
			close(drive_fd);
		}

		/* c) Mid-flow helper detach: CT_NEW with NLM_F_REPLACE,
		 *    no CTA_HELP.  Drives __nf_ct_helper_destroy() while
		 *    the expectation list may still hold an entry. */
		rc = build_ct_new(ictx->ctx, ictx->zone, ictx->l4proto,
				  ictx->sport, ictx->dport,
				  NULL, NLM_F_REPLACE);
		if (rc == 0)
			__atomic_add_fetch(&shm->stats.nf_conntrack_helper_churn.detach_ok,
					   1, __ATOMIC_RELAXED);
	}
}

/*
 * One outer iteration: pick zone + helper, insert master conntrack +
 * expectation, drive a packet through, then run a small race burst
 * (delete / zone-swap / detach).  Returns true on every path; the
 * stats counters carry the per-step success signal.
 */
static void iter_one(struct nfnl_ctx *ctx)
{
	struct nfct_helper_iter_ctx ictx = { .ctx = ctx };

	if (nfct_helper_iter_pick(&ictx) < 0)
		return;

	nfct_helper_iter_attach(&ictx);
	nfct_helper_iter_expect(&ictx);
	nfct_helper_iter_drive(&ictx);
	nfct_helper_iter_race(&ictx);
}

bool nf_conntrack_helper_churn(struct childdata *child)
{
	struct nfnl_ctx nfnl = { .nl = { .fd = -1 } };
	struct nfnl_open_opts opts = {
		.recv_timeo_s = NFCT_RECV_TIMEO_S,
	};
	unsigned int outer_iters, i;

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	__atomic_add_fetch(&shm->stats.nf_conntrack_helper_churn.runs,
			   1, __ATOMIC_RELAXED);

	if (ns_unsupported_nf_conntrack_helper) {
		__atomic_add_fetch(&shm->stats.nf_conntrack_helper_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (nfnl_open(&nfnl, &opts) < 0) {
		__atomic_add_fetch(&shm->stats.nf_conntrack_helper_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (!ctnetlink_probed) {
		probe_ctnetlink(&nfnl);
		if (ns_unsupported_nf_conntrack_helper) {
			if (valid_op)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_UNSUPPORTED,
						 __ATOMIC_RELAXED);
			__atomic_add_fetch(&shm->stats.nf_conntrack_helper_churn.setup_failed,
					   1, __ATOMIC_RELAXED);
			nfnl_close(&nfnl);
			return true;
		}
	}
	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	outer_iters = BUDGETED(CHILD_OP_NF_CONNTRACK_HELPER,
			       JITTER_RANGE(NFCT_LOOP_ITERS_BASE));
	if (outer_iters > NFCT_LOOP_BUDGET)
		outer_iters = NFCT_LOOP_BUDGET;
	if (outer_iters == 0U)
		outer_iters = 1U;

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	for (i = 0; i < outer_iters; i++)
		iter_one(&nfnl);

	nfnl_close(&nfnl);
	return true;
}

#else  /* !__has_include(<linux/netfilter/nfnetlink_conntrack.h>) */

bool nf_conntrack_helper_churn(struct childdata *child)
{
	(void)child;
	__atomic_add_fetch(&shm->stats.nf_conntrack_helper_churn.runs,
			   1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.nf_conntrack_helper_churn.setup_failed,
			   1, __ATOMIC_RELAXED);
	return true;
}

#endif /* __has_include(<linux/netfilter/nfnetlink_conntrack.h>) */
