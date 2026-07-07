/*
 * netlink-xfrm.c -- coherent XFRM (IPsec) netlink grammar.
 *
 * Second AF_NETLINK slot in the per-family grammar registry alongside
 * grammar_netlink (netlink.c).  Pinned to NETLINK_XFRM, walks
 * the SA + SP control surface message-by-message across NEWSA /
 * UPDSA / NEWAE / EXPIRE / DELSA / NEWPOLICY / DELPOLICY / FLUSHSA /
 * FLUSHPOLICY with coherent attribute pairing inside each message.
 * The random per-syscall fuzzer never assembles a NEWSA with paired
 * XFRMA_ALG_AUTH_TRUNC + XFRMA_ALG_CRYPT + XFRMA_ENCAP +
 * XFRMA_REPLAY_ESN_VAL and follows it with an UPDSA on the same shell.
 *
 * A per-process ring of installed SAs backs UPDSA / NEWAE / DELSA so
 * they target a real previously-installed SA -- without it the kernel
 * rejects on lookup and the parse path never runs.  NEW -> UPDATE ->
 * EXPIRE -> DEL is the natural lifecycle the ring closes; FLUSHSA on
 * accept drains the ring, and ring-full eviction does a synchronous
 * DELSA on the oldest entry so the SAD does not grow without bound.
 *
 * The grammar carries its own xfrm_unsupported latch instead of
 * sharing shm->sfg_unsupported[PF_NETLINK] -- a kernel without
 * CONFIG_XFRM_USER must not disable grammar_netlink's NETLINK_GENERIC
 * walk on its way down.  First -EPERM (no CAP_NET_ADMIN, no
 * CONFIG_XFRM_USER, or kernel-side lockdown) latches and subsequent
 * invocations early-return.
 *
 * EXPIRE ack consumption: NETLINK_XFRM multicasts xfrm_user_expire
 * events into the receive buffer when soft / hard lifetimes fire.
 * Each iteration drains the inbound side with non-blocking recv()
 * before send() so a full socket buffer does not block the next ack.
 *
 * Header gating via __has_include on linux/xfrm.h.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include <linux/netlink.h>

#if __has_include(<linux/xfrm.h>)
#include <linux/xfrm.h>
#include <fcntl.h>
#include <string.h>
#endif

#include "net.h"
#include "random.h"
#include "shm.h"
#include "socket-family-grammar.h"
#include "trinity.h"
#include "utils.h"
#include "compat.h"

#include "proto-netlink-xfrm-internal.h"

#include "kernel/netlink.h"
/* Latched-once flag: NETLINK_XFRM open or first NEWSA returns -EPERM
 * / -ENOPROTOOPT / -ENOSYS / -EAFNOSUPPORT / -EPROTONOSUPPORT.  Any
 * of those signal "this kernel build / process won't ever drive
 * NETLINK_XFRM successfully" and we early-return on every subsequent
 * grammar invocation. */
bool unsupported_xfrm;

/*
 * Ancillary multicast-subscribed NETLINK_XFRM fd.  Opened lazily on the
 * first data_leg invocation, lives for the lifetime of the trinity child
 * and is implicitly closed on exit.  Subscribes to XFRMNLGRP_ACQUIRE /
 * EXPIRE / SA / POLICY so the kernel-side multicast publish paths
 * (km_event() -> nlmsg_multicast -> netlink_broadcast) fire on every
 * NEWSA / DELSA / NEWPOLICY / DELPOLICY / soft-expire we emit through
 * the unicast parent_fd, exercising the multicast-deliver arms and the
 * acquire/expire serialiser on a non-empty subscriber list.  Drained
 * on every data_leg so the receive buffer doesn't fill.  -1 sentinel
 * once we've tried and failed (typically EPERM without CAP_NET_ADMIN). */
static int mcast_fd = -2;	/* -2 = not yet tried, -1 = tried + failed */

static __u32 g_xfrm_seq;

__u32 xfrm_next_seq(void)
{
	return ++g_xfrm_seq;
}

/*
 * Append a netlink attribute (TLV) at offset off in buf.  Returns the
 * new offset on success, 0 on overflow (caller must check).
 */
size_t xfrm_nla_put(unsigned char *buf, size_t off, size_t cap,
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

/*
 * Lazily open + bind the ancillary multicast fd and subscribe to the
 * four XFRMNLGRP_* groups the kernel publishes async events on.  Set
 * O_NONBLOCK so xfrm_drain_async never blocks.  On any failure (no
 * CAP_NET_ADMIN, kernel rejects the bind, setsockopt EPERM) latch -1
 * so we don't retry every data_leg.
 */
void mcast_fd_open(void)
{
	struct sockaddr_nl nl;
	int fd, flags;
	int grp;

	if (mcast_fd != -2)
		return;

	fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_XFRM);
	if (fd < 0) {
		mcast_fd = -1;
		return;
	}

	flags = fcntl(fd, F_GETFL, 0);
	if (flags >= 0)
		(void) fcntl(fd, F_SETFL, flags | O_NONBLOCK);

	memset(&nl, 0, sizeof(nl));
	nl.nl_family = AF_NETLINK;
	nl.nl_pid    = 0;
	nl.nl_groups = 0;

	if (bind(fd, (struct sockaddr *) &nl, sizeof(nl)) < 0) {
		close(fd);
		mcast_fd = -1;
		return;
	}

	for (grp = XFRMNLGRP_ACQUIRE; grp <= XFRMNLGRP_POLICY; grp++)
		(void) setsockopt(fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
				  &grp, sizeof(grp));

	mcast_fd = fd;
}

/*
 * Drain inbound traffic on the ancillary multicast fd.  ACQUIRE /
 * EXPIRE / async SA + POLICY events end up here; without drainage the
 * receive buffer fills and the kernel-side multicast deliver stops
 * picking us as a subscriber (NETLINK_NO_ENOBUFS is off so an ENOBUFS
 * burst would also break later reads).
 */
void xfrm_drain_mcast(void)
{
	unsigned char buf[2048];
	int n;

	if (mcast_fd < 0)
		return;

	for (n = 0; n < 32; n++) {
		ssize_t r = recv(mcast_fd, buf, sizeof(buf), MSG_DONTWAIT);

		if (r <= 0)
			break;
	}
}

/*
 * Drain any inbound multicast / event traffic the kernel queued on
 * this fd.  NETLINK_XFRM emits xfrm_user_expire when soft / hard
 * lifetimes fire and async events on UPDSA acks; without drainage the
 * receive buffer fills and the next iteration's recv() of an ack
 * blocks past the SIGALRM cap.
 */
void xfrm_drain_async(int fd)
{
	unsigned char buf[1024];
	int n;

	for (n = 0; n < 32; n++) {
		ssize_t r = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);

		if (r <= 0)
			break;
	}
}

/*
 * Send a netlink message and consume one ack.  Returns 0 on a positive
 * ack, the negated errno on a kernel rejection, -EIO on local I/O
 * failure.  Latches unsupported_xfrm on the first persistent
 * "structurally won't work" rejection.
 */
int xfrm_send_recv(int fd, void *msg, size_t len)
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
	return 0;
}

/* Transition-once latch.  EPERM / EAFNOSUPPORT / EPROTONOSUPPORT /
 * EOPNOTSUPP from NEWSA all signal "this kernel won't accept any of
 * our control-plane messages on this fd" -- early-return forever. */
bool is_structural_reject(int rc)
{
	return rc == -EPERM || rc == -EAFNOSUPPORT ||
	       rc == -EPROTONOSUPPORT || rc == -EOPNOTSUPP ||
	       rc == -ENOSYS || rc == -ENOPROTOOPT;
}

void latch_unsupported(int rc)
{
	if (unsupported_xfrm)
		return;
	unsupported_xfrm = true;
	outputerr("xfrm grammar: NETLINK_XFRM rejected with %s -- latching unsupported_xfrm\n",
		  strerror(-rc));
}

/*
 * Message rotation table.  Each grammar invocation rolls one slot.
 * NEWSA / NEWPOLICY get higher weight when the SA ring is empty so
 * the ring fills before UPDSA / NEWAE / DELSA show up; FLUSHSA /
 * FLUSHPOLICY get low weight so they don't dominate.
 */
enum xfrm_msg_kind {
	XMK_NEWSA,
	XMK_ALLOCSPI,
	XMK_UPDSA,
	XMK_NEWAE,
	XMK_EXPIRE,
	XMK_DELSA,
	XMK_NEWPOLICY,
	XMK_DELPOLICY,
	XMK_MIGRATE,
	XMK_ACQUIRE,
	XMK_FLUSHSA,
	XMK_FLUSHPOLICY,
	XMK_SETDEFAULT,
	XMK_GETDEFAULT,
	XMK_POLEXPIRE,
	XMK_MAX,
};

/* Weights -- higher = more often.  When ring empty, NEWSA / NEWPOLICY
 * dominate so the ring fills.  When ring non-empty, UPDSA / NEWAE /
 * EXPIRE / DELSA become first-class.  FLUSHSA / FLUSHPOLICY stay rare.
 *
 * EXPIRE rotates between hard==0 (lifetime-fired notification only,
 * SA stays installed) and hard==1 (lifetime-fired + teardown, SA
 * removed).  The hard==1 path covers the natural NEW -> UPDATE ->
 * EXPIRE -> DEL lifecycle; the soft path leaves the SA in the ring so
 * subsequent UPDSA / NEWAE keep working against the same shell. */
static const unsigned int xmk_weights_empty_ring[XMK_MAX] = {
	[XMK_NEWSA]		= 50,
	[XMK_ALLOCSPI]		= 15,
	[XMK_UPDSA]		= 0,
	[XMK_NEWAE]		= 0,
	[XMK_EXPIRE]		= 0,
	[XMK_DELSA]		= 0,
	[XMK_NEWPOLICY]		= 30,
	[XMK_DELPOLICY]		= 5,
	[XMK_MIGRATE]		= 4,
	[XMK_ACQUIRE]		= 4,
	[XMK_FLUSHSA]		= 1,
	[XMK_FLUSHPOLICY]	= 1,
	[XMK_SETDEFAULT]	= 5,
	[XMK_GETDEFAULT]	= 3,
	[XMK_POLEXPIRE]		= 0,
};
static const unsigned int xmk_weights_full_ring[XMK_MAX] = {
	[XMK_NEWSA]		= 20,
	[XMK_ALLOCSPI]		= 10,
	[XMK_UPDSA]		= 18,
	[XMK_NEWAE]		= 13,
	[XMK_EXPIRE]		= 12,
	[XMK_DELSA]		= 13,
	[XMK_NEWPOLICY]		= 14,
	[XMK_DELPOLICY]		= 8,
	[XMK_MIGRATE]		= 4,
	[XMK_ACQUIRE]		= 6,
	[XMK_FLUSHSA]		= 2,
	[XMK_FLUSHPOLICY]	= 1,
	[XMK_SETDEFAULT]	= 5,
	[XMK_GETDEFAULT]	= 3,
	[XMK_POLEXPIRE]		= 5,
};

static enum xfrm_msg_kind pick_msg_kind(void)
{
	const unsigned int *weights = sa_ring_count() == 0
		? xmk_weights_empty_ring : xmk_weights_full_ring;
	unsigned int total = 0, pick, accum = 0;
	unsigned int i;

	for (i = 0; i < XMK_MAX; i++)
		total += weights[i];

	if (total == 0)
		return XMK_NEWSA;	/* defensive */

	pick = rnd_modulo_u32(total);
	for (i = 0; i < XMK_MAX; i++) {
		accum += weights[i];
		if (pick < accum)
			return (enum xfrm_msg_kind)i;
	}
	return XMK_NEWSA;
}

static void dispatch_msg_kind(int fd, enum xfrm_msg_kind k)
{
	int rc;

	switch (k) {
	case XMK_NEWSA:		rc = xfrm_emit_newsa(fd); break;
	case XMK_ALLOCSPI:	rc = xfrm_emit_allocspi(fd); break;
	case XMK_UPDSA:		rc = xfrm_emit_updsa(fd); break;
	case XMK_NEWAE:		rc = xfrm_emit_newae(fd); break;
	case XMK_EXPIRE:	rc = xfrm_emit_expire(fd); break;
	case XMK_DELSA:		rc = xfrm_emit_delsa_random(fd); break;
	case XMK_NEWPOLICY:	rc = xfrm_emit_newpolicy(fd); break;
	case XMK_DELPOLICY:	rc = xfrm_emit_delpolicy(fd); break;
	case XMK_MIGRATE:	rc = xfrm_emit_migrate(fd); break;
	case XMK_ACQUIRE:	rc = xfrm_emit_acquire(fd); break;
	case XMK_FLUSHSA:	rc = xfrm_emit_flushsa(fd); break;
	case XMK_FLUSHPOLICY:	rc = xfrm_emit_flushpolicy(fd); break;
	case XMK_SETDEFAULT:	rc = xfrm_emit_setdefault(fd); break;
	case XMK_GETDEFAULT:	rc = xfrm_emit_getdefault(fd); break;
	case XMK_POLEXPIRE:	rc = xfrm_emit_polexpire(fd); break;
	default:		rc = 0; break;
	}

	if (rc != 0 && is_structural_reject(rc))
		latch_unsupported(rc);
}

/*
 * Grammar callbacks.
 *
 * can_run probes socket(PF_NETLINK, SOCK_RAW, NETLINK_XFRM) once and
 * caches the verdict.  A kernel without CONFIG_XFRM_USER fails the
 * socket() with EPROTONOSUPPORT; can_run returns false and
 * sfg_pick_random_active filters us out.  The shared
 * shm->sfg_unsupported[PF_NETLINK] latch is intentionally untouched
 * -- failing here does not affect grammar_netlink (which probes
 * NETLINK_GENERIC).
 */
static bool xfrm_grammar_can_run(void)
{
	int fd;

	if (unsupported_xfrm)
		return false;

	fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_XFRM);
	if (fd < 0) {
		unsupported_xfrm = true;
		return false;
	}
	close(fd);
	return true;
}

static void xfrm_grammar_pick_triplet(struct socket_triplet *out)
{
	out->family   = PF_NETLINK;
	out->type     = SOCK_RAW;
	out->protocol = NETLINK_XFRM;
}

static void xfrm_grammar_configure_pre_bind(int fd, struct socket_triplet *t)
{
	int flags;
	int one = 1;

	(void) t;

	flags = fcntl(fd, F_GETFL, 0);
	if (flags >= 0)
		(void) fcntl(fd, F_SETFL, flags | O_NONBLOCK);

	/* NETLINK_EXT_ACK + NETLINK_CAP_ACK so the kernel includes the
	 * extended attribute on errors -- the parser-side ack-build
	 * paths get coverage on every rejected message. */
	(void) setsockopt(fd, SOL_NETLINK, NETLINK_EXT_ACK,
			  &one, sizeof(one));
	(void) setsockopt(fd, SOL_NETLINK, NETLINK_CAP_ACK,
			  &one, sizeof(one));
}

static int xfrm_grammar_bind(int fd, struct socket_triplet *t)
{
	struct sockaddr_nl nl;

	(void) t;

	memset(&nl, 0, sizeof(nl));
	nl.nl_family = AF_NETLINK;
	nl.nl_pid    = 0;
	/* nl_groups = 0 -- multicast subscription on NETLINK_XFRM
	 * requires CAP_NET_ADMIN at bind time (NL_CFG_F_NONROOT_RECV is
	 * not set on this protocol).  We only need the unicast ack
	 * channel for sync send/recv; xfrm_drain_async stays as a
	 * defensive no-op. */
	nl.nl_groups = 0;

	if (bind(fd, (struct sockaddr *) &nl, sizeof(nl)) < 0)
		return -1;
	return 0;
}

static bool xfrm_grammar_needs_listen_accept(struct socket_triplet *t)
{
	(void) t;
	return false;
}

/*
 * walk_setsockopts is intentionally minimal -- the XFRM-shaped
 * coverage lives in data_leg via the message-rotation walker, and the
 * SOL_NETLINK toggle / membership churn is grammar_netlink's
 * responsibility.  We do exercise NETLINK_EXT_ACK / NETLINK_CAP_ACK
 * toggling and NETLINK_NO_ENOBUFS once each so the SOL_NETLINK arms
 * see at least some coverage on the XFRM-pinned fd shape too.
 */
static void xfrm_grammar_walk_setsockopts(int fd, struct socket_triplet *t,
					  unsigned int n)
{
	int v;
	unsigned int step = 0;

	(void) t;

	if (step++ < n) {
		v = (int)(rand32() & 1);
		(void) setsockopt(fd, SOL_NETLINK, NETLINK_EXT_ACK,
				  &v, sizeof(v));
	}
	if (step++ < n) {
		v = (int)(rand32() & 1);
		(void) setsockopt(fd, SOL_NETLINK, NETLINK_CAP_ACK,
				  &v, sizeof(v));
	}
	if (step++ < n) {
		v = 1;
		(void) setsockopt(fd, SOL_NETLINK, 5 /* NETLINK_NO_ENOBUFS */,
				  &v, sizeof(v));
	}
}

/*
 * data_leg is where the actual XFRM message-rotation happens.  One
 * message per invocation; the picker weights bias NEWSA / NEWPOLICY
 * up when the ring is empty, then UPDSA / NEWAE / DELSA become
 * first-class once the ring has SAs to target.
 *
 * The fd is a transient: the grammar dispatcher closes it after this
 * callback returns.  All persistent state (SA ring, latches, seq
 * counter) lives in file-scope statics so the next invocation's fresh
 * fd inherits the SAD shape this fd just installed.
 */
static void xfrm_grammar_data_leg(int parent_fd, int child_fd,
				  struct socket_triplet *t)
{
	enum xfrm_msg_kind k;

	(void) child_fd;
	(void) t;

	if (unsupported_xfrm)
		return;

	/* P3.14 multicast bind: lazily open an ancillary fd subscribed to
	 * XFRMNLGRP_ACQUIRE / EXPIRE / SA / POLICY.  The unicast parent_fd
	 * still carries every emit + ack; the mcast fd just gives the
	 * kernel a non-empty subscriber list so the multicast publish
	 * paths fire and the async events end up drained here. */
	mcast_fd_open();

	xfrm_drain_async(parent_fd);
	xfrm_drain_mcast();
	k = pick_msg_kind();
	dispatch_msg_kind(parent_fd, k);
	xfrm_drain_async(parent_fd);
	xfrm_drain_mcast();
}

const struct socket_family_grammar grammar_xfrm = {
	.family			= PF_NETLINK,
	.name			= "netlink-xfrm",
	.can_run		= xfrm_grammar_can_run,
	.pick_triplet		= xfrm_grammar_pick_triplet,
	.configure_pre_bind	= xfrm_grammar_configure_pre_bind,
	.bind_or_connect	= xfrm_grammar_bind,
	.walk_setsockopts	= xfrm_grammar_walk_setsockopts,
	.needs_listen_accept	= xfrm_grammar_needs_listen_accept,
	.data_leg		= xfrm_grammar_data_leg,
};
