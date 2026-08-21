/*
 * xfrm-churn-devteardown - race RTM_DELLINK of the bundle's egress
 * netdev against xfrm_bundle_create()/xfrm{4,6}_fill_dst().
 *
 * net/xfrm/xfrm_policy.c:xfrm_bundle_create() reads `dev = dst->dev`
 * into a local with no reference held, then hands it to
 * xfrm_fill_dst() -> xfrm{4,6}_fill_dst() which netdev_hold()s it.  A
 * concurrent netdev unregister swaps dst->dev via dst_dev_put() and
 * frees the old netdev underneath.  The rest of xfrm-churn runs on a
 * netns whose only device is lo, which cannot be RTM_DELLINK'd, so
 * that arm has no reachable half at all.  This one installs a
 * deletable dummy, routes the SA's outer endpoint over it, and races
 * the two.
 */

#include "xfrm-churn-internal.h"

#include <linux/if_addr.h>
#include <signal.h>

#include "signals.h"
#include "userns-bootstrap.h"

#include "kernel/socket.h"

#define XDT_DEV_NAME		"trxfrmdt0"
#define XDT_RTNL_BUF		512U
#define XDT_RECV_TIMEO_S	1
#define XDT_WORKER_WALL_NS	(150ULL * 1000ULL * 1000ULL)
#define XDT_PARENT_WALL_NS	(220ULL * 1000ULL * 1000ULL)

/* Inner destinations rotate across the low byte of the selector
 * prefix.  Each distinct flow key misses the policy's cached bundle
 * list, so every send re-enters xfrm_resolve_and_create_bundle() ->
 * xfrm_bundle_create() rather than reusing a live xdst. */
#define XDT_INNER_ROTATE	64U
#define XDT_PAYLOAD_BYTES	64U

#ifndef IFA_F_NODAD
#define IFA_F_NODAD		0x02
#endif

/*
 * Two ESP transforms, tried in order.  The algorithm is incidental
 * here -- the arm needs any SA the kernel will install so a tunnel
 * bundle exists to race -- so a rejection just falls through to the
 * next entry instead of arming a per-algo latch.
 */
static const struct xfrm_algo_def xdt_algos[] = {
	{ XFRM_ALG_ESP_NULL, IPPROTO_ESP, "ecb(cipher_null)",  0,   "hmac(sha1)", 160, 96, 0,   "esp4" },
	{ XFRM_ALG_AEAD,     IPPROTO_ESP, "rfc4106(gcm(aes))", 160, NULL,         0,   0,  128, "esp4" },
};

/*
 * Topology for one invocation.  @local sits on the dummy, @peer is
 * the tunnel-mode outer destination reached on-link over it (so the
 * outer route's dst->dev is the dummy, not lo), and @inner_net is the
 * policy selector's destination prefix, routed via @peer.
 */
struct xdt_topo {
	__u16		family;
	xfrm_address_t	local;
	xfrm_address_t	peer;
	xfrm_address_t	inner_net;
	__u8		addr_plen;	/* on-link prefix of @local */
	__u8		inner_plen;	/* selector + route prefix */
	__u8		full_plen;	/* 32 or 128 */
};

static bool ns_unsupported_dummy(void)
{
	return __atomic_load_n(&shm->xfrm_churn_ns_unsupported_dummy,
			       __ATOMIC_RELAXED);
}

static void mark_ns_unsupported_dummy(void)
{
	__atomic_store_n(&shm->xfrm_churn_ns_unsupported_dummy, true,
			 __ATOMIC_RELAXED);
}

static void xdt_topo_init(struct xdt_topo *t, bool v6)
{
	memset(t, 0, sizeof(*t));

	if (v6) {
		/* fc02::1 on the dummy, outer peer fc02::2, inner
		 * selector fc03::/64 routed via the peer. */
		t->family          = AF_INET6;
		t->local.a6[0]     = htonl(0xfc020000U);
		t->local.a6[3]     = htonl(1U);
		t->peer.a6[0]      = htonl(0xfc020000U);
		t->peer.a6[3]      = htonl(2U);
		t->inner_net.a6[0] = htonl(0xfc030000U);
		t->addr_plen       = 64;
		t->inner_plen      = 64;
		t->full_plen       = 128;
		return;
	}

	/* 198.51.100.1/24 on the dummy (TEST-NET-2), outer peer .2,
	 * inner selector 192.0.2.0/24 (TEST-NET-1) via the peer. */
	t->family       = AF_INET;
	t->local.a4     = htonl(0xc6336401U);
	t->peer.a4      = htonl(0xc6336402U);
	t->inner_net.a4 = htonl(0xc0000200U);
	t->addr_plen    = 24;
	t->inner_plen   = 24;
	t->full_plen    = 32;
}

static size_t xdt_addr_len(const struct xdt_topo *t)
{
	return (t->family == AF_INET6) ? 16U : 4U;
}

/* Nth inner destination in the selector prefix, low byte rotated. */
static void xdt_inner_dst(const struct xdt_topo *t, unsigned int n,
			  xfrm_address_t *out)
{
	*out = t->inner_net;
	if (t->family == AF_INET6)
		out->a6[3] = htonl((n % XDT_INNER_ROTATE) + 1U);
	else
		out->a4 = htonl(ntohl(t->inner_net.a4) +
				(n % XDT_INNER_ROTATE) + 1U);
}

/*
 * RTM_NEWLINK with a nested IFLA_LINKINFO { IFLA_INFO_KIND="dummy" }.
 * A dummy carries IFF_NOARP, so neither IPv4 ARP nor IPv6 DAD can
 * stall the first transmit through a freshly created device.
 */
static int xdt_create_dummy(struct nl_ctx *ctx)
{
	unsigned char buf[XDT_RTNL_BUF];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off, li_off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, XDT_DEV_NAME);
	if (!off)
		return -EIO;

	li_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_LINKINFO);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), IFLA_INFO_KIND, "dummy");
	if (!off)
		return -EIO;
	nla_nest_end(buf, li_off, off);

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

static int xdt_dellink_byname(struct nl_ctx *ctx)
{
	unsigned char buf[XDT_RTNL_BUF];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_DELLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));
	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, XDT_DEV_NAME);
	if (!off)
		return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

static int xdt_addr_add(struct nl_ctx *ctx, int ifindex,
			const struct xdt_topo *t)
{
	unsigned char buf[XDT_RTNL_BUF];
	struct nlmsghdr *nlh;
	struct ifaddrmsg *ifa;
	size_t alen = xdt_addr_len(t);
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWADDR;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_REPLACE;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifa = (struct ifaddrmsg *)NLMSG_DATA(nlh);
	ifa->ifa_family    = (__u8)t->family;
	ifa->ifa_prefixlen = t->addr_plen;
	ifa->ifa_flags     = IFA_F_NODAD;
	ifa->ifa_scope     = 0;		/* RT_SCOPE_UNIVERSE */
	ifa->ifa_index     = (unsigned int)ifindex;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifa));
	off = nla_put(buf, off, sizeof(buf), IFA_LOCAL, &t->local, alen);
	if (!off)
		return -EIO;
	off = nla_put(buf, off, sizeof(buf), IFA_ADDRESS, &t->local, alen);
	if (!off)
		return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * RTM_NEWROUTE for the selector prefix via @peer out of the dummy.
 * The gateway sits inside the dummy's own on-link prefix, so the
 * outer (tunnel-mode) lookup for @peer also resolves to the dummy --
 * both the inner route and the SA's outer route hang off the device
 * the teardown worker is about to delete.
 */
static int xdt_route_add(struct nl_ctx *ctx, int ifindex,
			 const struct xdt_topo *t)
{
	unsigned char buf[XDT_RTNL_BUF];
	struct nlmsghdr *nlh;
	struct rtmsg *rtm;
	size_t alen = xdt_addr_len(t);
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWROUTE;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_REPLACE;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	rtm = (struct rtmsg *)NLMSG_DATA(nlh);
	rtm->rtm_family   = (__u8)t->family;
	rtm->rtm_dst_len  = t->inner_plen;
	rtm->rtm_table    = RT_TABLE_MAIN;
	rtm->rtm_protocol = RTPROT_BOOT;
	rtm->rtm_scope    = 0;		/* RT_SCOPE_UNIVERSE */
	rtm->rtm_type     = RTN_UNICAST;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*rtm));
	off = nla_put(buf, off, sizeof(buf), RTA_DST, &t->inner_net, alen);
	if (!off)
		return -EIO;
	off = nla_put(buf, off, sizeof(buf), RTA_GATEWAY, &t->peer, alen);
	if (!off)
		return -EIO;
	off = nla_put_u32(buf, off, sizeof(buf), RTA_OIF, (__u32)ifindex);
	if (!off)
		return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * Create the dummy, bring it up, address it and install the selector
 * route.  Returns the ifindex, or 0 when the device could not be
 * created (CONFIG_DUMMY absent latches the arm off for the fleet).
 */
static unsigned int xdt_setup_dev(struct nl_ctx *ctx, const struct xdt_topo *t,
				  unsigned long *dc)
{
	unsigned int ifx;
	int rc;

	rc = xdt_create_dummy(ctx);
	if (rc != 0) {
		if (rc == -EOPNOTSUPP || rc == -ENODEV || rc == -EAFNOSUPPORT ||
		    rc == -EPROTONOSUPPORT || rc == -ENOENT)
			mark_ns_unsupported_dummy();
		return 0;
	}

	ifx = if_nametoindex(XDT_DEV_NAME);
	*dc += 3;	/* if_nametoindex: socket + ioctl + close */
	if (ifx == 0)
		return 0;

	(void)rtnl_setlink_up(ctx, (int)ifx);
	(void)xdt_addr_add(ctx, (int)ifx, t);
	(void)xdt_route_add(ctx, (int)ifx, t);
	return ifx;
}

/*
 * XFRM_MSG_NEWSA for a tunnel-mode SA whose outer endpoints are
 * @local -> @peer.  Family-parameterised so the v6 arm reaches
 * xfrm6_fill_dst(), which is the frame the upstream report names;
 * the shared builders in xfrm-churn-builders.c are hard-wired to the
 * v4 loopback selector and cannot express this topology.
 */
static int xdt_build_sa(struct nl_ctx *ctx, const struct xfrm_algo_def *def,
			const struct xdt_topo *t, __be32 spi, __u32 reqid)
{
	unsigned char buf[XFRM_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct xfrm_usersa_info *sa;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = XFRM_MSG_NEWSA;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	sa = (struct xfrm_usersa_info *)NLMSG_DATA(nlh);
	sa->sel.saddr       = t->local;
	sa->sel.daddr       = t->inner_net;
	sa->sel.family      = t->family;
	sa->sel.prefixlen_s = t->full_plen;
	sa->sel.prefixlen_d = t->inner_plen;
	sa->sel.proto       = IPPROTO_UDP;
	sa->id.daddr        = t->peer;
	sa->id.spi          = spi;
	sa->id.proto        = def->proto;
	sa->saddr           = t->local;
	xfrm_churn_fill_lifetime(&sa->lft);
	sa->seq             = pick_sa_seq();
	sa->reqid           = reqid;
	sa->family          = t->family;
	sa->mode            = XFRM_MODE_TUNNEL;
	/* XFRMA_SA_DIR_OUT below makes a nonzero replay_window an
	 * outright rejection. */
	sa->replay_window   = 0;
	sa->flags           = 0;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*sa));
	off = xfrm_churn_append_algo_attrs(buf, off, sizeof(buf), def);
	if (!off)
		return -EIO;

	off = nla_put_u8(buf, off, sizeof(buf), XFRMA_SA_DIR, XFRM_SA_DIR_OUT);
	if (!off)
		return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv_retry(ctx, buf, off);
}

static int xdt_build_policy(struct nl_ctx *ctx, const struct xfrm_algo_def *def,
			    const struct xdt_topo *t, __be32 spi, __u32 reqid)
{
	unsigned char buf[XFRM_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct xfrm_userpolicy_info *pol;
	struct xfrm_user_tmpl tmpl;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = XFRM_MSG_NEWPOLICY;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	pol = (struct xfrm_userpolicy_info *)NLMSG_DATA(nlh);
	pol->sel.saddr       = t->local;
	pol->sel.daddr       = t->inner_net;
	pol->sel.family      = t->family;
	pol->sel.prefixlen_s = t->full_plen;
	pol->sel.prefixlen_d = t->inner_plen;
	pol->sel.proto       = IPPROTO_UDP;
	xfrm_churn_fill_lifetime(&pol->lft);
	pol->priority = 1024;
	pol->index    = 0;
	pol->dir      = XFRM_POLICY_OUT;
	pol->action   = XFRM_POLICY_ALLOW;
	pol->flags    = 0;
	pol->share    = XFRM_SHARE_ANY;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*pol));

	memset(&tmpl, 0, sizeof(tmpl));
	tmpl.id.daddr = t->peer;
	tmpl.id.spi   = spi;
	tmpl.id.proto = def->proto;
	tmpl.family   = t->family;
	tmpl.saddr    = t->local;
	tmpl.reqid    = reqid;
	tmpl.mode     = XFRM_MODE_TUNNEL;
	tmpl.share    = XFRM_SHARE_ANY;
	tmpl.optional = 0;
	tmpl.aalgos   = (__u32)~0U;
	tmpl.ealgos   = (__u32)~0U;
	tmpl.calgos   = (__u32)~0U;

	off = nla_put(buf, off, sizeof(buf), XFRMA_TMPL, &tmpl, sizeof(tmpl));
	if (!off)
		return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv_retry(ctx, buf, off);
}

/*
 * Worker A.  Rotating-destination sendto loop.  Every distinct inner
 * destination misses the policy's bundle list and drives a fresh
 * xfrm_resolve_and_create_bundle() -> xfrm_bundle_create() ->
 * xfrm{4,6}_fill_dst() over the dummy while worker B deletes it.
 * MSG_DONTWAIT so a dead route (ENETUNREACH between DELLINK and the
 * recreate) costs nothing; self-bounded by XDT_WORKER_WALL_NS.
 */
static void xdt_worker_send(const struct xdt_topo *t, int op_type)
{
	unsigned char payload[XDT_PAYLOAD_BYTES];
	struct timespec start, now;
	unsigned long dc = 0;
	unsigned int i = 0;
	int fd;

	fd = socket(t->family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	dc++;
	if (fd < 0)
		_exit(0);

	if (t->family == AF_INET6) {
		struct sockaddr_in6 src;

		memset(&src, 0, sizeof(src));
		src.sin6_family = AF_INET6;
		memcpy(&src.sin6_addr, t->local.a6, 16);
		dc++;
		(void)bind(fd, (struct sockaddr *)&src, sizeof(src));
	} else {
		struct sockaddr_in src;

		memset(&src, 0, sizeof(src));
		src.sin_family      = AF_INET;
		src.sin_addr.s_addr = t->local.a4;
		dc++;
		(void)bind(fd, (struct sockaddr *)&src, sizeof(src));
	}

	generate_rand_bytes(payload, sizeof(payload));
	if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
		start.tv_sec = 0;

	for (;; i++) {
		xfrm_address_t dst;
		ssize_t r;

		xdt_inner_dst(t, i, &dst);

		if (t->family == AF_INET6) {
			struct sockaddr_in6 to;

			memset(&to, 0, sizeof(to));
			to.sin6_family = AF_INET6;
			to.sin6_port   = htons(XFRM_INNER_PORT);
			memcpy(&to.sin6_addr, dst.a6, 16);
			r = sendto(fd, payload, sizeof(payload),
				   MSG_DONTWAIT | MSG_NOSIGNAL,
				   (struct sockaddr *)&to, sizeof(to));
		} else {
			struct sockaddr_in to;

			memset(&to, 0, sizeof(to));
			to.sin_family      = AF_INET;
			to.sin_port        = htons(XFRM_INNER_PORT);
			to.sin_addr.s_addr = dst.a4;
			r = sendto(fd, payload, sizeof(payload),
				   MSG_DONTWAIT | MSG_NOSIGNAL,
				   (struct sockaddr *)&to, sizeof(to));
		}
		dc++;
		if (r > 0)
			__atomic_add_fetch(&shm->stats.xfrm_churn.devteardown_sent,
					   1, __ATOMIC_RELAXED);

		if ((i & 0x1fU) == 0U &&
		    clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
			unsigned long long elapsed =
				(unsigned long long)(now.tv_sec - start.tv_sec) *
					1000000000ULL +
				(unsigned long long)(now.tv_nsec - start.tv_nsec);
			if (elapsed >= XDT_WORKER_WALL_NS)
				break;
		}
	}

	(void)close(fd);
	if (op_type >= 0 && op_type < NR_CHILD_OP_TYPES)
		childop_direct_syscalls_add((enum child_op_type)op_type, dc);
	_exit(0);
}

/*
 * Worker B.  RTM_DELLINK the dummy, then recreate + readdress +
 * reroute so the next cycle has something to delete.  The DELLINK is
 * the half the loopback-only netns could never supply: it runs
 * dst_dev_put() over every dst still pointing at the device while
 * worker A is mid-bundle-build on it.
 */
static void xdt_worker_dellink(const struct xdt_topo *t)
{
	struct nl_ctx ctx = NL_CTX_INIT;
	struct nl_open_opts opts = {
		.proto        = NETLINK_ROUTE,
		.recv_timeo_s = XDT_RECV_TIMEO_S,
		.caller_op    = CHILD_OP_XFRM_CHURN,
	};
	struct timespec start, now;
	unsigned long dc = 0;
	unsigned int i = 0;

	if (nl_open(&ctx, &opts) < 0)
		_exit(0);

	if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
		start.tv_sec = 0;

	for (;; i++) {
		if (xdt_dellink_byname(&ctx) == 0)
			__atomic_add_fetch(&shm->stats.xfrm_churn.devteardown_dellink,
					   1, __ATOMIC_RELAXED);

		(void)xdt_setup_dev(&ctx, t, &dc);

		if ((i & 0x07U) == 0U &&
		    clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
			unsigned long long elapsed =
				(unsigned long long)(now.tv_sec - start.tv_sec) *
					1000000000ULL +
				(unsigned long long)(now.tv_nsec - start.tv_nsec);
			if (elapsed >= XDT_WORKER_WALL_NS)
				break;
		}
	}

	/* nl_close() publishes the transport's own syscalls via
	 * caller_op; the if_nametoindex triples tallied in dc are
	 * own-body and need their own publish before _exit(). */
	nl_close(&ctx);
	childop_direct_syscalls_add(CHILD_OP_XFRM_CHURN, dc);
	_exit(0);
}

/*
 * Reap one worker, SIGKILLing it past *deadline so a wedged worker
 * cannot outrun child.c's alarm(1).
 */
static void xdt_reap(pid_t pid, const struct timespec *deadline,
		     unsigned long *dc)
{
	for (;;) {
		struct timespec now;
		int status;
		pid_t r;

		r = waitpid_eintr(pid, &status, WNOHANG);
		*dc += 1;
		if (r == pid)
			return;
		if (r < 0 && errno != ECHILD)
			return;

		if (clock_gettime(CLOCK_MONOTONIC, &now) == 0 &&
		    (now.tv_sec > deadline->tv_sec ||
		     (now.tv_sec == deadline->tv_sec &&
		      now.tv_nsec >= deadline->tv_nsec))) {
			(void)kill(pid, SIGKILL);
			*dc += 1;
			(void)waitpid_eintr(pid, &status, 0);
			*dc += 1;
			return;
		}
		(void)usleep(2000);
	}
}

static void xdt_spawn_and_reap(const struct xdt_topo *t, int op_type,
			       unsigned long *dc)
{
	struct timespec deadline;
	pid_t a, b;

	a = fork();
	*dc += 1;
	if (a < 0)
		return;
	if (a == 0)
		xdt_worker_send(t, op_type);

	b = fork();
	*dc += 1;
	if (b < 0) {
		(void)kill(a, SIGKILL);
		*dc += 1;
		(void)waitpid_eintr(a, NULL, 0);
		*dc += 1;
		return;
	}
	if (b == 0)
		xdt_worker_dellink(t);

	if (clock_gettime(CLOCK_MONOTONIC, &deadline) != 0) {
		deadline.tv_sec  = 0;
		deadline.tv_nsec = 0;
	}
	deadline.tv_nsec += (long)XDT_PARENT_WALL_NS;
	while (deadline.tv_nsec >= 1000000000L) {
		deadline.tv_nsec -= 1000000000L;
		deadline.tv_sec  += 1;
	}

	xdt_reap(a, &deadline, dc);
	xdt_reap(b, &deadline, dc);
}

bool xfrm_dev_teardown_race(struct childdata *child, unsigned long *dc)
{
	struct nl_ctx rtnl = NL_CTX_INIT;
	struct nl_ctx xnl = NL_CTX_INIT;
	struct nl_open_opts rtnl_opts = {
		.proto        = NETLINK_ROUTE,
		.recv_timeo_s = XDT_RECV_TIMEO_S,
		.caller_op    = CHILD_OP_XFRM_CHURN,
	};
	struct nl_open_opts xfrm_opts = {
		.proto        = NETLINK_XFRM,
		.recv_timeo_s = XDT_RECV_TIMEO_S,
		.caller_op    = CHILD_OP_XFRM_CHURN,
	};
	struct xdt_topo topo;
	unsigned int aidx, ifx = 0;
	__be32 spi;
	__u32 reqid;
	bool sa_up = false;
	/* Fork-invariant snapshot: op_type is the only childdata member
	 * touched, and it is read before any worker fork. */
	const int op_type = child->op_type;

	if (ns_unsupported_xfrm || ns_unsupported_dummy())
		return false;

	__atomic_add_fetch(&shm->stats.xfrm_churn.devteardown_runs, 1,
			   __ATOMIC_RELAXED);

	/* v6 half the time: xfrm6_fill_dst() is the frame the upstream
	 * report names, and it holds an extra in6_dev_get(dev) on the
	 * same unreferenced device. */
	xdt_topo_init(&topo, ONE_IN(2));
	if (topo.family == AF_INET6)
		__atomic_add_fetch(&shm->stats.xfrm_churn.devteardown_v6_runs,
				   1, __ATOMIC_RELAXED);

	if (nl_open(&rtnl, &rtnl_opts) < 0)
		goto fail;
	rtnl_bring_lo_up(&rtnl);
	*dc += 3;	/* if_nametoindex component; see RTNL_BRING_LO_UP_DIRECT_CALLS */

	ifx = xdt_setup_dev(&rtnl, &topo, dc);
	if (ifx == 0)
		goto fail;

	if (nl_open(&xnl, &xfrm_opts) < 0)
		goto fail;

	spi   = htonl((rand32() % XFRM_SPI_RANGE) + XFRM_SPI_MIN);
	reqid = (rand32() % XFRM_REQID_RANGE) + 1U;

	for (aidx = 0; aidx < ARRAY_SIZE(xdt_algos); aidx++) {
		if (xdt_build_sa(&xnl, &xdt_algos[aidx], &topo, spi,
				 reqid) == 0) {
			sa_up = true;
			break;
		}
	}
	if (!sa_up)
		goto fail;

	if (xdt_build_policy(&xnl, &xdt_algos[aidx], &topo, spi, reqid) != 0)
		goto fail;

	/* Close both control sockets before forking so the workers do
	 * not inherit a shared sequence counter; worker B opens its
	 * own rtnl context. */
	nl_close(&rtnl);
	nl_close(&xnl);

	__atomic_add_fetch(&shm->stats.xfrm_churn.devteardown_armed, 1,
			   __ATOMIC_RELAXED);
	xdt_spawn_and_reap(&topo, op_type, dc);
	return true;

fail:
	nl_close(&rtnl);
	nl_close(&xnl);
	__atomic_add_fetch(&shm->stats.xfrm_churn.devteardown_setup_failed, 1,
			   __ATOMIC_RELAXED);
	/* The topology never came up, so nothing raced.  Returning false
	 * lets the caller fall through to the normal loopback flow
	 * instead of burning the whole invocation. */
	return false;
}
