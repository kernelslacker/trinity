/*
 * netdev_netns_migrate - churn cross-netns migration of a virtual
 * netdev between two sibling user-namespace-owned network namespaces.
 *
 * Generalises the single-shot ip6erspan_netns_migrate shape into a
 * lifetime-oriented pattern over the netdev types most likely to
 * surface refcount / lifetime bugs when RTM_SETLINK IFLA_NET_NS_FD
 * hands the device between namespaces.  The failure class we're after
 * is any per-netdev state (per-net hash entries, per-netdev sockets
 * held by drivers, cached dev_net(dev) pointers) that a ->dellink /
 * ->exit_batch pernet hook thinks still belongs to the original ns
 * after the device has moved.
 *
 * Per iteration:
 *   (a) userns_run_in_ns(CLONE_NEWNET) forks a transient grandchild
 *       into an owned user namespace + private net namespace ("source
 *       ns").  All later steps run inside that grandchild; its
 *       _exit() reaps every namespace, link, socket and ns FD left
 *       behind.  Helper -EPERM latches the whole op via
 *       ns_unsupported_netdev_migrate; transient setup failure
 *       (-EAGAIN) skips the iter without latching.
 *   (b) Snapshot the source-ns FD.  Open an AF_INET SOCK_DGRAM
 *       socket bound to INADDR_ANY -- the socket is pinned to the
 *       source ns and stays pinned across the netdev's move (a
 *       socket does NOT migrate with setns()+rebind; that is the
 *       point).  It holds a reference the migrating device path
 *       must survive around.
 *   (c) Open a NETLINK_ROUTE rtnl socket in the source ns.  Roll a
 *       kind (veth / vxlan / gretap) and RTM_NEWLINK it with the
 *       kind-specific IFLA_INFO_DATA envelope.  ENOENT /
 *       EAFNOSUPPORT / EPROTONOSUPPORT / EOPNOTSUPP is a missing
 *       kind module -- counted, not fatally latched, so the next
 *       iter can try a different kind.  EPERM latches the master
 *       gate (caps-deficient child / locked-down kernel).
 *   (d) unshare(CLONE_NEWNET) again inside the grandchild's owned
 *       user namespace to obtain a fresh sibling ("target") netns.
 *       CAP_NET_ADMIN is held here; the FD dance below needs both
 *       source and target ns FDs held concurrently to pass one as
 *       IFLA_NET_NS_FD while the rtnl socket lives in the other, so
 *       this cannot be delegated to a second userns_run_in_ns()
 *       grandchild.  setns() back into the source ns so the rtnl
 *       socket from (c) still talks to the link's current ns.
 *   (e) RTM_SETLINK on the link with IFLA_NET_NS_FD pointing at the
 *       target ns FD -- migrates the device across.  Best-effort
 *       recvfrom() on the pinned source-ns socket right after,
 *       proving it still resolves against the source ns even though
 *       the device it named has moved.
 *   (f) setns() into the target ns; open a fresh rtnl socket there.
 *       RTM_SETLINK ifi_flags=IFF_UP + RTM_NEWADDR 127.0.0.<n>/24
 *       to bring the migrated device up and give it an address --
 *       this drives the per-netdev state that any stale dev_net
 *       pointer would resolve wrong.  IFF_UP failure latches
 *       ns_unsupported_drive once (bring-up refused by the kernel
 *       for the kind -- keep going for other kinds).  Best-effort
 *       RTM_DELLINK in the target ns at the tail so cleanup_net
 *       does not have to walk the device.
 *   (g) setns() back to the source ns for the unified teardown.
 *
 * Bounds: BUDGETED outer loop (base 2, small; each iter opens a
 * userns + private netns and issues four rtnl round-trips).  Every
 * rtnl socket carries SO_RCVTIMEO so a lost ACK never wedges.  All
 * work stays inside the grandchild's private user + net namespaces.
 */

#include <errno.h>
#include <net/if.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/if_link.h>
#include <linux/if_tunnel.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/veth.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>

#include "child.h"
#include "childops-netlink.h"
#include "name-pool.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "userns-bootstrap.h"
#include "utils.h"

#include "kernel/fcntl.h"

/* UAPI fallbacks.  Same rationale as the ip6erspan_netns_migrate
 * exemplar: numeric values match upstream if a stripped sysroot lacks
 * the symbol; inline shims stay under the ~30 LOC / 3 consumer
 * threshold for a dedicated compat header. */
#ifndef IFLA_NET_NS_FD
#define IFLA_NET_NS_FD			28
#endif

#ifndef IFLA_GRE_LINK
#define IFLA_GRE_LINK			1
#define IFLA_GRE_LOCAL			5
#define IFLA_GRE_REMOTE			6
#endif

#ifndef IFLA_VXLAN_ID
#define IFLA_VXLAN_ID			1
#endif

#define NNM_BUF				1024
#define NNM_OUTER_BASE			2U

enum nnm_kind {
	NNM_KIND_VETH,
	NNM_KIND_VXLAN,
	NNM_KIND_GRETAP,
	NNM_KIND_NR,
};

static const char * const nnm_kind_names[NNM_KIND_NR] = {
	[NNM_KIND_VETH]		= "veth",
	[NNM_KIND_VXLAN]	= "vxlan",
	[NNM_KIND_GRETAP]	= "gretap",
};

/* Master gate.  Persistent across iterations in the persistent fuzz
 * child.  Set only when userns_run_in_ns() returns -EPERM (hardened
 * userns policy refused CLONE_NEWUSER -- user.max_user_namespaces=0
 * or kernel.unprivileged_userns_clone=0) or on EPERM from the initial
 * RTM_NEWLINK inside the grandchild.  Writes from inside the
 * grandchild only affect the grandchild's COW copy, so the
 * persistent-child latch is authoritatively driven by the outer
 * wrapper's helper-EPERM branch. */
static bool ns_unsupported_netdev_migrate;
/* Secondary gate: post-migration IFF_UP returned EOPNOTSUPP for the
 * rolled kind.  Bump inm_drive_unsupported_observed once per child
 * so a missing bring-up path doesn't kill the whole childop -- create
 * + migrate + teardown still walk. */
static bool ns_unsupported_drive;
static __u32 g_iter;

struct nnm_iter_ctx {
	struct nl_ctx	src_nl;
	struct nl_ctx	tgt_nl;
	enum nnm_kind	k;
	int		src_ns_fd;
	int		tgt_ns_fd;
	int		pin_sock;	/* AF_INET dgram held in source ns */
	int		ifindex;
	bool		migrated;
	char		ifname[IFNAMSIZ];
	char		peer_ifname[IFNAMSIZ];	/* veth only */
	struct childdata *child;
};

static void latch_master(struct childdata *child)
{
	if (ns_unsupported_netdev_migrate)
		return;
	ns_unsupported_netdev_migrate = true;
	{
		const enum child_op_type op = child->op_type;
		if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
	}
	__atomic_add_fetch(&shm->stats.nnm_unsupported_observed,
			   1, __ATOMIC_RELAXED);
}

/* Append the per-kind IFLA_INFO_DATA payload.  veth carries a nested
 * VETH_INFO_PEER holding a peer ifinfomsg + IFLA_IFNAME.  vxlan takes
 * a single u32 VNI.  gretap takes IFLA_GRE_LINK plus IPv4 local /
 * remote so the tunnel resolves against the loopback route the new
 * ns' pernet init installs.  Caller wraps this in the surrounding
 * IFLA_INFO_DATA + IFLA_LINKINFO nest. */
static size_t nnm_append_info_data(unsigned char *buf, size_t off, size_t cap,
				   enum nnm_kind k, const char *peer_name)
{
	if (k == NNM_KIND_VETH) {
		struct ifinfomsg *peer_ifi;
		size_t peer_off = off;

		off = nla_nest_start(buf, off, cap, VETH_INFO_PEER);
		if (!off) return 0;
		if (off + NLMSG_ALIGN(sizeof(*peer_ifi)) > cap)
			return 0;
		peer_ifi = (struct ifinfomsg *)(buf + off);
		memset(peer_ifi, 0, sizeof(*peer_ifi));
		peer_ifi->ifi_family = AF_UNSPEC;
		off += NLMSG_ALIGN(sizeof(*peer_ifi));
		off = nla_put_str(buf, off, cap, IFLA_IFNAME, peer_name);
		if (!off) return 0;
		nla_nest_end(buf, peer_off, off);
		return off;
	}

	if (k == NNM_KIND_VXLAN) {
		return nla_put_u32(buf, off, cap, IFLA_VXLAN_ID,
				   (rand32() & 0xfffffU) + 1U);
	}

	/* gretap */
	{
		__u32 local  = htonl(0x7f000001U);
		__u32 remote = htonl(0x7f000002U);

		off = nla_put_u32(buf, off, cap, IFLA_GRE_LINK, 0);
		if (!off) return 0;
		off = nla_put(buf, off, cap, IFLA_GRE_LOCAL,
			      &local, sizeof(local));
		if (!off) return 0;
		off = nla_put(buf, off, cap, IFLA_GRE_REMOTE,
			      &remote, sizeof(remote));
		if (!off) return 0;
		return off;
	}
}

static int nnm_create_link(struct nl_ctx *ctx, struct nnm_iter_ctx *ictx)
{
	unsigned char buf[NNM_BUF];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off, li_off, id_off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, ictx->ifname);
	if (!off) return -EIO;

	li_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_LINKINFO);
	if (!off) return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), IFLA_INFO_KIND,
			  nnm_kind_names[ictx->k]);
	if (!off) return -EIO;
	id_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_INFO_DATA);
	if (!off) return -EIO;

	off = nnm_append_info_data(buf, off, sizeof(buf), ictx->k,
				   ictx->peer_ifname);
	if (!off) return -EIO;

	nla_nest_end(buf, id_off, off);
	nla_nest_end(buf, li_off, off);

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

static int nnm_setlink_netns(struct nl_ctx *ctx, int ifindex, int ns_fd)
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
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = ifindex;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));
	off = nla_put(buf, off, sizeof(buf), IFLA_NET_NS_FD,
		      &fdval, sizeof(fdval));
	if (!off) return -EIO;
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

static int nnm_setlink_up(struct nl_ctx *ctx, int ifindex)
{
	unsigned char buf[128];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = ifindex;
	ifi->ifi_flags  = IFF_UP;
	ifi->ifi_change = IFF_UP;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

static int nnm_newaddr_v4(struct nl_ctx *ctx, int ifindex, __u8 last_octet)
{
	unsigned char buf[128];
	struct nlmsghdr *nlh;
	struct ifaddrmsg *ifa;
	size_t off;
	__u32 addr = htonl(0x7f000000U | (__u32)last_octet);

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWADDR;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifa = (struct ifaddrmsg *)NLMSG_DATA(nlh);
	ifa->ifa_family    = AF_INET;
	ifa->ifa_prefixlen = 24;
	ifa->ifa_flags     = 0;
	ifa->ifa_scope     = 0;
	ifa->ifa_index     = (unsigned int)ifindex;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifa));
	off = nla_put(buf, off, sizeof(buf), IFA_LOCAL, &addr, sizeof(addr));
	if (!off) return -EIO;
	off = nla_put(buf, off, sizeof(buf), IFA_ADDRESS, &addr, sizeof(addr));
	if (!off) return -EIO;
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

static int nnm_dellink(struct nl_ctx *ctx, int ifindex)
{
	unsigned char buf[64];
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
	ifi->ifi_index  = ifindex;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

static int nnm_open_self_netns(void)
{
	return open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
}

/* Pin an AF_INET SOCK_DGRAM socket into the source ns.  Bind is
 * best-effort -- an unbound socket still resolves against the ns it
 * was created in, which is the invariant the rest of the op relies
 * on (the socket does NOT follow the migrating netdev).  Returns
 * a valid fd or -1 with errno preserved. */
static int nnm_pin_source_socket(void)
{
	struct sockaddr_in sin;
	int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_port = 0;
	(void)bind(fd, (struct sockaddr *)&sin, sizeof(sin));
	return fd;
}

static int nnm_iter_setup(struct nnm_iter_ctx *ctx,
			  const struct nl_open_opts *opts)
{
	ctx->k = (enum nnm_kind)rnd_modulo_u32((unsigned int)NNM_KIND_NR);
	snprintf(ctx->ifname, sizeof(ctx->ifname), "nnm%u",
		 g_iter & 0xffffU);
	snprintf(ctx->peer_ifname, sizeof(ctx->peer_ifname), "nnp%u",
		 g_iter & 0xffffU);

	ctx->pin_sock = nnm_pin_source_socket();
	if (ctx->pin_sock >= 0)
		__atomic_add_fetch(&shm->stats.nnm_pin_sock_ok,
				   1, __ATOMIC_RELAXED);

	if (nl_open(&ctx->src_nl, opts) < 0)
		return -1;
	return 0;
}

static int nnm_iter_create(struct nnm_iter_ctx *ctx)
{
	int rc = nnm_create_link(&ctx->src_nl, ctx);

	if (rc != 0) {
		if (rc == -EPERM) {
			__atomic_add_fetch(&shm->stats.nnm_eperm,
					   1, __ATOMIC_RELAXED);
			latch_master(ctx->child);
		} else if (rc == -ENOENT || rc == -EAFNOSUPPORT ||
			   rc == -EPROTONOSUPPORT || rc == -EOPNOTSUPP) {
			__atomic_add_fetch(&shm->stats.nnm_unsupported,
					   1, __ATOMIC_RELAXED);
		}
		return -1;
	}
	__atomic_add_fetch(&shm->stats.nnm_link_create_ok, 1, __ATOMIC_RELAXED);

	ctx->ifindex = (int)if_nametoindex(ctx->ifname);
	if (ctx->ifindex <= 0)
		return -1;
	name_pool_record(NAME_KIND_NETDEV, ctx->ifname, strlen(ctx->ifname));
	return 0;
}

static int nnm_iter_migrate(struct nnm_iter_ctx *ctx)
{
	int rc;

	/* Intentional in-ns sub-netns unshare -- runs inside the
	 * grandchild's owned user namespace where CAP_NET_ADMIN is
	 * held.  Cannot be delegated to a second userns_run_in_ns()
	 * because the FD dance needs both source and target ns FDs
	 * held concurrently. */
	if (unshare(CLONE_NEWNET) < 0) {
		latch_master(ctx->child);
		return -1;
	}
	ctx->tgt_ns_fd = nnm_open_self_netns();
	if (ctx->tgt_ns_fd < 0) {
		(void)setns(ctx->src_ns_fd, CLONE_NEWNET);
		latch_master(ctx->child);
		return -1;
	}
	if (setns(ctx->src_ns_fd, CLONE_NEWNET) < 0) {
		close(ctx->tgt_ns_fd);
		ctx->tgt_ns_fd = -1;
		latch_master(ctx->child);
		return -1;
	}

	rc = nnm_setlink_netns(&ctx->src_nl, ctx->ifindex, ctx->tgt_ns_fd);
	if (rc != 0) {
		if (rc == -EOPNOTSUPP || rc == -EINVAL)
			__atomic_add_fetch(&shm->stats.nnm_migrate_rejected,
					   1, __ATOMIC_RELAXED);
		return -1;
	}
	__atomic_add_fetch(&shm->stats.nnm_migrate_ok, 1, __ATOMIC_RELAXED);
	ctx->migrated = true;

	/* Best-effort read on the pinned source-ns socket.  Nothing
	 * has sent to it; the point is that it still resolves against
	 * the source ns even after the netdev it named has moved.  A
	 * kernel bug that dropped the source ns' ref on migration
	 * could unbind or invalidate the socket -- the failure would
	 * surface as a recvfrom() return of -1/EBADF/ENOTCONN rather
	 * than the expected -1/EAGAIN. */
	if (ctx->pin_sock >= 0) {
		char scratch[16];
		(void)recv(ctx->pin_sock, scratch, sizeof(scratch),
			   MSG_DONTWAIT);
	}
	return 0;
}

static void nnm_iter_drive_target(struct nnm_iter_ctx *ctx,
				  const struct nl_open_opts *opts)
{
	int rc;

	if (setns(ctx->tgt_ns_fd, CLONE_NEWNET) < 0) {
		latch_master(ctx->child);
		return;
	}
	if (nl_open(&ctx->tgt_nl, opts) < 0)
		return;

	rc = nnm_setlink_up(&ctx->tgt_nl, ctx->ifindex);
	if (rc == 0) {
		__atomic_add_fetch(&shm->stats.nnm_up_ok,
				   1, __ATOMIC_RELAXED);
	} else if (rc == -EOPNOTSUPP && !ns_unsupported_drive) {
		ns_unsupported_drive = true;
		__atomic_add_fetch(&shm->stats.nnm_drive_unsupported_observed,
				   1, __ATOMIC_RELAXED);
	}

	rc = nnm_newaddr_v4(&ctx->tgt_nl, ctx->ifindex,
			    (__u8)(1U + (g_iter & 0x3fU)));
	if (rc == 0)
		__atomic_add_fetch(&shm->stats.nnm_addr_ok,
				   1, __ATOMIC_RELAXED);

	(void)nnm_dellink(&ctx->tgt_nl, ctx->ifindex);
}

static void nnm_iter_teardown(struct nnm_iter_ctx *ctx)
{
	if (ctx->migrated) {
		(void)setns(ctx->src_ns_fd, CLONE_NEWNET);
	} else if (ctx->ifindex > 0 && ctx->src_nl.fd >= 0) {
		(void)nnm_dellink(&ctx->src_nl, ctx->ifindex);
	}
	if (ctx->tgt_nl.fd >= 0)
		nl_close(&ctx->tgt_nl);
	if (ctx->tgt_ns_fd >= 0)
		close(ctx->tgt_ns_fd);
	if (ctx->pin_sock >= 0)
		close(ctx->pin_sock);
	if (ctx->src_ns_fd >= 0)
		close(ctx->src_ns_fd);
	if (ctx->src_nl.fd >= 0)
		nl_close(&ctx->src_nl);
}

static int netdev_netns_migrate_in_ns(void *arg)
{
	struct childdata *child = (struct childdata *)arg;
	struct nnm_iter_ctx ictx = {
		.src_nl = NL_CTX_INIT,
		.tgt_nl = NL_CTX_INIT,
		.src_ns_fd = -1,
		.tgt_ns_fd = -1,
		.pin_sock = -1,
		.child = child,
	};
	struct nl_open_opts opts = {
		.proto = NETLINK_ROUTE,
		.recv_timeo_s = 1,
	};

	ictx.src_ns_fd = nnm_open_self_netns();
	if (ictx.src_ns_fd < 0) {
		latch_master(child);
		return 0;
	}

	if (nnm_iter_setup(&ictx, &opts) != 0)
		goto out;
	if (nnm_iter_create(&ictx) != 0)
		goto out;
	if (nnm_iter_migrate(&ictx) != 0)
		goto out;
	{
		const enum child_op_type op = child->op_type;
		if ((int) op >= 0 && op < NR_CHILD_OP_TYPES) {
			__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
					   1, __ATOMIC_RELAXED);
			__atomic_add_fetch(&shm->stats.childop.data_path[op],
					   1, __ATOMIC_RELAXED);
		}
	}
	nnm_iter_drive_target(&ictx, &opts);

out:
	nnm_iter_teardown(&ictx);
	return 0;
}

bool netdev_netns_migrate(struct childdata *child)
{
	unsigned int iters, i;

	__atomic_add_fetch(&shm->stats.nnm_iters, 1, __ATOMIC_RELAXED);

	if (ns_unsupported_netdev_migrate)
		return true;

	iters = BUDGETED(CHILD_OP_NETDEV_NETNS_MIGRATE, NNM_OUTER_BASE);
	if (iters == 0)
		iters = 1;

	for (i = 0; i < iters; i++) {
		int rc;

		g_iter++;
		rc = userns_run_in_ns(CLONE_NEWNET,
				      netdev_netns_migrate_in_ns, child);
		if (rc == -EPERM) {
			latch_master(child);
			__atomic_add_fetch(&shm->stats.nnm_eperm,
					   1, __ATOMIC_RELAXED);
			return true;
		}
		if (rc < 0) {
			/* Transient grandchild setup failure -- skip
			 * this iter without latching, the failure is
			 * not policy and may not recur. */
			continue;
		}
		if (ns_unsupported_netdev_migrate)
			return true;
	}

	return true;
}
