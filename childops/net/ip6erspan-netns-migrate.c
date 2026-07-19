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
 *   (a) userns_run_in_ns(CLONE_NEWNET) forks a transient grandchild into
 *       an owned user namespace + private net namespace ("original
 *       ns").  Steps (b)-(g) run inside that grandchild; its _exit()
 *       tears down both namespaces along with the link, socket and
 *       target-ns FDs left behind.  Helper -EPERM (hardened userns
 *       policy refused CLONE_NEWUSER) latches the whole op off via
 *       ns_unsupported_ip6erspan; transient setup failure (-EAGAIN --
 *       fork, id-map write, secondary unshare) skips the iteration
 *       without latching.
 *   (b) Open AF_NETLINK NETLINK_ROUTE socket; bind.
 *   (c) RTM_NEWLINK creating a link of the rolled kind: nested
 *       IFLA_LINKINFO with IFLA_INFO_KIND=<kind>; nested IFLA_INFO_DATA
 *       holding a small kind-specific attr blob (IFLA_GRE_LOCAL/REMOTE/
 *       LINK + ERSPAN_VER/INDEX for GRE family, IFLA_VXLAN_ID for vxlan,
 *       IFLA_GENEVE_ID for geneve).  EPERM/EOPNOTSUPP/EAFNOSUPPORT/
 *       ENOENT latch ns_unsupported_ip6erspan -- typically a kernel
 *       missing the corresponding tunnel module / erspan ver bits.
 *   (d) unshare(CLONE_NEWNET) again to obtain a fresh sibling
 *       ("target") netns.  This is an intentional in-ns sub-netns
 *       unshare: it runs inside the grandchild's owned user namespace,
 *       where CAP_NET_ADMIN is held, so it succeeds where the
 *       persistent child's bare unshare would EPERM.  The FD dance in
 *       step (e) needs to hold both the original and target ns FDs
 *       simultaneously to pass one as IFLA_NET_NS_FD while the
 *       rtnetlink socket lives in the other, so this call cannot be
 *       delegated to a second userns_run_in_ns() grandchild.  Keep an
 *       FD on the sibling via /proc/self/ns/net opened before
 *       re-entering the original.  setns() back to the original ns so
 *       the rtnetlink socket still talks to the link's current ns.
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
 *                               from create or from setns/unshare; bumps
 *                               inm_ip6erspan_unsupported_observed once
 *                               per child then skip.
 *   ns_unsupported_changelink -- secondary gate; set when NLM_F_REPLACE
 *                                returns -EOPNOTSUPP for any kind so a
 *                                missing changelink op doesn't kill the
 *                                whole childop -- create + migrate +
 *                                teardown still walk.  Bumps
 *                                inm_changelink_unsupported_observed
 *                                once per child first-observation.
 *
 * Self-bounding: one create + migrate + changelink + teardown cycle per
 * invocation; no inner loops over kinds (one kind per outer iter, rolled
 * uniformly).  All rtnetlink I/O carries SO_RCVTIMEO.  Loopback-class
 * activity stays inside private netns FDs.
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
/*
 * UAPI fallbacks.  linux/if_link.h and linux/if_tunnel.h are present on
 * every sysroot trinity targets, but if a stripped build host lacks any
 * of these enum tags the numeric values match the upstream UAPI.  Inline
 * shims rather than a topic-specific compat-iftunnel.h: ~6 LOC total
 * across 2 consumers (this file + the test build), well under the
 * ~30 LOC / 3 consumer threshold for a dedicated kernel fallback header.
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

/* Master gate.  Persistent across iterations in the persistent fuzz
 * child.  Set only when userns_run_in_ns() returns -EPERM (hardened
 * userns policy refused CLONE_NEWUSER -- typically
 * user.max_user_namespaces=0 or kernel.unprivileged_userns_clone=0)
 * or, from inside the grandchild, when create_link EPERM / setns /
 * open-self-netns fails; writes from inside the grandchild only
 * affect the grandchild's own copy and die with _exit(), so the
 * persistent-child latch is authoritatively driven by the outer
 * wrapper's helper-EPERM branch. */
static bool ns_unsupported_ip6erspan;
static bool ns_unsupported_changelink;
static __u32 g_iter;

/* Per-invocation state shared across the extracted phase helpers.
 * nl.fd / target_nl.fd / orig_ns_fd / target_ns_fd default to -1 via
 * the orchestrator's designated initialiser so the teardown helper
 * can close them unconditionally regardless of which earlier phase
 * bailed.  orig_ns_fd is snapshotted at the top of the in-ns callback
 * so migrate/teardown can setns() back into the grandchild's outer
 * netns after step (d) unshares into the sibling.  k + ifname are
 * filled in by setup; ifindex by create_link; target_ns_fd by
 * migrate; migrated flips true once the link has crossed into the
 * target ns, switching teardown from in-orig dellink to
 * setns-back-then-drop-target-ns. */
struct ip6erspan_migrate_iter_ctx {
	struct nl_ctx	nl;
	struct nl_ctx	target_nl;
	enum inm_kind	k;
	int		orig_ns_fd;
	int		target_ns_fd;
	int		ifindex;
	bool		migrated;
	char		ifname[IFNAMSIZ];
	struct childdata *child;
};

static void warn_once_unsupported(struct childdata *child)
{
	if (ns_unsupported_ip6erspan)
		return;
	ns_unsupported_ip6erspan = true;
	/* child->op_type lives in shared memory and can be scribbled by a
	 * poisoned-arena write from a sibling; bounds-check the snapshot
	 * before indexing the NR_CHILD_OP_TYPES-sized stats array, same
	 * pattern the child.c dispatch loop uses. */
	{
		const enum child_op_type op = child->op_type;
		if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
	}
	/* init_child redirected stderr to /dev/null, so an outputerr
	 * here would be lost.  Bump a shm counter under the same
	 * one-shot gate so the unsupported-observation survives. */
	__atomic_add_fetch(&shm->stats.ip6erspan_netns_migrate.ip6erspan_unsupported_observed,
			   1, __ATOMIC_RELAXED);
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
		off = nla_put_u32(buf, off, cap, IFLA_GRE_LINK, 0);
		if (!off) return 0;
		if (inm_kind_is_v6(k)) {
			off = nla_put(buf, off, cap, IFLA_GRE_LOCAL,
				      inm_v6_local, sizeof(inm_v6_local));
			if (!off) return 0;
			off = nla_put(buf, off, cap, IFLA_GRE_REMOTE,
				      inm_v6_remote, sizeof(inm_v6_remote));
			if (!off) return 0;
		} else {
			__u32 local  = htonl(0x7f000001U);
			__u32 remote = htonl(0x7f000002U);
			off = nla_put(buf, off, cap, IFLA_GRE_LOCAL,
				      &local, sizeof(local));
			if (!off) return 0;
			off = nla_put(buf, off, cap, IFLA_GRE_REMOTE,
				      &remote, sizeof(remote));
			if (!off) return 0;
		}
		if (k == INM_KIND_IP6ERSPAN || k == INM_KIND_ERSPAN) {
			__u8  ver   = (rand32() & 1U) ? 2 : 1;
			__u32 index = (rand32() & 0xfffU) + 1U;
			off = nla_put_u8(buf, off, cap,
					 IFLA_GRE_ERSPAN_VER, ver);
			if (!off) return 0;
			off = nla_put_u32(buf, off, cap,
					  IFLA_GRE_ERSPAN_INDEX, index);
			if (!off) return 0;
			if (ver == 2) {
				__u8 hwid = (__u8)(rand32() & 0x3fU);
				off = nla_put_u8(buf, off, cap,
						 IFLA_GRE_ERSPAN_HWID, hwid);
				if (!off) return 0;
				off = nla_put_u8(buf, off, cap,
						 IFLA_GRE_ERSPAN_DIR, 0);
				if (!off) return 0;
			}
		}
		return off;
	}

	if (k == INM_KIND_VXLAN) {
		off = nla_put_u32(buf, off, cap, IFLA_VXLAN_ID,
				  (rand32() & 0xfffffU) + 1U);
		return off;
	}

	if (k == INM_KIND_GENEVE) {
		off = nla_put_u32(buf, off, cap, IFLA_GENEVE_ID,
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
static int inm_create_or_replace(struct nl_ctx *ctx, const char *ifname,
				 enum inm_kind k, bool replace)
{
	unsigned char buf[INM_BUF];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off, li_off, id_off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   (replace ? NLM_F_REPLACE
				    : (NLM_F_CREATE | NLM_F_EXCL));
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, ifname);
	if (!off) return -EIO;

	li_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_LINKINFO);
	if (!off) return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), IFLA_INFO_KIND,
			  inm_kind_names[k]);
	if (!off) return -EIO;
	id_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_INFO_DATA);
	if (!off) return -EIO;

	off = append_kind_info_data(buf, off, sizeof(buf), k);
	if (!off) return -EIO;

	nla_nest_end(buf, id_off, off);
	nla_nest_end(buf, li_off, off);

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * RTM_SETLINK on @ifindex with IFLA_NET_NS_FD = @ns_fd.  Migrates the
 * link into the ns referred to by @ns_fd.  This is the trigger for the
 * dev_net change the upstream commit was about: subsequent changelink
 * messages issued in the target ns must use dev_net(dev) rather than a
 * stale t->net captured at create time.
 */
static int inm_setlink_netns(struct nl_ctx *ctx, int ifindex, int ns_fd)
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

static int inm_dellink(struct nl_ctx *ctx, int ifindex)
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

/*
 * Snapshot the current net ns FD for setns()-back use.  Returned FD is
 * owned by the caller and must be closed.  -1 on failure.
 */
static int inm_open_self_netns(void)
{
	return open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
}

/*
 * Phase 1: pick the per-iteration kind, open the rtnetlink socket
 * pinned to the original ns, and roll the per-link interface name.
 * The kind roll runs ahead of the socket open so a failed nl_open()
 * still consumes the rand32 -- avoids correlated kind selection
 * across siblings that all bail at nl_open().  ifname uses the same
 * 16-bit g_iter suffix the original carried so a long-lived child's
 * traces correlate by suffix.  Returns 0 on success or -1 if the
 * rtnetlink socket could not be opened; the orchestrator goes
 * straight to the unified teardown on -1.
 */
static int ip6erspan_migrate_iter_setup(struct ip6erspan_migrate_iter_ctx *ctx,
					const struct nl_open_opts *opts)
{
	ctx->k = (enum inm_kind)rnd_modulo_u32((unsigned int)INM_KIND_NR);

	if (nl_open(&ctx->nl, opts) < 0)
		return -1;

	/* g_iter is bumped by the outer wrapper before dispatch so each
	 * grandchild sees a distinct suffix -- a fresh COW copy inside
	 * the grandchild would freeze at whatever value the persistent
	 * child last wrote, defeating traceability and starving the
	 * NETDEV name-pool of variety. */
	snprintf(ctx->ifname, sizeof(ctx->ifname), "inm%u",
		 g_iter & 0xffffU);
	return 0;
}

/*
 * Phase 2: RTM_NEWLINK the per-kind link into the original ns and
 * resolve its ifindex.  EPERM latches ns_unsupported_ip6erspan
 * (caps-deficient child / locked-down kernel); ENOENT /
 * EAFNOSUPPORT / EPROTONOSUPPORT / EOPNOTSUPP are the modular-
 * tunnel-missing shapes the upstream rtnetlink layer returns when
 * the kind module isn't loaded -- counted but not fatally latched
 * so the kind roll keeps trying other kinds for this child.  A
 * zero ifindex from if_nametoindex makes every later phase a no-op
 * so we bail to the unified teardown.  Returns 0 on success or -1
 * if the iteration should bail.
 */
static int ip6erspan_migrate_iter_create_link(struct ip6erspan_migrate_iter_ctx *ctx)
{
	int rc;

	rc = inm_create_or_replace(&ctx->nl, ctx->ifname, ctx->k, false);
	if (rc != 0) {
		if (rc == -EPERM) {
			__atomic_add_fetch(&shm->stats.ip6erspan_netns_migrate.eperm,
					   1, __ATOMIC_RELAXED);
			ns_unsupported_ip6erspan = true;
			/* ctx->child->op_type lives in shared memory and can
			 * be scribbled by a poisoned-arena write from a
			 * sibling; bounds-check the snapshot before indexing
			 * the NR_CHILD_OP_TYPES-sized stats array. */
			{
				const enum child_op_type op = ctx->child->op_type;
				if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
					__atomic_store_n(&shm->stats.childop.latch_reason[op],
							 CHILDOP_LATCH_NS_UNSUPPORTED,
							 __ATOMIC_RELAXED);
			}
		} else if (rc == -ENOENT || rc == -EAFNOSUPPORT ||
			   rc == -EPROTONOSUPPORT || rc == -EOPNOTSUPP) {
			__atomic_add_fetch(&shm->stats.ip6erspan_netns_migrate.unsupported,
					   1, __ATOMIC_RELAXED);
		}
		return -1;
	}
	__atomic_add_fetch(&shm->stats.ip6erspan_netns_migrate.link_create_ok, 1, __ATOMIC_RELAXED);

	ctx->ifindex = (int)if_nametoindex(ctx->ifname);
	if (ctx->ifindex <= 0)
		return -1;

	/* Kernel confirmed ctx->ifname now names a real device; publish it
	 * via the NETDEV name pool so sibling childops (and per-syscall
	 * fuzzers drawing this kind) can collide with it on subsequent
	 * invocations -- reaches "name a previous syscall planted" lookup
	 * codepaths instead of always-fresh-random near-miss space. */
	name_pool_record(NAME_KIND_NETDEV, ctx->ifname, strlen(ctx->ifname));

	return 0;
}

/*
 * Phase 3: unshare into a sibling ns, snapshot its FD, setns()
 * back into the original ns (so the rtnetlink socket from setup is
 * still talking to the link's current ns), then RTM_SETLINK
 * IFLA_NET_NS_FD to migrate the link across.  Any failure on the
 * setup of the sibling ns or on the migration setlink latches via
 * warn_once_unsupported and tells the orchestrator to bail to the
 * teardown_orig cleanup path: at that point the link still lives in
 * the original ns and must be RTM_DELLINK'd against ctx->nl.  On
 * the open-self-netns failure path the caller has just re-unshared
 * into the sibling -- mirror the original code's setns()-back so
 * cleanup runs in the original ns even though we don't yet hold the
 * target FD.  On success ctx->migrated flips true; the orchestrator
 * now owes the target ns a setns-back and an FD drop instead of a
 * dellink.  Returns 0 on success or -1 if the iteration should bail
 * to teardown_orig.
 */
static int ip6erspan_migrate_iter_migrate(struct ip6erspan_migrate_iter_ctx *ctx)
{
	int rc;

	/* Intentional in-ns sub-netns unshare -- see file-header step (d).
	 * Runs inside the grandchild's owned user namespace so CAP_NET_ADMIN
	 * is held; cannot be delegated to a second userns_run_in_ns() call
	 * because the FD dance below needs to hold both the outer (original)
	 * and inner (target) netns FDs concurrently. */
	if (unshare(CLONE_NEWNET) < 0) {
		warn_once_unsupported(ctx->child);
		return -1;
	}
	ctx->target_ns_fd = inm_open_self_netns();
	if (ctx->target_ns_fd < 0) {
		warn_once_unsupported(ctx->child);
		(void)setns(ctx->orig_ns_fd, CLONE_NEWNET);
		return -1;
	}
	if (setns(ctx->orig_ns_fd, CLONE_NEWNET) < 0) {
		warn_once_unsupported(ctx->child);
		close(ctx->target_ns_fd);
		ctx->target_ns_fd = -1;
		return -1;
	}

	rc = inm_setlink_netns(&ctx->nl, ctx->ifindex, ctx->target_ns_fd);
	if (rc != 0)
		return -1;
	__atomic_add_fetch(&shm->stats.ip6erspan_netns_migrate.netns_migrate_ok,
			   1, __ATOMIC_RELAXED);
	ctx->migrated = true;
	return 0;
}

/*
 * Phase 4: hop into the target ns, open a fresh rtnetlink socket
 * pinned there, and issue NLM_F_REPLACE -- this is the call that
 * walks the kind's ->changelink op against the post-migration
 * dev_net(dev) (the upstream-CVE shape the whole childop exists
 * to drive).  setns failure latches via warn_once_unsupported and
 * returns early so the orchestrator runs its in-target restore
 * sequence (setns-back-to-orig + drop target_nl/target_ns_fd) --
 * the link has already migrated so this is the right cleanup
 * regardless of whether we ever opened target_nl.
 * EOPNOTSUPP from the replace latches ns_unsupported_changelink
 * once per child (so a kernel without a ->changelink op for any
 * kind still walks create + migrate + teardown).  Best-effort
 * RTM_DELLINK in the target ns at the tail trims the link before
 * the orchestrator drops the target-ns FD so the cleanup_net path
 * doesn't have to do it.
 */
static void ip6erspan_migrate_iter_changelink(struct ip6erspan_migrate_iter_ctx *ctx,
					      const struct nl_open_opts *opts)
{
	int rc;

	if (setns(ctx->target_ns_fd, CLONE_NEWNET) < 0) {
		warn_once_unsupported(ctx->child);
		return;
	}
	if (nl_open(&ctx->target_nl, opts) < 0)
		return;

	rc = inm_create_or_replace(&ctx->target_nl, ctx->ifname, ctx->k, true);
	if (rc == 0) {
		__atomic_add_fetch(&shm->stats.ip6erspan_netns_migrate.changelink_ok,
				   1, __ATOMIC_RELAXED);
	} else if (rc == -EOPNOTSUPP && !ns_unsupported_changelink) {
		ns_unsupported_changelink = true;
		/* init_child redirected stderr to /dev/null, so an
		 * outputerr here would be lost.  Bump a shm counter
		 * under the same one-shot gate so the unsupported-
		 * changelink observation survives. */
		__atomic_add_fetch(&shm->stats.ip6erspan_netns_migrate.changelink_unsupported_observed,
				   1, __ATOMIC_RELAXED);
	}

	(void)inm_dellink(&ctx->target_nl, ctx->ifindex);
}

/*
 * Phase 5: unified teardown.  Runs on every exit path -- both the
 * success path after changelink returns and any early-bail from
 * setup/create_link/migrate.  Branches on ctx->migrated to pick the
 * right cleanup:
 *   migrated=true  -- the link has already crossed into the target
 *                     ns, so setns()-back into the original ns and
 *                     let the target_ns_fd close below trigger
 *                     cleanup_net to drop the link.
 *   migrated=false -- the link still lives in the original ns (or
 *                     was never created); RTM_DELLINK it against
 *                     ctx->nl while we still own the original-ns
 *                     rtnetlink socket.
 * The trailing fd / socket closes are guarded so they're safe
 * regardless of which earlier phase bailed; all three handles
 * default to -1 via the orchestrator's designated initialiser.
 */
static void ip6erspan_migrate_iter_teardown(struct ip6erspan_migrate_iter_ctx *ctx)
{
	if (ctx->migrated) {
		(void)setns(ctx->orig_ns_fd, CLONE_NEWNET);
	} else if (ctx->ifindex > 0 && ctx->nl.fd >= 0) {
		(void)inm_dellink(&ctx->nl, ctx->ifindex);
	}
	if (ctx->target_nl.fd >= 0)
		nl_close(&ctx->target_nl);
	if (ctx->target_ns_fd >= 0)
		close(ctx->target_ns_fd);
	if (ctx->orig_ns_fd >= 0)
		close(ctx->orig_ns_fd);
	if (ctx->nl.fd >= 0)
		nl_close(&ctx->nl);
}

/*
 * Per-invocation body that runs inside the grandchild's private net
 * namespace.  Executed by userns_run_in_ns(CLONE_NEWNET); the
 * grandchild's userns + netns are torn down on _exit() so any link,
 * rtnetlink socket and target-ns FD left behind is reaped along with
 * the namespace.  Explicit teardown is still issued so the in-ns
 * stats counters (inm_link_create_ok etc.) reflect only what actually
 * succeeded and so the target-ns dellink in phase 4 runs before the
 * grandchild dies.  Per-grandchild latch writes to
 * ns_unsupported_ip6erspan die with the grandchild -- helper-EPERM in
 * the outer wrapper is the only signal that survives across
 * iterations.  Return value is ignored by the helper.
 */
static int ip6erspan_netns_migrate_in_ns(void *arg)
{
	struct childdata *child = (struct childdata *)arg;
	struct ip6erspan_migrate_iter_ctx ictx = {
		.nl = { .fd = -1 },
		.target_nl = { .fd = -1 },
		.orig_ns_fd = -1,
		.target_ns_fd = -1,
		.child = child,
	};
	struct nl_open_opts opts = {
		.proto = NETLINK_ROUTE,
		.recv_timeo_s = 1,
	};

	ictx.orig_ns_fd = inm_open_self_netns();
	if (ictx.orig_ns_fd < 0) {
		warn_once_unsupported(child);
		return 0;
	}

	if (ip6erspan_migrate_iter_setup(&ictx, &opts) != 0)
		goto out;

	if (ip6erspan_migrate_iter_create_link(&ictx) != 0)
		goto out;

	if (ip6erspan_migrate_iter_migrate(&ictx) != 0)
		goto out;
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot. */
	{
		const enum child_op_type op = child->op_type;
		const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

		if (valid_op) {
			__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
					   1, __ATOMIC_RELAXED);
			__atomic_add_fetch(&shm->stats.childop.data_path[op],
					   1, __ATOMIC_RELAXED);
		}
	}
	ip6erspan_migrate_iter_changelink(&ictx, &opts);

out:
	ip6erspan_migrate_iter_teardown(&ictx);
	return 0;
}

bool ip6erspan_netns_migrate(struct childdata *child)
{
	int rc;

	__atomic_add_fetch(&shm->stats.ip6erspan_netns_migrate.iters, 1, __ATOMIC_RELAXED);

	if (ns_unsupported_ip6erspan)
		return true;

	g_iter++;
	rc = userns_run_in_ns(CLONE_NEWNET, ip6erspan_netns_migrate_in_ns,
			      child);
	if (rc == -EPERM) {
		warn_once_unsupported(child);
		__atomic_add_fetch(&shm->stats.ip6erspan_netns_migrate.eperm, 1, __ATOMIC_RELAXED);
		return true;
	}
	if (rc < 0) {
		/* Transient grandchild setup failure (fork, id-map write,
		 * secondary unshare).  Skip this iteration without latching
		 * -- the failure is not policy and may not recur. */
		return true;
	}

	return true;
}
