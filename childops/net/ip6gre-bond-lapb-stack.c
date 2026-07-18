/*
 * ip6gre_bond_lapb_stack - exercise the lapb data-transmit path against a
 * bond device whose first slave is an ip6gre tunnel.  The bug shape is a
 * device-stacking pathological combo: the bond inherits its slave's
 * header_ops on enslave (bond_setup_by_slave), so once an ip6gre slave is
 * attached the bond's ->header_ops->create dispatches into ip6gre_header.
 * The lapb upper layer reaches that hard_header via lapbeth_data_transmit
 * -> dev_hard_header(lapbeth->ethdev, ETH_P_DEC, bcast_addr, ...) on the
 * bond.  ip6gre_header expects callers that have reserved enough headroom
 * for the GRE header it pushes onto the skb; lapbeth has only pushed a
 * single X25_IFACE_DATA byte, so the GRE write underflows the skb head
 * and scribbles globally-allocated memory adjacent to the SKB allocator
 * arena.  upstream CI trace:
 *
 *   __dev_notify_flags
 *     -> lapb_device_event
 *       -> lapb_establish_data_link
 *         -> lapb_transmit_buffer
 *           -> lapb_data_transmit  (lapbeth_data_transmit upstream)
 *             -> dev_hard_header(bond, ...)
 *               -> bond_header_create
 *                 -> ip6gre_header   <-- global-OOB
 *
 * Sequence (per invocation, all inside a private netns):
 *   1. userns_run_in_ns(CLONE_NEWNET) forks a transient grandchild into
 *      an owned user namespace + private net namespace.  The whole
 *      sequence below runs inside that grandchild; _exit() tears down
 *      both namespaces along with any bond / gre / lapb device left
 *      behind, so no host link is touched.  Helper -EPERM (hardened
 *      userns policy refused CLONE_NEWUSER) latches the whole op off;
 *      transient setup failure (-EAGAIN) skips the iteration without
 *      latching.
 *   2. RTM_NEWLINK type=bond name=bondN.  bond is ARPHRD_ETHER at create
 *      time, so lapbether's NETDEV_REGISTER notifier auto-creates the
 *      paired lapb%d (typically "lapb0" in a fresh netns).
 *   3. RTM_NEWLINK type=ip6gre name=gre6N with v6 local/remote endpoints.
 *   4. RTM_SETLINK IFLA_MASTER=bondN_idx on gre6N -- enslaves the tunnel
 *      to the bond.  bond_enslave's first-slave path picks up the slave's
 *      header_ops, so bond->header_ops->create now dispatches to
 *      ip6gre_header.
 *   5. RTM_SETLINK ifi_flags=IFF_UP on the auto-created lapb device --
 *      __dev_notify_flags -> lapb notifier chain -> lapb_establish_data_link
 *      -> SABME transmit -> lapbeth_data_transmit -> bond_header_create
 *      -> ip6gre_header on a skb with insufficient headroom.
 *   6. RTM_SETLINK ifi_flags=0 (IFF_DOWN) on the same lapb -- runs the
 *      teardown half of the establish/release races.  Repeated UP/DOWN
 *      cycles inside one invocation widen the data-transmit window.
 *
 * Latches: a single g_unsupported flag is set on the first
 * EAFNOSUPPORT/ENODEV/ENETDOWN/EOPNOTSUPP/EPROTONOSUPPORT from the
 * unshare or the first NEWLINK -- a kernel without CONFIG_BONDING /
 * CONFIG_IP6_GRE / CONFIG_LAPB / lapbether pays one cheap rtnetlink
 * round-trip per invocation thereafter and bails at the gate.  This op
 * is dormant-by-default precisely because none of those configs are in
 * the standard fuzz config; a fleet that flips bonding/ip6gre/lapb on
 * gets coverage of the device-stacking shape without breaking the
 * default-config run.
 *
 * Generalises beyond just this single bug: any pair of (lower-layer
 * pseudo-device with a non-Ethernet header_ops) + (aggregating device
 * that inherits its slave's header_ops on enslave) + (upper-layer
 * driver that calls dev_hard_header on the aggregator with insufficient
 * headroom) hits the same shape.  Bond+ip6gre+lapb is the first known
 * crashing instance; the same childop framework will pick up future
 * (team|bridge|...) + (tunnel|wireguard|...) + (lapb|x25|...) variants
 * by extending the kind tables here.
 *
 * Self-bounding: one bond + one ip6gre + a small UP/DOWN cycle count per
 * invocation; no inner loops over kinds.  All rtnetlink I/O carries
 * SO_RCVTIMEO so an unresponsive netlink can't wedge us past the
 * SIGALRM(1s) cap inherited from child.c.  Loopback only (private netns).
 */

#include <errno.h>
#include <net/if.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>

#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <stdio.h>
#include <string.h>

#include "child.h"
#include "childops-netlink.h"
#include "name-pool.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"
#include "userns-bootstrap.h"

#ifndef IFLA_GRE_LINK
#define IFLA_GRE_LINK		1
#define IFLA_GRE_LOCAL		5
#define IFLA_GRE_REMOTE		6
#endif

#define IBLS_BUF_BYTES		1024
#define IBLS_FLAG_CYCLES_BASE	3U
#define IBLS_FLAG_CYCLES_CAP	8U

/* ::1 / ::2 -- loopback-class endpoints; the bug fires on header build,
 * never reaches the wire. */
static const __u8 ibls_v6_local[16] = {
	0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1,
};
static const __u8 ibls_v6_remote[16] = {
	0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,2,
};

/* Per-grandchild latch.  Inherited as false at grandchild fork time
 * (the persistent child never writes it -- the in-ns callback runs
 * exclusively in transient grandchildren) and flipped on the first
 * CONFIG-absent rejection from one of the bond / ip6gre / lapbether
 * subsystems.  Dies with the grandchild on _exit(); the next grand-
 * child re-discovers the latch in its own fresh netns.  The
 * EAFNOSUPPORT / ENODEV / EOPNOTSUPP / EPROTONOSUPPORT detection
 * arms are preserved because a fresh user namespace cannot
 * manufacture an absent kernel CONFIG -- the gate still short-
 * circuits the rest of the grandchild's iteration once it fires. */
static bool g_unsupported;

/* Master gate: persistent across iterations in the persistent child.
 * Set when userns_run_in_ns returns -EPERM (hardened userns policy
 * refused CLONE_NEWUSER -- typically user.max_user_namespaces=0 or
 * kernel.unprivileged_userns_clone=0).  The per-grandchild gate
 * above dies with the grandchild; helper-EPERM is the only signal
 * that survives long enough to short-circuit subsequent invocations. */
static bool g_ns_unsupported;

static __u32 g_iter;

static void warn_once_unsupported_ip6gre_lapb(const char *reason, int err)
{
	if (g_ns_unsupported)
		return;
	g_ns_unsupported = true;
	outputerr("ip6gre_bond_lapb_stack: %s failed (errno=%d), latching unsupported_ns\n",
		  reason, err);
}

static void latch_unsupported(int op_type, const char *reason, int err)
{
	if (g_unsupported)
		return;
	g_unsupported = true;
	outputerr("ip6gre_bond_lapb_stack: %s failed (errno=%d), latching unsupported\n",
		  reason, err);
	/* op_type originates in shared memory (child->op_type) and can be
	 * scribbled by a poisoned-arena write from a sibling; bounds-check
	 * the snapshot before indexing the NR_CHILD_OP_TYPES-sized stats
	 * array, same pattern the child.c dispatch loop uses for the
	 * unguarded write that motivated this guard. */
	{
		const enum child_op_type op = op_type;
		if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_UNSUPPORTED,
					 __ATOMIC_RELAXED);
	}
}

/* errnos that mean "kernel cannot do this op shape on this build" --
 * latch the whole op off so subsequent invocations bail cheaply. */
static bool err_is_unsupported(int rc)
{
	return rc == -EAFNOSUPPORT || rc == -ENODEV ||
	       rc == -ENETDOWN     || rc == -EOPNOTSUPP ||
	       rc == -EPROTONOSUPPORT;
}

/*
 * RTM_NEWLINK with IFLA_LINKINFO carrying IFLA_INFO_KIND=@kind and an
 * optional kind-specific IFLA_INFO_DATA blob built by @append_data
 * (NULL for kinds that don't need one).  Same envelope across kinds so
 * the call sites stay short.
 */
typedef size_t (*ibls_data_fn)(unsigned char *buf, size_t off, size_t cap);

static int ibls_newlink(struct nl_ctx *ctx, const char *ifname, const char *kind,
			ibls_data_fn append_data)
{
	unsigned char buf[IBLS_BUF_BYTES];
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

	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, ifname);
	if (!off) return -EIO;

	li_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_LINKINFO);
	if (!off) return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), IFLA_INFO_KIND, kind);
	if (!off) return -EIO;

	if (append_data) {
		id_off = off;
		off = nla_nest_start(buf, off, sizeof(buf), IFLA_INFO_DATA);
		if (!off) return -EIO;
		off = append_data(buf, off, sizeof(buf));
		if (!off) return -EIO;
		nla_nest_end(buf, id_off, off);
	}

	nla_nest_end(buf, li_off, off);
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

static size_t append_ip6gre_data(unsigned char *buf, size_t off, size_t cap)
{
	off = nla_put_u32(buf, off, cap, IFLA_GRE_LINK, 0);
	if (!off) return 0;
	off = nla_put(buf, off, cap, IFLA_GRE_LOCAL,
		      ibls_v6_local, sizeof(ibls_v6_local));
	if (!off) return 0;
	off = nla_put(buf, off, cap, IFLA_GRE_REMOTE,
		      ibls_v6_remote, sizeof(ibls_v6_remote));
	return off;
}

/*
 * RTM_SETLINK on @ifindex.  When @master_ifindex > 0 the message carries
 * IFLA_MASTER for the enslave step; @flags / @change drive ifi_flags /
 * ifi_change for the IFF_UP / IFF_DOWN cycles on the lapb dev.
 */
static int ibls_setlink(struct nl_ctx *ctx, int ifindex, int master_ifindex,
			__u32 flags, __u32 change)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_SETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);
	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = ifindex;
	ifi->ifi_flags  = flags;
	ifi->ifi_change = change;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	if (master_ifindex > 0) {
		off = nla_put_u32(buf, off, sizeof(buf), IFLA_MASTER,
				  (__u32)master_ifindex);
		if (!off) return -EIO;
	}
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

static int ibls_dellink(struct nl_ctx *ctx, int ifindex)
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
 * Locate the lapb%d device that lapbether's NETDEV_REGISTER notifier
 * auto-created when the bond was added.  In a fresh netns the index
 * starts at 0; we sweep a small range so a kernel that picked a higher
 * suffix (rare but possible if the lapbether module had churn before
 * unshare) still resolves.
 */
static int find_lapb_ifindex(void)
{
	char name[IFNAMSIZ];
	unsigned int i;
	int idx;

	for (i = 0; i < 8; i++) {
		snprintf(name, sizeof(name), "lapb%u", i);
		idx = (int)if_nametoindex(name);
		if (idx > 0)
			return idx;
	}
	return 0;
}

/*
 * Per-invocation state shared across the ip6gre_lapb_iter_* helpers
 * below.  ctx.fd defaults to -1 via the orchestrator's designated
 * initialiser so the teardown helper can close it unconditionally
 * regardless of which earlier phase bailed; bond_idx / gre_idx default
 * to 0 so teardown's per-link RTM_DELLINK gates skip work that was
 * never set up.  bond_name / gre_name are filled in by the netlink-open
 * phase and consumed by the per-link create phases.
 */
struct ip6gre_lapb_iter_ctx {
	struct nl_ctx	ctx;
	int		bond_idx;
	int		gre_idx;
	char		bond_name[IFNAMSIZ];
	char		gre_name[IFNAMSIZ];
	struct childdata *child;
};

/*
 * Phase: open the rtnetlink fd into ctx->ctx and roll the
 * per-iteration bond/gre device names off g_iter.  The netns itself
 * is set up by userns_run_in_ns() before the in-ns callback runs, so
 * this helper only has to bring up the rtnetlink fd subsequent
 * phases batch link work over.  nl_open failure has no fd to clean
 * up (the orchestrator's out: cleanup only runs once ctx.fd >= 0),
 * so a failure here also wants to return immediately rather than
 * goto out.  Returns 0 on success; -1 means caller should return
 * immediately.
 */
static int ip6gre_lapb_iter_open_netlink(struct ip6gre_lapb_iter_ctx *ctx)
{
	struct nl_open_opts opts = {
		.proto = NETLINK_ROUTE,
		.recv_timeo_s = 1,
	};

	if (nl_open(&ctx->ctx, &opts) < 0) {
		__atomic_add_fetch(&shm->stats.ip6gre_lapb.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}

	g_iter++;
	snprintf(ctx->bond_name, sizeof(ctx->bond_name), "ibls_b%u",
		 g_iter & 0xffffU);
	snprintf(ctx->gre_name,  sizeof(ctx->gre_name),  "ibls_g%u",
		 g_iter & 0xffffU);

	return 0;
}

/*
 * Phase: RTM_NEWLINK type=bond and ifindex resolution.  Creating the
 * bond also auto-creates the paired lapb%d via lapbether's
 * NETDEV_REGISTER notifier, so this single helper produces both the
 * bond device the later enslave targets and the lapb device the flag-
 * cycles phase drives.  Latches g_unsupported on the
 * EAFNOSUPPORT/EOPNOTSUPP/EPROTONOSUPPORT shape of CONFIG_BONDING
 * absence so subsequent invocations bail at the gate.  Returns 0 on
 * success; -1 means caller should goto out -- the netlink fd is open
 * and needs the teardown helper to close it.
 */
static int ip6gre_lapb_iter_create_bond(struct ip6gre_lapb_iter_ctx *ctx)
{
	int rc;

	rc = ibls_newlink(&ctx->ctx, ctx->bond_name, "bond", NULL);
	if (rc != 0) {
		if (err_is_unsupported(rc))
			latch_unsupported(ctx->child->op_type,
					  "NEWLINK type=bond", -rc);
		__atomic_add_fetch(&shm->stats.ip6gre_lapb.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	ctx->bond_idx = (int)if_nametoindex(ctx->bond_name);
	if (ctx->bond_idx <= 0) {
		__atomic_add_fetch(&shm->stats.ip6gre_lapb.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}

	/* Kernel confirmed ctx->bond_name now names a real device; publish
	 * it via the NETDEV name pool so sibling childops (and per-syscall
	 * fuzzers drawing this kind) can reference it on subsequent
	 * invocations -- reaches "name a previous syscall planted" lookup
	 * codepaths (SO_BINDTODEVICE, generic ARG_STRING draws) instead of
	 * always-fresh-random near-miss space. */
	name_pool_record(NAME_KIND_NETDEV, ctx->bond_name,
			 strlen(ctx->bond_name));
	return 0;
}

/*
 * Phase: RTM_NEWLINK type=ip6gre, ifindex resolution, and the
 * RTM_SETLINK IFLA_MASTER=bond enslave that arms the bug shape.
 * bond_enslave's first-slave path picks up the slave's header_ops, so
 * bond->header_ops->create starts dispatching to ip6gre_header from
 * the moment the SETLINK lands -- subsequent flag-cycle traffic on the
 * paired lapb dev fans through that mis-aimed header build.  Latches
 * g_unsupported on the ip6gre / bond_enslave EAFNOSUPPORT-class shapes
 * so a CONFIG_IP6_GRE-less or older-bonding kernel bails at the gate
 * next invocation.  Returns 0 on success; -1 means caller should goto
 * out -- the bond is created and needs teardown.
 */
static int ip6gre_lapb_iter_attach_gre(struct ip6gre_lapb_iter_ctx *ctx)
{
	int rc;

	rc = ibls_newlink(&ctx->ctx, ctx->gre_name, "ip6gre",
			  append_ip6gre_data);
	if (rc != 0) {
		if (err_is_unsupported(rc))
			latch_unsupported(ctx->child->op_type,
					  "NEWLINK type=ip6gre", -rc);
		__atomic_add_fetch(&shm->stats.ip6gre_lapb.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	ctx->gre_idx = (int)if_nametoindex(ctx->gre_name);
	if (ctx->gre_idx <= 0)
		return -1;

	/* Kernel confirmed ctx->gre_name now names a real ip6gre device;
	 * publish it via the NETDEV name pool before the enslave step so a
	 * later SO_BINDTODEVICE / ARG_STRING draw can reference the primary
	 * tunnel name -- recorded once on the create-success branch, not on
	 * the request path, so a failed NEWLINK never plants a phantom. */
	name_pool_record(NAME_KIND_NETDEV, ctx->gre_name,
			 strlen(ctx->gre_name));

	rc = ibls_setlink(&ctx->ctx, ctx->gre_idx, ctx->bond_idx, 0, 0);
	if (rc != 0) {
		if (err_is_unsupported(rc))
			latch_unsupported(ctx->child->op_type,
					  "SETLINK IFLA_MASTER=bond", -rc);
		__atomic_add_fetch(&shm->stats.ip6gre_lapb.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	return 0;
}

/*
 * Phase: locate the lapbether-auto-created lapb%d device and drive
 * IBLS_FLAG_CYCLES_BASE..IBLS_FLAG_CYCLES_CAP IFF_UP/IFF_DOWN cycles
 * against it.  This is the bug trigger: __dev_notify_flags on the
 * lapb dev runs the lapb notifier chain, which kicks
 * lapb_establish_data_link and eventually lapbeth_data_transmit ->
 * bond_header_create -> ip6gre_header on a skb with insufficient
 * headroom.  A few UP/DOWN cycles widen the window.  A missing
 * lapb%d (no lapbether module) latches g_unsupported via
 * latch_unsupported() and stat-bumps the setup_failed counter
 * before returning early; the orchestrator's out: teardown still
 * drains the bond + gre links that the earlier phases created.
 */
static void ip6gre_lapb_iter_flag_cycles(struct ip6gre_lapb_iter_ctx *ctx)
{
	unsigned int cycles, i;
	int lapb_idx;

	lapb_idx = find_lapb_ifindex();
	if (lapb_idx <= 0) {
		latch_unsupported(ctx->child->op_type, "find lapb%d", ENODEV);
		__atomic_add_fetch(&shm->stats.ip6gre_lapb.setup_failed,
				   1, __ATOMIC_RELAXED);
		return;
	}

	/* Snapshot ctx->child->op_type once and bounds-check before
	 * indexing the per-op stats array.  The field lives in shared
	 * memory and can be scribbled by a poisoned-arena write from a
	 * sibling; the child.c dispatch loop already gates its dispatch +
	 * alt-op accounting on the same valid_op snapshot. */
	{
		const enum child_op_type op = ctx->child->op_type;
		if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
			__atomic_add_fetch(&shm->stats.childop.data_path[op],
					   1, __ATOMIC_RELAXED);
	}

	cycles = rnd_modulo_u32(IBLS_FLAG_CYCLES_CAP - IBLS_FLAG_CYCLES_BASE + 1U)
	         + IBLS_FLAG_CYCLES_BASE;
	for (i = 0; i < cycles; i++) {
		(void)ibls_setlink(&ctx->ctx, lapb_idx, 0, IFF_UP, IFF_UP);
		__atomic_add_fetch(&shm->stats.ip6gre_lapb.flag_toggles,
				   1, __ATOMIC_RELAXED);
		(void)ibls_setlink(&ctx->ctx, lapb_idx, 0, 0, IFF_UP);
		__atomic_add_fetch(&shm->stats.ip6gre_lapb.flag_toggles,
				   1, __ATOMIC_RELAXED);
	}
}

/*
 * Phase: close whichever resources we managed to open.  Runs on every
 * exit path -- both the success path after flag_cycles returns and any
 * early-bail goto out from an earlier phase.  Order matches the
 * original out: cleanup: RTM_DELLINK the gre tunnel first (so its
 * enslave-to-bond is torn down before the bond itself disappears),
 * then the bond, then close the rtnetlink fd.  All fields default to
 * -1 / 0 via the orchestrator's designated initialiser so the guards
 * skip work that was never set up.
 */
static void ip6gre_lapb_iter_teardown(struct ip6gre_lapb_iter_ctx *ctx)
{
	if (ctx->ctx.fd >= 0) {
		if (ctx->gre_idx > 0)
			(void)ibls_dellink(&ctx->ctx, ctx->gre_idx);
		if (ctx->bond_idx > 0)
			(void)ibls_dellink(&ctx->ctx, ctx->bond_idx);
		nl_close(&ctx->ctx);
	}
}

/*
 * Per-invocation body that must run inside the private net namespace.
 * Executed in a transient grandchild forked by userns_run_in_ns(); the
 * grandchild's userns + netns are torn down on _exit() so the bond,
 * ip6gre tunnel, lapbether device and any sockets they brought up are
 * reaped along with the namespace.  Explicit RTM_DELLINK / nl_close
 * calls in the teardown helper are still issued so the in-ns stats
 * counters move on the success path; correctness does not depend on
 * them.  Per-grandchild latches set inside this callback (g_unsupported
 * via latch_unsupported()) die with the grandchild and the next
 * invocation re-discovers them -- helper-EPERM in the wrapper is the
 * only signal that survives across iterations.  Return value is
 * ignored by the helper.
 */
static int ip6gre_bond_lapb_stack_in_ns(void *arg)
{
	struct ip6gre_lapb_iter_ctx *ictx = (struct ip6gre_lapb_iter_ctx *)arg;
	struct childdata *child = ictx->child;

	if (g_unsupported)
		return 0;

	if (ip6gre_lapb_iter_open_netlink(ictx) != 0)
		return 0;

	if (ip6gre_lapb_iter_create_bond(ictx) != 0)
		goto out;

	if (ip6gre_lapb_iter_attach_gre(ictx) != 0)
		goto out;

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats array.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot. */
	{
		const enum child_op_type op = child->op_type;
		if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
			__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
					   1, __ATOMIC_RELAXED);
	}

	ip6gre_lapb_iter_flag_cycles(ictx);

out:
	ip6gre_lapb_iter_teardown(ictx);
	return 0;
}

bool ip6gre_bond_lapb_stack(struct childdata *child)
{
	struct ip6gre_lapb_iter_ctx ictx = {
		.ctx = { .fd = -1 },
		.child = child,
	};
	int rc;
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op latch slot.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the latch
	 * store entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	__atomic_add_fetch(&shm->stats.ip6gre_lapb.runs, 1, __ATOMIC_RELAXED);

	if (g_ns_unsupported)
		return true;

	rc = userns_run_in_ns(CLONE_NEWNET, ip6gre_bond_lapb_stack_in_ns,
			      &ictx);
	if (rc == -EPERM) {
		if (valid_op)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		warn_once_unsupported_ip6gre_lapb("userns_run_in_ns(CLONE_NEWNET)",
						  EPERM);
		return true;
	}
	if (rc < 0) {
		/* Transient grandchild setup failure (fork, id-map write,
		 * secondary unshare).  Skip this iteration without
		 * latching -- the failure is not policy and may not
		 * recur. */
		__atomic_add_fetch(&shm->stats.ip6gre_lapb.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	return true;
}
