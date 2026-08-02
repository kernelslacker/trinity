/*
 * bridge_fdb_stp - bridge fdb learn vs delete vs STP topology race.
 *
 * Flat netlink fuzzing rarely stands up the full chain the software
 * bridge needs to co-fire learning + topology-change: a bridge dev,
 * enslaved+UP ports with BR_LEARNING, rx-path traffic driving
 * net/bridge/br_fdb.c:br_fdb_update (not RTM_NEWNEIGH NTF_MASTER,
 * which bypasses the receive-path window), and a live STP state
 * machine.  Bug class: br_fdb_delete_by_port lineage (UAF on port
 * teardown racing br_fdb_update from rx softirq), STP topology-change
 * timer races (br_stp_change_bridge_id vs port state transition).
 *
 * Per invocation, inside a private user+net namespace via
 * userns_run_in_ns (grandchild _exit reaps the bridge/veths/fdb/
 * netns): create a bridge, two veth pairs enslaved and UP with
 * BR_LEARNING armed, AF_PACKET SOCK_RAW into one port sending frames
 * with random unicast SMACs to drive br_fdb_update, toggle STP via
 * /sys/class/net/<br>/bridge/stp_state, then race RTM_DELNEIGH on a
 * just-learned entry and RTM_DELLINK on the bridge against the still-
 * draining rx path.
 *
 * Brick-safety: one create/destroy cycle per invocation inside the
 * private netns; loopback only; packet burst BUDGETED+JITTER (base 3,
 * 200 ms wall cap); MSG_DONTWAIT + SO_RCVTIMEO=1s so no I/O outlives
 * child.c's SIGALRM(1s).
 *
 * Latches: userns -EPERM permanently gates the op off for this child;
 * -EAGAIN skips without latching.  Per-feature latches
 * (ns_unsupported_bridge / _veth / _sysfs_stp) fire on the first
 * EOPNOTSUPP/EROFS/EACCES so a kernel without CONFIG_BRIDGE / veth /
 * sysfs-writable knobs pays the failure once.  Header-gated by
 * __has_include on <linux/if_bridge.h>/<linux/veth.h>.
 */

#include <errno.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_packet.h>
#include <linux/neighbour.h>
#include <linux/rtnetlink.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#include "child.h"
#include "childops-netlink.h"
#include "jitter.h"
#include "name-pool.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"
#include "userns-bootstrap.h"

#include "kernel/fcntl.h"
#include "kernel/socket.h"

#include "bridge-fdb-stp-internal.h"

/* Per-child latched gates.  Set on the first failure of the
 * corresponding subsystem and never cleared — kernel module / config
 * presence is static for the child's lifetime, so we pay the EFAIL
 * once and skip the path on subsequent invocations.  ns_unsupported_*
 * bridge/veth are consumed by the mass-VLAN TU too; extern-declared in
 * bridge-fdb-stp-internal.h. */
bool ns_unsupported_bridge;
bool ns_unsupported_veth;

/* Latched per-child: userns_run_in_ns() reported -EPERM, meaning the
 * grandchild's unshare(CLONE_NEWUSER) was refused by a hardened policy
 * (user.max_user_namespaces=0 or kernel.unprivileged_userns_clone=0).
 * Without a private netns we MUST NOT touch the host's main bridge /
 * fdb / veth tables, so the op stays disabled for the remainder of
 * this child's lifetime.  Transient setup failures (helper return
 * -EAGAIN) do not set this — they may not recur on the next
 * iteration. */
static bool ns_unsupported;

/* Per-grandchild "lo up" setup latch lives in shm
 * (shm->bridge_fdb_stp_lo_brought_up).  The write site sits inside the
 * userns_run_in_ns() grandchild body -- a process-local static would
 * die with the grandchild on _exit() and every subsequent invocation
 * would re-pay the "lo up" rtnetlink round-trip.  RELAXED atomic
 * load/store is safe: only false -> true, idempotent write. */
static bool lo_brought_up(void)
{
	return __atomic_load_n(&shm->bridge_fdb_stp_lo_brought_up,
			       __ATOMIC_RELAXED);
}

static void mark_lo_brought_up(void)
{
	__atomic_store_n(&shm->bridge_fdb_stp_lo_brought_up, true,
			 __ATOMIC_RELAXED);
}

/*
 * Bring lo up inside the private netns.  A freshly-unshared netns has
 * lo present but DOWN; some bridge / fdb code paths short-circuit on
 * the upper-layer carrier state, so flip lo up once-per-child.
 * Failures are ignored — they latch through the rest of the sequence
 * naturally.
 */
/*
 * Phase 1: pick the per-invocation interface names.  All five names
 * (one bridge + two veth pairs) share a single 16-bit random suffix so
 * a long-lived child's traces correlate by suffix inside its private
 * netns.  Cheap and infallible — no return value.
 */
static void bridge_fdb_stp_iter_setup_names(struct bridge_fdb_stp_iter_ctx *ctx)
{
	unsigned int rng = (unsigned int)(rand32() & 0xffffu);

	snprintf(ctx->br_name, sizeof(ctx->br_name), "trbr%u", rng);
	snprintf(ctx->veth0a, sizeof(ctx->veth0a), "trbv%ua0", rng);
	snprintf(ctx->veth0b, sizeof(ctx->veth0b), "trbv%ub0", rng);
	snprintf(ctx->veth1a, sizeof(ctx->veth1a), "trbv%ua1", rng);
	snprintf(ctx->veth1b, sizeof(ctx->veth1b), "trbv%ub1", rng);
}

/*
 * Phase 2: create the bridge link and capture its ifindex.  Latches
 * ns_unsupported_bridge on the family/proto rejection codes the
 * rtnetlink layer returns when CONFIG_BRIDGE is absent so siblings
 * stop probing; EBUSY / EEXIST from a stale name are NOT latched —
 * those leave the gate open for the next iteration to retry with
 * fresh rng.  The if_nametoindex call is folded in because losing
 * the index makes every later step a no-op.  Returns 0 on success
 * or -1 if the iteration should bail to the out: cleanup path; on
 * success ctx->bridge_added is set so the teardown helper knows to
 * RTM_DELLINK it.
 */
static int bridge_fdb_stp_iter_bridge_create(struct bridge_fdb_stp_iter_ctx *ctx)
{
	int rc;

	rc = bfs_build_bridge_create(&ctx->ctx, ctx->br_name);
	if (rc != 0) {
		if (rc == -EAFNOSUPPORT || rc == -EOPNOTSUPP ||
		    rc == -ENOTSUP || rc == -ENOENT || rc == -EPROTONOSUPPORT)
			ns_unsupported_bridge = true;
		return -1;
	}
	ctx->bridge_added = true;
	__atomic_add_fetch(&shm->stats.bridge_fdb_stp.bridge_create_ok,
			   1, __ATOMIC_RELAXED);

	ctx->br_idx = (int)if_nametoindex(ctx->br_name);
	if (ctx->br_idx == 0)
		return -1;

	/* Kernel confirmed ctx->br_name now names a real bridge master;
	 * publish it via the NETDEV name pool so sibling childops (and
	 * per-syscall fuzzers drawing this kind) can collide with it on
	 * subsequent invocations -- reaches "name a previous syscall
	 * planted" lookup codepaths instead of always-fresh-random
	 * near-miss space.  Record the master only; the two veth pairs
	 * created later are deliberately skipped to keep the per-kind
	 * 16-slot ring from being dominated by a single op's leaves. */
	name_pool_record(NAME_KIND_NETDEV, ctx->br_name,
			 strlen(ctx->br_name));
	return 0;
}

/*
 * Phase 3: create both veth pairs, resolve their port ifindices,
 * enslave each end to the bridge, bring all five interfaces (bridge
 * + four veth ends) UP, and arm BR_LEARNING on every surviving port.
 * ns_unsupported_veth latches on pair 0's structural-errno failure
 * (CONFIG_VETH absent) so pair 1 short-circuits in the same call.
 * The setlink_master / setlink_up / brport_learning calls are
 * best-effort by design (they were (void)-casts in the original) — a
 * missing slave or DOWN port still leaves the receive-path learning
 * window partially open; the failure shape just shrinks the surface
 * area rather than aborting the iteration.  No return value: later
 * phases gate independently on ctx->port_idx[i] > 0.
 */
static void bridge_fdb_stp_iter_veth_attach(struct bridge_fdb_stp_iter_ctx *ctx)
{
	const char *port_names[4];
	unsigned int i;
	int rc;

	if (!ns_unsupported_veth) {
		rc = bfs_build_veth_create(&ctx->ctx, ctx->veth0a, ctx->veth0b);
		if (rc != 0) {
			if (rc == -EAFNOSUPPORT || rc == -EOPNOTSUPP ||
			    rc == -ENOTSUP || rc == -ENOENT)
				ns_unsupported_veth = true;
		} else {
			ctx->veth0_added = true;
			__atomic_add_fetch(&shm->stats.bridge_fdb_stp.veth_create_ok,
					   1, __ATOMIC_RELAXED);
		}
	}

	if (!ns_unsupported_veth) {
		rc = bfs_build_veth_create(&ctx->ctx, ctx->veth1a, ctx->veth1b);
		if (rc == 0) {
			ctx->veth1_added = true;
			__atomic_add_fetch(&shm->stats.bridge_fdb_stp.veth_create_ok,
					   1, __ATOMIC_RELAXED);
		}
	}

	port_names[0] = ctx->veth0_added ? ctx->veth0a : NULL;
	port_names[1] = ctx->veth0_added ? ctx->veth0b : NULL;
	port_names[2] = ctx->veth1_added ? ctx->veth1a : NULL;
	port_names[3] = ctx->veth1_added ? ctx->veth1b : NULL;

	for (i = 0; i < 4; i++) {
		if (!port_names[i])
			continue;
		ctx->port_idx[i] = (int)if_nametoindex(port_names[i]);
		if (ctx->port_idx[i] > 0)
			(void)bfs_build_setlink_master(&ctx->ctx, ctx->port_idx[i],
						   ctx->br_idx);
	}

	(void)rtnl_setlink_up(&ctx->ctx, ctx->br_idx);
	for (i = 0; i < 4; i++) {
		if (ctx->port_idx[i] > 0)
			(void)rtnl_setlink_up(&ctx->ctx, ctx->port_idx[i]);
	}

	for (i = 0; i < 4; i++) {
		if (ctx->port_idx[i] > 0)
			(void)bfs_build_setlink_brport_learning(&ctx->ctx,
							    ctx->port_idx[i]);
	}
}

/*
 * Phase 6: close whichever resources we managed to open.  Runs on
 * every exit path — both the success path after stp_toggle returns
 * and any early-bail goto out from an earlier phase.  Order matches
 * the original out: cleanup: close the raw fd first (any frames still
 * buffered there get discarded), then RTM_DELLINK the bridge before
 * closing rtnl itself.  The bridge dellink cascades both veth pairs
 * via br_dev_delete — that's the targeted teardown-vs-rx window, so
 * the veths must NOT be pre-DELLINKed.  The mop-up DELLINKs on
 * port_idx[0]/port_idx[2] catch veths whose bridge enslave failed,
 * so a long-lived child doesn't accumulate orphan veths in its
 * private netns.  All fields default to -1 / false via the
 * orchestrator's designated initialiser so the guards skip work that
 * was never set up.
 */
static void bridge_fdb_stp_iter_teardown(struct bridge_fdb_stp_iter_ctx *ctx)
{
	if (ctx->raw >= 0)
		close(ctx->raw);

	if (ctx->ctx.fd >= 0) {
		if (ctx->bridge_added && ctx->br_idx > 0) {
			if (rtnl_dellink(&ctx->ctx, ctx->br_idx) == 0)
				__atomic_add_fetch(&shm->stats.bridge_fdb_stp.link_del_ok,
						   1, __ATOMIC_RELAXED);
		}
		if (ctx->veth0_added && ctx->port_idx[0] > 0)
			(void)rtnl_dellink(&ctx->ctx, ctx->port_idx[0]);
		if (ctx->veth1_added && ctx->port_idx[2] > 0)
			(void)rtnl_dellink(&ctx->ctx, ctx->port_idx[2]);
		nl_close(&ctx->ctx);
	}
}

/*
 * Per-invocation state handed to the in-ns callback so it can keep
 * accounting against the right childop slot.
 */
struct bridge_fdb_stp_ctx {
	struct childdata *child;
};

/*
 * Per-invocation body that must run inside the private net namespace.
 * Executed in a transient grandchild forked by userns_run_in_ns(); the
 * grandchild's userns + netns are torn down on _exit() so any bridges,
 * veth pairs, fdb entries, sockets and sysfs handles left behind are
 * reaped by the kernel along with the namespace.  Return value is
 * ignored by the helper.
 */
static int bridge_fdb_stp_in_ns(void *arg)
{
	struct bridge_fdb_stp_ctx *cctx = (struct bridge_fdb_stp_ctx *)arg;
	struct childdata *child = cctx->child;
	struct bridge_fdb_stp_iter_ctx ictx = {
		.ctx = { .fd = -1 },
		.raw = -1,
	};
	struct nl_open_opts nl_opts = {
		.proto = NETLINK_ROUTE,
		.recv_timeo_s = 1,
	};

	if (nl_open(&ictx.ctx, &nl_opts) < 0) {
		__atomic_add_fetch(&shm->stats.bridge_fdb_stp.setup_failed,
				   1, __ATOMIC_RELAXED);
		return 0;
	}

	if (!lo_brought_up()) {
		rtnl_bring_lo_up(&ictx.ctx);
		mark_lo_brought_up();
	}

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	if (ONE_IN(8)) {
		bridge_vlan_mass_add(&ictx.ctx);
		nl_close(&ictx.ctx);
		return 0;
	}

	bridge_fdb_stp_iter_setup_names(&ictx);

	if (bridge_fdb_stp_iter_bridge_create(&ictx) != 0)
		goto out;

	bridge_fdb_stp_iter_veth_attach(&ictx);

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);

	bridge_fdb_stp_iter_traffic_burst(&ictx);

	bridge_fdb_stp_iter_stp_toggle(&ictx);

out:
	bridge_fdb_stp_iter_teardown(&ictx);
	return 0;
}

bool bridge_fdb_stp(struct childdata *child)
{
	struct bridge_fdb_stp_ctx cctx = { .child = child };
	int rc;

	__atomic_add_fetch(&shm->stats.bridge_fdb_stp.runs, 1,
			   __ATOMIC_RELAXED);

	if (ns_unsupported || ns_unsupported_bridge)
		return true;

	rc = userns_run_in_ns(CLONE_NEWNET, bridge_fdb_stp_in_ns, &cctx);
	if (rc == -EPERM) {
		ns_unsupported = true;
		/* child->op_type lives in shared memory and can be scribbled
		 * by a poisoned-arena write from a sibling; bounds-check the
		 * snapshot before indexing the NR_CHILD_OP_TYPES-sized stats
		 * array, same pattern the child.c dispatch loop uses for the
		 * unguarded write that motivated this guard. */
		{
			const enum child_op_type op = child->op_type;
			if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_NS_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		__atomic_add_fetch(&shm->stats.bridge_fdb_stp.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}
	if (rc < 0) {
		/* Transient grandchild setup failure (fork, id-map write,
		 * secondary unshare).  Skip this iteration without latching
		 * -- the failure is not policy and may not recur. */
		__atomic_add_fetch(&shm->stats.bridge_fdb_stp.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	return true;
}
