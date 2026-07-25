/*
 * nl80211_churn - cfg80211 state-machine churn under mac80211_hwsim.
 *
 * Targets async cfg80211 transitions in net/wireless/nl80211.c, scan.c,
 * sme.c: a second scan / regdom change / disconnect arriving while the
 * previous async transition is still in flight.  Bug lineage:
 * cfg80211_inform_bss OOB (CVE-2022-41674), cfg80211_scan_done UAF
 * (CVE-2025-21672 scan-while-connected), regdom-vs-in-flight wiphy_idx
 * race (CVE-2023-3090).  Reaching any of it needs a live wiphy backed by
 * mac80211_hwsim + a NL80211_IFTYPE_STATION iface on it + traffic; random
 * syscall fuzz never assembles the coherent stack.
 *
 * Sequence per iteration inside a userns_run_in_ns grandchild (identity
 * userns + CLONE_NEWNET, _exit reaps): genl_open("nl80211") + cap-probe
 * (mac80211_hwsim sysfs presence, one-shot modprobe, NL80211_CMD_GET_WIPHY
 * enumerate, latch if zero phys); NL80211_CMD_NEW_INTERFACE STATION on
 * phy0; TRIGGER_SCAN active with 1..3 random 32-byte SSIDs; brief poll for
 * NEW_SCAN_RESULTS; CONNECT to a discovered BSSID (or random SSID);
 * SO_BINDTODEVICE UDP burst (5..32 pkts) to 224.0.0.1:9 to walk cfg80211
 * state via the bind/route lookup; TRIGGER_SCAN AGAIN (the scan_done UAF
 * window); REQ_SET_REG alpha2="ZZ" (regdom-vs-in-flight); DISCONNECT +
 * DEL_INTERFACE racing whatever's still draining.  Per-child cleanup ring
 * catches leaked ifaces; netns destroy sweeps the rest.
 *
 * Spec-vs-reality: spec called it NL80211_CMD_SET_REG; the userspace-
 * initiated regdom command that the kernel accepts on NETLINK_GENERIC is
 * NL80211_CMD_REQ_SET_REG (== 26).
 *
 * Brick-safety: all wireless mutation inside CLONE_NEWNET; mac80211_hwsim
 * provides a synthetic PHY so no spectrum is touched; all I/O MSG_DONTWAIT
 * or short SO_RCVTIMEO; bounded retries (<=8) on EAGAIN / EBUSY /
 * EINPROGRESS so a sibling iteration mid-teardown doesn't waste this iter.
 *
 * Latches: ns_unsupported_nl80211_userns on userns_run_in_ns -EPERM.
 * Cap-gate ns_unsupported_nl80211 latches on nl80211 family ENOENT or on
 * a zero-phys GET_WIPHY enumerate; subsequent invocations short-circuit.
 * The genl_send_recv_retry wrapper is local (nl80211 needs it; the shared
 * childops-genl wrapper stays unicast-single-ack).
 *
 * Header-gated by __has_include() on linux/genetlink.h, linux/if_link.h,
 * linux/rtnetlink.h.  NL80211 UAPI integers (NL80211_CMD_*, NL80211_ATTR_*,
 * NL80211_IFTYPE_STATION) get #define fallbacks at their stable UAPI
 * values; unrecognised on the kernel -> -EOPNOTSUPP/-ENOPROTOOPT and the
 * cap-gate latches.
 */

#if __has_include(<linux/genetlink.h>) && \
	__has_include(<linux/if_link.h>) && \
	__has_include(<linux/rtnetlink.h>)

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <net/if.h>
#include <time.h>
#include <unistd.h>

#include <linux/genetlink.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "kernel/nl80211.h"

#include "child.h"
#include "childops-genl.h"
#include "childops-util.h"
#include "jitter.h"
#include "name-pool.h"
#include "nl80211-churn-internal.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "userns-bootstrap.h"

/* Per-grandchild latched gates.  Inherited as false at grandchild
 * fork time (the persistent child never writes them -- the in-ns
 * callback runs exclusively in transient grandchildren) and flipped
 * on the first config-absent rejection from the corresponding probe.
 * Die with the grandchild on _exit(); each subsequent grandchild
 * re-discovers the latch in its own fresh netns.  The EPERM / ENOSYS
 * / EOPNOTSUPP / ENOPROTOOPT / EAFNOSUPPORT / EPROTONOSUPPORT /
 * ENODEV detection arms are preserved because a fresh user namespace
 * cannot manufacture an absent kernel CONFIG -- the gate still
 * short-circuits the rest of the grandchild's iteration once it
 * fires.
 *
 * ns_unsupported_nl80211 is declared extern in nl80211-churn-internal.h
 * because the split phase TUs (discovery/iface/scan/station) each
 * latch it on their own probe outcomes; the definition lives here. */
bool ns_unsupported_nl80211;

/* Master gate: persistent across iterations in the persistent child.
 * Set when userns_run_in_ns returns -EPERM (hardened userns policy
 * refused CLONE_NEWUSER -- typically user.max_user_namespaces=0 or
 * kernel.unprivileged_userns_clone=0).  The per-grandchild gates
 * above die with the grandchild; helper-EPERM is the only signal
 * that survives long enough to short-circuit subsequent invocations. */
static bool ns_unsupported_nl80211_userns;

static void warn_once_unsupported_nl80211_userns(const char *reason, int err)
{
	if (ns_unsupported_nl80211_userns)
		return;
	ns_unsupported_nl80211_userns = true;
	/* check-static: child-output-ok */
	outputerr("nl80211_churn: %s failed (errno=%d), latching unsupported_nl80211_userns\n",
		  reason, err);
}

/* Per-child scratch state.  Family id is resolved per-ctx by genl_open
 * now (was a cached static); only the first-wiphy lookup result needs
 * to survive across invocations so we don't pay the GET_WIPHY enumerate
 * every churn call.  nl80211_phy0 is declared extern in
 * nl80211-churn-internal.h so the iface + station phases can read the
 * cached index; nl80211_phy0_cached stays file-local (only the
 * coordinator in this TU writes it, from nl80211_churn_in_ns). */
uint32_t nl80211_phy0;
static bool nl80211_phy0_cached;

/* Created-iface ring for the cleanup sweep.  Both symbols are declared
 * extern in nl80211-churn-internal.h so the iface-setup phase can
 * append, the teardown phase can clear slots, and the end-of-child
 * sweep can drain the tail. */
int created_ifindex[NL80211_IFACE_RING_CAP];
unsigned int created_count;

/*
 * Send the inner UDP burst over @ifname.  AF_INET / SOCK_DGRAM bound to
 * the wlan iface via SO_BINDTODEVICE; destination 224.0.0.1:9
 * (loopback-class multicast on the discard port).  Each send walks the
 * iface route lookup which threads through cfg80211 state for the
 * STATION iface.  Wall-bounded by NL80211_WALL_CAP_NS at the outer-
 * iter level so the burst can't punch through the SIGALRM cap.
 */
static void send_inner_burst(const char *ifname, const struct timespec *t_outer)
{
	int s;
	struct sockaddr_in dst;
	unsigned int n = NL80211_BURST_MIN +
			 rnd_modulo_u32(NL80211_BURST_MAX - NL80211_BURST_MIN + 1U);
	unsigned int i;

	s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (s < 0)
		return;
	(void)setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE,
			 ifname, (socklen_t)(strlen(ifname) + 1));

	memset(&dst, 0, sizeof(dst));
	dst.sin_family      = AF_INET;
	dst.sin_port        = htons(NL80211_BURST_PORT);
	dst.sin_addr.s_addr = htonl(0xE0000001U);	/* 224.0.0.1 */

	for (i = 0; i < n; i++) {
		unsigned char payload[64];
		ssize_t r;

		if ((unsigned long long)ns_since(t_outer) >= NL80211_WALL_CAP_NS)
			break;
		generate_rand_bytes(payload, sizeof(payload));
		r = sendto(s, payload, sizeof(payload), MSG_DONTWAIT,
			   (struct sockaddr *)&dst, sizeof(dst));
		if (r > 0)
			__atomic_add_fetch(&shm->stats.nl80211.bursts_sent,
					   1, __ATOMIC_RELAXED);
	}
	close(s);
}

/*
 * Phase: trigger the initial scan, drain its results, drive CONNECT, then
 * send the inner traffic burst that gives the scan/connect/assoc paths
 * something to chew on.  Pure side-effects via shm stats and the
 * ns_unsupported_nl80211 latch -- callers don't branch on the outcome.
 */
static void nl80211_iter_scan_connect(struct genl_ctx *ctx, int ifindex,
				      const char *ifname,
				      const struct timespec *t_outer)
{
	int rc;

	rc = trigger_scan(ctx, ifindex);
	if (rc == 0)
		__atomic_add_fetch(&shm->stats.nl80211.scan_triggered,
				   1, __ATOMIC_RELAXED);
	else if (errno_is_unsupported(-rc))
		ns_unsupported_nl80211 = true;

	(void)wait_scan_results(ctx);

	rc = connect_iface(ctx, ifindex);
	__atomic_add_fetch(&shm->stats.nl80211.connect_attempted,
			   1, __ATOMIC_RELAXED);
	if (rc == 0)
		__atomic_add_fetch(&shm->stats.nl80211.connect_succeeded,
				   1, __ATOMIC_RELAXED);
	else if (errno_is_unsupported(-rc))
		ns_unsupported_nl80211 = true;

	send_inner_burst(ifname, t_outer);
}

/*
 * Phase: post-connect race burst.  Re-triggers scan against the now-
 * connected iface (the cfg80211_scan_done UAF window, CVE-2025-21672) and
 * flips the regulatory domain to "ZZ" to race
 * reg_process_self_managed_hint (CVE-2023-3090 wiphy-index race).  Both
 * are best-effort -- the kernel-side races are the point, not the rc.
 */
static void nl80211_iter_races(struct genl_ctx *ctx, int ifindex)
{
	int rc;

	rc = trigger_scan(ctx, ifindex);
	if (rc == 0)
		__atomic_add_fetch(&shm->stats.nl80211.scan_triggered,
				   1, __ATOMIC_RELAXED);

	rc = set_reg_zz(ctx);
	if (rc == 0)
		__atomic_add_fetch(&shm->stats.nl80211.regdom_changed,
				   1, __ATOMIC_RELAXED);
}

/*
 * Phase: disconnect the iface, then run the two sub-modes guarded by their
 * own ONE_IN gates.  PMSR FTM (ONE_IN(8)) picks a random slot from the
 * created-iface ring and flips FTMS_PER_BURST between u8 and u32 widths
 * (upstream 0f3c0a197309).  Admin-gate probe (ONE_IN(16)) forks a child in
 * an unmapped user namespace to walk cmds that must be admin-gated
 * (upstream 381cd547bc6e); its lower rate budgets the fork+waitpid cost.
 */
static void nl80211_iter_submodes(struct genl_ctx *ctx, int ifindex)
{
	int rc;

	rc = disconnect_iface(ctx, ifindex);
	__atomic_add_fetch(&shm->stats.nl80211.disconnect_attempted,
			   1, __ATOMIC_RELAXED);
	(void)rc;

	if (ONE_IN(8) && created_count > 0) {
		bool as_u32 = ONE_IN(2);
		int slot = (int)rnd_modulo_u32(created_count);
		int target = created_ifindex[slot];

		if (target > 0) {
			__atomic_add_fetch(&shm->stats.nl80211.pmsr_runs,
					   1, __ATOMIC_RELAXED);
			if (build_pmsr_ftm_req(ctx, (uint32_t)target,
					       as_u32) == 0)
				__atomic_add_fetch(&shm->stats.nl80211.pmsr_ok,
						   1, __ATOMIC_RELAXED);
		}
	}

	if (ONE_IN(16))
		nl80211_admin_gate_probe(nl80211_phy0);
}

/*
 * Phase: drive DEL_INTERFACE and reconcile the created-iface ring.  On a
 * successful delete, bumps the destroyed stat and clears the matching ring
 * slot so cleanup_ifaces() at child exit doesn't try to re-delete it.
 * Linear search is fine: the ring is bounded at NL80211_IFACE_RING_CAP
 * (64) and this runs once per outer iter, not per syscall.
 */
static void nl80211_iter_teardown(struct genl_ctx *ctx, int ifindex)
{
	int rc;

	rc = del_iface_by_index(ctx, ifindex);
	if (rc == 0) {
		unsigned int j;

		__atomic_add_fetch(&shm->stats.nl80211.iface_destroyed,
				   1, __ATOMIC_RELAXED);
		for (j = 0; j < created_count; j++) {
			if (created_ifindex[j] == ifindex) {
				created_ifindex[j] = 0;
				break;
			}
		}
	}
}

/*
 * Single outer iteration of the churn loop.  Each iter creates one
 * STATION iface, runs the full scan/connect/burst/scan-again/regdom/
 * disconnect/del-iface chain on it, and tears it down at the end.  The
 * created-iface ring catches the leak case where a NEW_INTERFACE landed
 * but the per-iter DEL_INTERFACE was skipped (jump-out / wall cap hit).
 */
static void iter_one(struct genl_ctx *ctx, struct childdata *child,
		     unsigned int iter_idx, const struct timespec *t_outer)
{
	char ifname[IFNAMSIZ];
	int ifindex;

	(void)iter_idx;

	if (nl80211_iter_setup(ctx, ifname, &ifindex, t_outer) < 0)
		return;

	/* child->op_type lives in shared memory and can be scribbled by a
	 * poisoned-arena write from a sibling; bounds-check the snapshot
	 * before indexing the NR_CHILD_OP_TYPES-sized stats arrays, same
	 * pattern the child.c dispatch loop uses for the unguarded write
	 * that motivated this guard. */
	{
		const enum child_op_type op = child->op_type;
		if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
			__atomic_add_fetch(&shm->stats.childop.data_path[op],
					   1, __ATOMIC_RELAXED);
	}

	nl80211_iter_scan_connect(ctx, ifindex, ifname, t_outer);
	nl80211_iter_races(ctx, ifindex);
	nl80211_iter_submodes(ctx, ifindex);
	nl80211_iter_teardown(ctx, ifindex);
}

struct nl80211_churn_in_ns_ctx {
	struct childdata *child;
	enum child_op_type op;
	bool valid_op;
};

/*
 * Per-invocation body that must run inside the private net namespace.
 * Executed in a transient grandchild forked by userns_run_in_ns(); the
 * grandchild's userns + netns are torn down on _exit() so any STATION
 * iface, scan / connect state, genl socket and FTM PMSR slot left
 * behind is reaped along with the namespace.  Explicit DEL_INTERFACE
 * calls are still issued via cleanup_ifaces() so the in-ns stats
 * counters (nl80211_iface_destroyed etc.) move on the success path;
 * correctness does not depend on them.  Per-grandchild latches set
 * inside this callback die with the grandchild and the per-grandchild
 * gate above is re-discovered on the next invocation -- helper-EPERM
 * in the wrapper is the only signal that survives across iterations.
 * Return value is ignored by the helper.
 */
static int nl80211_churn_in_ns(void *arg)
{
	struct nl80211_churn_in_ns_ctx *cctx =
		(struct nl80211_churn_in_ns_ctx *)arg;
	struct childdata *child = cctx->child;
	struct genl_ctx ctx;
	struct genl_open_opts opts;
	bool ctx_open = false;
	struct timespec t_outer;
	unsigned int outer_iters, i;
	int rc;

	if (ns_unsupported_nl80211)
		return 0;

	memset(&opts, 0, sizeof(opts));
	opts.family_name  = NL80211_GENL_NAME;
	opts.version      = 1;
	/* SO_RCVTIMEO has 1 s granularity at the kernel API; the
	 * NL80211_TIMEO_MS (100 ms) brief-yield bound is enforced by the
	 * per-iter wall cap and the SIGALRM(1s) child cap, not by the
	 * socket timeout. */
	opts.recv_timeo_s = 1;

	rc = genl_open(&ctx, &opts);
	if (rc != 0) {
		if (rc == -ENOENT || errno_is_unsupported(-rc))
			ns_unsupported_nl80211 = true;
		__atomic_add_fetch(&shm->stats.nl80211.setup_failed,
				   1, __ATOMIC_RELAXED);
		return 0;
	}
	ctx_open = true;

	if (!nl80211_phy0_cached) {
		if (!hwsim_present(&ctx)) {
			ns_unsupported_nl80211 = true;
			__atomic_add_fetch(&shm->stats.nl80211.setup_failed,
					   1, __ATOMIC_RELAXED);
			goto out;
		}
		nl80211_phy0_cached = true;
	}

	if (cctx->valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[cctx->op],
				   1, __ATOMIC_RELAXED);

	if (clock_gettime(CLOCK_MONOTONIC, &t_outer) < 0) {
		t_outer.tv_sec  = 0;
		t_outer.tv_nsec = 0;
	}

	outer_iters = BUDGETED(CHILD_OP_NL80211_CHURN,
			       JITTER_RANGE(NL80211_OUTER_BASE));
	if (outer_iters < NL80211_OUTER_FLOOR)
		outer_iters = NL80211_OUTER_FLOOR;
	if (outer_iters > NL80211_OUTER_CAP)
		outer_iters = NL80211_OUTER_CAP;

	for (i = 0; i < outer_iters; i++) {
		if ((unsigned long long)ns_since(&t_outer) >=
		    NL80211_WALL_CAP_NS)
			break;
		iter_one(&ctx, child, i, &t_outer);
		if (ns_unsupported_nl80211)
			break;
	}

	cleanup_ifaces(&ctx);

out:
	if (ctx_open)
		genl_close(&ctx);
	return 0;
}

bool nl80211_churn(struct childdata *child)
{
	struct nl80211_churn_in_ns_ctx cctx;
	int rc;
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op latch slot.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the latch
	 * store entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	__atomic_add_fetch(&shm->stats.nl80211.runs, 1, __ATOMIC_RELAXED);

	if (ns_unsupported_nl80211_userns)
		return true;

	cctx.child    = child;
	cctx.op       = op;
	cctx.valid_op = valid_op;

	rc = userns_run_in_ns(CLONE_NEWNET, nl80211_churn_in_ns, &cctx);
	if (rc == -EPERM) {
		if (valid_op)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		warn_once_unsupported_nl80211_userns("userns_run_in_ns(CLONE_NEWNET)",
						     EPERM);
		return true;
	}
	if (rc < 0) {
		/* Transient grandchild setup failure (fork, id-map write,
		 * secondary unshare).  Skip this iteration without
		 * latching -- the failure is not policy and may not
		 * recur. */
		__atomic_add_fetch(&shm->stats.nl80211.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	return true;
}

#else  /* missing one of <linux/genetlink.h> / <linux/if_link.h> / <linux/rtnetlink.h> */

#include <stdbool.h>
#include "child.h"
#include "shm.h"

#include "kernel/fcntl.h"
#include "kernel/socket.h"
bool nl80211_churn(struct childdata *child)
{
	(void)child;

	__atomic_add_fetch(&shm->stats.nl80211.runs, 1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.nl80211.setup_failed,
			   1, __ATOMIC_RELAXED);
	return true;
}

#endif
