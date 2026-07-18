/*
 * netns_teardown_churn - race net namespace teardown against in-flight
 * sockets, raw sockets, and an XFRM netlink socket.
 *
 * cleanup_net walks every module's ->exit / ->exit_batch pernet hooks in
 * order when the last struct net ref drops.  Any hook that releases an
 * object another thread is mid-walk through is a UAF candidate -- the most
 * prolific late-2024 / 2025 networking UAF bug class.  Anchors:
 * CVE-2024-26865 (unix_gc vs SCM_RIGHTS in flight), CVE-2024-26851 (netfilter
 * pernet exit dropping nft refs early), CVE-2024-1085 (nft pernet exit vs
 * nft_del_chain), CVE-2025-21684 (tcp_metrics pernet exit vs concurrent
 * metrics).
 *
 * Per invocation runs inside a userns_run_in_ns grandchild (identity userns
 * + CLONE_NEWNET, _exit reaps).  BUDGETED outer loop body:
 *   a. save anchor nsfd = open("/proc/self/ns/net", O_RDONLY);
 *   b. unshare(CLONE_NEWNET) -- grandchild enters a nested doomed ns;
 *   c. rtnl best-effort lo up + 127.0.0.1;
 *   d/e. establish a loopback SOCK_STREAM pair (listen + connect + accept
 *        so the pair is truly bidirectional);
 *   f. fork() an in-ns great-grandchild.  Great-grandchild closes the
 *      anchor, opens AF_INET/SOCK_RAW/IPPROTO_ICMP (exercises raw pernet
 *      exit) and NETLINK_XFRM (exercises xfrm4/xfrm6 pernet exit), then
 *      tight send/recv on the pair (BUDGETED+JITTER, 200 ms wall) until
 *      SIGKILL.  Grandchild setns(anchor, CLONE_NEWNET) back out, closes
 *      its own pair copies (so only the great-grandchild holds
 *      doomed-net refs), brief jitter usleep, kill(SIGKILL) + waitpid.
 * Doing the unshare+setns dance with full caps inside the grandchild's
 * userns means cap-dropped persistent children stop silently EPERM'ing
 * out of the race entirely.
 *
 * Brick-safety: everything runs inside the private user+net ns; doomed ns
 * is reaped by cleanup_net within a few jiffies of the SIGKILL; no
 * persistent state; raw + xfrm netlink are best-effort (failure benign).
 * fork() failure latches off + returns clean.  Benign coverage: rtnl
 * bring-up failure (sends return EHOSTUNREACH but the teardown still
 * races); send/recv EAGAIN/EPIPE (teardown already started); raw EPERM
 * (variant skipped for that iter); waitpid EINTR (retried).
 *
 * Cap-gate latch: ns_unsupported_netns_teardown on userns_run_in_ns()
 * -EPERM in the persistent child; subsequent invocations bump
 * setup_failed and return.  The grandchild's setns-back failure path
 * writes CHILDOP_LATCH_NS_UNSUPPORTED to shm as a debug signal (the
 * grandchild's COW copy of the master bool dies with _exit, but
 * latch_reason is process-shared).
 *
 * Bounds: outer BUDGETED base NETNS_TD_OUTER_BASE / cap NETNS_TD_OUTER_CAP,
 * JITTER +/-50%.  Inner send/recv BUDGETED base NETNS_TD_INNER_BASE / cap
 * NETNS_TD_INNER_CAP + 200 ms CLOCK_MONOTONIC wall cap.
 */

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "child.h"
#include "childops-util.h"
#include "shm.h"
#include "trinity.h"
#include "userns-bootstrap.h"

#if __has_include(<sched.h>) && __has_include(<linux/netlink.h>)

#include <netinet/in.h>
#include <sched.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_addr.h>
#include <linux/if.h>

#include "childops-netlink.h"
#include "jitter.h"
#include "random.h"

#include "kernel/fcntl.h"
#include "kernel/netlink.h"
#include "kernel/socket.h"
/* Per-process latched gate: userns_run_in_ns() returned -EPERM,
 * meaning the grandchild's unshare(CLONE_NEWUSER) was refused by a
 * hardened policy (user.max_user_namespaces=0 or
 * kernel.unprivileged_userns_clone=0).  Without a private user+net
 * namespace we cannot race pernet teardown at all (the persistent
 * fuzz child runs cap-dropped and would silently EPERM out of the
 * inline unshare too), so the op stays disabled for the remainder of
 * this child's lifetime.  Transient helper failures (-EAGAIN) do not
 * set this -- they may not recur on the next iteration.  Mirrors the
 * bridge_vlan_churn / genetlink_fuzzer userns-adoption latch. */
static bool ns_unsupported_netns_teardown;

#define NETNS_TD_OUTER_BASE		1U
#define NETNS_TD_OUTER_CAP		3U
#define NETNS_TD_INNER_BASE		4U
#define NETNS_TD_INNER_CAP		32U
#define NETNS_TD_WALL_CAP_NS		(200ULL * 1000ULL * 1000ULL)
#define NETNS_TD_PARENT_USLEEP_MAX	2000U
#define NETNS_TD_PAYLOAD_BYTES		16U

/*
 * RTM_NEWLINK setlink ifindex IFLA_IFI_UP — flip the loopback
 * device's IFF_UP bit on inside the fresh net ns.  ifi_change set
 * to IFF_UP only so we don't mask any other flags.
 */
static int lo_set_up(struct nl_ctx *ctx, int ifindex)
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

/*
 * RTM_NEWADDR ipv4 /8 attached to ifindex with address 127.0.0.1.
 * The /8 is what the kernel installs by default on lo so we match;
 * EEXIST is benign because the loopback already has the address in
 * a freshly-created net ns on most kernels via the v4 zero-config
 * path — bring-up is just belt-and-braces.
 */
static int lo_add_addr(struct nl_ctx *ctx, int ifindex)
{
	unsigned char buf[128];
	struct nlmsghdr *nlh;
	struct ifaddrmsg *ifa;
	__u32 addr;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWADDR;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifa = (struct ifaddrmsg *)NLMSG_DATA(nlh);
	ifa->ifa_family    = AF_INET;
	ifa->ifa_prefixlen = 8;
	ifa->ifa_flags     = 0;
	ifa->ifa_scope     = RT_SCOPE_HOST;
	ifa->ifa_index     = (unsigned int)ifindex;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifa));

	addr = htonl(0x7f000001U);
	off = nla_put(buf, off, sizeof(buf), IFA_LOCAL, &addr, sizeof(addr));
	if (!off)
		return -EIO;
	off = nla_put(buf, off, sizeof(buf), IFA_ADDRESS, &addr, sizeof(addr));
	if (!off)
		return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * Bring the loopback interface up and assign 127.0.0.1.  Best-effort;
 * any rtnl error is non-fatal — the send/recv burst still races
 * pernet teardown even with a half-configured lo.  Returns 0 on
 * full success, -1 on nl_open failure.
 */
static int bring_up_loopback(void)
{
	struct nl_ctx ctx = { .fd = -1 };
	struct nl_open_opts opts = {
		.proto = NETLINK_ROUTE,
		.recv_timeo_s = 1,
	};
	const int lo_ifindex = 1;	/* lo is always ifindex 1 in a fresh net ns */

	if (nl_open(&ctx, &opts) < 0)
		return -1;

	(void)lo_add_addr(&ctx, lo_ifindex);
	(void)lo_set_up(&ctx, lo_ifindex);
	nl_close(&ctx);
	return 0;
}

/*
 * Inside the in-ns child, open a raw ICMP socket and an XFRM netlink
 * socket and let them sit open until SIGKILL.  Both fds (any fd of an
 * AF_INET / AF_NETLINK socket created in the doomed ns) hold a
 * sock_net reference that the child carries to its grave; when the
 * child dies, those refs drop simultaneously and pernet exit hooks
 * for the raw and xfrm subsystems run on the doomed net.  Failures
 * are benign coverage and silently ignored.
 */
static void open_extras(int *raw_fd, int *xfrm_fd)
{
	int fd;
	struct nl_ctx ctx;
	struct nl_open_opts opts = { .proto = NETLINK_XFRM };

	*raw_fd = -1;
	*xfrm_fd = -1;

	fd = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMP);
	if (fd >= 0)
		*raw_fd = fd;

	if (nl_open(&ctx, &opts) == 0)
		*xfrm_fd = ctx.fd;
}

/*
 * Pump payload bytes back and forth on the connected (s_conn,
 * s_accept) pair until either the inner-iteration budget is exhausted
 * or the wall-clock cap fires.  Both fds are non-blocking so EAGAIN
 * just bounces us out of the inner loop early.
 */
static void child_pump(int s_conn, int s_accept)
{
	unsigned int iters, i;
	struct timespec start, now;
	char tx[NETNS_TD_PAYLOAD_BYTES];
	char rx[NETNS_TD_PAYLOAD_BYTES];

	(void)fcntl(s_conn, F_SETFL, O_NONBLOCK);
	(void)fcntl(s_accept, F_SETFL, O_NONBLOCK);

	memset(tx, 0xa5, sizeof(tx));

	iters = BUDGETED(CHILD_OP_NETNS_TEARDOWN_CHURN,
			 JITTER_RANGE(NETNS_TD_INNER_BASE));
	if (iters > NETNS_TD_INNER_CAP)
		iters = NETNS_TD_INNER_CAP;
	if (iters == 0U)
		iters = 1U;

	if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
		start.tv_sec = 0;

	for (i = 0; i < iters; i++) {
		ssize_t r;

		r = send(s_conn, tx, sizeof(tx), MSG_DONTWAIT | MSG_NOSIGNAL);
		if (r < 0 && errno == EPIPE)
			break;

		r = recv(s_accept, rx, sizeof(rx), MSG_DONTWAIT);
		if (r < 0 && errno != EAGAIN && errno != EINTR)
			break;

		if (clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
			unsigned long long elapsed_ns =
				(unsigned long long)(now.tv_sec - start.tv_sec) *
					1000000000ULL +
				(unsigned long long)(now.tv_nsec - start.tv_nsec);
			if (elapsed_ns >= NETNS_TD_WALL_CAP_NS)
				break;
		}
	}
}

/*
 * Reap one fork-child via waitpid_eintr().  The caller has already
 * SIGKILL'd so the wait should land essentially immediately; the
 * EINTR-restart in the helper covers SIGALRM landing on the trinity
 * child mid-wait.
 */
static void reap_inflight_child(pid_t pid)
{
	int status;

	(void)waitpid_eintr(pid, &status, 0);
}

/*
 * Per-iteration scratch carried across the netns_teardown_iter_<phase>
 * helpers.  Lifetime is exactly one iter_one() invocation; avoids
 * threading the anchor fd, the three socket fds, and the in-ns child
 * pid through every helper signature.  Sentinel values (-1) mark
 * "not established" so the recover path can act selectively.  child
 * is the caller's struct childdata so phase helpers can attribute
 * per-childop yield counters to child->op_type.
 */
struct netns_teardown_iter_ctx {
	int	nsfd;
	int	s_listen;
	int	s_conn;
	int	s_accept;
	pid_t	pid;
	struct childdata *child;
};

/*
 * Phase 1: open the /proc/self/ns/net anchor fd, unshare into a fresh
 * net ns, then best-effort bring loopback up inside it.  Bumps
 * unshare_ok on success.  The open/unshare failure paths predate any
 * socket state (no recover-label cleanup needed), so they bump
 * setup_failed, clean up their own nsfd, and signal -1; on -1 the
 * caller returns from iter_one without touching the recover path.
 */
static int netns_teardown_iter_setup_ns(struct netns_teardown_iter_ctx *it)
{
	it->nsfd = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
	if (it->nsfd < 0) {
		__atomic_add_fetch(&shm->stats.netns_teardown.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}

	if (unshare(CLONE_NEWNET) < 0) {
		__atomic_add_fetch(&shm->stats.netns_teardown.setup_failed,
				   1, __ATOMIC_RELAXED);
		close(it->nsfd);
		it->nsfd = -1;
		return -1;
	}
	__atomic_add_fetch(&shm->stats.netns_teardown.unshare_ok,
			   1, __ATOMIC_RELAXED);

	(void)bring_up_loopback();
	return 0;
}

/*
 * Phase 2: build the AF_INET / SOCK_STREAM loopback socket pair the
 * in-ns child will pump on.  s_listen binds 127.0.0.1:0, listens, then
 * s_conn connects to the kernel-assigned port and s_accept pulls the
 * completed connection off the listen queue.  Bumps socket_pair_ok on
 * full success.  Any failure leaves the partially-opened fds parked in
 * the ctx for the recover path to close and returns -1; the caller
 * does `goto recover` on -1.
 */
static int netns_teardown_iter_sock_pair(struct netns_teardown_iter_ctx *it)
{
	struct sockaddr_in addr;
	socklen_t addrlen;

	it->s_listen = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (it->s_listen < 0)
		return -1;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(0x7f000001U);
	addr.sin_port = 0;
	if (bind(it->s_listen, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		return -1;
	if (listen(it->s_listen, 4) < 0)
		return -1;

	addrlen = sizeof(addr);
	if (getsockname(it->s_listen, (struct sockaddr *)&addr, &addrlen) < 0)
		return -1;

	it->s_conn = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (it->s_conn < 0)
		return -1;
	if (connect(it->s_conn, (struct sockaddr *)&addr, sizeof(addr)) < 0 &&
	    errno != EINPROGRESS)
		return -1;

	it->s_accept = accept(it->s_listen, NULL, NULL);
	if (it->s_accept < 0)
		return -1;

	__atomic_add_fetch(&shm->stats.netns_teardown.socket_pair_ok,
			   1, __ATOMIC_RELAXED);
	return 0;
}

/*
 * Phase 3: fork the in-ns child.  In the child we drop the anchor fd
 * (so the child stays in the doomed ns), open the raw + xfrm netlink
 * extra fds whose pernet exit hooks we want to exercise, then pump
 * the socket pair until SIGKILL -- the helper does NOT return on the
 * child side, it _exit(0)s in place.  In the parent we stash the pid
 * in the ctx, bump fork_ok, and return 0.  Fork failure returns -1;
 * caller does goto recover (sockets open, no child to clean up).
 */
static int netns_teardown_iter_fork_child(struct netns_teardown_iter_ctx *it)
{
	it->pid = fork();
	if (it->pid < 0)
		return -1;

	if (it->pid == 0) {
		int raw_fd = -1, xfrm_fd = -1;

		(void)close(it->nsfd);
		it->nsfd = -1;
		open_extras(&raw_fd, &xfrm_fd);
		child_pump(it->s_conn, it->s_accept);
		(void)raw_fd;
		(void)xfrm_fd;
		_exit(0);
	}

	__atomic_add_fetch(&shm->stats.netns_teardown.fork_ok,
			   1, __ATOMIC_RELAXED);
	return 0;
}

/*
 * Phase 4 (parent only): setns back to the anchor net ns so the parent
 * isn't stuck in the doomed ns, then drop the parent's copies of the
 * three socket fds so only the in-ns child keeps the doomed net
 * alive.  On setns success: bumps setns_ok, closes the three sockets,
 * returns 0.  On setns failure: latches ns_unsupported, kills + reaps
 * the in-ns child to release one ref, bumps setup_failed, closes
 * every fd in the ctx, and returns -1; the caller just returns from
 * iter_one (no recover-path setns retry — we already failed it here).
 */
static int netns_teardown_iter_parent_setns_back(struct netns_teardown_iter_ctx *it)
{
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats array.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * write entirely when the snapshot is out of range. */
	const enum child_op_type op = it->child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (setns(it->nsfd, CLONE_NEWNET) < 0) {
		/* setns failure leaves us stuck in the doomed ns.  Best
		 * effort: kill the child to release one ref so the
		 * cleanup_net workqueue can fire when this trinity child
		 * itself eventually exits.  Then bail out — every
		 * subsequent invocation will re-enter the same broken
		 * state, so latch off. */
		ns_unsupported_netns_teardown = true;
		if (valid_op)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		(void)kill(it->pid, SIGKILL);
		reap_inflight_child(it->pid);
		__atomic_add_fetch(&shm->stats.netns_teardown.setup_failed,
				   1, __ATOMIC_RELAXED);
		(void)close(it->s_listen); it->s_listen = -1;
		(void)close(it->s_conn);   it->s_conn = -1;
		(void)close(it->s_accept); it->s_accept = -1;
		(void)close(it->nsfd);     it->nsfd = -1;
		return -1;
	}
	__atomic_add_fetch(&shm->stats.netns_teardown.setns_ok,
			   1, __ATOMIC_RELAXED);

	/* Drop parent's doomed-ns socket refs so only the in-ns child
	 * keeps the net alive.  Without this the ns can't die when the
	 * child does — defeats the whole race. */
	(void)close(it->s_listen); it->s_listen = -1;
	(void)close(it->s_conn);   it->s_conn = -1;
	(void)close(it->s_accept); it->s_accept = -1;
	return 0;
}

/*
 * Phase 5 (parent only, post-setns-back): brief usleep jitter so the
 * cleanup_net workqueue may or may not have already started, kill the
 * in-ns child so the last sock_net ref drops, reap, then close the
 * anchor fd.  Bumps kill_ok on a successful kill and completed_ok at
 * the end -- the pair carries the "full iteration succeeded" signal.
 */
static void netns_teardown_iter_drive_teardown(struct netns_teardown_iter_ctx *it)
{
	(void)usleep(rnd_modulo_u32(NETNS_TD_PARENT_USLEEP_MAX));

	if (kill(it->pid, SIGKILL) == 0) {
		__atomic_add_fetch(&shm->stats.netns_teardown.kill_ok,
				   1, __ATOMIC_RELAXED);
	}
	reap_inflight_child(it->pid);

	(void)close(it->nsfd);
	it->nsfd = -1;
	__atomic_add_fetch(&shm->stats.netns_teardown.completed_ok,
			   1, __ATOMIC_RELAXED);
}

/*
 * Phase R (recover label): reached when sock_pair / fork_child fails
 * with sockets potentially open and the parent still parked in the
 * doomed ns.  Bump setup_failed, close any open socket fds, and try
 * to setns back to the anchor so the trinity child isn't stuck in
 * the doomed ns for the rest of its life.  A setns-back failure here
 * latches ns_unsupported so subsequent invocations short-circuit
 * (preserving the byte-exact latch path the original carried).
 */
static void netns_teardown_iter_recover(struct netns_teardown_iter_ctx *it)
{
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats array.  See setns_back for the rationale. */
	const enum child_op_type op = it->child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	__atomic_add_fetch(&shm->stats.netns_teardown.setup_failed,
			   1, __ATOMIC_RELAXED);
	if (it->s_accept >= 0) (void)close(it->s_accept);
	if (it->s_conn   >= 0) (void)close(it->s_conn);
	if (it->s_listen >= 0) (void)close(it->s_listen);
	if (it->nsfd >= 0) {
		if (setns(it->nsfd, CLONE_NEWNET) < 0) {
			ns_unsupported_netns_teardown = true;
			if (valid_op)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_NS_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		(void)close(it->nsfd);
	}
}

/*
 * One outer iteration: anchor open, unshare, lo bring-up, sockets,
 * fork, race, kill, waitpid.  Best-effort; per-step counter bumps
 * carry the success signal.  Latches ns_unsupported on a probe-style
 * failure only (full-flow failures past the probe don't latch).
 */
static void iter_one(struct childdata *child)
{
	struct netns_teardown_iter_ctx it = {
		.nsfd = -1, .s_listen = -1, .s_conn = -1, .s_accept = -1,
		.pid = -1,
		.child = child,
	};
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  See setns_back for the rationale. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (netns_teardown_iter_setup_ns(&it) != 0)
		return;

	if (netns_teardown_iter_sock_pair(&it) != 0)
		goto recover;

	if (netns_teardown_iter_fork_child(&it) != 0)
		goto recover;

	if (netns_teardown_iter_parent_setns_back(&it) != 0)
		return;
	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	}
	netns_teardown_iter_drive_teardown(&it);
	return;

recover:
	netns_teardown_iter_recover(&it);
}

/*
 * Per-invocation state handed to the in-ns callback so iter_one's
 * stats writes keep landing against the right childop slot.
 */
struct netns_teardown_churn_ctx {
	struct childdata *child;
};

/*
 * Per-invocation body that must run inside a private user + net
 * namespace.  Executed in a transient grandchild forked by
 * userns_run_in_ns(); the grandchild's userns + netns are torn down
 * on _exit() so every socket, ns anchor fd, and in-ns great-grandchild
 * left behind by the BUDGETED outer loop is reaped by the kernel
 * along with the namespace stack.  Return value is ignored by the
 * helper.
 */
static int netns_teardown_churn_in_ns(void *arg)
{
	struct netns_teardown_churn_ctx *cctx = arg;
	struct childdata *child = cctx->child;
	unsigned int outer_iters, i;

	outer_iters = BUDGETED(CHILD_OP_NETNS_TEARDOWN_CHURN,
			       JITTER_RANGE(NETNS_TD_OUTER_BASE));
	if (outer_iters > NETNS_TD_OUTER_CAP)
		outer_iters = NETNS_TD_OUTER_CAP;
	if (outer_iters == 0U)
		outer_iters = 1U;

	for (i = 0; i < outer_iters; i++)
		iter_one(child);

	return 0;
}

bool netns_teardown_churn(struct childdata *child)
{
	struct netns_teardown_churn_ctx cctx = { .child = child };
	int rc;

	__atomic_add_fetch(&shm->stats.netns_teardown.runs,
			   1, __ATOMIC_RELAXED);

	if (ns_unsupported_netns_teardown) {
		__atomic_add_fetch(&shm->stats.netns_teardown.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	rc = userns_run_in_ns(CLONE_NEWNET, netns_teardown_churn_in_ns, &cctx);
	if (rc == -EPERM) {
		ns_unsupported_netns_teardown = true;
		/* child->op_type lives in shared memory and can be scribbled
		 * by a poisoned-arena write from a sibling; bounds-check the
		 * snapshot before indexing the NR_CHILD_OP_TYPES-sized stats
		 * array. */
		{
			const enum child_op_type op = child->op_type;
			if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_NS_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		__atomic_add_fetch(&shm->stats.netns_teardown.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}
	if (rc < 0) {
		/* Transient grandchild setup failure (fork, id-map write,
		 * secondary CLONE_NEWNET unshare).  Skip this iteration
		 * without latching -- the failure is not policy and may not
		 * recur. */
		__atomic_add_fetch(&shm->stats.netns_teardown.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	return true;
}

#else  /* !__has_include(<sched.h>) || !__has_include(<linux/netlink.h>) */

bool netns_teardown_churn(struct childdata *child)
{
	(void)child;
	__atomic_add_fetch(&shm->stats.netns_teardown.runs,
			   1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.netns_teardown.setup_failed,
			   1, __ATOMIC_RELAXED);
	return true;
}

#endif /* __has_include(<sched.h>) && __has_include(<linux/netlink.h>) */
