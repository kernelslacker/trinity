/*
 * netns_teardown_churn - race net namespace teardown against in-flight
 * sockets, raw sockets, and an XFRM netlink socket.
 *
 * Net namespace destruction is the single most prolific generator of
 * late-2024 / 2025 networking use-after-frees in the Linux kernel.
 * Whenever the last user of a struct net drops its reference, the
 * cleanup_net workqueue walks the per-pernet ops registered by every
 * networking module (ipv4, ipv6, netfilter, xfrm, conntrack, sctp,
 * tipc, mptcp, tcp_metrics, netrom, nf_tables, unix gc, ...) and runs
 * their ->exit / ->exit_batch hooks in a defined order.  Any module
 * whose pernet hook drops a reference to an object that another
 * still-running thread is mid-walk through is a candidate for the
 * race.  The bug-class spans:
 *
 *   - CVE-2024-26865 unix_gc namespace teardown vs SCM_RIGHTS in flight
 *   - CVE-2024-26851 netfilter pernet exit dropping nft refs early
 *   - CVE-2023-32269 netrom pernet destroy leaving sock with stale net
 *   - CVE-2024-1085  nft pernet exit racing nft_del_chain
 *   - CVE-2025-21684 tcp_metrics pernet exit vs concurrent metrics
 *
 * Sequence (per outer-loop iteration, BUDGETED):
 *   1.  Save anchor net namespace via open("/proc/self/ns/net", O_RDONLY).
 *   2.  unshare(CLONE_NEWNET) — parent enters a fresh net ns.
 *   3.  rtnetlink: bring lo up + assign 127.0.0.1 (best-effort; the
 *       send/recv burst still exercises pernet hooks even without
 *       a routable loopback because the sockets bind 127.0.0.1
 *       which the kernel always recognises in the v4 zero-config path).
 *   4.  s_listen = socket(AF_INET, SOCK_STREAM); bind 127.0.0.1:0;
 *       listen(); s_conn = socket(AF_INET, SOCK_STREAM); connect to
 *       s_listen's port — loopback completes the 3-way handshake on
 *       the listen queue without an accept().
 *   5.  s_accept = accept(s_listen) — pulls the connection off the
 *       queue so child has a true bidirectional pair.
 *   6.  fork() the in-ns child.
 *       Child:
 *         a) close anchor nsfd (child stays in doomed ns).
 *         b) opens AF_INET/SOCK_RAW/IPPROTO_ICMP — exercises raw
 *            pernet exit hook on the doomed net.
 *         c) opens AF_NETLINK/NETLINK_XFRM if the build supports it
 *            — exercises xfrm6/xfrm4 pernet exit hooks.
 *         d) tight send/recv loop on (s_conn ↔ s_accept), BUDGETED
 *            with JITTER and a 200ms wall-clock cap.
 *         e) keeps every fd open until SIGKILL.
 *       Parent:
 *         a) setns(nsfd, CLONE_NEWNET) — leaves the doomed ns.
 *         b) close its own copies of s_listen / s_conn / s_accept
 *            so only the in-ns child holds the doomed-net refs.
 *         c) brief usleep jitter so cleanup_net may or may not have
 *            already started.
 *         d) kill(child, SIGKILL) — last user of doomed ns dies.
 *         e) waitpid(child).
 *   7.  close anchor nsfd.
 *
 * Brick-safety: every operation runs inside a private net ns we just
 * unshared — no host-visible mutation possible.  The doomed ns is
 * cleaned up by the kernel within a few jiffies of the SIGKILL via
 * cleanup_net.  No persistent state left behind.  The raw socket and
 * xfrm netlink socket are best-effort; failure is benign.
 *
 * Cap-gate latch: first invocation per process probes
 *   nsfd = open("/proc/self/ns/net")
 *   unshare(CLONE_NEWNET)
 *   setns(nsfd, CLONE_NEWNET)
 * and latches ns_unsupported_netns_teardown on EPERM/ENOSYS from
 * either of the namespace ops.  Once latched, every subsequent
 * invocation just bumps setup_failed and returns — same shape as
 * the AF_UNIX SCM_RIGHTS / nf_conntrack_helper latches.
 *
 * Bound costs:
 *   - Outer loop: BUDGETED with base NETNS_TD_OUTER_BASE and
 *     cap NETNS_TD_OUTER_CAP, JITTER ±50%.
 *   - Inner send/recv: BUDGETED with base NETNS_TD_INNER_BASE
 *     and cap NETNS_TD_INNER_CAP, plus a 200ms wall-clock cap
 *     enforced via clock_gettime(CLOCK_MONOTONIC).
 *   - fork() failure: latch off + return clean.
 *
 * Failure modes treated as benign coverage:
 *   - rtnl bring-up failure: the send/recv path may sendto a socket
 *     bound to 127.0.0.1 with the loopback link still down; sends
 *     return EHOSTUNREACH but the pernet teardown still races.
 *   - send/recv EAGAIN/EPIPE: the racing teardown may have already
 *     started; we just stop pumping and let the kernel finish.
 *   - raw socket EPERM: unprivileged execution; raw socket variant
 *     is skipped that iteration.
 *   - waitpid EINTR: retried until WIFEXITED or WIFSIGNALED.
 */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "child.h"
#include "shm.h"
#include "trinity.h"

#if __has_include(<sched.h>) && __has_include(<linux/netlink.h>)

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sched.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_addr.h>
#include <linux/if.h>

#include "jitter.h"
#include "random.h"

#ifndef NETLINK_XFRM
#define NETLINK_XFRM			6
#endif

/* Per-process latched gate: namespace ops returned EPERM/ENOSYS in
 * the probe.  Once latched, every subsequent invocation short-
 * circuits with setup_failed bump.  Mirrors the af_unix_scm_rights_gc
 * / nf_conntrack_helper / handshake_req_abort latches. */
static bool ns_unsupported_netns_teardown;

/* Per-process probe-once latch: false until the first invocation has
 * confirmed the unshare+setns roundtrip works. */
static bool netns_teardown_probed;

#define NETNS_TD_OUTER_BASE		1U
#define NETNS_TD_OUTER_CAP		3U
#define NETNS_TD_INNER_BASE		4U
#define NETNS_TD_INNER_CAP		32U
#define NETNS_TD_WALL_CAP_NS		(200ULL * 1000ULL * 1000ULL)
#define NETNS_TD_PARENT_USLEEP_MAX	2000U
#define NETNS_TD_PAYLOAD_BYTES		16U

/*
 * Rtnetlink helpers.  Inlined here to avoid pulling another childop's
 * symbols across translation units; sequence ids are a per-process
 * counter (own AF_NETLINK socket per invocation, no cross-talk).
 */
static __u32 g_rtnl_seq;

static __u32 next_seq(void)
{
	return ++g_rtnl_seq;
}

static int rtnl_open(void)
{
	struct sockaddr_nl sa;
	struct timeval tv;
	int fd;

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (fd < 0)
		return -1;

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(fd);
		return -1;
	}

	tv.tv_sec  = 1;
	tv.tv_usec = 0;
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	return fd;
}

/*
 * Send a fully formed nlmsghdr and consume one ack.  Returns 0 on
 * positive ack, the negated kernel errno on rejection, or -EIO on
 * local sendmsg/recv failure.  Best-effort: callers don't propagate
 * the value beyond bumping a counter.
 */
static int rtnl_send_recv(int fd, void *msg, size_t len)
{
	struct sockaddr_nl dst;
	struct iovec iov;
	struct msghdr mh;
	unsigned char rbuf[256];
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

/*
 * RTM_NEWLINK setlink ifindex IFLA_IFI_UP — flip the loopback
 * device's IFF_UP bit on inside the fresh net ns.  ifi_change set
 * to IFF_UP only so we don't mask any other flags.
 */
static int lo_set_up(int fd, int ifindex)
{
	unsigned char buf[128];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = next_seq();

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = ifindex;
	ifi->ifi_flags  = IFF_UP;
	ifi->ifi_change = IFF_UP;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));
	nlh->nlmsg_len = (__u32)off;
	return rtnl_send_recv(fd, buf, off);
}

/*
 * RTM_NEWADDR ipv4 /8 attached to ifindex with address 127.0.0.1.
 * The /8 is what the kernel installs by default on lo so we match;
 * EEXIST is benign because the loopback already has the address in
 * a freshly-created net ns on most kernels via the v4 zero-config
 * path — bring-up is just belt-and-braces.
 */
static int lo_add_addr(int fd, int ifindex)
{
	unsigned char buf[128];
	struct nlmsghdr *nlh;
	struct ifaddrmsg *ifa;
	__u32 addr;
	struct nlattr *nla;
	size_t off, addr_off, total, aligned;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWADDR;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = next_seq();

	ifa = (struct ifaddrmsg *)NLMSG_DATA(nlh);
	ifa->ifa_family    = AF_INET;
	ifa->ifa_prefixlen = 8;
	ifa->ifa_flags     = 0;
	ifa->ifa_scope     = RT_SCOPE_HOST;
	ifa->ifa_index     = (unsigned int)ifindex;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifa));

	addr = htonl(0x7f000001U);
	addr_off = off;
	total = NLA_HDRLEN + sizeof(addr);
	aligned = NLA_ALIGN(total);
	if (off + aligned > sizeof(buf))
		return -EIO;
	nla = (struct nlattr *)(buf + off);
	nla->nla_type = IFA_LOCAL;
	nla->nla_len  = (unsigned short)total;
	memcpy(buf + off + NLA_HDRLEN, &addr, sizeof(addr));
	off += aligned;

	if (off + aligned > sizeof(buf))
		return -EIO;
	nla = (struct nlattr *)(buf + off);
	nla->nla_type = IFA_ADDRESS;
	nla->nla_len  = (unsigned short)total;
	memcpy(buf + off + NLA_HDRLEN, &addr, sizeof(addr));
	off += aligned;

	(void)addr_off;
	nlh->nlmsg_len = (__u32)off;
	return rtnl_send_recv(fd, buf, off);
}

/*
 * Bring the loopback interface up and assign 127.0.0.1.  Best-effort;
 * any rtnl error is non-fatal — the send/recv burst still races
 * pernet teardown even with a half-configured lo.  Returns 0 on full
 * success, -1 on rtnl_open failure.
 */
static int bring_up_loopback(void)
{
	int fd;
	int rc = 0;
	const int lo_ifindex = 1;	/* lo is always ifindex 1 in a fresh net ns */

	fd = rtnl_open();
	if (fd < 0)
		return -1;

	(void)lo_add_addr(fd, lo_ifindex);
	(void)lo_set_up(fd, lo_ifindex);
	close(fd);
	return rc;
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
	struct sockaddr_nl sa;

	*raw_fd = -1;
	*xfrm_fd = -1;

	fd = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMP);
	if (fd >= 0)
		*raw_fd = fd;

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_XFRM);
	if (fd < 0)
		return;
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(fd);
		return;
	}
	*xfrm_fd = fd;
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
 * Reap one fork-child via waitpid, retrying through EINTR.  The
 * caller has already SIGKILL'd so the wait should land essentially
 * immediately; the loop is purely to handle SIGALRM landing on the
 * trinity child mid-wait.
 */
static void reap_inflight_child(pid_t pid)
{
	int status;

	for (;;) {
		pid_t r = waitpid(pid, &status, 0);

		if (r == pid)
			return;
		if (r < 0 && errno == EINTR)
			continue;
		return;
	}
}

/*
 * One outer iteration: anchor open, unshare, lo bring-up, sockets,
 * fork, race, kill, waitpid.  Best-effort; per-step counter bumps
 * carry the success signal.  Latches ns_unsupported on a probe-style
 * failure only (full-flow failures past the probe don't latch).
 */
static void iter_one(void)
{
	int nsfd = -1;
	int s_listen = -1, s_conn = -1, s_accept = -1;
	struct sockaddr_in addr;
	socklen_t addrlen;
	pid_t pid;

	nsfd = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
	if (nsfd < 0) {
		__atomic_add_fetch(&shm->stats.netns_teardown_setup_failed,
				   1, __ATOMIC_RELAXED);
		return;
	}

	if (unshare(CLONE_NEWNET) < 0) {
		__atomic_add_fetch(&shm->stats.netns_teardown_setup_failed,
				   1, __ATOMIC_RELAXED);
		close(nsfd);
		return;
	}
	__atomic_add_fetch(&shm->stats.netns_teardown_unshare_ok,
			   1, __ATOMIC_RELAXED);

	(void)bring_up_loopback();

	s_listen = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (s_listen < 0)
		goto recover;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(0x7f000001U);
	addr.sin_port = 0;
	if (bind(s_listen, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		goto recover;
	if (listen(s_listen, 4) < 0)
		goto recover;

	addrlen = sizeof(addr);
	if (getsockname(s_listen, (struct sockaddr *)&addr, &addrlen) < 0)
		goto recover;

	s_conn = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (s_conn < 0)
		goto recover;
	if (connect(s_conn, (struct sockaddr *)&addr, sizeof(addr)) < 0 &&
	    errno != EINPROGRESS)
		goto recover;

	s_accept = accept(s_listen, NULL, NULL);
	if (s_accept < 0)
		goto recover;

	__atomic_add_fetch(&shm->stats.netns_teardown_socket_pair_ok,
			   1, __ATOMIC_RELAXED);

	pid = fork();
	if (pid < 0)
		goto recover;

	if (pid == 0) {
		int raw_fd = -1, xfrm_fd = -1;

		(void)close(nsfd);
		nsfd = -1;
		open_extras(&raw_fd, &xfrm_fd);
		child_pump(s_conn, s_accept);
		(void)raw_fd;
		(void)xfrm_fd;
		_exit(0);
	}

	__atomic_add_fetch(&shm->stats.netns_teardown_fork_ok,
			   1, __ATOMIC_RELAXED);

	if (setns(nsfd, CLONE_NEWNET) < 0) {
		/* setns failure leaves us stuck in the doomed ns.  Best
		 * effort: kill the child to release one ref so the
		 * cleanup_net workqueue can fire when this trinity child
		 * itself eventually exits.  Then bail out — every
		 * subsequent invocation will re-enter the same broken
		 * state, so latch off. */
		ns_unsupported_netns_teardown = true;
		(void)kill(pid, SIGKILL);
		reap_inflight_child(pid);
		__atomic_add_fetch(&shm->stats.netns_teardown_setup_failed,
				   1, __ATOMIC_RELAXED);
		(void)close(s_listen); s_listen = -1;
		(void)close(s_conn);   s_conn = -1;
		(void)close(s_accept); s_accept = -1;
		(void)close(nsfd);     nsfd = -1;
		return;
	}
	__atomic_add_fetch(&shm->stats.netns_teardown_setns_ok,
			   1, __ATOMIC_RELAXED);

	/* Drop parent's doomed-ns socket refs so only the in-ns child
	 * keeps the net alive.  Without this the ns can't die when the
	 * child does — defeats the whole race. */
	(void)close(s_listen); s_listen = -1;
	(void)close(s_conn);   s_conn = -1;
	(void)close(s_accept); s_accept = -1;

	(void)usleep(rand32() % NETNS_TD_PARENT_USLEEP_MAX);

	if (kill(pid, SIGKILL) == 0) {
		__atomic_add_fetch(&shm->stats.netns_teardown_kill_ok,
				   1, __ATOMIC_RELAXED);
	}
	reap_inflight_child(pid);

	(void)close(nsfd);
	nsfd = -1;
	__atomic_add_fetch(&shm->stats.netns_teardown_completed_ok,
			   1, __ATOMIC_RELAXED);
	return;

recover:
	/* Setup failed before fork: drop everything and try to setns
	 * back to the anchor so the trinity child isn't stuck in the
	 * doomed ns for the rest of its life.  Counter bump happens
	 * unconditionally; a setns-back failure here means we land in
	 * the latched-off state (subsequent invocations short-circuit). */
	__atomic_add_fetch(&shm->stats.netns_teardown_setup_failed,
			   1, __ATOMIC_RELAXED);
	if (s_accept >= 0) (void)close(s_accept);
	if (s_conn   >= 0) (void)close(s_conn);
	if (s_listen >= 0) (void)close(s_listen);
	if (nsfd >= 0) {
		if (setns(nsfd, CLONE_NEWNET) < 0)
			ns_unsupported_netns_teardown = true;
		(void)close(nsfd);
	}
}

/*
 * One-time probe: open anchor, unshare, setns back, close.  Latches
 * ns_unsupported on EPERM / ENOSYS / EINVAL from either ns op.  Uses
 * a separate code path from iter_one so the probe cost is paid once
 * and the bulk path doesn't carry the probe scaffolding.
 */
static void probe_netns(void)
{
	int probe_fd;

	netns_teardown_probed = true;

	probe_fd = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
	if (probe_fd < 0) {
		ns_unsupported_netns_teardown = true;
		return;
	}

	if (unshare(CLONE_NEWNET) < 0) {
		ns_unsupported_netns_teardown = true;
		(void)close(probe_fd);
		return;
	}

	if (setns(probe_fd, CLONE_NEWNET) < 0) {
		/* Stuck in fresh ns; mark unsupported so subsequent
		 * invocations short-circuit, and accept that this
		 * trinity child will run in a private ns from now on. */
		ns_unsupported_netns_teardown = true;
	}
	(void)close(probe_fd);
}

bool netns_teardown_churn(struct childdata *child)
{
	unsigned int outer_iters, i;

	(void)child;

	__atomic_add_fetch(&shm->stats.netns_teardown_runs,
			   1, __ATOMIC_RELAXED);

	if (ns_unsupported_netns_teardown) {
		__atomic_add_fetch(&shm->stats.netns_teardown_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (!netns_teardown_probed) {
		probe_netns();
		if (ns_unsupported_netns_teardown) {
			__atomic_add_fetch(&shm->stats.netns_teardown_setup_failed,
					   1, __ATOMIC_RELAXED);
			return true;
		}
	}

	outer_iters = BUDGETED(CHILD_OP_NETNS_TEARDOWN_CHURN,
			       JITTER_RANGE(NETNS_TD_OUTER_BASE));
	if (outer_iters > NETNS_TD_OUTER_CAP)
		outer_iters = NETNS_TD_OUTER_CAP;
	if (outer_iters == 0U)
		outer_iters = 1U;

	for (i = 0; i < outer_iters; i++)
		iter_one();

	return true;
}

#else  /* !__has_include(<sched.h>) || !__has_include(<linux/netlink.h>) */

bool netns_teardown_churn(struct childdata *child)
{
	(void)child;
	__atomic_add_fetch(&shm->stats.netns_teardown_runs,
			   1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.netns_teardown_setup_failed,
			   1, __ATOMIC_RELAXED);
	return true;
}

#endif /* __has_include(<sched.h>) && __has_include(<linux/netlink.h>) */
