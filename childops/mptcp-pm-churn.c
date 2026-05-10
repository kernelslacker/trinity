/*
 * mptcp_pm_churn - subflow add/remove race over a live MPTCP connection.
 *
 * The MPTCP path manager netlink family is the userspace control plane
 * for endpoint addresses, subflow steering, and per-namespace limits.
 * The bug class clustered here is the post-DEL race window: a
 * MPTCP_PM_CMD_DEL_ADDR followed promptly by data on the parent socket
 * exercises mptcp_pm_remove_anno_addr() and __mptcp_pm_release_addr()
 * concurrently with the data-plane subflow walker.  Subflow cleanup
 * (mptcp_pm_nl_subflow_chk_stale_on_addr / mptcp_pm_close_subflow)
 * runs against a sk that may still be writing through the very subflow
 * we're tearing down — exactly the shape of CVE-2024-26622
 * (mptcp_pm_remove_anno_addr UAF) and the sk_release-vs-pm-event family.
 *
 * Reaching that window from flat per-syscall fuzzing is hopeless: it
 * needs an established MPTCP socket on both ends, a primary subflow
 * carrying data, plus a sequence of genetlink ADD/DEL/SET pokes against
 * mptcp_pm_genl_ops[] with structurally valid MPTCP_PM_ATTR_ADDR
 * payloads.  No combination of independent setsockopt/sendto calls
 * assembles that without active orchestration.
 *
 * Sequence (per invocation):
 *   1.  socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP) for both server and
 *       client; bind/listen the server on 127.0.0.1:0 and connect.
 *       EPROTONOSUPPORT latches ns_unsupported_mptcp for the rest of
 *       this child's lifetime — CONFIG_MPTCP=n is fixed for the process.
 *   2.  accept() on the server side, drive a baseline send() over the
 *       primary subflow so the connection is in mptcp_established().
 *   3.  genl_resolve_families(); fam_mptcp_pm.resolved == 0 latches
 *       ns_unsupported_genetlink_mptcp.  The CTRL_GETFAMILY dump runs
 *       once per process and is shared with the genetlink-fuzzer
 *       childop and any other consumer that pulls in the registry.
 *   4.  BUDGETED loop:
 *         a) MPTCP_PM_CMD_ADD_ADDR with MPTCP_PM_ATTR_ADDR carrying
 *            FAMILY=AF_INET, ID=loc_id, ADDR4=127.0.0.<rot>.  Drives
 *            mptcp_pm_nl_add_addr_received() on the listener / pm_nl
 *            tables and queues an MP_ADD_ADDR option for transmit.
 *         b) MPTCP_PM_CMD_GET_ADDR with the same nested ADDR (LOC_ID
 *            inside) — exercises the lookup-by-id path under the same
 *            pernet lock the ADD just released.
 *         c) send() on the live MPTCP socket — race window vs the
 *            ADD_ADDR option emit on the wire.
 *         d) MPTCP_PM_CMD_DEL_ADDR with the same nested ADDR — drives
 *            mptcp_pm_remove_anno_addr() and any in-flight subflow
 *            cleanup against the address we just installed.
 *         e) send() on the live MPTCP socket — the targeted race
 *            window: data path running concurrently with subflow
 *            teardown for the just-removed loc_id.
 *         f) Coin-flip: SET_LIMITS (rcv/subflows u32) or FLUSH_ADDRS
 *            (no attrs).  Both reach pernet pm_nl state under the
 *            spinlock and exercise the broader teardown vs walker
 *            shape (FLUSH walks every endpoint, SET_LIMITS just
 *            updates two counters but reaches the same lock).
 *   5.  Tear down the MPTCP sockets.  loc_id rolls forward bounded
 *       to [1, 127] — the kernel mptcp_pm rejects loc_id > 127 with
 *       EINVAL (per __mptcp_pm_addr_id_check), so going past that
 *       point just plateaus the rejection counter and burns budget.
 *
 * Self-bounding: one full cycle per invocation, all sockets O_NONBLOCK
 * (so a wedged peer can't pin past child.c's SIGALRM(1s) safety net),
 * loopback only.  The genetlink ack socket has SO_RCVTIMEO so an
 * unresponsive controller can't wedge the child either.  All address
 * payloads stay inside 127.0.0.0/8 so nothing hits the wire.
 *
 * Header gating: <linux/mptcp_pm.h> is the YNL-generated UAPI header
 * that ships from kernel 6.11 onward.  Older sysroots without it (the
 * legacy <linux/mptcp.h> doesn't expose the same constants) fall to a
 * stub that bumps runs+setup_failed and returns — same shape as
 * tipc-link-churn's __has_include fallback.
 *
 * Failure modes treated as benign coverage:
 *   - EPROTONOSUPPORT on the first IPPROTO_MPTCP socket(): kernel built
 *     without CONFIG_MPTCP.  Latched ns_unsupported_mptcp.
 *   - fam_mptcp_pm.resolved == 0 after CTRL_GETFAMILY: the running
 *     kernel doesn't expose the mptcp_pm genl family.  Latched.
 *   - EPERM on any genl op: trinity wasn't run with CAP_NET_ADMIN in
 *     the current netns.  Counted as a reject; the data-plane sends
 *     still exercise the MPTCP socket layer.
 *   - EADDRINUSE on bind: another child grabbed the same port; the
 *     kernel will pick a fresh ephemeral on the next iteration.
 */

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "child.h"
#include "shm.h"
#include "trinity.h"

#if __has_include(<linux/mptcp_pm.h>)

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <linux/genetlink.h>
#include <linux/mptcp_pm.h>
#include <linux/netlink.h>

#include "jitter.h"
#include "netlink-genl-families.h"
#include "random.h"
#include "utils.h"

extern struct genl_family_grammar fam_mptcp_pm;

/* Latched per-child: IPPROTO_MPTCP socket() returned EPROTONOSUPPORT
 * once.  CONFIG_MPTCP is fixed for the life of the process so further
 * attempts are pure waste. */
static bool ns_unsupported_mptcp;

/* Latched per-child: genl_resolve_families() ran but fam_mptcp_pm.resolved
 * stayed 0 — kernel doesn't expose the family.  Same lifetime semantics
 * as ns_unsupported_mptcp. */
static bool ns_unsupported_genetlink_mptcp;

/* Per-process running netlink seq.  Shared across calls in the same
 * process — concurrent siblings each have their own netlink socket so
 * the seq overlap is harmless on the wire (the kernel doesn't dedupe
 * across sockets). */
static __u32 g_mptcp_pm_seq;

#define MPTCP_PM_GENL_BUF_BYTES		1024
#define MPTCP_PM_GENL_RECV_TIMEO_S	1

/* Base inner-loop iteration count for the ADD/DEL churn.  Real value
 * gets ±50% jitter via JITTER_RANGE() and per-op multiplier scaling
 * via BUDGETED() so adapt_budget can grow it on productive runs.
 * Kept small — every iteration emits two genl messages plus an
 * MP_ADD_ADDR option queued for transmit on the live MPTCP socket. */
#define CHURN_ITERS_BASE	3U

/* Loc-id ceiling.  The kernel's mptcp_pm address-id namespace is u8
 * but __mptcp_pm_addr_id_check rejects ids beyond 127 with EINVAL —
 * staying at or below 127 keeps the ADD_ADDR path past the front-door
 * validator and into the per-namespace endpoint table. */
#define MPTCP_PM_LOC_ID_MAX	127U

#define MPTCP_PM_LOOPBACK_BASE	0x7f000001U	/* 127.0.0.1 */
#define NR_MPTCP_LOOPBACK_ADDRS	5U

static __u32 next_seq(void)
{
	return ++g_mptcp_pm_seq;
}

static int mptcp_pm_genl_open(void)
{
	struct timeval tv;
	int fd;

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
	if (fd < 0)
		return -1;

	tv.tv_sec  = MPTCP_PM_GENL_RECV_TIMEO_S;
	tv.tv_usec = 0;
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	return fd;
}

/*
 * Append a flat NLA at *off with the given type and payload.  Returns
 * the new offset, or 0 on overflow (caller treats 0 as fail).  Same
 * shape as tipc-link-churn's nla_put — kept duplicated rather than
 * hoisted into a shared header because each childop's NLA construction
 * is tight enough that an inlined version is easier to follow than a
 * cross-file helper, and the duplication has stayed small.
 */
static size_t nla_put(unsigned char *buf, size_t off, size_t cap,
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

static size_t nla_put_u8(unsigned char *buf, size_t off, size_t cap,
			 unsigned short type, __u8 v)
{
	return nla_put(buf, off, cap, type, &v, sizeof(v));
}

static size_t nla_put_u16(unsigned char *buf, size_t off, size_t cap,
			  unsigned short type, __u16 v)
{
	return nla_put(buf, off, cap, type, &v, sizeof(v));
}

static size_t nla_put_u32(unsigned char *buf, size_t off, size_t cap,
			  unsigned short type, __u32 v)
{
	return nla_put(buf, off, cap, type, &v, sizeof(v));
}

/*
 * Send a complete genetlink message and wait for an NLMSG_ERROR ack.
 * Returns the kernel's ack errno (0 on success, negated errno on
 * rejection, or -EIO on local send/recv failure).  Caller fills the
 * full nlmsghdr+genlmsghdr+payload at offset 0 with NLM_F_ACK already
 * set in flags.
 */
static int mptcp_pm_genl_send_recv(int fd, void *msg, size_t len)
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

	if (sendmsg(fd, &mh, MSG_DONTWAIT) < 0)
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
	return -EIO;
}

/*
 * Build the start of an mptcp_pm genetlink message: nlmsghdr +
 * genlmsghdr, with NLM_F_ACK and the resolved family_id stamped in.
 * Returns the offset past the genl header; callers append per-cmd
 * attrs from there.  Bumps the per-family call counter so the
 * genl_family_calls_mptcp_pm stat row reflects this childop's traffic.
 */
static size_t mptcp_pm_genl_msg_start(unsigned char *buf, size_t cap, __u8 cmd)
{
	struct nlmsghdr *nlh;
	struct genlmsghdr *gnh;

	if (cap < NLMSG_HDRLEN + GENL_HDRLEN)
		return 0;

	memset(buf, 0, NLMSG_HDRLEN + GENL_HDRLEN);
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = fam_mptcp_pm.family_id;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = next_seq();

	gnh = (struct genlmsghdr *)NLMSG_DATA(nlh);
	gnh->cmd     = cmd;
	gnh->version = MPTCP_PM_VER;

	genl_family_bump_calls(&fam_mptcp_pm);
	return NLMSG_HDRLEN + GENL_HDRLEN;
}

/*
 * Build a MPTCP_PM_ATTR_ADDR nested entry carrying FAMILY=AF_INET,
 * ID=loc_id, ADDR4=addr_h.  Used by ADD_ADDR / DEL_ADDR / GET_ADDR
 * which all share the same outer nest shape.  Returns the new outer-
 * buf offset, or 0 on overflow.  NLA_F_NESTED set on the outer per the
 * libnl/iproute2 convention so the kernel's nla_parse_nested matches
 * cleanly under strict-mode validation.
 */
static size_t put_mptcp_addr_nest(unsigned char *buf, size_t off, size_t cap,
				  __u8 loc_id, __u32 addr_h)
{
	struct nlattr *outer;
	size_t outer_off = off;

	off = nla_put(buf, off, cap, MPTCP_PM_ATTR_ADDR | NLA_F_NESTED,
		      NULL, 0);
	if (!off)
		return 0;

	off = nla_put_u16(buf, off, cap, MPTCP_PM_ADDR_ATTR_FAMILY, AF_INET);
	if (!off)
		return 0;

	off = nla_put_u8(buf, off, cap, MPTCP_PM_ADDR_ATTR_ID, loc_id);
	if (!off)
		return 0;

	{
		__u32 addr_n = htonl(addr_h);

		off = nla_put(buf, off, cap, MPTCP_PM_ADDR_ATTR_ADDR4,
			      &addr_n, sizeof(addr_n));
	}
	if (!off)
		return 0;

	outer = (struct nlattr *)(buf + outer_off);
	outer->nla_len = (unsigned short)(off - outer_off);
	return off;
}

/*
 * Build & send MPTCP_PM_CMD_<cmd> carrying just an MPTCP_PM_ATTR_ADDR
 * nest with the given loc_id + addr.  Used for ADD_ADDR, DEL_ADDR, and
 * GET_ADDR.  Returns the kernel's ack errno.
 */
static int mptcp_pm_addr_cmd(int fd, __u8 cmd, __u8 loc_id, __u32 addr_h)
{
	unsigned char buf[MPTCP_PM_GENL_BUF_BYTES];
	struct nlmsghdr *nlh;
	size_t off;

	off = mptcp_pm_genl_msg_start(buf, sizeof(buf), cmd);
	if (!off)
		return -EIO;

	off = put_mptcp_addr_nest(buf, off, sizeof(buf), loc_id, addr_h);
	if (!off)
		return -EIO;

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = (__u32)off;
	return mptcp_pm_genl_send_recv(fd, buf, off);
}

/*
 * Build & send MPTCP_PM_CMD_SET_LIMITS with random small u32 values
 * for RCV_ADD_ADDRS and SUBFLOWS (capped at 8 each).  The kernel
 * validates the values into an mptcp_pm_data and overwrites the
 * pernet limits under the spinlock — same lock the FLUSH walker
 * needs, so this is a useful coverage edge even when the values are
 * trivial.  Returns the kernel's ack errno.
 */
static int mptcp_pm_set_limits(int fd)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	size_t off;
	__u32 rcv = (rand32() & 0x7U) + 1U;
	__u32 sub = (rand32() & 0x7U) + 1U;

	off = mptcp_pm_genl_msg_start(buf, sizeof(buf), MPTCP_PM_CMD_SET_LIMITS);
	if (!off)
		return -EIO;

	off = nla_put_u32(buf, off, sizeof(buf),
			  MPTCP_PM_ATTR_RCV_ADD_ADDRS, rcv);
	if (!off)
		return -EIO;

	off = nla_put_u32(buf, off, sizeof(buf),
			  MPTCP_PM_ATTR_SUBFLOWS, sub);
	if (!off)
		return -EIO;

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = (__u32)off;
	return mptcp_pm_genl_send_recv(fd, buf, off);
}

/*
 * Build & send MPTCP_PM_CMD_FLUSH_ADDRS — no attrs.  The kernel walks
 * the pernet endpoint table and removes every entry under the pm
 * spinlock, racing the data-plane subflow walker.  Returns the
 * kernel's ack errno.
 */
static int mptcp_pm_flush_addrs(int fd)
{
	unsigned char buf[128];
	struct nlmsghdr *nlh;
	size_t off;

	off = mptcp_pm_genl_msg_start(buf, sizeof(buf), MPTCP_PM_CMD_FLUSH_ADDRS);
	if (!off)
		return -EIO;

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = (__u32)off;
	return mptcp_pm_genl_send_recv(fd, buf, off);
}

/*
 * Drive one short non-blocking send.  Counts the success — a
 * succeeded send_ok stat tick distinguishes "MPTCP socket up + data
 * path usable" from "TCP fallback / wedged subflow / kernel rejection".
 */
static void churn_send(int fd)
{
	unsigned char buf[128];
	ssize_t n;

	generate_rand_bytes(buf, sizeof(buf));
	n = send(fd, buf, 1U + ((unsigned int)rand() % sizeof(buf)),
		 MSG_DONTWAIT | MSG_NOSIGNAL);
	if (n > 0)
		__atomic_add_fetch(&shm->stats.mptcp_pm_churn_send_ok,
				   1, __ATOMIC_RELAXED);
}

/*
 * Static table of TCP-level sockopts that mptcp's setsockopt_all_sf()
 * propagates from the master mptcp socket to every current and future
 * subflow.  Upstream commit 70ece9d7021c restored a missing
 * sockopt_seq_inc() in that propagation path: without the seq bump,
 * subflows created AFTER the master setsockopt() inherit stale state.
 *
 * Each entry pairs an SOL_TCP optname with a small value generator.
 * TCP_CONGESTION is intentionally omitted — its string-arg path doesn't
 * fit the int-valued table here.
 */
struct mptcp_sf_optspec {
	const char	*name;
	int		 optname;
	int		 (*genval)(void);
};

static int genval_maxseg(void)		{ return 536 + (int)(rand32() % 800U); }
static int genval_bool(void)		{ return RAND_BOOL() ? 1 : 0; }
static int genval_keepidle(void)	{ return 1 + (int)(rand32() % 600U); }
static int genval_keepintvl(void)	{ return 1 + (int)(rand32() % 60U); }
static int genval_keepcnt(void)		{ return 1 + (int)(rand32() % 16U); }
static int genval_user_to(void)		{ return 1 + (int)(rand32() % 30000U); }
static int genval_defer(void)		{ return 1 + (int)(rand32() % 60U); }

static const struct mptcp_sf_optspec mptcp_sf_opts[] = {
	{ "TCP_MAXSEG",		TCP_MAXSEG,		genval_maxseg },
	{ "TCP_NODELAY",	TCP_NODELAY,		genval_bool },
	{ "TCP_CORK",		TCP_CORK,		genval_bool },
	{ "TCP_KEEPIDLE",	TCP_KEEPIDLE,		genval_keepidle },
	{ "TCP_KEEPINTVL",	TCP_KEEPINTVL,		genval_keepintvl },
	{ "TCP_KEEPCNT",	TCP_KEEPCNT,		genval_keepcnt },
	{ "TCP_USER_TIMEOUT",	TCP_USER_TIMEOUT,	genval_user_to },
	{ "TCP_DEFER_ACCEPT",	TCP_DEFER_ACCEPT,	genval_defer },
};

/* Local shims so the sweep sub-mode below compiles on sysroots whose
 * <netinet/tcp.h> / <linux/mptcp.h> predate these constants.  Values
 * match the kernel UAPI; same defines live in include/compat.h. */
#ifndef SOL_MPTCP
#define SOL_MPTCP	284
#endif
#ifndef MPTCP_INFO
#define MPTCP_INFO	1
#endif

/*
 * Curated sweep table for the sockopt-inheritance sub-mode below.
 * Each entry is a TCP-level option that mptcp_setsockopt_all_sf()
 * propagates from the master to every existing AND future subflow.
 * Upstream commit 70ece9d7021c restored a missing sockopt_seq_inc()
 * in that path: without it, subflows added AFTER a master setsockopt
 * silently inherited the pre-set value.  Wider value ranges than the
 * sibling all_sf_recipe — this sweep is specifically poking the
 * inheritance edge, not the value-validation edge.
 */
static int sweep_genval_u32(void)	{ return (int)rand32(); }
static int sweep_genval_syncnt(void)	{ return 1 + (int)(rand32() % 127U); }
static int sweep_genval_keepidle_w(void){ return 1 + (int)(rand32() % 32767U); }
static int sweep_genval_keepintvl_w(void){ return 1 + (int)(rand32() % 32767U); }
static int sweep_genval_keepcnt_w(void)	{ return 1 + (int)(rand32() % 127U); }
static int sweep_genval_maxseg_w(void)	{ return 88 + (int)(rand32() % (32767U - 88U)); }

static const struct mptcp_sf_optspec mptcp_sf_sweep_opts[] = {
	{ "TCP_MAXSEG",		TCP_MAXSEG,		sweep_genval_maxseg_w },
	{ "TCP_NODELAY",	TCP_NODELAY,		genval_bool },
	{ "TCP_CORK",		TCP_CORK,		genval_bool },
	{ "TCP_KEEPIDLE",	TCP_KEEPIDLE,		sweep_genval_keepidle_w },
	{ "TCP_KEEPINTVL",	TCP_KEEPINTVL,		sweep_genval_keepintvl_w },
	{ "TCP_KEEPCNT",	TCP_KEEPCNT,		sweep_genval_keepcnt_w },
	{ "TCP_USER_TIMEOUT",	TCP_USER_TIMEOUT,	sweep_genval_u32 },
	{ "TCP_SYNCNT",		TCP_SYNCNT,		sweep_genval_syncnt },
	{ "TCP_LINGER2",	TCP_LINGER2,		sweep_genval_u32 },
	{ "TCP_NOTSENT_LOWAT",	TCP_NOTSENT_LOWAT,	sweep_genval_u32 },
	{ "TCP_DEFER_ACCEPT",	TCP_DEFER_ACCEPT,	sweep_genval_u32 },
	{ "TCP_QUICKACK",	TCP_QUICKACK,		genval_bool },
	{ "TCP_FASTOPEN_CONNECT", TCP_FASTOPEN_CONNECT,	genval_bool },
};

/* Per-opt unsupported-latch bitmap.  When the master's setsockopt
 * returns EOPNOTSUPP/ENOPROTOOPT, that opt is dropped from the
 * rotation for the rest of the process — the kernel's MPTCP build
 * gating won't change mid-run.  Sized for ARRAY_SIZE(...) ≤ 32. */
static unsigned int sweep_unsupported_mask;

/*
 * Read MPTCP_INFO and return num_subflows (mptcpi_subflows is the
 * first byte of struct mptcp_info, stable since the option was
 * introduced).  Returns 0 on any error path so the bump-detect loop
 * just keeps polling — child.c's SIGALRM(1s) is the outer cap.
 */
static unsigned int sweep_get_subflow_count(int sk)
{
	unsigned char buf[256];
	socklen_t len = sizeof(buf);

	memset(buf, 0, sizeof(buf));
	if (getsockopt(sk, SOL_MPTCP, MPTCP_INFO, buf, &len) < 0)
		return 0;
	if (len < 1)
		return 0;
	return buf[0];
}

/*
 * Sockopt-inheritance sweep.  Order matters: setsockopt FIRST on the
 * live MPTCP master, then ADD_ADDR via the existing PM machinery so
 * the kernel MP_JOINs to the new endpoint AFTER the option is in
 * place.  Bounded poll on MPTCP_INFO num_subflows confirms the new
 * subflow actually came up before we readback.  A readback drift on
 * the master is the bug-signal counter — collected, not asserted;
 * upstream 70ece9d7021c is the fix shape.
 */
static void mptcp_sockopt_inheritance_sweep(int cli, int genl_fd)
{
	const struct mptcp_sf_optspec *spec;
	unsigned int idx = 0, tries;
	unsigned int n_before, n_after;
	int set_val, get_val = 0;
	socklen_t glen;
	__u8 loc_id;
	__u32 addr_h;
	const unsigned int n_opts = ARRAY_SIZE(mptcp_sf_sweep_opts);
	const unsigned int all_mask = (n_opts >= 32U) ? ~0U
					: ((1U << n_opts) - 1U);

	__atomic_add_fetch(&shm->stats.mptcp_sockopt_sweep_runs,
			   1, __ATOMIC_RELAXED);

	if (sweep_unsupported_mask == all_mask)
		return;

	for (tries = 0; tries < n_opts * 2U; tries++) {
		idx = (unsigned int)(rand32() % n_opts);
		if (!(sweep_unsupported_mask & (1U << idx)))
			break;
	}
	if (sweep_unsupported_mask & (1U << idx))
		return;

	spec = &mptcp_sf_sweep_opts[idx];
	set_val = spec->genval();

	n_before = sweep_get_subflow_count(cli);

	if (setsockopt(cli, IPPROTO_TCP, spec->optname,
		       &set_val, sizeof(set_val)) < 0) {
		if (errno == EOPNOTSUPP || errno == ENOPROTOOPT) {
			sweep_unsupported_mask |= (1U << idx);
			__atomic_add_fetch(&shm->stats.mptcp_sockopt_unsupported_latched,
					   1, __ATOMIC_RELAXED);
		}
		__atomic_add_fetch(&shm->stats.mptcp_sockopt_set_failed,
				   1, __ATOMIC_RELAXED);
		return;
	}
	__atomic_add_fetch(&shm->stats.mptcp_sockopt_set_ok,
			   1, __ATOMIC_RELAXED);

	loc_id = 1U + (__u8)(rand32() % MPTCP_PM_LOC_ID_MAX);
	addr_h = MPTCP_PM_LOOPBACK_BASE + (rand32() % NR_MPTCP_LOOPBACK_ADDRS);
	(void)mptcp_pm_addr_cmd(genl_fd, MPTCP_PM_CMD_ADD_ADDR,
				loc_id, addr_h);

	n_after = n_before;
	for (tries = 0; tries < 8U; tries++) {
		n_after = sweep_get_subflow_count(cli);
		if (n_after > n_before)
			break;
		sched_yield();
	}
	if (n_after > n_before)
		__atomic_add_fetch(&shm->stats.mptcp_sockopt_subflow_added,
				   1, __ATOMIC_RELAXED);

	glen = sizeof(get_val);
	if (getsockopt(cli, IPPROTO_TCP, spec->optname,
		       &get_val, &glen) == 0 && glen == sizeof(get_val)) {
		__atomic_add_fetch(&shm->stats.mptcp_sockopt_readback_ok,
				   1, __ATOMIC_RELAXED);
		if (get_val != set_val)
			__atomic_add_fetch(&shm->stats.mptcp_sockopt_inherit_mismatch,
					   1, __ATOMIC_RELAXED);
	}
}

/*
 * Per-iteration recipe targeting the setsockopt_all_sf seq window:
 *   1. open a fresh master IPPROTO_MPTCP socket (separate from the
 *      live churn connection so we don't interfere with the ADD/DEL
 *      race window the outer loop drives),
 *   2. setsockopt() a randomly-picked TCP-level option on the master,
 *   3. drive an MPTCP_PM_CMD_ADD_ADDR so the path manager creates a
 *      subflow AFTER the master setsockopt — this is the seq window
 *      upstream commit 70ece9d7021c closes,
 *   4. yield briefly so the subflow create can run,
 *   5. getsockopt() the same optname on the master and verify the
 *      value matches — catches the trivially-broken case where the
 *      master itself wasn't applied.
 *
 * Subflow sockopt state isn't directly fd-addressable from userspace,
 * so the kernel-level seq miss is observable as a behavioural drift in
 * subflow connect timing / TCP behaviour, not via a userspace
 * getsockopt on the subflow.  Goal here is just to drive the codepath
 * under fuzz so KASAN/UBSAN/lockdep can fire.
 */
static void mptcp_setsockopt_all_sf_recipe(int genl_fd)
{
	const struct mptcp_sf_optspec *spec;
	int sk;
	int set_val;
	int get_val = 0;
	socklen_t glen;
	__u8 loc_id;
	__u32 addr_h;
	unsigned int idle;

	sk = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_MPTCP);
	if (sk < 0) {
		if (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT ||
		    errno == ESOCKTNOSUPPORT) {
			ns_unsupported_mptcp = true;
			__atomic_add_fetch(&shm->stats.mptcp_setsockopt_unsupported,
					   1, __ATOMIC_RELAXED);
		}
		return;
	}

	spec = &mptcp_sf_opts[rand32() % ARRAY_SIZE(mptcp_sf_opts)];
	set_val = spec->genval();

	if (setsockopt(sk, IPPROTO_TCP, spec->optname,
		       &set_val, sizeof(set_val)) < 0) {
		__atomic_add_fetch(&shm->stats.mptcp_setsockopt_master_fail,
				   1, __ATOMIC_RELAXED);
	} else {
		__atomic_add_fetch(&shm->stats.mptcp_setsockopt_master_set,
				   1, __ATOMIC_RELAXED);
	}

	/* Trigger a subflow create AFTER the master setsockopt — this is
	 * the seq window upstream commit 70ece9d7021c closes.  loc_id and
	 * addr ranges match the outer loop's bounds so the kernel's
	 * pernet endpoint validator accepts the request. */
	loc_id = 1U + (__u8)(rand32() % MPTCP_PM_LOC_ID_MAX);
	addr_h = MPTCP_PM_LOOPBACK_BASE + (rand32() % NR_MPTCP_LOOPBACK_ADDRS);
	(void)mptcp_pm_addr_cmd(genl_fd, MPTCP_PM_CMD_ADD_ADDR,
				loc_id, addr_h);

	idle = 1U + (rand32() % 3U);
	while (idle--)
		sched_yield();

	glen = sizeof(get_val);
	if (getsockopt(sk, IPPROTO_TCP, spec->optname,
		       &get_val, &glen) == 0 && glen == sizeof(get_val)) {
		if (get_val == set_val)
			__atomic_add_fetch(&shm->stats.mptcp_getsockopt_verify_ok,
					   1, __ATOMIC_RELAXED);
		else
			__atomic_add_fetch(&shm->stats.mptcp_getsockopt_verify_drift,
					   1, __ATOMIC_RELAXED);
	}

	close(sk);
}

bool mptcp_pm_churn(struct childdata *child)
{
	struct sockaddr_in srv_addr, cli_addr;
	socklen_t slen;
	int srv = -1;
	int cli = -1;
	int srv_acc = -1;
	int genl_fd = -1;
	uint16_t srv_port_n;
	unsigned int iters;
	unsigned int i;
	__u8 loc_id;
	unsigned int rot_idx;

	(void)child;

	__atomic_add_fetch(&shm->stats.mptcp_pm_churn_runs,
			   1, __ATOMIC_RELAXED);

	if (ns_unsupported_mptcp || ns_unsupported_genetlink_mptcp)
		return true;

	srv = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_MPTCP);
	if (srv < 0) {
		if (errno == EPROTONOSUPPORT || errno == ESOCKTNOSUPPORT)
			ns_unsupported_mptcp = true;
		__atomic_add_fetch(&shm->stats.mptcp_pm_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}
	__atomic_add_fetch(&shm->stats.mptcp_pm_churn_sock_mptcp_ok,
			   1, __ATOMIC_RELAXED);

	memset(&srv_addr, 0, sizeof(srv_addr));
	srv_addr.sin_family = AF_INET;
	srv_addr.sin_addr.s_addr = htonl(MPTCP_PM_LOOPBACK_BASE);
	srv_addr.sin_port = 0;
	if (bind(srv, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) < 0) {
		__atomic_add_fetch(&shm->stats.mptcp_pm_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}
	slen = sizeof(srv_addr);
	if (getsockname(srv, (struct sockaddr *)&srv_addr, &slen) < 0) {
		__atomic_add_fetch(&shm->stats.mptcp_pm_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}
	srv_port_n = srv_addr.sin_port;

	if (listen(srv, 4) < 0) {
		__atomic_add_fetch(&shm->stats.mptcp_pm_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}

	cli = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_MPTCP);
	if (cli < 0) {
		__atomic_add_fetch(&shm->stats.mptcp_pm_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}

	/* Non-blocking from here so a wedged peer can't pin us past
	 * SIGALRM(1s).  TCP-style connect on loopback completes
	 * synchronously almost always, but on rare overload the kernel
	 * may return EINPROGRESS — fine, the assoc completes and the
	 * later send() either piggybacks or queues. */
	(void)fcntl(cli, F_SETFL, O_NONBLOCK);
	(void)fcntl(srv, F_SETFL, O_NONBLOCK);

	memset(&cli_addr, 0, sizeof(cli_addr));
	cli_addr.sin_family = AF_INET;
	cli_addr.sin_addr.s_addr = htonl(MPTCP_PM_LOOPBACK_BASE);
	cli_addr.sin_port = srv_port_n;
	if (connect(cli, (struct sockaddr *)&cli_addr,
		    sizeof(cli_addr)) < 0 && errno != EINPROGRESS) {
		__atomic_add_fetch(&shm->stats.mptcp_pm_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}

	srv_acc = accept(srv, NULL, NULL);
	if (srv_acc >= 0)
		(void)fcntl(srv_acc, F_SETFL, O_NONBLOCK);
	/* accept failure here is fine — the SYN/cookie may not have
	 * landed yet, and the genl ADD/DEL churn still exercises the
	 * pernet endpoint table and the client-side option emit path
	 * even if the server-side state machine hasn't caught up. */

	/* Drive the data path before the first ADD_ADDR so the
	 * connection has actually transitioned to ESTABLISHED on both
	 * ends.  Otherwise the post-handshake genl ops race against
	 * the cookie itself, which isn't the bug class we're targeting. */
	churn_send(cli);
	if (srv_acc >= 0)
		churn_send(srv_acc);

	genl_resolve_families();
	if (!fam_mptcp_pm.resolved) {
		ns_unsupported_genetlink_mptcp = true;
		goto out;
	}

	genl_fd = mptcp_pm_genl_open();
	if (genl_fd < 0) {
		__atomic_add_fetch(&shm->stats.mptcp_pm_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}

	/* Initial loc_id: random in [1, MPTCP_PM_LOC_ID_MAX].  The
	 * kernel's loc_id 0 is reserved for the primary subflow auto-
	 * assigned at connect time; staying [1, 127] keeps every iter
	 * past the front-door validator. */
	loc_id = 1U + (__u8)(rand32() % MPTCP_PM_LOC_ID_MAX);
	rot_idx = 1U;	/* start with 127.0.0.2 — primary 127.0.0.1 is
			 * already in use by the connect itself. */

	iters = BUDGETED(CHILD_OP_MPTCP_PM_CHURN,
			 JITTER_RANGE(CHURN_ITERS_BASE));
	for (i = 0; i < iters; i++) {
		__u32 addr_h = MPTCP_PM_LOOPBACK_BASE +
			       (rot_idx % NR_MPTCP_LOOPBACK_ADDRS);
		int rc;

		/* a) ADD_ADDR with FAMILY+ID+ADDR4 inside the nested
		 *    MPTCP_PM_ATTR_ADDR.  Kernel installs the endpoint
		 *    in the pernet table and queues an MP_ADD_ADDR
		 *    option for transmit on every up MPTCP socket. */
		rc = mptcp_pm_addr_cmd(genl_fd, MPTCP_PM_CMD_ADD_ADDR,
				       loc_id, addr_h);
		if (rc == 0)
			__atomic_add_fetch(&shm->stats.mptcp_pm_churn_addr_added_ok,
					   1, __ATOMIC_RELAXED);

		/* b) GET_ADDR with the same nested ADDR — exercises
		 *    the lookup-by-id path under the same pernet lock
		 *    the ADD just released.  Reply is a NEWADDR-style
		 *    response we don't parse — recv consumes it. */
		(void)mptcp_pm_addr_cmd(genl_fd, MPTCP_PM_CMD_GET_ADDR,
					loc_id, addr_h);

		/* c) Send during the ADD_ADDR option emit window. */
		churn_send(cli);
		if (srv_acc >= 0)
			churn_send(srv_acc);

		/* d) DEL_ADDR — drives mptcp_pm_remove_anno_addr() and
		 *    any in-flight subflow cleanup against the address
		 *    we just installed. */
		rc = mptcp_pm_addr_cmd(genl_fd, MPTCP_PM_CMD_DEL_ADDR,
				       loc_id, addr_h);
		if (rc == 0)
			__atomic_add_fetch(&shm->stats.mptcp_pm_churn_addr_removed_ok,
					   1, __ATOMIC_RELAXED);

		/* e) Targeted race window: data path running
		 *    concurrently with subflow teardown for the just-
		 *    removed loc_id. */
		churn_send(cli);
		if (srv_acc >= 0)
			churn_send(srv_acc);

		/* f) Coin-flip between SET_LIMITS and FLUSH_ADDRS —
		 *    both reach pernet pm_nl state under the spinlock
		 *    and exercise the broader teardown vs walker
		 *    shape.  Splitting at random gives rough 50/50
		 *    coverage of each command across runs. */
		if (RAND_BOOL())
			(void)mptcp_pm_set_limits(genl_fd);
		else
			(void)mptcp_pm_flush_addrs(genl_fd);

		/* g) Occasional setsockopt_all_sf seq-window probe:
		 *    open a fresh master mptcp socket, set a TCP-level
		 *    sockopt, drive an ADD_ADDR to create a subflow
		 *    during the propagation seq window, and verify the
		 *    master got the value.  Same cadence as other
		 *    sub-modes, drives the path 70ece9d7021c fixed. */
		if (ONE_IN(8))
			mptcp_setsockopt_all_sf_recipe(genl_fd);

		/* h) Sockopt-inheritance sweep on the live master.  Walks
		 *    a curated TCP_* table, sets one opt, drives ADD_ADDR
		 *    to spawn a subflow AFTER the option is in place, then
		 *    polls MPTCP_INFO until num_subflows bumps and reads
		 *    the option back.  A drift bumps the bug-signal
		 *    counter (70ece9d7021c).  Higher cadence than the
		 *    fresh-socket recipe above — reusing the established
		 *    connection is much cheaper. */
		if (ONE_IN(4))
			mptcp_sockopt_inheritance_sweep(cli, genl_fd);

		/* Walk loc_id forward bounded to [1, MPTCP_PM_LOC_ID_MAX].
		 * The kernel rejects loc_id > 127 with EINVAL so capping
		 * here avoids an EINVAL plateau that would burn budget
		 * without exercising the post-validator paths. */
		loc_id = (loc_id % MPTCP_PM_LOC_ID_MAX) + 1U;
		rot_idx = (rot_idx + 1U) % NR_MPTCP_LOOPBACK_ADDRS;
	}

out:
	if (genl_fd >= 0)
		close(genl_fd);
	if (srv_acc >= 0)
		close(srv_acc);
	if (cli >= 0)
		close(cli);
	if (srv >= 0)
		close(srv);
	return true;
}

#else  /* !__has_include(<linux/mptcp_pm.h>) */

bool mptcp_pm_churn(struct childdata *child)
{
	(void)child;
	__atomic_add_fetch(&shm->stats.mptcp_pm_churn_runs,
			   1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.mptcp_pm_churn_setup_failed,
			   1, __ATOMIC_RELAXED);
	return true;
}

#endif /* __has_include(<linux/mptcp_pm.h>) */
