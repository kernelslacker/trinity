/*
 * mptcp_pm_churn - subflow add/remove race over a live MPTCP connection.
 *
 * Targets the post-DEL race window on the MPTCP path-manager genl family:
 * MPTCP_PM_CMD_DEL_ADDR followed promptly by data on the parent socket runs
 * mptcp_pm_remove_anno_addr() / __mptcp_pm_release_addr() and the subflow
 * cleanup path (mptcp_pm_nl_subflow_chk_stale_on_addr / mptcp_pm_close_subflow)
 * concurrently with the data-plane subflow walker -- exactly the shape of
 * CVE-2024-26622 and the wider sk_release-vs-pm-event family.  Flat per-syscall
 * fuzzing can't assemble the coherent quad this op needs: an established MPTCP
 * socket on both ends, a primary subflow carrying data, and structurally-valid
 * ADD/GET/DEL/SET pokes against mptcp_pm_genl_ops[].
 *
 * Each invocation opens an IPPROTO_MPTCP client+server on 127.0.0.1, drives a
 * baseline send() to reach mptcp_established(), then runs a BUDGETED loop
 * pairing ADD_ADDR / GET_ADDR / DEL_ADDR against live send()s, occasionally
 * folding in SET_LIMITS or FLUSH_ADDRS to walk the pernet pm_nl state under
 * the same spinlock.  loc_id rolls in [1, 127] to stay inside
 * __mptcp_pm_addr_id_check.
 *
 * Brick-safety: loopback only; all sockets O_NONBLOCK so a wedged peer can't
 * pin past child.c's SIGALRM(1s) backstop; genl ack socket has SO_RCVTIMEO.
 * All addresses stay inside 127.0.0.0/8, nothing hits the wire.
 *
 * Latches (per-process): ns_unsupported_mptcp on EPROTONOSUPPORT from
 * IPPROTO_MPTCP socket() -- CONFIG_MPTCP=n is fixed for the process's life.
 * ns_unsupported_genetlink_mptcp on ENOENT resolving the "mptcp_pm" family.
 * EPERM / EADDRINUSE are counted and continued.
 *
 * Header-gated by __has_include(<linux/mptcp_pm.h>) (YNL header, 6.11+); older
 * sysroots fall to the stub (setup_failed++), same shape as tipc-link-churn.
 */

#include <errno.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>

#include "child.h"
#include "errno-classify.h"
#include "shm.h"
#include "trinity.h"

#if __has_include(<linux/mptcp_pm.h>)

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <linux/mptcp_pm.h>
#include <linux/net_tstamp.h>
#include <linux/netlink.h>

#include "childops-genl.h"
#include "jitter.h"
#include "random.h"
#include "rnd.h"
#include "utils.h"

#include "kernel/socket.h"
#include "kernel/mptcp.h"
/* Latched per-child: IPPROTO_MPTCP socket() returned EPROTONOSUPPORT
 * once.  CONFIG_MPTCP is fixed for the life of the process so further
 * attempts are pure waste. */
static bool ns_unsupported_mptcp;

/* Latched per-child: genl_open("mptcp_pm", ...) returned -ENOENT, so
 * the kernel doesn't expose the mptcp_pm genl family at all.  Same
 * lifetime semantics as ns_unsupported_mptcp. */
static bool ns_unsupported_genetlink_mptcp;

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
static int mptcp_pm_addr_cmd(struct genl_ctx *ctx, __u8 cmd, __u8 loc_id,
			     __u32 addr_h)
{
	unsigned char buf[MPTCP_PM_GENL_BUF_BYTES];
	struct nlmsghdr *nlh;
	size_t off;

	off = genl_msg_put(buf, 0, sizeof(buf), ctx,
			   nl_seq_next(&ctx->nl), cmd, 0);
	if (!off)
		return -EIO;

	off = put_mptcp_addr_nest(buf, off, sizeof(buf), loc_id, addr_h);
	if (!off)
		return -EIO;

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = (__u32)off;
	return genl_send_recv(ctx, buf, off);
}

/*
 * Build & send MPTCP_PM_CMD_SET_LIMITS with random small u32 values
 * for RCV_ADD_ADDRS and SUBFLOWS (capped at 8 each).  The kernel
 * validates the values into an mptcp_pm_data and overwrites the
 * pernet limits under the spinlock — same lock the FLUSH walker
 * needs, so this is a useful coverage edge even when the values are
 * trivial.  Returns the kernel's ack errno.
 */
static int mptcp_pm_set_limits(struct genl_ctx *ctx)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	size_t off;
	__u32 rcv = (rand32() & 0x7U) + 1U;
	__u32 sub = (rand32() & 0x7U) + 1U;

	off = genl_msg_put(buf, 0, sizeof(buf), ctx,
			   nl_seq_next(&ctx->nl),
			   MPTCP_PM_CMD_SET_LIMITS, 0);
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
	return genl_send_recv(ctx, buf, off);
}

/*
 * Build & send MPTCP_PM_CMD_FLUSH_ADDRS — no attrs.  The kernel walks
 * the pernet endpoint table and removes every entry under the pm
 * spinlock, racing the data-plane subflow walker.  Returns the
 * kernel's ack errno.
 */
static int mptcp_pm_flush_addrs(struct genl_ctx *ctx)
{
	unsigned char buf[128];
	struct nlmsghdr *nlh;
	size_t off;

	off = genl_msg_put(buf, 0, sizeof(buf), ctx,
			   nl_seq_next(&ctx->nl),
			   MPTCP_PM_CMD_FLUSH_ADDRS, 0);
	if (!off)
		return -EIO;

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = (__u32)off;
	return genl_send_recv(ctx, buf, off);
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
	n = send(fd, buf, 1U + rnd_modulo_u32(sizeof(buf)),
		 MSG_DONTWAIT | MSG_NOSIGNAL);
	if (n > 0)
		__atomic_add_fetch(&shm->stats.mptcp_pm_churn_send_ok,
				   1, __ATOMIC_RELAXED);
}

/*
 * Best-effort TFO + SO_TIMESTAMPING enable on a TCP/MPTCP fd.  Both
 * options ignore errors — older kernels / missing HW return
 * EOPNOTSUPP and we don't care.  Goal is to drive the TFO +
 * timestamping combo path (upstream commit 6254a16d6f0c) on both
 * listener and connector before the pm churn loop starts pushing
 * subflow add/remove against the live socket.
 */
static void mptcp_enable_tfo_ts(int fd)
{
	int qlen = 5;
	int ts_flags = SOF_TIMESTAMPING_RX_HARDWARE |
		       SOF_TIMESTAMPING_SOFTWARE |
		       SOF_TIMESTAMPING_RAW_HARDWARE;

	(void)setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN,
			 &qlen, sizeof(qlen));
	(void)setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPING,
			 &ts_flags, sizeof(ts_flags));
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
static int genval_keepcnt(void)		{ return 1 + (int)rnd_modulo_u32(16U); }
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
static int sweep_genval_syncnt(void)	{ return 1 + (int)rnd_modulo_u32(127U); }
static int sweep_genval_keepidle_w(void){ return 1 + (int)(rand32() % 32767U); }
static int sweep_genval_keepintvl_w(void){ return 1 + (int)(rand32() % 32767U); }
static int sweep_genval_keepcnt_w(void)	{ return 1 + (int)rnd_modulo_u32(127U); }
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

/* Per-invocation state shared across the extracted phase helpers.  Fd
 * fields default to -1 so the teardown helper can close them
 * unconditionally regardless of which earlier phase bailed.  srv_addr +
 * srv_port_n are populated by setup_sockets and consumed by connect_pair
 * for the client connect.  ctx + ctx_open are populated by genl_attach
 * and used by pm_ops_burst / teardown — ctx_open gates genl_close so a
 * bail before attach doesn't try to close an uninitialised ctx.  child
 * is the caller's struct childdata so phase helpers can attribute
 * per-childop yield counters to child->op_type. */
struct mptcp_pm_churn_iter_ctx {
	int srv;
	int cli;
	int srv_acc;
	bool ctx_open;
	struct genl_ctx ctx;
	struct sockaddr_in srv_addr;
	uint16_t srv_port_n;
	struct childdata *child;
};

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
static void mptcp_sockopt_inheritance_sweep(int cli, struct genl_ctx *ctx)
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
		idx = (unsigned int)rnd_modulo_u32(n_opts);
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
	addr_h = MPTCP_PM_LOOPBACK_BASE + rnd_modulo_u32(NR_MPTCP_LOOPBACK_ADDRS);
	(void)mptcp_pm_addr_cmd(ctx, MPTCP_PM_CMD_ADD_ADDR,
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
static void mptcp_setsockopt_all_sf_recipe(struct genl_ctx *ctx)
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
		if (is_proto_family_unsupported(errno)) {
			ns_unsupported_mptcp = true;
			__atomic_add_fetch(&shm->stats.mptcp_setsockopt_unsupported,
					   1, __ATOMIC_RELAXED);
		}
		return;
	}

	spec = &RAND_ARRAY(mptcp_sf_opts);
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
	addr_h = MPTCP_PM_LOOPBACK_BASE + rnd_modulo_u32(NR_MPTCP_LOOPBACK_ADDRS);
	(void)mptcp_pm_addr_cmd(ctx, MPTCP_PM_CMD_ADD_ADDR,
				loc_id, addr_h);

	idle = 1U + rnd_modulo_u32(3U);
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

/*
 * Phase 1: open the loopback MPTCP server (socket + bind + getsockname
 * to capture the ephemeral port + listen), then open the matching client
 * MPTCP socket.  Both sides get the TFO + SO_TIMESTAMPING combo enabled
 * before any connect so the kernel commit 6254a16d6f0c path is exercised
 * on every iteration.  The server-side socket() is the support gate:
 * EPROTONOSUPPORT / ESOCKTNOSUPPORT latch ns_unsupported_mptcp so
 * siblings stop probing.  Returns 0 on success, -1 if the iteration
 * should bail to the out: cleanup path; on failure the appropriate
 * setup_failed counter is bumped and the caller's teardown helper closes
 * whichever fds we did manage to open.
 */
static int mptcp_pm_churn_iter_setup_sockets(struct mptcp_pm_churn_iter_ctx *ctx)
{
	socklen_t slen;
	/* Snapshot ctx->child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats write
	 * entirely when the snapshot is out of range. */
	const enum child_op_type op = ctx->child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	ctx->srv = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_MPTCP);
	if (ctx->srv < 0) {
		if (errno == EPROTONOSUPPORT || errno == ESOCKTNOSUPPORT) {
			ns_unsupported_mptcp = true;
			if (valid_op)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_NS_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		__atomic_add_fetch(&shm->stats.mptcp_pm_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	__atomic_add_fetch(&shm->stats.mptcp_pm_churn_sock_mptcp_ok,
			   1, __ATOMIC_RELAXED);

	mptcp_enable_tfo_ts(ctx->srv);

	memset(&ctx->srv_addr, 0, sizeof(ctx->srv_addr));
	ctx->srv_addr.sin_family = AF_INET;
	ctx->srv_addr.sin_addr.s_addr = htonl(MPTCP_PM_LOOPBACK_BASE);
	ctx->srv_addr.sin_port = 0;
	if (bind(ctx->srv, (struct sockaddr *)&ctx->srv_addr,
		 sizeof(ctx->srv_addr)) < 0) {
		__atomic_add_fetch(&shm->stats.mptcp_pm_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	slen = sizeof(ctx->srv_addr);
	if (getsockname(ctx->srv, (struct sockaddr *)&ctx->srv_addr, &slen) < 0) {
		__atomic_add_fetch(&shm->stats.mptcp_pm_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	ctx->srv_port_n = ctx->srv_addr.sin_port;

	if (listen(ctx->srv, 4) < 0) {
		__atomic_add_fetch(&shm->stats.mptcp_pm_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}

	ctx->cli = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_MPTCP);
	if (ctx->cli < 0) {
		__atomic_add_fetch(&shm->stats.mptcp_pm_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}

	mptcp_enable_tfo_ts(ctx->cli);
	return 0;
}

/*
 * Phase 2: bring the loopback MPTCP connection to ESTABLISHED and prime
 * the data plane.  Both srv + cli flip to O_NONBLOCK first so a wedged
 * peer can't pin past child.c's SIGALRM(1s); EINPROGRESS on the connect
 * is fine — the assoc completes in the background and the later send()
 * either piggybacks or queues.  accept() failure is intentionally NOT
 * fatal: the SYN/cookie may not have landed yet and the genl ADD/DEL
 * churn still exercises the pernet table + client-side option emit
 * even without a server-side accepted fd.  The two priming churn_sends
 * drive the connection past ESTABLISHED on both ends so the first
 * ADD_ADDR doesn't race the cookie itself.  Returns 0 on success or -1
 * if the iteration should bail to the out: cleanup path.
 */
static int mptcp_pm_churn_iter_connect_pair(struct mptcp_pm_churn_iter_ctx *ctx)
{
	struct sockaddr_in cli_addr;

	(void)fcntl(ctx->cli, F_SETFL, O_NONBLOCK);
	(void)fcntl(ctx->srv, F_SETFL, O_NONBLOCK);

	memset(&cli_addr, 0, sizeof(cli_addr));
	cli_addr.sin_family = AF_INET;
	cli_addr.sin_addr.s_addr = htonl(MPTCP_PM_LOOPBACK_BASE);
	cli_addr.sin_port = ctx->srv_port_n;
	if (connect(ctx->cli, (struct sockaddr *)&cli_addr,
		    sizeof(cli_addr)) < 0 && errno != EINPROGRESS) {
		__atomic_add_fetch(&shm->stats.mptcp_pm_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}

	ctx->srv_acc = accept(ctx->srv, NULL, NULL);
	if (ctx->srv_acc >= 0)
		(void)fcntl(ctx->srv_acc, F_SETFL, O_NONBLOCK);

	churn_send(ctx->cli);
	if (ctx->srv_acc >= 0)
		churn_send(ctx->srv_acc);
	return 0;
}

/*
 * Phase 3: open a genetlink ctx against the mptcp_pm family.  The family
 * resolve is the support gate for the genl side: -ENOENT latches
 * ns_unsupported_genetlink_mptcp so siblings stop probing for the rest
 * of the process; any other failure is a transient setup error and just
 * bumps setup_failed.  ctx_open flips to true on success so the
 * teardown helper knows to genl_close — leaving it false means an
 * earlier-phase bail won't try to close an uninitialised ctx.  Returns
 * 0 on success or -1 if the iteration should bail to the out: cleanup
 * path.
 */
static int mptcp_pm_churn_iter_genl_attach(struct mptcp_pm_churn_iter_ctx *ctx)
{
	struct genl_open_opts opts;
	int rc;
	/* Snapshot ctx->child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats write
	 * entirely when the snapshot is out of range. */
	const enum child_op_type op = ctx->child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	memset(&opts, 0, sizeof(opts));
	opts.family_name  = MPTCP_PM_NAME;
	opts.version      = MPTCP_PM_VER;
	opts.recv_timeo_s = MPTCP_PM_GENL_RECV_TIMEO_S;

	rc = genl_open(&ctx->ctx, &opts);
	if (rc != 0) {
		if (rc == -ENOENT) {
			ns_unsupported_genetlink_mptcp = true;
			if (valid_op)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_NS_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		} else {
			__atomic_add_fetch(&shm->stats.mptcp_pm_churn_setup_failed,
					   1, __ATOMIC_RELAXED);
		}
		return -1;
	}
	ctx->ctx_open = true;
	return 0;
}

/*
 * Phase 4: the BUDGETED pm-churn loop.  Each iteration walks the same
 * ADD_ADDR -> GET_ADDR -> send -> DEL_ADDR -> send -> coin-flip
 * (SET_LIMITS or FLUSH_ADDRS) sequence, with occasional
 * setsockopt_all_sf_recipe (1/8) and sockopt_inheritance_sweep (1/4)
 * sub-modes for the 70ece9d7021c propagation-seq window.  loc_id walks
 * [1, MPTCP_PM_LOC_ID_MAX] bounded — the kernel rejects loc_id > 127
 * with EINVAL so capping avoids an EINVAL plateau that burns budget
 * without coverage.  rot_idx starts at 1 (127.0.0.2) because the
 * connect already pinned 127.0.0.1.  No return value: every per-iter
 * failure mode is already accounted to its own counter; the orchestrator
 * just falls through to teardown when the loop ends.
 */
static void mptcp_pm_churn_iter_pm_ops_burst(struct mptcp_pm_churn_iter_ctx *ctx)
{
	unsigned int iters, i;
	__u8 loc_id;
	unsigned int rot_idx;
	int rc;

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

		/* a) ADD_ADDR with FAMILY+ID+ADDR4 inside the nested
		 *    MPTCP_PM_ATTR_ADDR.  Kernel installs the endpoint
		 *    in the pernet table and queues an MP_ADD_ADDR
		 *    option for transmit on every up MPTCP socket. */
		rc = mptcp_pm_addr_cmd(&ctx->ctx, MPTCP_PM_CMD_ADD_ADDR,
				       loc_id, addr_h);
		if (rc == 0)
			__atomic_add_fetch(&shm->stats.mptcp_pm_churn_addr_added_ok,
					   1, __ATOMIC_RELAXED);

		/* b) GET_ADDR with the same nested ADDR — exercises
		 *    the lookup-by-id path under the same pernet lock
		 *    the ADD just released.  Reply is a NEWADDR-style
		 *    response we don't parse — recv consumes it. */
		(void)mptcp_pm_addr_cmd(&ctx->ctx, MPTCP_PM_CMD_GET_ADDR,
					loc_id, addr_h);

		/* c) Send during the ADD_ADDR option emit window. */
		churn_send(ctx->cli);
		if (ctx->srv_acc >= 0)
			churn_send(ctx->srv_acc);

		/* d) DEL_ADDR — drives mptcp_pm_remove_anno_addr() and
		 *    any in-flight subflow cleanup against the address
		 *    we just installed. */
		rc = mptcp_pm_addr_cmd(&ctx->ctx, MPTCP_PM_CMD_DEL_ADDR,
				       loc_id, addr_h);
		if (rc == 0)
			__atomic_add_fetch(&shm->stats.mptcp_pm_churn_addr_removed_ok,
					   1, __ATOMIC_RELAXED);

		/* e) Targeted race window: data path running
		 *    concurrently with subflow teardown for the just-
		 *    removed loc_id. */
		churn_send(ctx->cli);
		if (ctx->srv_acc >= 0)
			churn_send(ctx->srv_acc);

		/* f) Coin-flip between SET_LIMITS and FLUSH_ADDRS —
		 *    both reach pernet pm_nl state under the spinlock
		 *    and exercise the broader teardown vs walker
		 *    shape.  Splitting at random gives rough 50/50
		 *    coverage of each command across runs. */
		if (RAND_BOOL())
			(void)mptcp_pm_set_limits(&ctx->ctx);
		else
			(void)mptcp_pm_flush_addrs(&ctx->ctx);

		/* g) Occasional setsockopt_all_sf seq-window probe:
		 *    open a fresh master mptcp socket, set a TCP-level
		 *    sockopt, drive an ADD_ADDR to create a subflow
		 *    during the propagation seq window, and verify the
		 *    master got the value.  Same cadence as other
		 *    sub-modes, drives the path 70ece9d7021c fixed. */
		if (ONE_IN(8))
			mptcp_setsockopt_all_sf_recipe(&ctx->ctx);

		/* h) Sockopt-inheritance sweep on the live master.  Walks
		 *    a curated TCP_* table, sets one opt, drives ADD_ADDR
		 *    to spawn a subflow AFTER the option is in place, then
		 *    polls MPTCP_INFO until num_subflows bumps and reads
		 *    the option back.  A drift bumps the bug-signal
		 *    counter (70ece9d7021c).  Higher cadence than the
		 *    fresh-socket recipe above — reusing the established
		 *    connection is much cheaper. */
		if (ONE_IN(4))
			mptcp_sockopt_inheritance_sweep(ctx->cli, &ctx->ctx);

		/* Walk loc_id forward bounded to [1, MPTCP_PM_LOC_ID_MAX].
		 * The kernel rejects loc_id > 127 with EINVAL so capping
		 * here avoids an EINVAL plateau that would burn budget
		 * without exercising the post-validator paths. */
		loc_id = (loc_id % MPTCP_PM_LOC_ID_MAX) + 1U;
		rot_idx = (rot_idx + 1U) % NR_MPTCP_LOOPBACK_ADDRS;
	}
}

/*
 * Phase 5: close whichever resources we managed to acquire.  Runs on
 * every exit path — both the success path falling through to out: after
 * pm_ops_burst returns, and the early-bail goto out from any earlier
 * phase failure.  Order matches the original out: cleanup: genl ctx
 * first (gated on ctx_open so a pre-attach bail doesn't touch an
 * uninitialised ctx), then accepted server fd, then client, then the
 * listener.  Fields default to -1 via the orchestrator's designated
 * initialiser so the fd guards skip whatever was never opened.
 */
static void mptcp_pm_churn_iter_teardown(struct mptcp_pm_churn_iter_ctx *ctx)
{
	if (ctx->ctx_open)
		genl_close(&ctx->ctx);
	if (ctx->srv_acc >= 0)
		close(ctx->srv_acc);
	if (ctx->cli >= 0)
		close(ctx->cli);
	if (ctx->srv >= 0)
		close(ctx->srv);
}

bool mptcp_pm_churn(struct childdata *child)
{
	struct mptcp_pm_churn_iter_ctx ctx = {
		.srv     = -1,
		.cli     = -1,
		.srv_acc = -1,
		.child   = child,
	};
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats writes
	 * entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	__atomic_add_fetch(&shm->stats.mptcp_pm_churn_runs,
			   1, __ATOMIC_RELAXED);

	if (ns_unsupported_mptcp || ns_unsupported_genetlink_mptcp)
		return true;

	if (mptcp_pm_churn_iter_setup_sockets(&ctx) != 0)
		goto out;

	if (mptcp_pm_churn_iter_connect_pair(&ctx) != 0)
		goto out;

	if (mptcp_pm_churn_iter_genl_attach(&ctx) != 0)
		goto out;
	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	}
	mptcp_pm_churn_iter_pm_ops_burst(&ctx);

out:
	mptcp_pm_churn_iter_teardown(&ctx);
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
