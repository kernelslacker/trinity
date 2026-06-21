/*
 * l2tp_ifname_race - race L2TP session ifname registration against
 * concurrent SESSION_CREATE / SESSION_MODIFY / SESSION_DELETE on the
 * same pseudo-wire interface name inside a private netns.
 *
 * Background.  L2TP exposes a genetlink family ("l2tp",
 * net/l2tp/l2tp_netlink.c) whose SESSION_CREATE handler allocates a
 * pseudo-wire (PPP / ETH / ETH_VLAN) and, for pw_type == ETH, lands
 * in l2tp_eth.c which builds a per-session netdevice carrying the
 * caller-supplied L2TP_ATTR_IFNAME.  Two concurrent SESSION_CREATEs
 * picking the same ifname from two tasks race the register_netdev()
 * +-namespace name-uniqueness check against each other; SESSION_MODIFY
 * walks the same per-tunnel session list the second CREATE is
 * splicing into, and SESSION_DELETE tears the netdev down via
 * l2tp_session_delete -> __l2tp_session_unhash -> __l2tp_eth_dev_uninit
 * while the other path is still mid-init.  Per-syscall genl fuzzing
 * never assembles the shape: it can't keep CONN_ID consistent across
 * the TUNNEL_CREATE then a SESSION_CREATE referencing the same
 * tunnel, and it can't keep two siblings on a matching ifname long
 * enough for the race to fire.
 *
 * Shape (per outer iteration, BUDGETED+capped):
 *   1.  Pick a per-iter (conn_id, session_id_base, ifname-suffix)
 *       triple, all random in safe ranges so two concurrent children
 *       don't collide on the same tunnel inside the same netns.
 *   2.  Open a UDP/loopback socket bound to an ephemeral port and
 *       issue L2TP_CMD_TUNNEL_CREATE with L2TP_ATTR_FD pointing at
 *       it; PROTO_VERSION=3, ENCAP_TYPE=UDP.  The kernel takes the
 *       fd as the tunnel transport.  Failure to create the tunnel
 *       short-circuits the iteration -- coverage already counted via
 *       the iter counter.
 *   3.  Fork a "creator" sibling: opens its own genl socket and
 *       tight-loops SESSION_CREATE (pwtype=ETH, ifname=<chosen>)
 *       followed by SESSION_DELETE.  Each cycle re-registers the
 *       same netdevice name in the same netns, exercising
 *       l2tp_eth_create + register_netdev + the matching unregister.
 *   4.  Fork a "racer" sibling: opens its own genl socket and
 *       tight-loops SESSION_CREATE with the SAME ifname against the
 *       SAME tunnel.  Two concurrent CREATEs on one ifname is the
 *       core race; the loser typically gets -EEXIST from
 *       register_netdevice after the winner has already started
 *       wiring the session into the tunnel's session list.
 *       Interleaved with periodic SESSION_MODIFY against the
 *       walker's session_id range so the per-tunnel session list is
 *       being walked while the creator is splicing into it.
 *   5.  Parent reaps both via waitpid_eintr().  WIFSIGNALED on
 *       either bumps the forensic sibling_crashed counter.
 *   6.  Parent issues a best-effort L2TP_CMD_TUNNEL_DELETE so a
 *       stuck tunnel doesn't accumulate across iters; the netns
 *       itself is reaped when this trinity child exits, so leftover
 *       state is bounded.
 *
 * Self-gating.  Three latches.
 *   - l2tp_family_probed: first invocation per process resolves the
 *     "l2tp" genl family via CTRL_CMD_GETFAMILY.  Any failure
 *     (family absent, kernel without CONFIG_L2TP=y/m, l2tp_netlink
 *     module not loaded) latches the op off for the rest of this
 *     child's life.  Same shape as the qrtr / pfkey latches.
 *   - ns_unsupported_l2tp_ifname_race: probe / open failure on the
 *     genl socket itself latches the op off.
 *   - ns_unshare_failed_l2tp_ifname_race: first invocation issues
 *     unshare(CLONE_NEWNET) once per child so every tunnel/session
 *     stays in a private netns the kernel destroys when this trinity
 *     child exits.  EPERM (no CAP_SYS_ADMIN) latches the op off.
 *
 * Brick-safety.  All tunnel/session creates land in a freshly-
 * unshared netns; the UDP socket is bound to 127.0.0.1; on failure
 * to unshare we latch off rather than mutate the host L2TP state.
 * No module load, no rtnetlink-on-host, no globally-reachable
 * resource.  Bounded outer loop with a hard wall-clock cap; each
 * sibling caps its own create burst at 32 messages or 150 ms.
 *
 * Header compat.  <linux/l2tp.h> ships the L2TP_CMD_* / L2TP_ATTR_* /
 * L2TP_PWTYPE_* / L2TP_ENCAPTYPE_* enums and the family-name macro
 * L2TP_GENL_NAME ("l2tp"); fallback constants matching the UAPI
 * numbering are defined under __has_include guards for stripped
 * sysroots.
 *
 * CONFIG_L2TP=m + L2TP_V3=y on the test config.
 */

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <linux/genetlink.h>
#include <linux/netlink.h>

#include "child.h"
#include "childops-genl.h"
#include "childops-netlink.h"
#include "childops-util.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"

#if __has_include(<linux/l2tp.h>)
#include <linux/l2tp.h>
#endif

/*
 * UAPI fallbacks.  Stripped sysroots may not ship <linux/l2tp.h>; the
 * enum numbering below matches include/uapi/linux/l2tp.h and is stable
 * UAPI.
 */
#ifndef L2TP_GENL_NAME
#define L2TP_GENL_NAME			"l2tp"
#endif

#ifndef L2TP_CMD_TUNNEL_CREATE
#define L2TP_CMD_TUNNEL_CREATE		1
#define L2TP_CMD_TUNNEL_DELETE		2
#define L2TP_CMD_TUNNEL_MODIFY		3
#define L2TP_CMD_TUNNEL_GET		4
#define L2TP_CMD_SESSION_CREATE		5
#define L2TP_CMD_SESSION_DELETE		6
#define L2TP_CMD_SESSION_MODIFY		7
#define L2TP_CMD_SESSION_GET		8
#endif

#ifndef L2TP_ATTR_PW_TYPE
#define L2TP_ATTR_PW_TYPE		1
#define L2TP_ATTR_ENCAP_TYPE		2
#define L2TP_ATTR_PROTO_VERSION		7
#define L2TP_ATTR_IFNAME		8
#define L2TP_ATTR_CONN_ID		9
#define L2TP_ATTR_PEER_CONN_ID		10
#define L2TP_ATTR_SESSION_ID		11
#define L2TP_ATTR_PEER_SESSION_ID	12
#define L2TP_ATTR_FD			23
#define L2TP_ATTR_IP_SADDR		24
#define L2TP_ATTR_IP_DADDR		25
#define L2TP_ATTR_UDP_SPORT		26
#define L2TP_ATTR_UDP_DPORT		27
#endif

#ifndef L2TP_PWTYPE_ETH
#define L2TP_PWTYPE_ETH			0x0005
#endif

#ifndef L2TP_ENCAPTYPE_UDP
#define L2TP_ENCAPTYPE_UDP		0
#define L2TP_ENCAPTYPE_IP		1
#endif

/*
 * Outer-loop sizing.  Per-iter cost is two fork/exit pairs plus a
 * burst of genl sends inside each plus a UDP socket + TUNNEL_CREATE/
 * DELETE pair; cap mirrors pfkey_spd_walk's outer cap so steady-state
 * load is comparable.
 */
#define L2TP_OUTER_BASE			3U
#define L2TP_OUTER_CAP			12U
#define L2TP_WALL_CAP_NS		(250L * 1000L * 1000L)

/*
 * Per-sibling inner cap.  Each session create/delete round-trip is
 * fairly heavy (netdev register/unregister inside the kernel); keep
 * the burst small so a fast kernel doesn't churn the netlink layer
 * for nothing.
 */
#define L2TP_INNER_BURST_CAP		32U
#define L2TP_INNER_WALL_NS		(150L * 1000L * 1000L)

/*
 * Per-process latches.  Same shape as pfkey_spd_walk: the genl
 * family probe runs once; the netns unshare runs once.  Either latch
 * makes the op a silent no-op for the rest of the child's life.
 */
static bool l2tp_family_probed;
static __u16 l2tp_family_id;
static bool ns_unsupported_l2tp_ifname_race;
static bool ns_unshared_l2tp_ifname_race;
static bool ns_unshare_failed_l2tp_ifname_race;

/*
 * Resolve the "l2tp" genl family id once per process.  Failure
 * (family absent on this kernel, l2tp_netlink module unloaded, no
 * CONFIG_L2TP) latches the op off uniformly.  child is the caller's
 * struct childdata so the latch-off site can record the per-childop
 * latch reason next to the boolean it sets.
 */
static void probe_l2tp_family(struct childdata *child)
{
	struct genl_ctx gctx = GENL_CTX_INIT;
	struct genl_open_opts opts = {
		.family_name = L2TP_GENL_NAME,
		.version = 1,
		.recv_timeo_s = 1,
	};
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats write
	 * entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	l2tp_family_probed = true;
	if (genl_open(&gctx, &opts) != 0) {
		ns_unsupported_l2tp_ifname_race = true;
		if (valid_op)
			__atomic_store_n(&shm->stats.childop_latch_reason[op],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		return;
	}
	l2tp_family_id = gctx.family_id;
	genl_close(&gctx);
}

/*
 * Per-child netns unshare.  All L2TP state lands in this private
 * netns so we never touch host tunnels even if the kernel happens to
 * accept the message.  EPERM (no CAP_SYS_ADMIN) latches the op off
 * uniformly.  child is the caller's struct childdata so the latch-off
 * site can record the per-childop latch reason next to the boolean it
 * sets.
 */
static void unshare_netns_once(struct childdata *child)
{
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats write
	 * entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (ns_unshared_l2tp_ifname_race || ns_unshare_failed_l2tp_ifname_race)
		return;
	if (unshare(CLONE_NEWNET) < 0) {
		ns_unshare_failed_l2tp_ifname_race = true;
		if (valid_op)
			__atomic_store_n(&shm->stats.childop_latch_reason[op],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		return;
	}
	ns_unshared_l2tp_ifname_race = true;
}

/*
 * Open a UDP/loopback socket bound to an ephemeral port to serve as
 * the L2TP tunnel transport.  Returned fd is owned by the caller;
 * out_port is the bound port in host order (for diagnostic / peer-
 * port wiring -- the kernel only needs the fd).
 */
static int open_tunnel_udp(uint16_t *out_port)
{
	int fd;
	struct sockaddr_in sin;
	socklen_t slen = sizeof(sin);

	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = 0;
	sin.sin_addr.s_addr = htonl(0x7f000001U);

	if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		close(fd);
		return -1;
	}
	if (getsockname(fd, (struct sockaddr *)&sin, &slen) < 0) {
		close(fd);
		return -1;
	}

	if (out_port)
		*out_port = ntohs(sin.sin_port);
	return fd;
}

/*
 * Build a L2TP_CMD_TUNNEL_CREATE message into buf and return its
 * byte length.  Layout:
 *   nlmsghdr + genlmsghdr
 *   L2TP_ATTR_CONN_ID            u32
 *   L2TP_ATTR_PEER_CONN_ID       u32
 *   L2TP_ATTR_PROTO_VERSION      u8 = 3
 *   L2TP_ATTR_ENCAP_TYPE         u16 = UDP
 *   L2TP_ATTR_FD                 u32 (file descriptor)
 *
 * The kernel reads L2TP_ATTR_FD when L2TP_ATTR_IP_SADDR / DADDR are
 * absent: a pre-bound UDP socket is the simplest transport setup and
 * avoids needing CAP_NET_BIND_SERVICE inside the userns.
 */
static size_t build_tunnel_create(struct genl_ctx *ctx, unsigned char *buf, size_t cap,
				  __u32 conn_id, __u32 peer_conn_id, int fd)
{
	struct nlmsghdr *nlh;
	size_t off;

	memset(buf, 0, cap);
	nlh = (struct nlmsghdr *)buf;

	off = genl_msg_put(buf, 0, cap, ctx, nl_seq_next(&ctx->nl),
			   L2TP_CMD_TUNNEL_CREATE, 0);
	if (!off)
		return 0;

	off = nla_put_u32(buf, off, cap, L2TP_ATTR_CONN_ID, conn_id);
	if (!off) return 0;
	off = nla_put_u32(buf, off, cap, L2TP_ATTR_PEER_CONN_ID, peer_conn_id);
	if (!off) return 0;
	off = nla_put_u8(buf, off, cap, L2TP_ATTR_PROTO_VERSION, 3);
	if (!off) return 0;
	off = nla_put_u16(buf, off, cap, L2TP_ATTR_ENCAP_TYPE, L2TP_ENCAPTYPE_UDP);
	if (!off) return 0;
	off = nla_put_u32(buf, off, cap, L2TP_ATTR_FD, (__u32)fd);
	if (!off) return 0;

	nlh->nlmsg_len = (__u32)off;
	return off;
}

/*
 * Build a header-only L2TP message carrying just a CONN_ID
 * (TUNNEL_DELETE / TUNNEL_GET shape).
 */
static size_t build_tunnel_delete(struct genl_ctx *ctx, unsigned char *buf, size_t cap,
				  __u32 conn_id)
{
	struct nlmsghdr *nlh;
	size_t off;

	memset(buf, 0, cap);
	nlh = (struct nlmsghdr *)buf;

	off = genl_msg_put(buf, 0, cap, ctx, nl_seq_next(&ctx->nl),
			   L2TP_CMD_TUNNEL_DELETE, 0);
	if (!off)
		return 0;

	off = nla_put_u32(buf, off, cap, L2TP_ATTR_CONN_ID, conn_id);
	if (!off) return 0;

	nlh->nlmsg_len = (__u32)off;
	return off;
}

/*
 * Build a L2TP_CMD_SESSION_CREATE message carrying the per-session
 * triple (conn_id, session_id, peer_session_id), pw_type=ETH, and a
 * caller-supplied ifname.  Two siblings calling this with the same
 * ifname on the same tunnel is the race shape.
 */
static size_t build_session_create(struct genl_ctx *ctx, unsigned char *buf, size_t cap,
				   __u32 conn_id, __u32 session_id,
				   __u32 peer_session_id, const char *ifname)
{
	struct nlmsghdr *nlh;
	size_t off;

	memset(buf, 0, cap);
	nlh = (struct nlmsghdr *)buf;

	off = genl_msg_put(buf, 0, cap, ctx, nl_seq_next(&ctx->nl),
			   L2TP_CMD_SESSION_CREATE, 0);
	if (!off)
		return 0;

	off = nla_put_u32(buf, off, cap, L2TP_ATTR_CONN_ID, conn_id);
	if (!off) return 0;
	off = nla_put_u32(buf, off, cap, L2TP_ATTR_SESSION_ID, session_id);
	if (!off) return 0;
	off = nla_put_u32(buf, off, cap, L2TP_ATTR_PEER_SESSION_ID, peer_session_id);
	if (!off) return 0;
	off = nla_put_u16(buf, off, cap, L2TP_ATTR_PW_TYPE, L2TP_PWTYPE_ETH);
	if (!off) return 0;
	off = nla_put_str(buf, off, cap, L2TP_ATTR_IFNAME, ifname);
	if (!off) return 0;

	nlh->nlmsg_len = (__u32)off;
	return off;
}

/*
 * Build a L2TP_CMD_SESSION_DELETE / SESSION_MODIFY message keyed by
 * (conn_id, session_id).  SESSION_MODIFY without any further attrs
 * is still a valid request -- the kernel walks the per-tunnel session
 * list to resolve the session, which is the walk we want to race
 * against a concurrent SESSION_CREATE splice.
 */
static size_t build_session_op(struct genl_ctx *ctx, unsigned char *buf, size_t cap,
			       __u8 cmd, __u32 conn_id, __u32 session_id)
{
	struct nlmsghdr *nlh;
	size_t off;

	memset(buf, 0, cap);
	nlh = (struct nlmsghdr *)buf;

	off = genl_msg_put(buf, 0, cap, ctx, nl_seq_next(&ctx->nl), cmd, 0);
	if (!off)
		return 0;

	off = nla_put_u32(buf, off, cap, L2TP_ATTR_CONN_ID, conn_id);
	if (!off) return 0;
	off = nla_put_u32(buf, off, cap, L2TP_ATTR_SESSION_ID, session_id);
	if (!off) return 0;

	nlh->nlmsg_len = (__u32)off;
	return off;
}

/*
 * Per-iter rotation knobs.  Each outer call picks one (tunnel,
 * session-base, ifname-suffix) triple; the two siblings then share
 * those values so they hammer the same per-tunnel state.
 */
struct l2tp_variant {
	__u32	conn_id;
	__u32	peer_conn_id;
	__u32	session_id;
	__u32	peer_session_id;
	char	ifname[16];
};

static void pick_variant(struct l2tp_variant *v)
{
	__u32 cid;

	/* CONN_ID 0 is reserved as a wildcard in l2tp; clamp to >=1
	 * and away from the high u32 range that some kernels reject
	 * for internal accounting. */
	cid = (rnd_u32() & 0x7ffffffU) + 1U;
	v->conn_id = cid;
	v->peer_conn_id = cid ^ 0xa5a5a5a5U;
	v->session_id = (rnd_u32() & 0xffffffU) + 1U;
	v->peer_session_id = v->session_id ^ 0x5a5a5a5aU;
	/* ifname stays under IFNAMSIZ (16) and starts with "l2r" so
	 * any leftover device is identifiable as ours. */
	(void)snprintf(v->ifname, sizeof(v->ifname), "l2r%u",
		       (unsigned int)(rnd_u32() & 0xffffU));
}

/*
 * Creator sibling: open its own genl ctx, tight-loop SESSION_CREATE
 * + SESSION_DELETE on the chosen ifname.  Each cycle re-registers
 * the same per-session netdevice name in the same netns, exercising
 * l2tp_eth_create + register_netdev + the matching unregister.
 */
static __attribute__((noreturn)) void l2tp_creator_child(struct l2tp_variant v)
{
	unsigned char buf[512];
	struct genl_ctx gctx = GENL_CTX_INIT;
	struct genl_open_opts opts = {
		.family_name = L2TP_GENL_NAME,
		.version = 1,
		.recv_timeo_s = 1,
	};
	struct timespec t0;
	unsigned int i;

	if (genl_open(&gctx, &opts) != 0)
		_exit(0);

	if (clock_gettime(CLOCK_MONOTONIC, &t0) < 0) {
		t0.tv_sec = 0;
		t0.tv_nsec = 0;
	}

	for (i = 0; i < L2TP_INNER_BURST_CAP; i++) {
		size_t len;

		len = build_session_create(&gctx, buf, sizeof(buf),
					   v.conn_id, v.session_id + i,
					   v.peer_session_id + i, v.ifname);
		if (len > 0)
			(void)genl_send_recv(&gctx, buf, len);

		len = build_session_op(&gctx, buf, sizeof(buf),
				       L2TP_CMD_SESSION_DELETE,
				       v.conn_id, v.session_id + i);
		if (len > 0)
			(void)genl_send_recv(&gctx, buf, len);

		if (budget_elapsed_ns(&t0, L2TP_INNER_WALL_NS))
			break;
	}

	genl_close(&gctx);
	_exit(0);
}

/*
 * Racer sibling: open its own genl ctx and tight-loop SESSION_CREATE
 * with the SAME ifname on the SAME tunnel.  Two concurrent CREATEs
 * on one ifname is the core race; the loser typically gets -EEXIST
 * from register_netdevice after the winner has started wiring the
 * session into the tunnel's session list.  Interleaved with a
 * SESSION_MODIFY against the creator's session_id range so the per-
 * tunnel session list is being walked while the creator is splicing
 * into it.
 */
static __attribute__((noreturn)) void l2tp_racer_child(struct l2tp_variant v)
{
	unsigned char buf[512];
	struct genl_ctx gctx = GENL_CTX_INIT;
	struct genl_open_opts opts = {
		.family_name = L2TP_GENL_NAME,
		.version = 1,
		.recv_timeo_s = 1,
	};
	struct timespec t0;
	unsigned int i;

	if (genl_open(&gctx, &opts) != 0)
		_exit(0);

	if (clock_gettime(CLOCK_MONOTONIC, &t0) < 0) {
		t0.tv_sec = 0;
		t0.tv_nsec = 0;
	}

	for (i = 0; i < L2TP_INNER_BURST_CAP; i++) {
		size_t len;
		__u32 racer_sid = v.session_id + L2TP_INNER_BURST_CAP + i;

		if ((i & 1U) == 0U) {
			/* SESSION_CREATE with the SAME ifname -- the
			 * core race against the creator sibling. */
			len = build_session_create(&gctx, buf, sizeof(buf),
						   v.conn_id, racer_sid,
						   v.peer_session_id + i,
						   v.ifname);
		} else {
			/* SESSION_MODIFY targeting an id the creator is
			 * plausibly mid-splice on; the walk of the
			 * per-tunnel session list is the race surface. */
			__u32 walk_sid = v.session_id +
				(rnd_u32() % L2TP_INNER_BURST_CAP);
			len = build_session_op(&gctx, buf, sizeof(buf),
					       L2TP_CMD_SESSION_MODIFY,
					       v.conn_id, walk_sid);
		}
		if (len > 0)
			(void)genl_send_recv(&gctx, buf, len);

		/* Best-effort delete to keep the racer's own netdev
		 * footprint bounded -- otherwise a successful CREATE
		 * leaves a lingering session in the per-tunnel list. */
		len = build_session_op(&gctx, buf, sizeof(buf),
				       L2TP_CMD_SESSION_DELETE,
				       v.conn_id, racer_sid);
		if (len > 0)
			(void)genl_send_recv(&gctx, buf, len);

		if (budget_elapsed_ns(&t0, L2TP_INNER_WALL_NS))
			break;
	}

	genl_close(&gctx);
	_exit(0);
}

/*
 * Reap one forked sibling.  WIFSIGNALED bumps the forensic counter --
 * the bug surface is precisely the one-sided crash where one task
 * frees a session/netdev the other is mid-walk through.
 */
static void reap_sibling(pid_t pid)
{
	int status;

	if (pid <= 0)
		return;
	if (waitpid_eintr(pid, &status, 0) != pid)
		return;
	if (WIFSIGNALED(status))
		__atomic_add_fetch(&shm->stats.l2tp_ifname_race_sibling_crashed,
				   1, __ATOMIC_RELAXED);
	else
		__atomic_add_fetch(&shm->stats.l2tp_ifname_race_sibling_reaped_ok,
				   1, __ATOMIC_RELAXED);
}

/*
 * One outer iteration: pick a tunnel/session variant, create the
 * tunnel (UDP fd transport), fork creator + racer, reap both,
 * best-effort tunnel delete.  Per-step counters live on every
 * success path so a child that latches off mid-run still leaves a
 * forensic trail in the per-op stats.
 */
static void iter_one(struct genl_ctx *parent_gctx)
{
	struct l2tp_variant v;
	unsigned char buf[512];
	size_t len;
	int udp = -1;
	uint16_t udp_port = 0;
	pid_t creator, racer;
	int rc;

	pick_variant(&v);

	__atomic_add_fetch(&shm->stats.l2tp_ifname_race_iter,
			   1, __ATOMIC_RELAXED);

	udp = open_tunnel_udp(&udp_port);
	if (udp < 0) {
		__atomic_add_fetch(&shm->stats.l2tp_ifname_race_setup_failed,
				   1, __ATOMIC_RELAXED);
		return;
	}

	len = build_tunnel_create(parent_gctx, buf, sizeof(buf),
				  v.conn_id, v.peer_conn_id, udp);
	if (len == 0) {
		close(udp);
		return;
	}
	rc = genl_send_recv(parent_gctx, buf, len);
	if (rc != 0) {
		__atomic_add_fetch(&shm->stats.l2tp_ifname_race_tunnel_fail,
				   1, __ATOMIC_RELAXED);
		close(udp);
		return;
	}
	__atomic_add_fetch(&shm->stats.l2tp_ifname_race_tunnel_ok,
			   1, __ATOMIC_RELAXED);

	creator = fork();
	if (creator < 0) {
		__atomic_add_fetch(&shm->stats.l2tp_ifname_race_fork_failed,
				   1, __ATOMIC_RELAXED);
		goto out_delete;
	}
	if (creator == 0) {
		close(udp);
		l2tp_creator_child(v);
	}

	racer = fork();
	if (racer < 0) {
		__atomic_add_fetch(&shm->stats.l2tp_ifname_race_fork_failed,
				   1, __ATOMIC_RELAXED);
		reap_sibling(creator);
		goto out_delete;
	}
	if (racer == 0) {
		close(udp);
		l2tp_racer_child(v);
	}

	__atomic_add_fetch(&shm->stats.l2tp_ifname_race_spawn_pair_ok,
			   1, __ATOMIC_RELAXED);

	reap_sibling(creator);
	reap_sibling(racer);

out_delete:
	len = build_tunnel_delete(parent_gctx, buf, sizeof(buf), v.conn_id);
	if (len > 0)
		(void)genl_send_recv(parent_gctx, buf, len);
	if (udp >= 0)
		close(udp);
}

bool l2tp_ifname_race(struct childdata *child)
{
	struct genl_ctx parent_gctx = GENL_CTX_INIT;
	struct genl_open_opts opts = {
		.family_name = L2TP_GENL_NAME,
		.version = 1,
		.recv_timeo_s = 1,
	};
	struct timespec t_outer;
	unsigned int outer_iters, i;
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	__atomic_add_fetch(&shm->stats.l2tp_ifname_race_runs,
			   1, __ATOMIC_RELAXED);

	if (ns_unsupported_l2tp_ifname_race ||
	    ns_unshare_failed_l2tp_ifname_race) {
		__atomic_add_fetch(&shm->stats.l2tp_ifname_race_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (!l2tp_family_probed) {
		probe_l2tp_family(child);
		if (ns_unsupported_l2tp_ifname_race) {
			__atomic_add_fetch(&shm->stats.l2tp_ifname_race_setup_failed,
					   1, __ATOMIC_RELAXED);
			return true;
		}
	}

	unshare_netns_once(child);
	if (ns_unshare_failed_l2tp_ifname_race) {
		__atomic_add_fetch(&shm->stats.l2tp_ifname_race_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (genl_open(&parent_gctx, &opts) != 0) {
		__atomic_add_fetch(&shm->stats.l2tp_ifname_race_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}
	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop_setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	if (clock_gettime(CLOCK_MONOTONIC, &t_outer) < 0) {
		t_outer.tv_sec = 0;
		t_outer.tv_nsec = 0;
	}

	outer_iters = BUDGETED(CHILD_OP_L2TP_IFNAME_RACE, L2TP_OUTER_BASE);
	if (outer_iters == 0U)
		outer_iters = 1U;
	if (outer_iters > L2TP_OUTER_CAP)
		outer_iters = L2TP_OUTER_CAP;

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop_data_path[op],
				   1, __ATOMIC_RELAXED);
	for (i = 0; i < outer_iters; i++) {
		if (budget_elapsed_ns(&t_outer, L2TP_WALL_CAP_NS))
			break;
		iter_one(&parent_gctx);
	}

	genl_close(&parent_gctx);
	return true;
}
