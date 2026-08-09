/*
 * crafted_icmp_rx — inject crafted ICMP error packets to populate the
 * kernel's PMTU exception (fnhe) table by driving:
 *   udp_err() → ipv4_sk_update_pmtu() → update_or_create_fnhe()
 *
 * Background: the kernel's PMTU exception table stores per-destination
 * next-hop MTU overrides (struct fib_nh_exception).  Entries are
 * created when a genuine ICMP frag-needed (type 3 / code 4) arrives for
 * a live UDP flow.  Random-syscall fuzzing cannot synthesize this path:
 * the ICMP must carry a quoted inner IP+UDP header whose
 * (saddr, daddr, sport, dport) 4-tuple matches a live connected socket,
 * and the ICMP source / outer IP src must pass basic loopback routing.
 * This primitive bridges that gap.
 *
 * Mechanism: open an AF_INET/SOCK_RAW/IPPROTO_RAW socket (IPPROTO_RAW
 * implies IP_HDRINCL on Linux so we supply the full IP header).  Hand-
 * craft the outer IP + ICMP header + quoted inner IP+UDP header, then
 * call sendto() to the local address.  The kernel routes the datagram
 * to loopback, the ICMP input handler calls icmp_unreach(), which looks
 * up the connected socket by the quoted (saddr, daddr, sport, dport)
 * and calls __udp4_lib_err() → ipv4_sk_update_pmtu() →
 * update_or_create_fnhe() for frag-needed.
 *
 * dst_override lets the caller vary the target address per call (the
 * caller has arranged a socket connected to that address, or is testing
 * the FNHE table directly); 0 means "use remote addr from init".
 *
 * Packet layout (56 bytes total):
 *   [20]  outer IPv4 header  src=icmp_src dst=local proto=ICMP
 *   [ 8]  ICMP header: type/code/checksum/rest-of-header
 *   [20]  quoted inner IPv4  src=local dst=icmp_src proto=inner_proto
 *   [ 8]  quoted inner L4    sport=local_port dport=remote_port
 *
 * Counters in shm->stats.icmp_inject:
 *   errors_injected:  sendto returned > 0
 *   inject_failed:    sendto failed or ctx not initialised
 *   selftest_runs/ok/fail: selftest_icmp_inject() accounting
 *   init_failed:      icmp_inject_init() could not open raw socket
 *   ns_unsupported:   userns_run_in_ns() returned -EPERM
 */

#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <poll.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/netlink.h>

#include "child.h"
#include "childop-outcome.h"
#include "childops-netlink.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"
#include "userns-bootstrap.h"
#include "utils-macros.h"

#include "childops/net/crafted-icmp-rx.h"

/* ICMP type / code constants — mirror <linux/icmp.h> so we do not
 * depend on a kernel header that may be absent on a stripped sysroot. */
#ifndef ICMP_DEST_UNREACH
#define ICMP_DEST_UNREACH	3
#define ICMP_FRAG_NEEDED	4
#define ICMP_TIME_EXCEEDED	11
#define ICMP_PARAMETERPROB	12
#endif

/* DF bit in the IPv4 fragment-offset field. */
#ifndef IP_DF
#define IP_DF			0x4000
#endif

/*
 * icmp_csum16 — one's-complement checksum over [data, data+len).
 * Used for both the outer IP header checksum and the ICMP checksum.
 * Kept local: no dependency on external utils/csum plumbing.
 */
static uint16_t icmp_csum16(const void *data, size_t len)
{
	const uint16_t *p = (const uint16_t *)data;
	uint32_t acc = 0;

	while (len >= 2) {
		acc += *p++;
		len -= 2;
	}
	if (len)
		acc += *(const uint8_t *)p;
	while (acc >> 16)
		acc = (acc & 0xffff) + (acc >> 16);
	return (uint16_t)~acc;
}

/*
 * build_icmp_pkt — assemble the 56-byte crafted ICMP error datagram
 * into buf[].  icmp_src is the outer IP source (appears to be the
 * router sending the error); inner_src is the original local address;
 * inner_dst is the original remote destination.  inner_proto is placed
 * in the quoted inner IP header's protocol field (IPPROTO_UDP or
 * IPPROTO_TCP); the L4 payload is identical for both (first four bytes
 * are sport/dport in both headers, which is all the error demux needs).
 *
 * Returns the total length written (always ICMP_PKT_LEN = 56).
 */
#define ICMP_PKT_LEN	56U

static size_t build_icmp_pkt(uint8_t *buf,
			     const struct in_addr icmp_src,
			     const struct in_addr local_addr,
			     const struct in_addr inner_dst,
			     in_port_t local_port,
			     in_port_t remote_port,
			     uint8_t type, uint8_t code,
			     uint16_t next_hop_mtu,
			     uint8_t inner_proto)
{
	struct iphdr *outer_ip  = (struct iphdr *)buf;
	uint8_t      *icmp_hdr  = buf + sizeof(struct iphdr);
	struct iphdr *inner_ip  = (struct iphdr *)(icmp_hdr + 8);
	uint8_t      *inner_l4  = (uint8_t *)inner_ip + sizeof(struct iphdr);

	/* --- Outer IP header --- */
	memset(outer_ip, 0, sizeof(*outer_ip));
	outer_ip->ihl      = 5;
	outer_ip->version  = 4;
	outer_ip->tos      = 0;
	outer_ip->tot_len  = htons((uint16_t)ICMP_PKT_LEN);
	outer_ip->id       = 0;
	outer_ip->frag_off = 0;
	outer_ip->ttl      = 64;
	outer_ip->protocol = IPPROTO_ICMP;
	outer_ip->check    = 0;
	outer_ip->saddr    = icmp_src.s_addr;
	outer_ip->daddr    = local_addr.s_addr;
	outer_ip->check    = icmp_csum16(outer_ip, sizeof(*outer_ip));

	/* --- ICMP header (8 bytes) ---
	 * Layout: type(1) code(1) checksum(2) rest-of-header(4)
	 * For frag-needed (type=3/code=4) rest-of-header =
	 *   unused[2] next_hop_mtu[2]; for all others rest = 0. */
	memset(icmp_hdr, 0, 8);
	icmp_hdr[0] = type;
	icmp_hdr[1] = code;
	/* icmp_hdr[2..3] = checksum, filled below */
	if (type == ICMP_DEST_UNREACH && code == ICMP_FRAG_NEEDED) {
		uint16_t mtu_be = htons(next_hop_mtu);

		memcpy(icmp_hdr + 6, &mtu_be, 2);
	}

	/* --- Quoted inner IP header ---
	 * Represents the original datagram that triggered the error.
	 * src = our local address, dst = the remote destination.  DF bit
	 * set for frag-needed to match a realistic original packet. */
	memset(inner_ip, 0, sizeof(*inner_ip));
	inner_ip->ihl      = 5;
	inner_ip->version  = 4;
	inner_ip->tos      = 0;
	inner_ip->tot_len  = htons(20 + 8);
	inner_ip->id       = 0;
	inner_ip->frag_off = (type == ICMP_DEST_UNREACH && code == ICMP_FRAG_NEEDED)
				? htons(IP_DF) : 0;
	inner_ip->ttl      = 64;
	inner_ip->protocol = inner_proto;
	inner_ip->check    = 0;
	inner_ip->saddr    = local_addr.s_addr;
	inner_ip->daddr    = inner_dst.s_addr;
	inner_ip->check    = icmp_csum16(inner_ip, sizeof(*inner_ip));

	/* --- Quoted inner L4 header (8 bytes) ---
	 * First four bytes are sport/dport for both UDP and TCP.  The
	 * kernel's __udp4_lib_err() and tcp_v4_err() both look up the
	 * socket by {inner_ip.saddr, l4.source, inner_ip.daddr, l4.dest}.
	 * For UDP we also set the length field; for TCP the remaining
	 * bytes (seqno) are left zero. */
	memset(inner_l4, 0, 8);
	memcpy(inner_l4 + 0, &local_port,  2);	/* sport */
	memcpy(inner_l4 + 2, &remote_port, 2);	/* dport */
	if (inner_proto == IPPROTO_UDP) {
		uint16_t udp_len = htons(8);

		memcpy(inner_l4 + 4, &udp_len, 2);
	}
	/* UDP checksum = 0 (permitted); TCP checksum = 0 (error path ignores it) */

	/* --- ICMP checksum: covers ICMP header + quoted IP + quoted L4 --- */
	{
		uint16_t cksum = icmp_csum16(icmp_hdr, 8 + sizeof(*inner_ip) + 8);

		memcpy(icmp_hdr + 2, &cksum, 2);
	}

	return ICMP_PKT_LEN;
}

/* ------------------------------------------------------------------ */

int icmp_inject_init(struct icmp_inject_ctx *ctx, int udp_fd,
		     struct sockaddr_in *local, struct sockaddr_in *remote)
{
	(void)udp_fd;	/* reserved: future getsockname() fallback */

	memset(ctx, 0, sizeof(*ctx));
	ctx->raw_fd = -1;

	ctx->local  = *local;
	ctx->remote = *remote;

	ctx->raw_fd = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_RAW);
	if (ctx->raw_fd < 0) {
		__atomic_add_fetch(&shm->stats.icmp_inject.init_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	return 0;
}

int icmp_inject_error(struct icmp_inject_ctx *ctx,
		      uint8_t type, uint8_t code,
		      uint16_t next_hop_mtu,
		      struct in_addr dst_override)
{
	uint8_t pkt[ICMP_PKT_LEN];
	struct sockaddr_in dst;
	struct in_addr icmp_src;
	struct in_addr inner_dst;
	ssize_t n;

	if (ctx->raw_fd < 0) {
		__atomic_add_fetch(&shm->stats.icmp_inject.inject_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}

	/* The ICMP appears to come from the remote (or dst_override).
	 * The quoted inner header's destination matches it too, so the
	 * kernel's socket lookup finds the right connected socket. */
	if (dst_override.s_addr != 0) {
		icmp_src  = dst_override;
		inner_dst = dst_override;
	} else {
		icmp_src  = ctx->remote.sin_addr;
		inner_dst = ctx->remote.sin_addr;
	}

	build_icmp_pkt(pkt,
		       icmp_src,
		       ctx->local.sin_addr,
		       inner_dst,
		       ctx->local.sin_port,
		       ctx->remote.sin_port,
		       type, code, next_hop_mtu,
		       IPPROTO_UDP);

	/* sendto destination must match outer IP daddr (= local address) */
	memset(&dst, 0, sizeof(dst));
	dst.sin_family      = AF_INET;
	dst.sin_addr        = ctx->local.sin_addr;

	n = sendto(ctx->raw_fd, pkt, ICMP_PKT_LEN, MSG_DONTWAIT,
		   (struct sockaddr *)&dst, sizeof(dst));
	if (n > 0) {
		__atomic_add_fetch(&shm->stats.icmp_inject.errors_injected,
				   1, __ATOMIC_RELAXED);
		return 0;
	}

	if (!ctx->first_fail_logged) {
		ctx->first_fail_errno  = errno;
		ctx->first_fail_logged = true;
		/* check-static: child-output-ok */
		outputerr("[icmp-inject] inject failed: errno=%d\n", errno);
	}
	__atomic_add_fetch(&shm->stats.icmp_inject.inject_failed,
			   1, __ATOMIC_RELAXED);
	return -1;
}

void icmp_inject_cleanup(struct icmp_inject_ctx *ctx)
{
	if (ctx->raw_fd >= 0) {
		close(ctx->raw_fd);
		ctx->raw_fd = -1;
	}
}

/* ------------------------------------------------------------------ *
 * Randomised injection burst                                          *
 * ------------------------------------------------------------------ */

/*
 * ICMP error classes drawn on each invocation.  Covers dest-unreach
 * codes 0-15, time-exceeded (both codes), and parameter-problem so
 * the fnhe / icmp_unreach / icmp_redirect code paths see varied input
 * across rotation slots rather than byte-identical packets.
 */
struct icmp_error_class {
	uint8_t type;
	uint8_t code;
};

static const struct icmp_error_class icmp_error_classes[] = {
	{ ICMP_DEST_UNREACH,  0  },	/* net-unreachable */
	{ ICMP_DEST_UNREACH,  1  },	/* host-unreachable */
	{ ICMP_DEST_UNREACH,  2  },	/* protocol-unreachable */
	{ ICMP_DEST_UNREACH,  3  },	/* port-unreachable */
	{ ICMP_DEST_UNREACH,  ICMP_FRAG_NEEDED },	/* frag-needed */
	{ ICMP_DEST_UNREACH,  5  },	/* source-route-failed */
	{ ICMP_DEST_UNREACH,  6  },	/* dst-net-unknown */
	{ ICMP_DEST_UNREACH,  7  },	/* dst-host-unknown */
	{ ICMP_DEST_UNREACH,  8  },	/* src-host-isolated */
	{ ICMP_DEST_UNREACH,  9  },	/* net-prohibited */
	{ ICMP_DEST_UNREACH, 10  },	/* host-prohibited */
	{ ICMP_DEST_UNREACH, 11  },	/* tos-net-unreachable */
	{ ICMP_DEST_UNREACH, 12  },	/* tos-host-unreachable */
	{ ICMP_DEST_UNREACH, 13  },	/* admin-prohibited */
	{ ICMP_DEST_UNREACH, 14  },	/* host-precedence-violation */
	{ ICMP_DEST_UNREACH, 15  },	/* precedence-cutoff */
	{ ICMP_TIME_EXCEEDED, 0  },	/* TTL exceeded in transit */
	{ ICMP_TIME_EXCEEDED, 1  },	/* fragment reassembly exceeded */
	{ ICMP_PARAMETERPROB, 0  },	/* pointer indicates error */
	{ ICMP_PARAMETERPROB, 1  },	/* missing required option */
};

/*
 * MTU sample points: ip_rt_min_pmtu (552) and values around the
 * common PMTU boundaries exercised by update_or_create_fnhe().
 */
static const uint16_t icmp_mtu_table[] = {
	552, 576, 1024, 1280, 1480, 1500,
};

#define NR_ICMP_CLASSES		ARRAY_SIZE(icmp_error_classes)
#define NR_ICMP_MTUS		ARRAY_SIZE(icmp_mtu_table)

/*
 * icmp_rand_burst — create a live socket pair on loopback, then inject
 * a small batch of ICMP errors with randomised type/code, MTU, and inner
 * protocol.  Each call produces a distinct packet stream so consecutive
 * rotation slots buy real coverage in icmp_unreach / udp_err / tcp_v4_err
 * / ipv4_sk_update_pmtu / update_or_create_fnhe.
 *
 * inner_proto is IPPROTO_UDP or IPPROTO_TCP; the socket type matches so
 * that errors are delivered to a real connected socket (driving the full
 * socket-error demux path), not just the non-socket PMTU update.
 */
static void icmp_rand_burst(void)
{
	int server_fd = -1, client_fd = -1;
	struct sockaddr_in srv_addr, cli_addr, peer_addr;
	socklen_t addrlen;
	struct icmp_inject_ctx ctx;
	struct in_addr zero_dst;
	unsigned int i;
	uint8_t inner_proto;
	int sock_type;

	/* Alternate between UDP and TCP on each invocation. */
	inner_proto = (rnd_modulo_u32(2) == 0) ? IPPROTO_UDP : IPPROTO_TCP;
	sock_type   = (inner_proto == IPPROTO_UDP) ? SOCK_DGRAM : SOCK_STREAM;

	server_fd = socket(AF_INET, sock_type | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if (server_fd < 0)
		return;

	memset(&srv_addr, 0, sizeof(srv_addr));
	srv_addr.sin_family      = AF_INET;
	srv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	srv_addr.sin_port        = 0;
	if (bind(server_fd, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) < 0)
		goto out;

	addrlen = sizeof(srv_addr);
	if (getsockname(server_fd, (struct sockaddr *)&srv_addr, &addrlen) < 0)
		goto out;

	if (inner_proto == IPPROTO_TCP && listen(server_fd, 1) < 0)
		goto out;

	client_fd = socket(AF_INET, sock_type | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if (client_fd < 0)
		goto out;

	memset(&cli_addr, 0, sizeof(cli_addr));
	cli_addr.sin_family      = AF_INET;
	cli_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	cli_addr.sin_port        = 0;
	if (bind(client_fd, (struct sockaddr *)&cli_addr, sizeof(cli_addr)) < 0)
		goto out;

	if (connect(client_fd, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) < 0) {
		/* TCP non-blocking connect returns EINPROGRESS; that is fine —
		 * the kernel has allocated the socket tuple and ICMP errors
		 * delivered against it will reach tcp_v4_err(). */
		if (!(inner_proto == IPPROTO_TCP && errno == EINPROGRESS))
			goto out;
	}

	addrlen = sizeof(cli_addr);
	if (getsockname(client_fd, (struct sockaddr *)&cli_addr, &addrlen) < 0)
		goto out;

	/* For a TCP socket still connecting, getpeername returns the
	 * address we passed to connect(). */
	peer_addr = srv_addr;

	if (icmp_inject_init(&ctx, client_fd, &cli_addr, &peer_addr) < 0)
		goto out;

	memset(&zero_dst, 0, sizeof(zero_dst));

	/* Inject a small burst of varied ICMP errors. */
	for (i = 0; i < 4; i++) {
		unsigned int cls  = rnd_modulo_u32(NR_ICMP_CLASSES);
		uint16_t     mtu  = icmp_mtu_table[rnd_modulo_u32(NR_ICMP_MTUS)];
		uint8_t type      = icmp_error_classes[cls].type;
		uint8_t code      = icmp_error_classes[cls].code;
		uint8_t pkt[ICMP_PKT_LEN];
		struct sockaddr_in dst;
		ssize_t n;

		build_icmp_pkt(pkt,
			       ctx.remote.sin_addr,
			       ctx.local.sin_addr,
			       ctx.remote.sin_addr,
			       ctx.local.sin_port,
			       ctx.remote.sin_port,
			       type, code, mtu,
			       inner_proto);

		memset(&dst, 0, sizeof(dst));
		dst.sin_family = AF_INET;
		dst.sin_addr   = ctx.local.sin_addr;

		n = sendto(ctx.raw_fd, pkt, ICMP_PKT_LEN, MSG_DONTWAIT,
			   (struct sockaddr *)&dst, sizeof(dst));
		if (n > 0)
			__atomic_add_fetch(&shm->stats.icmp_inject.errors_injected,
					   1, __ATOMIC_RELAXED);
		else
			__atomic_add_fetch(&shm->stats.icmp_inject.inject_failed,
					   1, __ATOMIC_RELAXED);
	}

	icmp_inject_cleanup(&ctx);

out:
	if (server_fd >= 0)
		close(server_fd);
	if (client_fd >= 0)
		close(client_fd);
}

/* ------------------------------------------------------------------ */

/*
 * Per-child master latch.  Set when userns_run_in_ns() returns -EPERM
 * (kernel policy has disabled unprivileged user namespaces: either
 * user.max_user_namespaces=0 or kernel.unprivileged_userns_clone=0).
 * Without a private netns we cannot obtain CAP_NET_RAW for the raw
 * socket, so the op stays disabled for this child's lifetime.
 */
static bool ns_unsupported_crafted_icmp_rx;

/*
 * One-shot selftest flag.  Set after the first successful invocation
 * so subsequent rotation slots skip the fixed smoke check and run
 * icmp_rand_burst() instead, earning real per-call coverage.
 */
static bool selftest_done_crafted_icmp_rx;

struct crafted_icmp_rx_arg {
	struct childdata *child;
	bool              run_selftest;
};

/*
 * crafted_icmp_rx_in_ns — body executed inside the transient grandchild
 * forked by userns_run_in_ns().  The grandchild has CLONE_NEWUSER +
 * CLONE_NEWNET, so it holds CAP_NET_RAW inside its own userns and the
 * raw socket open in icmp_inject_init() will succeed.  Lo is brought up
 * so that 127.0.0.1 is a valid loopback address in the fresh netns.
 *
 * On the first invocation (arg->run_selftest == true) the fixed
 * smoke test runs once to confirm end-to-end delivery.  All subsequent
 * invocations run icmp_rand_burst() with a different ICMP class, MTU,
 * and inner protocol each time, providing new coverage on every slot.
 */
static int crafted_icmp_rx_in_ns(void *arg)
{
	struct crafted_icmp_rx_arg *rx_arg = (struct crafted_icmp_rx_arg *)arg;
	struct nl_ctx nl = { .fd = -1 };
	struct nl_open_opts opts = {
		.proto        = NETLINK_ROUTE,
		.recv_timeo_s = 1,
		.caller_op    = CHILD_OP_CRAFTED_ICMP_RX,
	};

	if (nl_open(&nl, &opts) == 0) {
		rtnl_bring_lo_up(&nl);
		nl_close(&nl);
	}

	if (rx_arg->run_selftest)
		selftest_icmp_inject();
	else
		icmp_rand_burst();

	return 0;
}

/*
 * crafted_icmp_rx — childop entry point (registered in childop.def).
 *
 * Forks a transient grandchild with an identity user namespace and a
 * private net namespace via userns_run_in_ns(CLONE_NEWNET, ...).  Inside
 * the grandchild, CAP_NET_RAW is available and 127.0.0.1 is a valid
 * loopback address, so the raw-socket open in icmp_inject_init() and
 * the inject/observe sequence can both complete without EPERM.
 *
 * On the first call a one-shot selftest confirms the inject primitive
 * works end-to-end.  All subsequent calls run icmp_rand_burst() so
 * every rotation slot earns new coverage across the ICMP error space.
 *
 * On hosts where unprivileged user namespaces are disabled the first
 * userns_run_in_ns() call returns -EPERM; the op is then latched off
 * for the remainder of this persistent child's lifetime and the
 * ns_unsupported counter is bumped (distinct from init_failed which
 * counts raw-socket open failures and other non-EPERM errors).
 */
bool crafted_icmp_rx(struct childdata *child)
{
	const enum child_op_type op = child->op_type;
	struct crafted_icmp_rx_arg rx_arg;
	int rc;

	if (ns_unsupported_crafted_icmp_rx)
		return true;

	rx_arg.child        = child;
	rx_arg.run_selftest = !selftest_done_crafted_icmp_rx;

	rc = userns_run_in_ns(CLONE_NEWNET, crafted_icmp_rx_in_ns, &rx_arg);
	if (rc == -EPERM) {
		ns_unsupported_crafted_icmp_rx = true;
		if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.icmp_inject.ns_unsupported,
				   1, __ATOMIC_RELAXED);
		return true;
	}
	if (rc < 0) {
		__atomic_add_fetch(&shm->stats.icmp_inject.init_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	/* First successful run: latch so subsequent calls use rand burst. */
	selftest_done_crafted_icmp_rx = true;
	return true;
}

int selftest_icmp_inject(void)
{
	int server_fd = -1, client_fd = -1, rc = 0;
	struct sockaddr_in srv_addr, cli_addr, peer_addr;
	socklen_t addrlen;
	struct icmp_inject_ctx ctx;
	struct pollfd pfd;
	struct in_addr zero_override;
	int save_err;

	__atomic_add_fetch(&shm->stats.icmp_inject.selftest_runs,
			   1, __ATOMIC_RELAXED);

	/* Server socket: bind to 127.0.0.1:0 */
	server_fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (server_fd < 0)
		goto fail;

	memset(&srv_addr, 0, sizeof(srv_addr));
	srv_addr.sin_family      = AF_INET;
	srv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	srv_addr.sin_port        = 0;
	if (bind(server_fd, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) < 0)
		goto fail;

	addrlen = sizeof(srv_addr);
	if (getsockname(server_fd, (struct sockaddr *)&srv_addr, &addrlen) < 0)
		goto fail;

	/* Client socket: bind to 127.0.0.1:0, connect to server */
	client_fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (client_fd < 0)
		goto fail;

	memset(&cli_addr, 0, sizeof(cli_addr));
	cli_addr.sin_family      = AF_INET;
	cli_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	cli_addr.sin_port        = 0;
	if (bind(client_fd, (struct sockaddr *)&cli_addr, sizeof(cli_addr)) < 0)
		goto fail;

	if (connect(client_fd, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) < 0)
		goto fail;

	/* Retrieve the client's own address and the connected remote */
	addrlen = sizeof(cli_addr);
	if (getsockname(client_fd, (struct sockaddr *)&cli_addr, &addrlen) < 0)
		goto fail;
	addrlen = sizeof(peer_addr);
	if (getpeername(client_fd, (struct sockaddr *)&peer_addr, &addrlen) < 0)
		goto fail;

	/* Initialise the inject context using the client socket's addresses */
	if (icmp_inject_init(&ctx, client_fd, &cli_addr, &peer_addr) < 0) {
		/* EPERM = CAP_NET_RAW absent — skip, not fail */
		if (errno == EPERM) {
			close(server_fd);
			close(client_fd);
			return -1;
		}
		goto fail;
	}

	/* Inject ICMP type=3 / code=4 (frag-needed, MTU 1280) */
	memset(&zero_override, 0, sizeof(zero_override));
	if (icmp_inject_error(&ctx, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED,
			      1280, zero_override) < 0)
		goto fail_cleanup;

	/* Poll for the socket error to arrive (up to 200 ms) */
	pfd.fd     = client_fd;
	pfd.events = POLLERR;
	(void)poll(&pfd, 1, 200);

	/* recv() on a connected socket with a pending ICMP error returns
	 * the error code directly.  EMSGSIZE (frag-needed) and
	 * ECONNREFUSED (port unreachable) are both valid ICMP-demux results. */
	{
		char buf[1];
		ssize_t n = recv(client_fd, buf, sizeof(buf), MSG_DONTWAIT);

		save_err = errno;
		if (n < 0 &&
		    (save_err == EMSGSIZE || save_err == ECONNREFUSED)) {
			rc = 1;	/* pass */
		} else {
			rc = 0;	/* fail */
		}
	}

	icmp_inject_cleanup(&ctx);
	close(server_fd);
	close(client_fd);

	if (rc) {
		__atomic_add_fetch(&shm->stats.icmp_inject.selftest_ok,
				   1, __ATOMIC_RELAXED);
		/* check-static: child-output-ok */
		outputstd("[icmp-inject] selftest OK\n");
	} else {
		__atomic_add_fetch(&shm->stats.icmp_inject.selftest_fail,
				   1, __ATOMIC_RELAXED);
		/* check-static: child-output-ok */
		outputerr("[icmp-inject] selftest FAIL (recv errno=%d)\n",
			  save_err);
	}
	return rc;

fail_cleanup:
	icmp_inject_cleanup(&ctx);
fail:
	if (server_fd >= 0)
		close(server_fd);
	if (client_fd >= 0)
		close(client_fd);
	__atomic_add_fetch(&shm->stats.icmp_inject.selftest_fail,
			   1, __ATOMIC_RELAXED);
	/* check-static: child-output-ok */
	outputerr("[icmp-inject] selftest FAIL (setup error)\n");
	return 0;
}
