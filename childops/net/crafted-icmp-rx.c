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
 *   [20]  quoted inner IPv4  src=local dst=icmp_src proto=UDP
 *   [ 8]  quoted inner UDP   sport=local_port dport=remote_port
 *
 * Counters in shm->stats.icmp_inject:
 *   errors_injected: sendto returned > 0
 *   inject_failed:   sendto failed or ctx not initialised
 *   selftest_runs/ok/fail: selftest_icmp_inject() accounting
 *   init_failed:     icmp_inject_init() could not open raw socket
 */

#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "shm.h"
#include "trinity.h"

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
 * inner_dst is the original remote destination.
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
			     uint16_t next_hop_mtu)
{
	struct iphdr *outer_ip = (struct iphdr *)buf;
	uint8_t      *icmp_hdr = buf + sizeof(struct iphdr);
	struct iphdr *inner_ip = (struct iphdr *)(icmp_hdr + 8);
	uint8_t      *inner_udp = (uint8_t *)inner_ip + sizeof(struct iphdr);

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
	 * Represents the original UDP datagram that triggered the error.
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
	inner_ip->protocol = IPPROTO_UDP;
	inner_ip->check    = 0;
	inner_ip->saddr    = local_addr.s_addr;
	inner_ip->daddr    = inner_dst.s_addr;
	inner_ip->check    = icmp_csum16(inner_ip, sizeof(*inner_ip));

	/* --- Quoted inner UDP header (8 bytes) ---
	 * sport = our local port, dport = remote port.  The kernel's
	 * __udp4_lib_err() looks up by {inner_ip.saddr, udp.source,
	 * inner_ip.daddr, udp.dest} to find the connected socket. */
	memset(inner_udp, 0, 8);
	memcpy(inner_udp + 0, &local_port,  2);	/* sport */
	memcpy(inner_udp + 2, &remote_port, 2);	/* dport */
	{
		uint16_t udp_len = htons(8);

		memcpy(inner_udp + 4, &udp_len, 2);
	}
	/* inner UDP checksum = 0 (permitted for UDPv4) */

	/* --- ICMP checksum: covers ICMP header + quoted IP + quoted UDP --- */
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
		       type, code, next_hop_mtu);

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

/*
 * selftest_icmp_inject — end-to-end smoke that confirms the inject
 * primitive delivers an ICMP error to a connected UDP socket.
 *
 * Sequence:
 *   1. Create a UDP "server" socket bound to 127.0.0.1:ephemeral.
 *   2. Create a UDP "client" socket bound to 127.0.0.1:ephemeral and
 *      connected to the server.
 *   3. Initialise an icmp_inject_ctx with the client fd and its
 *      getsockname / getpeername addresses.
 *   4. Inject ICMP type=3 / code=4 (frag-needed, MTU=1280).
 *   5. Poll for POLLERR on the client socket (up to 200 ms).
 *   6. A pending socket error should cause the next recv() to return
 *      -1 with errno EMSGSIZE (frag-needed → PMTU) or ECONNREFUSED
 *      (dest-unreach generic).  Both are valid ICMP-demux results.
 *   7. Log [icmp-inject] selftest OK / FAIL.
 *
 * Returns 1 on pass, 0 on fail, -1 on cap-absent skip (EPERM opening
 * the raw socket — not a test failure, just capability absent).
 */
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
	 * ECONNREFUSED (port unreachable) are both valid demux results. */
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
