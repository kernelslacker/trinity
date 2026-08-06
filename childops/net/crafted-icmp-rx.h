#ifndef _CHILDOPS_NET_CRAFTED_ICMP_RX_H
#define _CHILDOPS_NET_CRAFTED_ICMP_RX_H

/*
 * crafted-icmp-rx.h — public API for the ICMP-error inject primitive.
 *
 * Provides icmp_inject_error(): given a connected UDP socket and its
 * local/remote address pair, craft a raw ICMP error packet with a
 * quoted inner IP+UDP header that matches the socket's flow, and inject
 * it so the kernel's udp_err() → ipv4_sk_update_pmtu() →
 * update_or_create_fnhe() path fires.
 *
 * The three injectable error classes:
 *   type=3, code=4  — dest-unreach / frag-needed (PMTU path)
 *   type=11, code=0 — time-exceeded / TTL exceeded in transit
 *   type=12, *      — parameter-problem
 *
 * Caller contract:
 *   1. Call icmp_inject_init() once with the connected UDP fd and the
 *      local/remote sockaddr_in pair extracted via getsockname() /
 *      getpeername().  On success the ctx holds an open raw socket.
 *   2. Call icmp_inject_error() N times (once per destination address
 *      to install into the fnhe table).  dst_override overrides the
 *      remote address in both the outer IP src and the quoted inner IP
 *      dst; pass a zero in_addr to use the remote address from init.
 *   3. Call icmp_inject_cleanup() to close the raw socket.
 *
 * Thread safety: ctx is single-threaded; no locking inside the helper.
 */

#include <stdbool.h>
#include <stdint.h>
#include <netinet/in.h>

struct icmp_inject_ctx {
	int		raw_fd;		/* AF_INET/SOCK_RAW/IPPROTO_RAW, HDRINCL */
	struct sockaddr_in local;	/* connected UDP socket's local end */
	struct sockaddr_in remote;	/* connected UDP socket's remote end */
	int		first_fail_errno; /* errno from first inject failure */
	bool		first_fail_logged;
};

/*
 * icmp_inject_init - open a raw socket and snapshot the socket's
 * local/remote address pair.  udp_fd must be a connected AF_INET
 * SOCK_DGRAM socket; local and remote must be pre-populated by the
 * caller (typically via getsockname + getpeername).
 *
 * Returns 0 on success, -1 on error (raw socket EPERM / ENOMEM etc.).
 * On -1 the ctx is left in a state safe to pass to icmp_inject_cleanup().
 */
int icmp_inject_init(struct icmp_inject_ctx *ctx, int udp_fd,
		     struct sockaddr_in *local, struct sockaddr_in *remote);

/*
 * icmp_inject_error - craft and inject one ICMP error packet.
 *
 * type / code: ICMP type and code (see ICMP_DEST_UNREACH / ICMP_FRAG_NEEDED
 *   etc. in <netinet/ip_icmp.h> / <linux/icmp.h>).
 *
 * next_hop_mtu: used only for type=3/code=4 (frag-needed); the MTU value
 *   placed in the ICMP rest-of-header word.  Ignored for other types.
 *
 * dst_override: if non-zero, used as the "original destination" of the
 *   quoted inner IP header (and as the ICMP outer-IP source), letting the
 *   caller install fnhe entries for arbitrary daddrs on the same connected
 *   socket.  Pass (struct in_addr){0} to use ctx->remote.sin_addr.
 *
 * Returns 0 on success, -1 on error.
 */
int icmp_inject_error(struct icmp_inject_ctx *ctx,
		      uint8_t type, uint8_t code,
		      uint16_t next_hop_mtu,
		      struct in_addr dst_override);

/*
 * icmp_inject_cleanup - close the raw socket.  Safe to call even if
 * icmp_inject_init() failed (ctx->raw_fd == -1 is a no-op).
 */
void icmp_inject_cleanup(struct icmp_inject_ctx *ctx);

/*
 * selftest_icmp_inject - end-to-end smoke: create a loopback UDP socket
 * pair, inject one frag-needed (type=3/code=4) ICMP error, and verify
 * that the target socket receives the expected error (EMSGSIZE or
 * ECONNREFUSED).
 *
 * Logs "[icmp-inject] selftest OK" or "[icmp-inject] selftest FAIL".
 * Returns 1 on pass, 0 on fail, -1 if the raw socket could not be
 * opened (capability absent — treat as skip, not fail).
 */
int selftest_icmp_inject(void);

#endif /* _CHILDOPS_NET_CRAFTED_ICMP_RX_H */
