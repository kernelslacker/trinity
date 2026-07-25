/*
 * esp-crafted-rx: stacked-ESP path.  Installs up to XFRM_MAX_DEPTH
 * additional v6 inbound cipher_null / digest_null SAs and emits a
 * matching max-depth stacked-ESP IPv6 frame with a mip6-shaped inner
 * extension header, so mip6's destopt / rthdr input handlers call
 * xfrm6_input_addr() against a full secpath at the depth boundary.
 */

#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "childops-netlink.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"

#include "childops/net/esp-crafted-rx-internal.h"

/*
 * Stamp the innermost mip6-shaped extension header at `buf`.  Both
 * variants are exactly 24 bytes (hdr_ext_len=2 in 8-octet units past
 * the first 8) and set next_header=UDP so the header walker resumes
 * on a fixed-size ULP after the extension.  Destination-options form
 * carries a HAO (opt type 0xC9) followed by PadN(2) to reach the
 * 8-octet boundary; routing form carries a type-2 (Mobile IPv6) header
 * with segments_left=1 and the home address set to ::1.  Both are the
 * shapes mip6's destopt/rthdr input handlers dispatch on the way to
 * xfrm6_input_addr().
 */
static size_t emit_inner_mip6_ext(uint8_t *buf, bool use_rthdr2)
{
	memset(buf, 0, 24);
	buf[0] = IPPROTO_UDP;		/* next_header */
	buf[1] = 2;			/* hdr_ext_len: 24 = 8 * (2 + 1) */
	if (use_rthdr2) {
		buf[2]      = 2;	/* routing_type: Type 2 (Mobile IPv6) */
		buf[3]      = 1;	/* segments_left */
		buf[8 + 15] = 1;	/* home address = ::1 */
	} else {
		buf[2]      = 0xC9;	/* HAO option type */
		buf[3]      = 16;	/* HAO opt data len */
		buf[4 + 15] = 1;	/* home address = ::1 */
		buf[20]     = 1;	/* PadN option type */
		buf[21]     = 2;	/* PadN option data len */
	}
	return 24;
}

/*
 * Build an IPv6 frame that stacks `depth` ESP headers ahead of an
 * inner mip6-shaped extension header (destination-options HAO when
 * !use_rthdr2, type-2 routing otherwise) plus a stub UDP header, then
 * emits `depth` ESP trailers in reverse order so each layer's trailer
 * lands after its own payload on the wire.  Innermost trailer's
 * next_header selects DSTOPTS / ROUTING; outer trailers chain ESP.
 * Returns 0 if depth is out of range; total wire length otherwise.
 */
static size_t build_v6_stacked_esp_frame(uint8_t *buf, const __be32 *spis,
					 unsigned int depth, __u32 seq,
					 bool use_rthdr2)
{
	size_t off;
	uint16_t payload_len;
	unsigned int i;
	uint8_t inner_nh;

	if (depth == 0 || depth > ESPRX_STACK_DEPTH)
		return 0;

	memset(buf, 0, ESPRX_STACK_PKT_MAX);

	buf[0]       = 0x60;
	buf[6]       = IPPROTO_ESP;
	buf[7]       = 64;
	buf[8 + 15]  = 1;		/* saddr = ::1 */
	buf[24 + 15] = 1;		/* daddr = ::1 */
	off = 40;

	for (i = 0; i < depth; i++) {
		*(__be32 *)(buf + off + 0) = spis[i];
		*(__be32 *)(buf + off + 4) = htonl(seq + i);
		off += 8;
	}

	off += emit_inner_mip6_ext(buf + off, use_rthdr2);

	/* Stub inner UDP header (dport/sport 0, len=8, csum 0).  Kernel
	 * walks the extension chain to a ULP; the UDP header just gives
	 * that walk a valid-shaped terminator. */
	buf[off + 5] = 8;
	off += 8;

	inner_nh = use_rthdr2 ? IPPROTO_ROUTING : IPPROTO_DSTOPTS;
	for (i = depth; i > 0; i--) {
		buf[off + 0] = 0;
		buf[off + 1] = (i == depth) ? inner_nh : IPPROTO_ESP;
		off += 2;
	}

	payload_len = (uint16_t)(off - 40);
	buf[4] = (uint8_t)(payload_len >> 8);
	buf[5] = (uint8_t)payload_len;
	return off;
}

/*
 * Install up to ESPRX_STACK_DEPTH additional v6 inbound null-cipher /
 * null-auth ESP SAs, all keyed on ::1 with sequential SPIs.  Runs only
 * on v6 invocations (v4 has no HAO / type-2 routing equivalent driving
 * xfrm6_input_addr()).  Best-effort: any per-SA install rejection stops
 * the loop early, so the emitter picks up whatever depth succeeded and
 * ctx->stack_depth remains an accurate count for the teardown loop.
 */
void install_stacked_null_esp_sas(struct esp_crafted_rx_iter_ctx *ctx)
{
	unsigned int i;
	__u32 base_spi;

	if (!ctx->v6)
		return;
	base_spi = (rand32() % ESPRX_SPI_RANGE) + ESPRX_SPI_MIN;
	/* Skip a SPI hole around the primary SA so the sequential rotate
	 * does not collide with ctx->spi's kernel-side hash bucket. */
	base_spi = ESPRX_SPI_MIN + ((base_spi + ESPRX_STACK_DEPTH + 1U) %
				    (ESPRX_SPI_RANGE - ESPRX_STACK_DEPTH));
	for (i = 0; i < ESPRX_STACK_DEPTH; i++) {
		__be32 spi = htonl(base_spi + i);
		__u32 reqid = ctx->reqid + i + 1U;

		if (install_null_esp_sa(&ctx->nl, spi, reqid, true) != 0)
			return;
		ctx->stack_spi[ctx->stack_depth++] = spi;
		__atomic_add_fetch(&shm->stats.esp_crafted_rx.stacked_sa_install_ok,
				   1, __ATOMIC_RELAXED);
	}
}

/*
 * Emit one stacked-ESP v6 frame at ::1 through the v6 raw socket.
 * SPIs are the stacked SAs' SPIs so every layer decapsulates; the
 * inner extension form (HAO destopts vs type-2 routing) flips 50/50
 * so mip6's two entry points into xfrm6_input_addr() are both walked.
 * MSG_DONTWAIT keeps the send inside the SIGALRM(1s) safety net.
 */
void esp_crafted_rx_send_stacked_v6(struct esp_crafted_rx_iter_ctx *ctx,
				    int fd)
{
	uint8_t pkt[ESPRX_STACK_PKT_MAX];
	struct sockaddr_in6 dst;
	size_t len;

	if (ctx->stack_depth == 0)
		return;

	memset(&dst, 0, sizeof(dst));
	dst.sin6_family           = AF_INET6;
	dst.sin6_addr.s6_addr[15] = 1;

	len = build_v6_stacked_esp_frame(pkt, ctx->stack_spi, ctx->stack_depth,
					 esprx_pick_esp_seq(), ONE_IN(2));
	if (len == 0)
		return;

	if (sendto(fd, pkt, len, MSG_DONTWAIT,
		   (struct sockaddr *)&dst, sizeof(dst)) > 0)
		__atomic_add_fetch(&shm->stats.esp_crafted_rx.stacked_sent_ok,
				   1, __ATOMIC_RELAXED);
}
