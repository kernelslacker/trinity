/*
 * pkt-builder L3 emitters: IPv4, IPv6, GRE-TEB, ESP and IPv6 SRH.
 *
 * Split out of childops/net/pkt-builder.c to keep the network-layer
 * (and IPsec / tunnel) headers together, distinct from the L2 framing
 * emitters and the L4 encap emitters.  Each emitter writes its
 * manifest-declared nominal_len bytes and, where relevant, patches
 * the preceding IPv4/IPv6 next-protocol byte so the assembled stack
 * still resolves down the intended parser path pre-mutation.
 *
 * Two SRH emitters live here:
 *   emit_rpl_srh  - routing type 3 (RPL Source Routing, RFC 9008)
 *                   → ipv6_rpl_srh_rcv
 *   emit_seg6_srh - routing type 4 (SRH, RFC 8754)
 *                   → ipv6_srh_rcv
 */

#include <stdint.h>
#include <string.h>

#include <linux/if_ether.h>
#include <netinet/in.h>

#include "pkt-builder.h"
#include "pkt-builder-internal.h"
#include "rnd.h"

size_t emit_ip4(struct pktb_frame *f)
{
	uint8_t *p = f->buf + f->len;

	if (f->n_layers > 0) {
		const struct pktb_layer_inst *prev = &f->layers[f->n_layers - 1];

		if (prev->kind == PKTB_LAYER_ETH)
			put_be16(f->buf + prev->offset + 12, ETH_P_IP);
	}
	memset(p, 0, 20);
	p[0] = 0x45;			/* version 4, ihl 5 */
	p[1] = 0;			/* tos */
	put_be16(p + 2, 20);		/* tot_len (repaired later) */
	put_be16(p + 4, (uint16_t)rnd_u32());	/* id */
	put_be16(p + 6, 0);		/* frag_off */
	p[8] = 64;			/* ttl */
	p[9] = IPPROTO_UDP;		/* protocol (patched by next layer) */
	put_be16(p + 10, 0);		/* checksum (repaired later) */
	put_be32(p + 12, 0x7f000001U);	/* saddr 127.0.0.1 */
	put_be32(p + 16, 0x7f000001U);	/* daddr 127.0.0.1 */
	f->inner_saddr = 0x7f000001U;
	f->inner_daddr = 0x7f000001U;
	return 20;
}

size_t emit_ip6(struct pktb_frame *f)
{
	uint8_t *p = f->buf + f->len;

	if (f->n_layers > 0) {
		const struct pktb_layer_inst *prev = &f->layers[f->n_layers - 1];

		if (prev->kind == PKTB_LAYER_ETH)
			put_be16(f->buf + prev->offset + 12, ETH_P_IPV6);
	}
	memset(p, 0, 40);
	p[0] = 0x60;			/* version 6 */
	put_be16(p + 4, 0);		/* payload_len (repaired) */
	p[6] = IPPROTO_UDP;		/* next-header (patched) */
	p[7] = 64;			/* hop limit */
	p[8 + 15]  = 0x01;		/* saddr @ +8:  ::1 */
	p[24 + 15] = 0x01;		/* daddr @ +24: ::1 */
	return 40;
}

size_t emit_gre_teb(struct pktb_frame *f)
{
	uint8_t *p = f->buf + f->len;

	if (f->n_layers > 0) {
		const struct pktb_layer_inst *prev = &f->layers[f->n_layers - 1];

		if (prev->kind == PKTB_LAYER_IP4)
			f->buf[prev->offset + 9] = IPPROTO_GRE;
		else if (prev->kind == PKTB_LAYER_IP6)
			f->buf[prev->offset + 6] = IPPROTO_GRE;
	}
	memset(p, 0, 8);
	p[0] = 0x20;			/* K bit set, key present */
	p[1] = 0;			/* version 0, reserved 0 */
	put_be16(p + 2, ETH_P_TEB);
	put_be32(p + 4, (uint32_t)rnd_u32());	/* key */
	return 8;
}

size_t emit_esp(struct pktb_frame *f)
{
	uint8_t *p = f->buf + f->len;

	if (f->n_layers > 0) {
		const struct pktb_layer_inst *prev = &f->layers[f->n_layers - 1];

		if (prev->kind == PKTB_LAYER_IP4)
			f->buf[prev->offset + 9] = IPPROTO_ESP;
		else if (prev->kind == PKTB_LAYER_IP6)
			f->buf[prev->offset + 6] = IPPROTO_ESP;
	}
	put_be32(p, (uint32_t)rnd_u32() | 0x00000001U);	/* SPI (nonzero) */
	put_be32(p + 4, 0);				/* seq */
	return 8;
}

size_t emit_rpl_srh(struct pktb_frame *f)
{
	/*
	 * IPv6 RPL Source Routing Header (RFC 9008), routing type 3.
	 *
	 * The kernel's ipv6_rpl_srh_rcv() validates the compressed-address
	 * length equation before doing any interesting work:
	 *
	 *   looped_w = (hdrlen * 8) - pad - (16 - cmpre)
	 *   looped_w % (16 - cmpri) == 0            ... or drop
	 *
	 * With cmpri=0 and cmpre=0 (no prefix compression) and pad=0 this
	 * simplifies to: (hdrlen * 8 - 16) % 16 == 0, i.e. hdrlen must be
	 * even.  We fix nsegments=3, giving hdrlen=6 (even) and a 56-byte
	 * header: (6*8 - 16) % 16 = 32 % 16 = 0. ✓
	 *
	 * segments_left=0 causes ipv6_rpl_srh_rcv() to return immediately
	 * before the dst-rewrite and CID-copy paths, so sweep {1,2,3}
	 * (all <= nsegments, so the "sl > n" rejection edge is not hit by
	 * the first two values; the third equals n exactly).
	 */
	const uint8_t  nsegments = 3;
	const size_t   srh_bytes = 8U + 16U * nsegments;  /* 56 bytes */
	const uint8_t  hdrlen    = (uint8_t)((srh_bytes / 8U) - 1U);  /* 6 */
	static const uint8_t sweep[3] = { 1, 2, 3 };
	uint8_t *p = f->buf + f->len;
	unsigned int i;

	if (f->n_layers > 0) {
		const struct pktb_layer_inst *prev = &f->layers[f->n_layers - 1];

		if (prev->kind == PKTB_LAYER_IP6)
			f->buf[prev->offset + 6] = IPPROTO_ROUTING;
	}
	memset(p, 0, srh_bytes);
	p[0] = IPPROTO_UDP;			/* next-header */
	p[1] = hdrlen;				/* hdr_ext_len (owned, repaired) */
	p[2] = 3;				/* routing type: RPL SRH */
	p[3] = sweep[rnd_modulo_u32(3)];	/* segments_left (nonzero) */
	/* p[4] = (cmpri << 4) | cmpre = 0: no prefix compression */
	/* p[5] = (pad << 4) | 0        = 0: no pad bytes needed */
	/* p[6..7] reserved, left zero */
	/* Addresses[1..nsegments] at +8: fill with ::1 so the dst
	 * rewrite in ipv6_rpl_srh_rcv() lands on loopback. */
	for (i = 0; i < nsegments; i++)
		p[8 + 16 * i + 15] = 0x01;
	return srh_bytes;
}

size_t emit_seg6_srh(struct pktb_frame *f)
{
	/*
	 * IPv6 Segment Routing Header (RFC 8754), routing type 4.  A
	 * segments_left of 0 short-circuits ipv6_srh_rcv() before any of
	 * the interesting work (decrement, dst rewrite, segments[] index)
	 * runs, so this emitter lays down a fixed 3-segment header and
	 * sweeps segments_left across {1, 2, nsegments+1} — the last
	 * value hits the "segments_left > last_entry+1" rejection edge.
	 */
	const uint8_t nsegments = 3;
	const size_t  srh_bytes = 8U + 16U * nsegments;
	static const uint8_t sweep[3] = { 1, 2, 4 };	/* nsegments+1 == 4 */
	uint8_t *p = f->buf + f->len;
	unsigned int i;

	if (f->n_layers > 0) {
		const struct pktb_layer_inst *prev = &f->layers[f->n_layers - 1];

		if (prev->kind == PKTB_LAYER_IP6)
			f->buf[prev->offset + 6] = IPPROTO_ROUTING;
	}
	memset(p, 0, srh_bytes);
	p[0] = IPPROTO_UDP;			/* next-header */
	p[1] = (uint8_t)(srh_bytes / 8U - 1U);	/* hdr_ext_len (owned, repaired) */
	p[2] = 4;				/* routing type: SRH */
	p[3] = sweep[rnd_modulo_u32(3)];	/* segments_left sweep */
	p[4] = (uint8_t)(nsegments - 1U);	/* last_entry */
	p[5] = 0;				/* flags */
	/* p[6..7] tag left zero */
	/* segments[] at +8: fill each 16-byte slot with ::1 so the dst
	 * rewrite in ipv6_srh_rcv() lands on loopback. */
	for (i = 0; i < nsegments; i++)
		p[8 + 16 * i + 15] = 0x01;
	return srh_bytes;
}
