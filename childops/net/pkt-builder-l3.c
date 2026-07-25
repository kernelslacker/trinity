/*
 * pkt-builder L3 emitters: IPv4, IPv6, GRE-TEB, ESP and IPv6 SRH.
 *
 * Split out of childops/net/pkt-builder.c to keep the network-layer
 * (and IPsec / tunnel) headers together, distinct from the L2 framing
 * emitters and the L4 encap emitters.  Each emitter writes its
 * manifest-declared nominal_len bytes and, where relevant, patches
 * the preceding IPv4/IPv6 next-protocol byte so the assembled stack
 * still resolves down the intended parser path pre-mutation.
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
	uint8_t *p = f->buf + f->len;

	if (f->n_layers > 0) {
		const struct pktb_layer_inst *prev = &f->layers[f->n_layers - 1];

		if (prev->kind == PKTB_LAYER_IP6)
			f->buf[prev->offset + 6] = IPPROTO_ROUTING;
	}
	memset(p, 0, 8);
	p[0] = IPPROTO_UDP;	/* next-header */
	p[1] = 0;		/* hdr_ext_len in 8-octet units past 8 (repaired) */
	p[2] = 4;		/* routing type: SRH */
	p[3] = 0;		/* segments_left */
	return 8;
}
