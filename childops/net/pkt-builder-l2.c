/*
 * pkt-builder L2 emitters: Ethernet, single/double VLAN, MPLS.
 *
 * Split out of childops/net/pkt-builder.c so the outer-most framing
 * headers live in one file per plane (L2 here, L3/L4 in their own).
 * Each emitter writes the manifest's nominal_len bytes and, where
 * relevant, patches the preceding layer's discriminator so a stacked
 * frame is plausible before the mutate/repair pass runs.
 */

#include <stdint.h>
#include <string.h>

#include <linux/if_ether.h>

#include "pkt-builder.h"
#include "pkt-builder-internal.h"
#include "rnd.h"

/*
 * Random MAC.  Locally administered, unicast, matching the convention
 * every other L2 emitter in trinity uses.
 */
static void rand_mac(uint8_t *dst)
{
	uint32_t r0 = rnd_u32();
	uint32_t r1 = rnd_u32();

	dst[0] = (uint8_t)((r0 & 0xfc) | 0x02);
	dst[1] = (uint8_t)(r0 >> 8);
	dst[2] = (uint8_t)(r0 >> 16);
	dst[3] = (uint8_t)r1;
	dst[4] = (uint8_t)(r1 >> 8);
	dst[5] = (uint8_t)(r1 >> 16);
}

size_t emit_eth(struct pktb_frame *f)
{
	uint8_t *p = f->buf + f->len;

	rand_mac(p);			/* dst */
	memcpy(f->dst_mac, p, 6);
	rand_mac(p + 6);		/* src */
	put_be16(p + 12, ETH_P_IP);	/* default ethertype, patched later */
	return 14;
}

size_t emit_vlan_single(struct pktb_frame *f)
{
	uint8_t *p = f->buf + f->len;

	/* Patch the OUTER-preceding ethertype to 0x8100 if there is one. */
	if (f->n_layers > 0) {
		const struct pktb_layer_inst *prev = &f->layers[f->n_layers - 1];

		if (prev->kind == PKTB_LAYER_ETH)
			put_be16(f->buf + prev->offset + 12, ETH_P_8021Q);
	}
	put_be16(p, (uint16_t)(rnd_modulo_u32(4096) & 0x0fff));	/* TCI */
	put_be16(p + 2, ETH_P_IP);				/* inner et */
	return 4;
}

size_t emit_vlan_double(struct pktb_frame *f)
{
	uint8_t *p = f->buf + f->len;

	if (f->n_layers > 0) {
		const struct pktb_layer_inst *prev = &f->layers[f->n_layers - 1];

		if (prev->kind == PKTB_LAYER_ETH)
			put_be16(f->buf + prev->offset + 12, ETH_P_8021AD);
	}
	put_be16(p, (uint16_t)(rnd_modulo_u32(4096) & 0x0fff));
	put_be16(p + 2, ETH_P_8021Q);				/* inner TPID */
	put_be16(p + 4, (uint16_t)(rnd_modulo_u32(4096) & 0x0fff));
	put_be16(p + 6, ETH_P_IP);
	return 8;
}

size_t emit_mpls(struct pktb_frame *f)
{
	uint8_t *p = f->buf + f->len;
	uint32_t label = rnd_u32() & 0xfffffU;

	if (f->n_layers > 0) {
		const struct pktb_layer_inst *prev = &f->layers[f->n_layers - 1];

		if (prev->kind == PKTB_LAYER_ETH)
			put_be16(f->buf + prev->offset + 12, ETH_P_MPLS_UC);
	}
	put_be32(p, (label << 12) | (1U << 8) | 64U);	/* BoS=1, TTL=64 */
	return 4;
}
