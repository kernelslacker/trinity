/*
 * pkt-builder L4 emitters: VXLAN, Geneve and the bare UDP-encap header.
 *
 * Split out of childops/net/pkt-builder.c to keep the L4 encap
 * emitters isolated from L2 framing and L3 IP/GRE/ESP/SRH headers.
 * All three are the same shape: they pin down or patch a well-known
 * dest port on the preceding UDP layer and pre-populate their own
 * VNI/opt field so the mutate/repair pass has a plausible base.
 */

#include <stdint.h>
#include <string.h>

#include <linux/if_ether.h>
#include <netinet/in.h>

#include "pkt-builder.h"
#include "pkt-builder-internal.h"
#include "rnd.h"

size_t emit_vxlan(struct pktb_frame *f)
{
	uint8_t *p = f->buf + f->len;

	if (f->n_layers > 0) {
		const struct pktb_layer_inst *prev = &f->layers[f->n_layers - 1];

		if (prev->kind == PKTB_LAYER_UDP_ENCAP)
			put_be16(f->buf + prev->offset + 2, UDP_PORT_VXLAN);
	}
	memset(p, 0, 8);
	p[0] = 0x08;					/* I flag = valid VNI */
	put_be32(p + 4, ((rnd_u32() & 0x00ffffffU) << 8));	/* VNI << 8 */
	return 8;
}

size_t emit_geneve(struct pktb_frame *f)
{
	uint8_t *p = f->buf + f->len;

	if (f->n_layers > 0) {
		const struct pktb_layer_inst *prev = &f->layers[f->n_layers - 1];

		if (prev->kind == PKTB_LAYER_UDP_ENCAP)
			put_be16(f->buf + prev->offset + 2, UDP_PORT_GENEVE);
	}
	memset(p, 0, 8);
	p[0] = 0;					/* opt_len (bits 0..5), Ver 0 */
	p[1] = 0;					/* O/C flags */
	put_be16(p + 2, ETH_P_TEB);			/* protocol type */
	put_be32(p + 4, ((rnd_u32() & 0x00ffffffU) << 8));	/* VNI << 8 */
	return 8;
}

size_t emit_udp_encap(struct pktb_frame *f)
{
	uint8_t *p = f->buf + f->len;

	if (f->n_layers > 0) {
		const struct pktb_layer_inst *prev = &f->layers[f->n_layers - 1];

		if (prev->kind == PKTB_LAYER_IP4)
			f->buf[prev->offset + 9] = IPPROTO_UDP;
		else if (prev->kind == PKTB_LAYER_IP6)
			f->buf[prev->offset + 6] = IPPROTO_UDP;
	}
	put_be16(p, (uint16_t)(1024 + rnd_modulo_u32(60000)));	/* sport */
	put_be16(p + 2, UDP_PORT_VXLAN);			/* dport default */
	put_be16(p + 4, 8);					/* len (repaired) */
	put_be16(p + 6, 0);					/* csum */
	return 8;
}
