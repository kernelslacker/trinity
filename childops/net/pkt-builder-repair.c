/*
 * pkt-builder mutate / repair / finalization pass.
 *
 * Split out of childops/net/pkt-builder.c so the checksum-finalization
 * (RFC 1071 IPv4), the per-layer length-field re-pointing, the
 * out-of-owned-field byte mutator and the outermost-truncation-point
 * hint all live in one translation unit.  These are the only routines
 * that touch the finished frame after the emitters have laid down
 * their nominal bytes; keeping them together makes the "mutation then
 * repair" invariant obvious.
 *
 * Exports pktb_mutate_and_repair (public entry); everything else is
 * file-scope static.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "pkt-builder.h"
#include "pkt-builder-internal.h"
#include "random.h"
#include "rnd.h"

/*
 * RFC 1071 internet checksum over a byte buffer.  Handles odd lengths
 * by zero-padding the trailing byte.  Used for IPv4 header checksum
 * repair (the only checksum this code fills in explicitly; GRE csum
 * is stripped to zero, UDP csum is zeroed, IP6 has no header csum,
 * ESP carries an ICV we don't compute).
 */
static uint16_t ip_checksum(const uint8_t *buf, size_t len)
{
	uint32_t sum = 0;
	size_t i;

	for (i = 0; i + 1 < len; i += 2)
		sum += ((uint32_t)buf[i] << 8) | buf[i + 1];
	if (i < len)
		sum += ((uint32_t)buf[i] << 8);

	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return (uint16_t)(~sum);
}

/*
 * Walks the stacked layers in order and re-fills every declared length
 * or checksum field so the finished frame is a plausibly-parseable
 * nested-encap shape.  Fields the manifest DOESN'T claim are left as
 * whatever the mutation pass wrote; that is where the fuzz coverage
 * comes from.
 *
 * Length fields are recomputed to cover EVERYTHING from the layer's
 * start to end-of-frame (the "outer wraps inner" convention every
 * IP/UDP/SRH-style header uses).  Checksum fields are recomputed only
 * for IPv4 (RFC 1071) and cleared to zero elsewhere (UDP zero-csum is
 * legal over IPv4; GRE csum is optional).
 */
static void repair_length_field(struct pktb_frame *f,
				const struct pktb_layer_inst *layer,
				const struct pktb_layer_manifest *m,
				const struct pktb_field *fld)
{
	uint8_t *p = f->buf + layer->offset + fld->offset;
	size_t coverage_from_layer_start;

	if ((size_t)layer->offset >= f->len)
		return;
	coverage_from_layer_start = f->len - layer->offset;

	switch (layer->kind) {
	case PKTB_LAYER_IP4:
		/* tot_len is the WHOLE IP datagram length from this hdr on. */
		put_be16(p, (uint16_t)coverage_from_layer_start);
		break;
	case PKTB_LAYER_IP6:
		/* payload_len EXCLUDES the 40-byte fixed header. */
		if (coverage_from_layer_start >= 40)
			put_be16(p, (uint16_t)(coverage_from_layer_start - 40));
		else
			put_be16(p, 0);
		break;
	case PKTB_LAYER_UDP_ENCAP:
		put_be16(p, (uint16_t)coverage_from_layer_start);
		break;
	case PKTB_LAYER_GENEVE:
		/* byte 0 = Ver (top 2 bits) | opt_len (low 6 bits), in
		 * 4-octet units past the 8-byte fixed header.  Header
		 * only, no options, so opt_len stays 0.  & 0x3f clears
		 * Ver and keeps opt_len - harmless here because byte 0
		 * is an owned length field pinned to 0. */
		p[0] = (uint8_t)(p[0] & 0x3f);
		break;
	case PKTB_LAYER_RPL_SRH:
		/* hdr_ext_len: 8-byte units past the first 8 bytes.  Derive
		 * from the layer's own written length so a 3-segment SRH
		 * (56B) reports 6, not 0 — and a trunc-shortened header
		 * (<8B) reports 0 rather than underflowing. */
		if (layer->len >= 8U)
			p[0] = (uint8_t)((layer->len - 8U) / 8U);
		else
			p[0] = 0;
		break;
	default:
		(void)m;
		break;
	}
}

static void repair_checksum_field(struct pktb_frame *f,
				  const struct pktb_layer_inst *layer,
				  const struct pktb_field *fld)
{
	uint8_t *p = f->buf + layer->offset + fld->offset;

	if ((size_t)layer->offset >= f->len)
		return;

	switch (layer->kind) {
	case PKTB_LAYER_IP4:
		put_be16(p, 0);
		put_be16(p, ip_checksum(f->buf + layer->offset, 20));
		break;
	case PKTB_LAYER_UDP_ENCAP:
		/* UDP zero-csum over IPv4 is legal (RFC 768). */
		put_be16(p, 0);
		break;
	case PKTB_LAYER_GRE_TEB:
		/* GRE checksum is optional; zero it and drop the C bit so the
		 * kernel doesn't try to validate an absent csum. */
		f->buf[layer->offset + 0] &= (uint8_t)~0x80U;
		put_be16(p, 0);
		break;
	default:
		break;
	}
}

/*
 * Uniformly mutate every byte range OUTSIDE the declared length /
 * checksum fields for a layer.  Rejects offsets past f->len so a
 * layer that was truncated in an earlier iteration doesn't reach
 * into unrelated memory.
 */
static bool byte_in_owned_field(const struct pktb_layer_manifest *m,
				uint16_t off)
{
	uint8_t i;

	for (i = 0; i < m->n_length_fields; i++) {
		if (off >= m->length_fields[i].offset &&
		    off <  m->length_fields[i].offset + m->length_fields[i].width)
			return true;
	}
	for (i = 0; i < m->n_checksum_fields; i++) {
		if (off >= m->checksum_fields[i].offset &&
		    off <  m->checksum_fields[i].offset + m->checksum_fields[i].width)
			return true;
	}
	return false;
}

/*
 * Some header bytes MUST keep specific values or the parser won't even
 * try to walk the frame (RX drops on the very first byte-compare).
 * Excluding them from the mutator keeps the frame reachable while
 * still letting every OTHER byte vary freely.  The excluded ranges are
 * small on purpose: mutation is what makes the fuzzer useful.
 */
static bool byte_is_structural(enum pktb_layer_kind kind, uint16_t off)
{
	switch (kind) {
	case PKTB_LAYER_ETH:
		return off < 12;		/* dst+src MAC, sockaddr_ll copy */
	case PKTB_LAYER_IP4:
		return off == 0;		/* version+ihl must be 0x45 */
	case PKTB_LAYER_IP6:
		return off == 0;		/* version */
	case PKTB_LAYER_VLAN_SINGLE:
	case PKTB_LAYER_VLAN_DOUBLE:
		return off == 2 || off == 3;	/* inner TPID: kernel routing */
	default:
		return false;
	}
}

static void mutate_layer(struct pktb_frame *f, struct pktb_layer_inst *layer,
			 const struct pktb_layer_manifest *m)
{
	uint16_t i;

	for (i = 0; i < layer->len; i++) {
		uint16_t abs_off = (uint16_t)(layer->offset + i);

		if (abs_off >= f->len)
			break;
		if (byte_in_owned_field(m, i))
			continue;
		if (byte_is_structural(layer->kind, i))
			continue;
		if (RAND_BOOL())
			f->buf[abs_off] = (uint8_t)rnd_u32();
	}
}

static void repair_layer(struct pktb_frame *f, struct pktb_layer_inst *layer,
			 const struct pktb_layer_manifest *m)
{
	uint8_t i;

	for (i = 0; i < m->n_length_fields; i++)
		repair_length_field(f, layer, m, &m->length_fields[i]);
	for (i = 0; i < m->n_checksum_fields; i++)
		repair_checksum_field(f, layer, &m->checksum_fields[i]);
}

/*
 * Apply the outermost declared truncation point.  Truncation is a
 * hint: a layer with no trunc_points is skipped so a stack of
 * (eth+ip4+gre_teb) still gets truncated at the gre_teb layer even
 * though eth+ip4 have no points of their own.  Truncation shortens
 * f->len; the mutator pass runs BEFORE this, so bytes past the cut
 * are simply forgotten by the delivery dispatcher.
 */
static void apply_truncation(struct pktb_frame *f)
{
	uint8_t li;

	for (li = 0; li < f->n_layers; li++) {
		struct pktb_layer_inst *layer = &f->layers[li];
		const struct pktb_layer_manifest *m = pktb_manifest(layer->kind);
		uint16_t pick;
		size_t new_len;

		if (m == NULL || m->n_trunc_points == 0)
			continue;

		pick = m->trunc_points[rnd_modulo_u32(m->n_trunc_points)];
		if (pick >= layer->len)
			continue;

		new_len = (size_t)layer->offset + pick;
		if (new_len >= f->len)
			continue;
		f->len = new_len;
		layer->len = pick;
		layer->truncated = true;
		return;
	}
}

void pktb_mutate_and_repair(struct pktb_frame *f, bool apply_trunc)
{
	uint8_t li;

	for (li = 0; li < f->n_layers; li++) {
		const struct pktb_layer_manifest *m = pktb_manifest(f->layers[li].kind);

		if (m != NULL)
			mutate_layer(f, &f->layers[li], m);
	}

	if (apply_trunc)
		apply_truncation(f);

	/* Repair walks outer -> inner so IP tot_len sees the FINAL frame
	 * length (post-truncation, post-mutation). */
	for (li = 0; li < f->n_layers; li++) {
		const struct pktb_layer_manifest *m = pktb_manifest(f->layers[li].kind);

		if (m != NULL)
			repair_layer(f, &f->layers[li], m);
	}
}
