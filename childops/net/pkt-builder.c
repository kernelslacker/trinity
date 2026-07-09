/*
 * pkt-builder - composable layered packet assembler with per-layer
 * manifest, mutation + repair pass, and multi-path delivery.
 *
 * See include/pkt-builder.h for the API contract and design rationale.
 * The pkt_builder_probe childop is the first consumer (childops/net/
 * pkt-builder-probe.c); the consolidation of eth-emitter /
 * flowtable-encap-vlan / bridge-vlan-churn / ipfrag-source-churn /
 * recipe-net onto this API is a follow-on.
 */

#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/if_ether.h>
#include <linux/if_packet.h>

#include "pkt-builder.h"
#include "random.h"
#include "rnd.h"
#include "trinity.h"

#include "kernel/socket.h"

#ifndef IP_HDRINCL
#define IP_HDRINCL		3
#endif
#ifndef ETH_P_TEB
#define ETH_P_TEB		0x6558
#endif
#ifndef ETH_P_MPLS_UC
#define ETH_P_MPLS_UC		0x8847
#endif
#ifndef IPPROTO_MPLS
#define IPPROTO_MPLS		137
#endif
#ifndef IPPROTO_ESP
#define IPPROTO_ESP		50
#endif
#ifndef IPPROTO_GRE
#define IPPROTO_GRE		47
#endif
#ifndef IPPROTO_ROUTING
#define IPPROTO_ROUTING		43
#endif

/* Well-known UDP encap destination ports (RFC 7348 / RFC 8926). */
#define UDP_PORT_VXLAN		4789
#define UDP_PORT_GENEVE		6081

/*
 * ==== Descriptor table ==================================================
 *
 * Manifest rows.  These are the authoritative source of truth for the
 * repair pass and the delivery dispatcher; every emitter below reads
 * only the row for the layer it is writing (indirectly via nominal_len)
 * so the row stays the single place a truncation-point / length-owner
 * change needs editing.
 *
 * Truncation points are chosen so a hit still leaves the parser looking
 * at a header with SOME plausible length claim: cutting mid-VLAN or
 * mid-IP options is the recurring tunnel-RX bug shape the audit lane
 * called out.  Bare "cut inside the fixed header" is deliberately NOT
 * a plausible truncation for these rows — the parser rejects those
 * before it does anything interesting.
 */
static const struct pktb_layer_manifest layer_descs[NR_PKTB_LAYER_KINDS] = {
	[PKTB_LAYER_ETH] = {
		.name             = "eth",
		.valid_min        = 14,
		.nominal_len      = 14,
		.n_length_fields  = 0,
		.n_checksum_fields = 0,
		.n_trunc_points   = 0,
		.delivery         = PKTB_DELIVER_AF_PACKET,
		.parser_hint      = "eth_type_trans",
	},
	[PKTB_LAYER_VLAN_SINGLE] = {
		.name             = "vlan",
		.valid_min        = 4,
		.nominal_len      = 4,
		.n_length_fields  = 0,
		.n_checksum_fields = 0,
		.n_trunc_points   = 1,
		.trunc_points     = { 2 },	/* cut inside TCI, kernel sees TPID */
		.delivery         = PKTB_DELIVER_AF_PACKET,
		.parser_hint      = "vlan_do_receive",
	},
	[PKTB_LAYER_VLAN_DOUBLE] = {
		.name             = "vlan_qinq",
		.valid_min        = 8,
		.nominal_len      = 8,
		.n_length_fields  = 0,
		.n_checksum_fields = 0,
		.n_trunc_points   = 2,
		.trunc_points     = { 4, 6 },
		.delivery         = PKTB_DELIVER_AF_PACKET,
		.parser_hint      = "vlan_do_receive/inner",
	},
	[PKTB_LAYER_IP4] = {
		.name             = "ip4",
		.valid_min        = 20,
		.nominal_len      = 20,
		.n_length_fields  = 1,
		.length_fields    = { { .offset = 2, .width = 2 } },	/* tot_len */
		.n_checksum_fields = 1,
		.checksum_fields  = { { .offset = 10, .width = 2 } },	/* check */
		.n_trunc_points   = 0,
		.delivery         = PKTB_DELIVER_RAW_IPV4,
		.parser_hint      = "ip_rcv_core",
	},
	[PKTB_LAYER_IP6] = {
		.name             = "ip6",
		.valid_min        = 40,
		.nominal_len      = 40,
		.n_length_fields  = 1,
		.length_fields    = { { .offset = 4, .width = 2 } },	/* payload_len */
		.n_checksum_fields = 0,
		.n_trunc_points   = 0,
		.delivery         = PKTB_DELIVER_RAW_IPV6,
		.parser_hint      = "ip6_rcv_core",
	},
	[PKTB_LAYER_GRE_TEB] = {
		.name             = "gre_teb",
		.valid_min        = 4,
		.nominal_len      = 8,	/* base 4B header + optional key */
		.n_length_fields  = 0,
		.n_checksum_fields = 1,
		.checksum_fields  = { { .offset = 4, .width = 2 } },	/* csum (opt) */
		.n_trunc_points   = 1,
		.trunc_points     = { 4 },	/* keep base hdr, drop key/csum */
		.delivery         = PKTB_DELIVER_RAW_IPV4,
		.parser_hint      = "gre_rcv",
	},
	[PKTB_LAYER_VXLAN] = {
		.name             = "vxlan",
		.valid_min        = 8,
		.nominal_len      = 8,
		.n_length_fields  = 0,
		.n_checksum_fields = 0,
		.n_trunc_points   = 1,
		.trunc_points     = { 4 },	/* cut before VNI, kernel sees flags */
		.delivery         = PKTB_DELIVER_LOOPBACK_UDP,
		.parser_hint      = "vxlan_rcv",
	},
	[PKTB_LAYER_GENEVE] = {
		.name             = "geneve",
		.valid_min        = 8,
		.nominal_len      = 8,
		.n_length_fields  = 1,
		.length_fields    = { { .offset = 0, .width = 1 } },	/* opt_len (bits 0..5) */
		.n_checksum_fields = 0,
		.n_trunc_points   = 1,
		.trunc_points     = { 4 },
		.delivery         = PKTB_DELIVER_LOOPBACK_UDP,
		.parser_hint      = "geneve_rx",
	},
	[PKTB_LAYER_MPLS] = {
		.name             = "mpls",
		.valid_min        = 4,
		.nominal_len      = 4,
		.n_length_fields  = 0,
		.n_checksum_fields = 0,
		.n_trunc_points   = 0,
		.delivery         = PKTB_DELIVER_AF_PACKET,
		.parser_hint      = "mpls_forward",
	},
	[PKTB_LAYER_ESP] = {
		.name             = "esp",
		.valid_min        = 8,
		.nominal_len      = 8,
		.n_length_fields  = 0,
		.n_checksum_fields = 0,
		.n_trunc_points   = 0,
		.delivery         = PKTB_DELIVER_RAW_IPV4,
		.parser_hint      = "xfrm4_esp_rcv",
	},
	[PKTB_LAYER_UDP_ENCAP] = {
		.name             = "udp_encap",
		.valid_min        = 8,
		.nominal_len      = 8,
		.n_length_fields  = 1,
		.length_fields    = { { .offset = 4, .width = 2 } },	/* udp len */
		.n_checksum_fields = 1,
		.checksum_fields  = { { .offset = 6, .width = 2 } },	/* udp csum */
		.n_trunc_points   = 0,
		.delivery         = PKTB_DELIVER_RAW_IPV4,
		.parser_hint      = "__udp4_lib_rcv",
	},
	[PKTB_LAYER_RPL_SRH] = {
		.name             = "rpl_srh",
		.valid_min        = 8,
		.nominal_len      = 8,
		.n_length_fields  = 1,
		.length_fields    = { { .offset = 1, .width = 1 } },	/* hdr_ext_len */
		.n_checksum_fields = 0,
		.n_trunc_points   = 1,
		.trunc_points     = { 4 },
		.delivery         = PKTB_DELIVER_RAW_IPV6,
		.parser_hint      = "ipv6_srh_rcv",
	},
};

const struct pktb_layer_manifest *pktb_manifest(enum pktb_layer_kind kind)
{
	if ((unsigned)kind >= NR_PKTB_LAYER_KINDS)
		return NULL;
	return &layer_descs[kind];
}

/*
 * ==== Endian helpers ====================================================
 * We build headers by hand rather than through struct casts so the
 * layer offsets used by the manifest (and the repair pass) are the
 * same byte offsets the emitter wrote.
 */
static void put_be16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

static void put_be32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

/*
 * RFC 1071 internet checksum over a byte buffer.  Handles odd lengths
 * by zero-padding the trailing byte.  Used for IPv4 header checksum
 * repair (the only ones checksum this code fills in explicitly — GRE
 * csum is stripped to zero, UDP csum is zeroed, IP6 has no header
 * csum, ESP carries an ICV we don't compute).
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
 * Random MAC.  Locally administered, unicast — matches the convention
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

/*
 * ==== Per-layer emitters ===============================================
 * Each emitter writes nominal_len bytes at frame->buf[frame->len] and
 * returns the number of bytes written (== manifest->nominal_len).
 *
 * The emitter picks a sensible default ethertype / next-protocol so a
 * frame that stacks (eth, ip4, gre_teb, eth, ip4, udp_encap) is
 * plausible without any repair; the repair pass then adjusts length /
 * checksum / discriminator fields after mutation.
 */

static size_t emit_eth(struct pktb_frame *f)
{
	uint8_t *p = f->buf + f->len;

	rand_mac(p);			/* dst */
	memcpy(f->dst_mac, p, 6);
	rand_mac(p + 6);		/* src */
	put_be16(p + 12, ETH_P_IP);	/* default ethertype, patched later */
	return 14;
}

static size_t emit_vlan_single(struct pktb_frame *f)
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

static size_t emit_vlan_double(struct pktb_frame *f)
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

static size_t emit_ip4(struct pktb_frame *f)
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

static size_t emit_ip6(struct pktb_frame *f)
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

static size_t emit_gre_teb(struct pktb_frame *f)
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
	p[0] = 0x20;			/* K bit set — key present */
	p[1] = 0;			/* version 0, reserved 0 */
	put_be16(p + 2, ETH_P_TEB);
	put_be32(p + 4, (uint32_t)rnd_u32());	/* key */
	return 8;
}

static size_t emit_vxlan(struct pktb_frame *f)
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

static size_t emit_geneve(struct pktb_frame *f)
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

static size_t emit_mpls(struct pktb_frame *f)
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

static size_t emit_esp(struct pktb_frame *f)
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

static size_t emit_udp_encap(struct pktb_frame *f)
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

static size_t emit_rpl_srh(struct pktb_frame *f)
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

typedef size_t (*pktb_emitter_fn)(struct pktb_frame *);

static const pktb_emitter_fn emitters[NR_PKTB_LAYER_KINDS] = {
	[PKTB_LAYER_ETH]         = emit_eth,
	[PKTB_LAYER_VLAN_SINGLE] = emit_vlan_single,
	[PKTB_LAYER_VLAN_DOUBLE] = emit_vlan_double,
	[PKTB_LAYER_IP4]         = emit_ip4,
	[PKTB_LAYER_IP6]         = emit_ip6,
	[PKTB_LAYER_GRE_TEB]     = emit_gre_teb,
	[PKTB_LAYER_VXLAN]       = emit_vxlan,
	[PKTB_LAYER_GENEVE]      = emit_geneve,
	[PKTB_LAYER_MPLS]        = emit_mpls,
	[PKTB_LAYER_ESP]         = emit_esp,
	[PKTB_LAYER_UDP_ENCAP]   = emit_udp_encap,
	[PKTB_LAYER_RPL_SRH]     = emit_rpl_srh,
};

/*
 * ==== Public API =======================================================
 */

void pktb_frame_init(struct pktb_frame *f)
{
	memset(f, 0, sizeof(*f));
}

bool pktb_push(struct pktb_frame *f, enum pktb_layer_kind kind)
{
	const struct pktb_layer_manifest *m = pktb_manifest(kind);
	size_t written;
	struct pktb_layer_inst *slot;

	if (m == NULL)
		return false;
	if (f->n_layers >= PKTB_MAX_LAYERS)
		return false;
	if (f->len + m->nominal_len > PKTB_FRAME_MAX)
		return false;

	slot = &f->layers[f->n_layers];
	slot->kind      = kind;
	slot->offset    = (uint16_t)f->len;
	slot->truncated = false;

	written = emitters[kind](f);
	slot->len = (uint16_t)written;
	f->len += written;
	f->n_layers++;
	return true;
}

/*
 * ==== Repair pass ======================================================
 *
 * Walks the stacked layers in order and re-fills every declared length
 * or checksum field so the finished frame is a plausibly-parseable
 * nested-encap shape.  Fields the manifest DOESN'T claim are left
 * whatever the mutation pass wrote — that's where the fuzz coverage
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
		/* opt_len is a 6-bit field (top 6 bits of byte 0), in
		 * 4-octet units past the 8-byte fixed header.  Header only,
		 * no options, so opt_len=0.  Preserve the low 2 Ver bits
		 * mutation may have written. */
		p[0] = (uint8_t)(p[0] & 0x3f);
		break;
	case PKTB_LAYER_RPL_SRH:
		/* hdr_ext_len: 8-byte units past the first 8 bytes.  With
		 * only the fixed 8-byte SRH, this is 0. */
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
 * small on purpose — mutation is what makes the fuzzer useful.
 */
static bool byte_is_structural(enum pktb_layer_kind kind, uint16_t off)
{
	switch (kind) {
	case PKTB_LAYER_ETH:
		return off < 12;		/* dst+src MAC — sockaddr_ll copy */
	case PKTB_LAYER_IP4:
		return off == 0;		/* version+ihl — must be 0x45 */
	case PKTB_LAYER_IP6:
		return off == 0;		/* version */
	case PKTB_LAYER_VLAN_SINGLE:
	case PKTB_LAYER_VLAN_DOUBLE:
		return off == 2 || off == 3;	/* inner TPID — kernel routing */
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
 * Apply the outermost declared truncation point.  Truncation is a hint
 * — a layer with no trunc_points is skipped so a stack of
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

/*
 * ==== Delivery =========================================================
 */

void pktb_ctx_init(struct pktb_ctx *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->af_packet_fd   = -1;
	ctx->raw_ipv4_fd    = -1;
	ctx->raw_ipv6_fd    = -1;
	ctx->loopback_udp_fd = -1;
	ctx->lo_ifindex     = 0;
}

void pktb_ctx_close(struct pktb_ctx *ctx)
{
	if (ctx->af_packet_fd >= 0)   { close(ctx->af_packet_fd);   ctx->af_packet_fd = -1; }
	if (ctx->raw_ipv4_fd >= 0)    { close(ctx->raw_ipv4_fd);    ctx->raw_ipv4_fd = -1; }
	if (ctx->raw_ipv6_fd >= 0)    { close(ctx->raw_ipv6_fd);    ctx->raw_ipv6_fd = -1; }
	if (ctx->loopback_udp_fd >= 0){ close(ctx->loopback_udp_fd); ctx->loopback_udp_fd = -1; }
}

static int ensure_lo_ifindex(struct pktb_ctx *ctx)
{
	unsigned int idx;

	if (ctx->lo_ifindex > 0)
		return ctx->lo_ifindex;
	idx = if_nametoindex("lo");
	if (idx == 0)
		idx = 1;
	ctx->lo_ifindex = (int)idx;
	return ctx->lo_ifindex;
}

static int deliver_af_packet(struct pktb_ctx *ctx, const struct pktb_frame *f)
{
	struct sockaddr_ll sll;
	ssize_t rc;

	if (ctx->af_packet_fd < 0) {
		int fd = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC,
				htons(ETH_P_ALL));
		if (fd < 0) {
			ctx->disabled = true;
			return -3;
		}
		ctx->af_packet_fd = fd;
	}
	if (ensure_lo_ifindex(ctx) <= 0)
		return -1;

	memset(&sll, 0, sizeof(sll));
	sll.sll_family   = AF_PACKET;
	sll.sll_ifindex  = ctx->lo_ifindex;
	sll.sll_halen    = 6;
	memcpy(sll.sll_addr, f->dst_mac, 6);

	rc = sendto(ctx->af_packet_fd, f->buf, f->len, 0,
		    (struct sockaddr *)&sll, sizeof(sll));
	return rc > 0 ? (int)rc : -1;
}

static int deliver_raw_ipv4(struct pktb_ctx *ctx, const struct pktb_frame *f,
			    uint16_t skip_bytes)
{
	struct sockaddr_in dst;
	ssize_t rc;
	uint32_t daddr_be = htonl(f->inner_daddr != 0 ?
				  f->inner_daddr : 0x7f000001U);
	const uint8_t *payload = f->buf + skip_bytes;
	size_t plen;

	if (skip_bytes > f->len)
		return -2;
	plen = f->len - skip_bytes;
	if (plen == 0)
		return -2;

	if (ctx->raw_ipv4_fd < 0) {
		int fd = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_RAW);
		int one = 1;

		if (fd < 0) {
			ctx->disabled = true;
			return -3;
		}
		(void)setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
		ctx->raw_ipv4_fd = fd;
	}

	memset(&dst, 0, sizeof(dst));
	dst.sin_family      = AF_INET;
	dst.sin_addr.s_addr = daddr_be;

	rc = sendto(ctx->raw_ipv4_fd, payload, plen, MSG_DONTWAIT,
		    (struct sockaddr *)&dst, sizeof(dst));
	return rc > 0 ? (int)rc : -1;
}

static int deliver_raw_ipv6(struct pktb_ctx *ctx, const struct pktb_frame *f,
			    uint16_t skip_bytes)
{
	struct sockaddr_in6 dst;
	ssize_t rc;
	const uint8_t *payload = f->buf + skip_bytes;
	size_t plen;

	if (skip_bytes > f->len)
		return -2;
	plen = f->len - skip_bytes;
	if (plen == 0)
		return -2;

	if (ctx->raw_ipv6_fd < 0) {
		int fd = socket(AF_INET6, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_RAW);

		if (fd < 0) {
			ctx->disabled = true;
			return -3;
		}
		ctx->raw_ipv6_fd = fd;
	}

	memset(&dst, 0, sizeof(dst));
	dst.sin6_family = AF_INET6;
	dst.sin6_addr.s6_addr[15] = 0x01;

	rc = sendto(ctx->raw_ipv6_fd, payload, plen, MSG_DONTWAIT,
		    (struct sockaddr *)&dst, sizeof(dst));
	return rc > 0 ? (int)rc : -1;
}

static int deliver_loopback_udp(struct pktb_ctx *ctx, const struct pktb_frame *f,
				uint16_t skip_bytes)
{
	struct sockaddr_in dst;
	ssize_t rc;
	const uint8_t *payload;
	size_t plen;

	if (skip_bytes > f->len)
		return -2;
	payload = f->buf + skip_bytes;
	plen = f->len - skip_bytes;
	if (plen == 0)
		return -2;

	if (ctx->loopback_udp_fd < 0) {
		int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);

		if (fd < 0) {
			ctx->disabled = true;
			return -3;
		}
		ctx->loopback_udp_fd = fd;
	}

	memset(&dst, 0, sizeof(dst));
	dst.sin_family      = AF_INET;
	dst.sin_addr.s_addr = htonl(0x7f000001U);
	dst.sin_port        = htons(UDP_PORT_VXLAN);

	rc = sendto(ctx->loopback_udp_fd, payload, plen, MSG_DONTWAIT,
		    (struct sockaddr *)&dst, sizeof(dst));
	return rc > 0 ? (int)rc : -1;
}

/*
 * When delivery is RAW_IPV4/6 (kernel prepends the L2), skip the L2
 * layers already in the frame so the raw socket doesn't double-encap.
 * Ditto for LOOPBACK_UDP delivery, which strips everything down to
 * the innermost VXLAN/GENEVE header + inner payload the kernel would
 * see on a real ingress.
 */
static uint16_t skip_for_delivery(const struct pktb_frame *f,
				  enum pktb_delivery via)
{
	uint16_t skip = 0;
	uint8_t li;

	for (li = 0; li < f->n_layers; li++) {
		const struct pktb_layer_inst *L = &f->layers[li];

		switch (via) {
		case PKTB_DELIVER_RAW_IPV4:
			if (L->kind == PKTB_LAYER_ETH ||
			    L->kind == PKTB_LAYER_VLAN_SINGLE ||
			    L->kind == PKTB_LAYER_VLAN_DOUBLE) {
				skip = (uint16_t)(L->offset + L->len);
				continue;
			}
			return skip;
		case PKTB_DELIVER_RAW_IPV6:
			if (L->kind == PKTB_LAYER_ETH ||
			    L->kind == PKTB_LAYER_VLAN_SINGLE ||
			    L->kind == PKTB_LAYER_VLAN_DOUBLE) {
				skip = (uint16_t)(L->offset + L->len);
				continue;
			}
			return skip;
		case PKTB_DELIVER_LOOPBACK_UDP:
			if (L->kind == PKTB_LAYER_ETH ||
			    L->kind == PKTB_LAYER_VLAN_SINGLE ||
			    L->kind == PKTB_LAYER_VLAN_DOUBLE ||
			    L->kind == PKTB_LAYER_IP4 ||
			    L->kind == PKTB_LAYER_IP6 ||
			    L->kind == PKTB_LAYER_UDP_ENCAP) {
				skip = (uint16_t)(L->offset + L->len);
				continue;
			}
			return skip;
		default:
			return 0;
		}
	}
	return skip;
}

int pktb_deliver(struct pktb_ctx *ctx, const struct pktb_frame *f)
{
	const struct pktb_layer_manifest *outer;
	enum pktb_delivery via;
	uint16_t skip;

	if (ctx->disabled)
		return -3;
	if (f->n_layers == 0 || f->len == 0 || f->len > PKTB_FRAME_MAX)
		return -2;

	outer = pktb_manifest(f->layers[0].kind);
	if (outer == NULL)
		return -2;

	via = outer->delivery;
	skip = skip_for_delivery(f, via);

	switch (via) {
	case PKTB_DELIVER_AF_PACKET:    return deliver_af_packet(ctx, f);
	case PKTB_DELIVER_RAW_IPV4:     return deliver_raw_ipv4(ctx, f, skip);
	case PKTB_DELIVER_RAW_IPV6:     return deliver_raw_ipv6(ctx, f, skip);
	case PKTB_DELIVER_LOOPBACK_UDP: return deliver_loopback_udp(ctx, f, skip);
	case PKTB_DELIVER_NONE:         return -2;
	}
	return -2;
}

/*
 * ==== Sanity self-test ==================================================
 * A trivial build-time gate: every manifest slot must be populated,
 * every declared length/checksum field must fit inside nominal_len,
 * and every trunc_point must be strictly less than nominal_len.  A
 * compile-time table with a broken row would otherwise silently drop
 * frames at delivery.  Called once from pkt_builder_probe's setup on
 * the first invocation per child.
 */
bool pktb_self_check(void)
{
	unsigned int i, j;

	for (i = 0; i < NR_PKTB_LAYER_KINDS; i++) {
		const struct pktb_layer_manifest *m = &layer_descs[i];

		if (m->name == NULL)
			return false;
		if (m->valid_min > m->nominal_len)
			return false;
		if (m->n_length_fields > PKTB_MAX_FIELDS ||
		    m->n_checksum_fields > PKTB_MAX_FIELDS ||
		    m->n_trunc_points > PKTB_MAX_TRUNC_POINTS)
			return false;
		for (j = 0; j < m->n_length_fields; j++) {
			if ((size_t)m->length_fields[j].offset +
			    m->length_fields[j].width > m->nominal_len)
				return false;
		}
		for (j = 0; j < m->n_checksum_fields; j++) {
			if ((size_t)m->checksum_fields[j].offset +
			    m->checksum_fields[j].width > m->nominal_len)
				return false;
		}
		for (j = 0; j < m->n_trunc_points; j++) {
			if (m->trunc_points[j] >= m->nominal_len)
				return false;
		}
		if (emitters[i] == NULL)
			return false;
	}
	return true;
}
