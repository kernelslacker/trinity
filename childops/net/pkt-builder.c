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
#include "pkt-builder-internal.h"
#include "random.h"
#include "rnd.h"
#include "trinity.h"

#include "kernel/socket.h"

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
 * ==== Per-layer emitters ===============================================
 * Each emitter writes nominal_len bytes at frame->buf[frame->len] and
 * returns the number of bytes written (== manifest->nominal_len).
 *
 * The emitter picks a sensible default ethertype / next-protocol so a
 * frame that stacks (eth, ip4, gre_teb, eth, ip4, udp_encap) is
 * plausible without any repair; the repair pass then adjusts length /
 * checksum / discriminator fields after mutation.
 *
 * L2 emitters (eth, vlan_single, vlan_double, mpls) live in
 * pkt-builder-l2.c; L3 emitters (ip4, ip6, gre_teb, esp, rpl_srh)
 * live in pkt-builder-l3.c; L4 encap emitters (vxlan, geneve,
 * udp_encap) live in pkt-builder-l4.c.  All prototypes come in via
 * pkt-builder-internal.h.
 */

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
 * The mutate / repair / finalization pass (checksum recompute,
 * length-field re-pointing, structural byte protection, outermost-
 * truncation-point hint, and pktb_mutate_and_repair itself) lives in
 * pkt-builder-repair.c.
 */

/*
 * The delivery dispatcher (pktb_ctx_init / pktb_ctx_close / pktb_deliver
 * and the per-family sender helpers) lives in pkt-builder-deliver.c.
 */

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
