#pragma once

/*
 * Composable layered structured-packet builder.
 *
 * The random-bytes / template-family emitters (eth-emitter, ipfrag-source-
 * churn, bridge-vlan-churn) each hand-roll ONE frame shape.  Any bug that
 * needs an outer L3 + tunnel header + inner L2/VLAN + inner L3 (gretap,
 * vxlan, geneve, gre-teb, mpls-over-udp, esp-in-udp, srh, ...) is out of
 * reach: a random arg-mutator cannot line up an inner ethertype with an
 * outer discriminator by chance.
 *
 * This module lets a caller stack N layer descriptors, mutate every
 * field freely, then repair length / checksum / discriminator coupling
 * (per a per-layer MANIFEST) so the frame is still syntactically
 * plausible enough to reach the target parser.  Delivery goes through
 * one of raw IPPROTO_RAW / AF_PACKET / loopback per the manifest.
 *
 * Design rule: every layer's manifest MUST declare
 *   - valid_min: minimum on-wire length,
 *   - length_field / checksum_field ownership,
 *   - plausible truncation points (byte offsets past which the parser
 *     will still attempt structural walk),
 *   - delivery path,
 *   - parser entry hint (informational — surfaces which kernel fn a
 *     hit is expected to attribute to).
 * Without the manifest the builder degrades into a random-byte emitter
 * with layer names on it.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PKTB_MAX_LAYERS		8	/* outer eth + up to 7 stacked layers */
#define PKTB_MAX_TRUNC_POINTS	4	/* per-layer plausible truncation offsets */
#define PKTB_MAX_FIELDS		4	/* per-layer owned length/checksum fields */
#define PKTB_FRAME_MAX		2048	/* upper bound on the assembled frame */

/*
 * Enumerates every layer kind the builder can emit.  Kept small on
 * purpose: the point of the API is composability, not exhaustive
 * enumeration of the RFC catalog.  Extended by adding a descriptor row
 * to the layer_descs[] table in childops/net/pkt-builder.c and a
 * matching enum member here — no other wiring.
 */
enum pktb_layer_kind {
	PKTB_LAYER_ETH = 0,		/* IEEE 802.3 Ethernet II */
	PKTB_LAYER_VLAN_SINGLE,		/* 802.1Q single VLAN tag */
	PKTB_LAYER_VLAN_DOUBLE,		/* 802.1ad Q-in-Q outer + 802.1Q inner */
	PKTB_LAYER_IP4,			/* IPv4 header (no options; ihl=5) */
	PKTB_LAYER_IP6,			/* IPv6 fixed header */
	PKTB_LAYER_GRE_TEB,		/* GRE with protocol=ETH_P_TEB (gretap) */
	PKTB_LAYER_VXLAN,		/* VXLAN over UDP dst 4789 */
	PKTB_LAYER_GENEVE,		/* Geneve over UDP dst 6081 */
	PKTB_LAYER_MPLS,		/* single MPLS shim (BoS=1) */
	PKTB_LAYER_ESP,			/* IPsec ESP header (no encryption) */
	PKTB_LAYER_UDP_ENCAP,		/* bare UDP header suitable for encap probes */
	PKTB_LAYER_RPL_SRH,		/* IPv6 routing header (SRH type 4) */

	NR_PKTB_LAYER_KINDS
};

/*
 * Choice of on-wire delivery path.  The delivery dispatcher (pktb_deliver)
 * reads the outermost layer's descriptor to pick which socket to send
 * over.  Manifests keep the delivery path declarative so the fuzz
 * loop's mutator cannot silently strand a frame in the wrong socket
 * class (e.g. push a raw IPv4 packet through a socket bound to
 * ETH_P_ALL).
 */
enum pktb_delivery {
	PKTB_DELIVER_AF_PACKET = 0,	/* AF_PACKET / SOCK_RAW bound to loopback */
	PKTB_DELIVER_RAW_IPV4,		/* AF_INET / SOCK_RAW / IPPROTO_RAW */
	PKTB_DELIVER_RAW_IPV6,		/* AF_INET6 / SOCK_RAW / IPPROTO_RAW */
	PKTB_DELIVER_LOOPBACK_UDP,	/* AF_INET / SOCK_DGRAM bound to lo */
	PKTB_DELIVER_NONE,		/* build-only; caller inspects frame */
};

/*
 * Per-layer manifest.  Each declared field the fuzzer mutates must have
 * a repair recipe the builder can re-run so length/checksum/
 * discriminator coupling stays intact.  Fields carry the byte offset
 * (relative to the layer's start in the frame) and byte width (1/2/4).
 */
struct pktb_field {
	uint16_t offset;
	uint16_t width;
};

struct pktb_layer_manifest {
	const char *name;			/* short label, for stats/logs */
	uint16_t   valid_min;			/* minimum on-wire length */
	uint16_t   nominal_len;			/* length the emitter defaults to */
	uint8_t    n_length_fields;		/* owned length fields (repaired) */
	uint8_t    n_checksum_fields;		/* owned checksum fields (repaired) */
	uint8_t    n_trunc_points;		/* plausible truncation offsets */
	struct pktb_field length_fields[PKTB_MAX_FIELDS];
	struct pktb_field checksum_fields[PKTB_MAX_FIELDS];
	uint16_t   trunc_points[PKTB_MAX_TRUNC_POINTS];
	enum pktb_delivery delivery;		/* dispatcher hint (outermost wins) */
	const char *parser_hint;		/* kernel fn / entry ("gre_rcv") */
};

/*
 * Runtime layer instance stacked in the frame.  The build loop keeps the
 * offset each layer's header starts at so the repair pass can re-visit
 * length_fields / checksum_fields declaratively without re-parsing the
 * finished byte buffer.
 */
struct pktb_layer_inst {
	enum pktb_layer_kind kind;
	uint16_t offset;			/* start of this layer in frame->buf */
	uint16_t len;				/* header (+ trailing payload for
						 * ip4/ip6/udp/esp/mpls tail-parent
						 * layers).  0 if not applicable. */
	bool truncated;				/* one of the trunc_points was hit */
};

/*
 * The frame being assembled.  layers[] records what was stacked; buf[]
 * holds the on-wire bytes in the same order (outermost header first,
 * inner nested layers after).
 */
struct pktb_frame {
	uint8_t buf[PKTB_FRAME_MAX];
	size_t  len;
	struct pktb_layer_inst layers[PKTB_MAX_LAYERS];
	uint8_t n_layers;
	uint8_t dst_mac[6];			/* used by AF_PACKET sockaddr_ll */
	uint32_t inner_saddr;			/* IPv4 inner saddr, for delivery */
	uint32_t inner_daddr;			/* IPv4 inner daddr, for delivery */
};

/*
 * Manifest lookup.  Returns NULL for out-of-range kinds so callers can
 * probe safely.  Defined in childops/net/pkt-builder.c.
 */
const struct pktb_layer_manifest *pktb_manifest(enum pktb_layer_kind kind);

void pktb_frame_init(struct pktb_frame *f);

/*
 * Push one layer onto the frame.  The layer's emitter writes a valid
 * default header (nominal_len bytes) at the current tail; on return
 * frame->layers[frame->n_layers-1] is populated.  Returns false if
 * appending would overflow frame->buf or PKTB_MAX_LAYERS.
 */
bool pktb_push(struct pktb_frame *f, enum pktb_layer_kind kind);

/*
 * Mutate every layer's headers (uniformly random bytes) except the
 * declared length_fields / checksum_fields, then re-run the repair pass
 * so length couplings and checksums are consistent again.  Optionally
 * hits one truncation point picked from the outermost layer's manifest.
 *
 * `apply_truncation` is a hint — the outermost layer with any declared
 * trunc_points wins; if none of the stacked layers have any, the
 * request is a no-op.
 */
void pktb_mutate_and_repair(struct pktb_frame *f, bool apply_truncation);

/*
 * Handle passed to pktb_deliver so the dispatcher can lazily open one
 * socket per delivery class and reuse it across many frames.  The
 * caller zero-initialises this struct once per childop invocation; the
 * dispatcher fills the fds as needed and closes them via pktb_ctx_close.
 */
struct pktb_ctx {
	int af_packet_fd;
	int raw_ipv4_fd;
	int raw_ipv6_fd;
	int loopback_udp_fd;
	int lo_ifindex;
	bool disabled;			/* CAP_NET_RAW absent — permanent */
};

void pktb_ctx_init(struct pktb_ctx *ctx);
void pktb_ctx_close(struct pktb_ctx *ctx);

/*
 * Push the assembled frame onto the kernel RX path.  Dispatch is
 * driven by the OUTERMOST layer's manifest delivery hint.  Returns:
 *   >0  bytes sent
 *   -1  send failure (kernel or socket setup)
 *   -2  frame invalid (empty / oversize / no plausible delivery path)
 *   -3  delivery permanently disabled (CAP_NET_RAW missing) — caller
 *       should short-circuit; the ctx's `disabled` bit is also latched
 */
int pktb_deliver(struct pktb_ctx *ctx, const struct pktb_frame *f);

/*
 * Build-time consistency check on the compiled-in manifest table.
 * Returns false if any layer descriptor is malformed (missing name,
 * overlong owned-field offset, trunc_point past nominal_len, missing
 * emitter).  Called once per child from pkt_builder_probe's first
 * dispatch — a false result latches the childop off with
 * CHILDOP_LATCH_INIT_FAILED.
 */
bool pktb_self_check(void);
