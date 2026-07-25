#ifndef _CHILDOPS_NET_PKT_BUILDER_INTERNAL_H
#define _CHILDOPS_NET_PKT_BUILDER_INTERNAL_H

/*
 * Private plumbing shared across the pkt-builder translation units.
 *
 * The public API surface (frame layout, layer enums, entry points) is
 * in include/pkt-builder.h and MUST stay stable: every childop that
 * links against the builder pins on that header.  This one exists only
 * so the split L2/L3/L4 emitter files, the mutate/repair file and the
 * delivery dispatcher can share:
 *
 *   - the tiny big-endian write helpers (kept static inline to avoid
 *     a symbol-per-emitter footprint);
 *   - the UAPI fallbacks for macros that older sysroots may lack, so
 *     each new .c file doesn't repeat the #ifndef ladder;
 *   - the emitter prototypes so the emitters[] dispatch table in
 *     pkt-builder.c can name-resolve every layer without pulling the
 *     emitter bodies back into the main file.
 */

#include <stdint.h>

#include "pkt-builder.h"

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

static inline void put_be16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

static inline void put_be32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

/*
 * Per-layer emitters.  Each writes its manifest.nominal_len bytes at
 * frame->buf[frame->len] and returns that byte count.  Split out so
 * the L2 / L3 / L4 families live in separate translation units; the
 * emitters[] dispatch table in pkt-builder.c still name-resolves each
 * of them through this header.
 */
size_t emit_eth(struct pktb_frame *f);
size_t emit_vlan_single(struct pktb_frame *f);
size_t emit_vlan_double(struct pktb_frame *f);
size_t emit_mpls(struct pktb_frame *f);

#endif /* _CHILDOPS_NET_PKT_BUILDER_INTERNAL_H */
