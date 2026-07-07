/*
 * cmsg_build() — fuzz-side cmsg ancillary-data builder.
 *
 * sanitise_sendmsg / sanitise_sendmmsg historically stuff the
 * msghdr control buffer with random bytes (get_address()), which
 * reaches the kernel's cmsg-walk early-reject path but almost
 * none of the per-cmsg attach logic (SCM_RIGHTS fd-passing,
 * SCM_CREDENTIALS validation, SCM_TIMESTAMPING flag parsing,
 * AF_PACKET aux metadata, UDP_SEGMENT GSO size).
 *
 * cmsg_build() replaces msg->msg_control with a properly-shaped
 * cmsg header + payload of one of those kinds, allocated out of
 * the writable pool (mmap-backed, so the iov scrub pass leaves it
 * alone and the kernel can write back to it on SCM_RIGHTS recv).
 *
 * Intended as a coin-flip mutation on top of the existing
 * random-bytes path -- the cmsg-aware kernel paths get exercised
 * a fraction of the time without losing unstructured coverage.
 *
 * Extended kinds and the multi-cmsg packer beyond NR_CMSG_KINDS_BASE
 * are reached only when the cmsg-richness lever is ON (see
 * cmsg-richness.h).  The OFF path stays bit-for-bit identical to a
 * build without the lever.
 */
#ifndef _TRINITY_CMSG_BUILD_H
#define _TRINITY_CMSG_BUILD_H

#include <sys/socket.h>

#include "kernel/udp.h"
enum cmsg_kind {
	/*
	 * Base kinds drawn unconditionally by the OFF picker via a single
	 * rnd_modulo_u32(NR_CMSG_KINDS_BASE) call.  Order and contiguity
	 * here are load-bearing -- NR_CMSG_KINDS_BASE is the OFF-path
	 * modulo bound and must keep its historical value of 5.
	 */
	CMSG_KIND_SCM_RIGHTS = 0,	/* AF_UNIX fd-passing */
	CMSG_KIND_SCM_CREDENTIALS,	/* AF_UNIX SO_PASSCRED */
	CMSG_KIND_SO_TIMESTAMPING,	/* IP / IPv6 timestamping */
	CMSG_KIND_PACKET_AUXDATA,	/* AF_PACKET aux */
	CMSG_KIND_UDP_GSO,		/* UDP segmentation offload */
	NR_CMSG_KINDS_BASE,

	/*
	 * Extra single-cmsg kinds reachable only under --cmsg-richness=on.
	 * Each is family-gated by pick_cmsg_kind().
	 */
	CMSG_KIND_IP_PKTINFO = NR_CMSG_KINDS_BASE,
	CMSG_KIND_IPV6_PKTINFO,
	CMSG_KIND_IP_TOS,
	CMSG_KIND_IP_TTL,
	CMSG_KIND_IP_RETOPTS,
	CMSG_KIND_IPV6_TCLASS,
	CMSG_KIND_IPV6_HOPLIMIT,
	CMSG_KIND_IPV6_RTHDR,
	CMSG_KIND_SCM_TXTIME,
	CMSG_KIND_TLS_SET_RECORD_TYPE,

	/* Sentinel: dispatches into the multi-cmsg packer in cmsg_build. */
	CMSG_KIND_MULTI,

	NR_CMSG_KINDS,
};

/*
 * Pick a cmsg kind for the supplied socket family.
 *
 * OFF: returns rnd_modulo_u32(NR_CMSG_KINDS_BASE) -- exactly one RNG
 * draw, no reference to @family, no path divergence vs the pre-lever
 * build.  Pass any value (0 is fine when the caller has no socketinfo).
 *
 * ON: draws the multi-cmsg sentinel with ONE_IN(4); otherwise picks
 * uniformly from the per-family eligible set of base + extra kinds.
 * Falls back to a base-kind draw if @family has no eligible extras.
 */
enum cmsg_kind pick_cmsg_kind(unsigned int family);

/*
 * Replaces msg->msg_control / msg->msg_controllen with a cmsg of the
 * requested kind (or, for CMSG_KIND_MULTI, a packed 2-3 cmsg buffer).
 * Returns 0 on success, -1 if the writable-pool allocation failed or
 * the multi-cmsg packer had nothing eligible for @family (caller
 * should fall back to the random-bytes path).  @family gates the
 * multi-cmsg pool and is otherwise unused.
 */
int cmsg_build(struct msghdr *m, enum cmsg_kind k, unsigned int family);

#endif /* _TRINITY_CMSG_BUILD_H */
