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
 */
#ifndef _TRINITY_CMSG_BUILD_H
#define _TRINITY_CMSG_BUILD_H

#include <sys/socket.h>

enum cmsg_kind {
	CMSG_KIND_SCM_RIGHTS,		/* AF_UNIX fd-passing */
	CMSG_KIND_SCM_CREDENTIALS,	/* AF_UNIX SO_PASSCRED */
	CMSG_KIND_SO_TIMESTAMPING,	/* IP / IPv6 timestamping */
	CMSG_KIND_PACKET_AUXDATA,	/* AF_PACKET aux */
	CMSG_KIND_UDP_GSO,		/* UDP segmentation offload */
	NR_CMSG_KINDS,
};

enum cmsg_kind pick_cmsg_kind(void);

/*
 * Replaces msg->msg_control / msg->msg_controllen with a single
 * cmsg of the requested kind.  Returns 0 on success, -1 if the
 * writable-pool allocation failed (caller should fall back to the
 * random-bytes path).
 */
int cmsg_build(struct msghdr *m, enum cmsg_kind k);

#endif /* _TRINITY_CMSG_BUILD_H */
