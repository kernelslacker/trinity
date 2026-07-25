/*
 * xfrm-churn-traffic - inner-UDP burst drivers for the xfrm_churn
 * childop.  Carved out of childops/net/xfrm/xfrm-churn.c so the two
 * sendto loops (copying and MSG_ZEROCOPY) plus the bounded errqueue
 * drain compile as their own TU alongside the netlink builders.
 *
 * Pure relocation: every function body is byte-for-byte the same as
 * the original.  The only linkage change is widening the two burst
 * entry points from file-static to external so the phase drivers in
 * xfrm-churn.c can reach them across the TU boundary; the errqueue
 * drain helper keeps file-static linkage because it has no cross-TU
 * callers.
 */

#include "xfrm-churn-internal.h"

#include "kernel/socket.h"

/* STORM_BUDGET_NS wall-clock cap: sendto is MSG_DONTWAIT and the inner
 * loop clamps to this ceiling so even an unbounded burst can't stall
 * past the SIGALRM(1s) cap upstream. */
#define STORM_BUDGET_NS		200000000L

/*
 * Backing pages for the MSG_ZEROCOPY inner-UDP variant.  Static
 * lifetime so the kernel-pinned pages stay valid for any in-flight
 * uarg until the completion notification lands on the socket's
 * errqueue and is drained — no early reuse, no GUP-vs-free race
 * window on our side.  One page is enough: __zerocopy_sg_from_iter
 * pins the buffer into skb_shinfo()->frags[] regardless of size, so
 * the SKBFL_SHARED_FRAG marker on the inner skb fires whether the
 * payload is 64 bytes or 4 KB.  Page-aligned so the kernel's GUP
 * walks a single page-aligned span rather than crossing a boundary.
 */
#define XFRM_ZC_PAYLOAD_BYTES	4096U
#define XFRM_ZC_DRAIN_CAP	128U	/* errqueue drain ceiling per burst */
static unsigned char zc_payload[XFRM_ZC_PAYLOAD_BYTES]
	__attribute__((aligned(4096)));

/*
 * Drain MSG_ERRQUEUE completion notifications from a UDP socket that
 * issued MSG_ZEROCOPY sends.  Each accepted zerocopy send accrues one
 * SO_EE_ORIGIN_ZEROCOPY entry when the kernel finishes with the
 * pinned pages; left undrained, the per-socket errqueue accumulates
 * until subsequent sends fall back to copy (or ENOBUFS).  Bounded by
 * `max` so a flood of stale completions can't stall the
 * STORM_BUDGET_NS wall-clock cap upstream.  Discards the body — the
 * page-lifecycle/COW bug class lives in skb-side state, not in the
 * cmsg shape (msg_zerocopy_churn already covers cmsg validation).
 */
static unsigned int drain_errqueue_bounded(int udp, unsigned int max)
{
	unsigned char ebuf[64];
	unsigned int i, drained = 0;

	for (i = 0; i < max; i++) {
		if (recv(udp, ebuf, sizeof(ebuf),
			 MSG_ERRQUEUE | MSG_DONTWAIT) < 0)
			break;
		drained++;
	}
	return drained;
}

/*
 * Drive the SPD-resolved bundle with MSG_ZEROCOPY sendto on the
 * inner UDP socket.  __zerocopy_sg_from_iter pins zc_payload[] into
 * skb_shinfo()->frags[] and skb_zcopy_set marks SKBFL_ZEROCOPY_FRAG
 * (a superset of SKBFL_SHARED_FRAG) on the inner skb.  The encrypt
 * path (xfrm_output -> esp_output) then takes the COW branch via
 * skb_has_shared_frag(): esp4.c:876 falls through to skb_cow_data()
 * instead of the skip_cow in-place fast path.  This is the precise
 * branch the shared-frag CVE family (CVE-2026-46300 skb_try_coalesce
 * SHARED_FRAG-loss; xfrm/iptfs iptfs_consume_frags SHARED_FRAG-loss
 * sibling) lives in but that the copying sendto path never reaches —
 * the in-place-encrypt fast path is fine on private skb pages, the
 * bug only manifests when COW logic is exercised against shared/
 * externally-owned frags.
 *
 * Bounded errqueue drain after the burst keeps zerocopy completion
 * notifications from accumulating on the socket; the static
 * zc_payload[] backing pages outlive any in-flight uarg so the
 * kernel's GUP refcount path can't race a userspace free.  Returns
 * the count of successful sends so the caller's burst-stats stay
 * symmetric with the regular sendto path.
 */
unsigned int drive_inner_traffic_zc(int udp, unsigned int iters,
				    const struct timespec *t0)
{
	struct sockaddr_in dst;
	unsigned int i, ok = 0;

	memset(&dst, 0, sizeof(dst));
	dst.sin_family      = AF_INET;
	dst.sin_port        = htons(XFRM_INNER_PORT);
	dst.sin_addr.s_addr = XFRM_DADDR_BE;

	/* Randomise a prefix of the persistent buffer so each burst's
	 * ciphertext differs — full-page regen would waste cycles and
	 * isn't required (the bug-class window is the page-pinning +
	 * AEAD-in-place decision, not the payload bytes). */
	generate_rand_bytes(zc_payload, 64);

	for (i = 0; i < iters; i++) {
		ssize_t n;

		if (ns_since(t0) >= STORM_BUDGET_NS)
			break;

		n = sendto(udp, zc_payload, sizeof(zc_payload),
			   MSG_DONTWAIT | MSG_ZEROCOPY,
			   (struct sockaddr *)&dst, sizeof(dst));
		if (n > 0) {
			ok++;
			__atomic_add_fetch(&shm->stats.xfrm_churn.zc_sent,
					   1, __ATOMIC_RELAXED);
		}
		/* Errors are benign here: EAGAIN means the socket
		 * buffer / errqueue is full (next iter or post-drain
		 * frees room), EOPNOTSUPP/EINVAL would mean a kernel
		 * rejected MSG_ZEROCOPY despite setsockopt accepting
		 * SO_ZEROCOPY (extremely rare; falls through). */
	}

	__atomic_add_fetch(&shm->stats.xfrm_churn.zc_errq_drained,
			   drain_errqueue_bounded(udp, XFRM_ZC_DRAIN_CAP),
			   __ATOMIC_RELAXED);
	return ok;
}

/*
 * Drive the SPD-resolved bundle with loopback UDP traffic.  Each
 * send walks ip_local_out -> xfrm_output -> esp_output (or ah_output
 * / ipcomp_output) through the freshly-installed SA + SP bundle.
 * Returns the number of successful sends so the caller can roll
 * stats.
 */
unsigned int drive_inner_traffic(int udp, unsigned int iters,
				 const struct timespec *t0)
{
	struct sockaddr_in dst;
	unsigned int i, ok = 0;

	memset(&dst, 0, sizeof(dst));
	dst.sin_family      = AF_INET;
	dst.sin_port        = htons(XFRM_INNER_PORT);
	dst.sin_addr.s_addr = XFRM_DADDR_BE;

	for (i = 0; i < iters; i++) {
		unsigned char payload[64];
		ssize_t n;

		if (ns_since(t0) >= STORM_BUDGET_NS)
			break;

		generate_rand_bytes(payload, sizeof(payload));
		n = sendto(udp, payload, sizeof(payload), MSG_DONTWAIT,
			   (struct sockaddr *)&dst, sizeof(dst));
		if (n > 0)
			ok++;
	}
	return ok;
}
