/*
 * netlink-xfrm-state.c -- NETLINK_XFRM SA-family message builders.
 * Carved from netlink-xfrm-emit.c.  Shares internals with the other
 * proto-netlink-xfrm-*.c modules via proto-netlink-xfrm-internal.h.
 */

#include <stdbool.h>
#include <errno.h>

#include <linux/netlink.h>
#include <string.h>

#include "proto-netlink-xfrm-internal.h"
#include "random.h"
#include "utils.h"

#include "kernel/netlink.h"

/*
 * Build XFRM_MSG_NEWSA.  Picks family / proto / mode / SPI / reqid,
 * builds a coherent attribute set (AEAD vs paired CRYPT+AUTH_TRUNC,
 * optional COMP for IPCOMP, optional ENCAP, optional REPLAY/ESN,
 * optional marks/if/offload/extra-flags), and on accept pushes the
 * (daddr, spi, proto, family, reqid) onto the SA ring for later
 * UPDSA/NEWAE/DELSA targeting.
 */
int xfrm_emit_newsa(int fd)
{
	unsigned char buf[XFRM_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct xfrm_usersa_info *sa;
	struct xfrm_sa_track entry;
	__u16 family = pick_family();
	__u8 mode = pick_mode();
	__u8 proto = pick_sa_proto();
	__u32 reqid = (rand32() & 0xff) + 1U;
	__be32 spi = htonl(0x100U + rnd_modulo_u32(0xfff000U));
	size_t off;
	int rc;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = XFRM_MSG_NEWSA;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = xfrm_next_seq();

	sa = (struct xfrm_usersa_info *)NLMSG_DATA(nlh);
	fill_selector(&sa->sel, family);
	sa->id.proto      = proto;
	sa->id.spi        = spi;
	fill_addresses(family, &sa->saddr, &sa->id.daddr);
	fill_lifetime(&sa->lft);
	sa->reqid         = reqid;
	sa->family        = family;
	sa->mode          = mode;
	sa->replay_window = (__u8)rnd_modulo_u32(64);
	sa->flags         = (__u8)(rand32() & 0x7f);

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*sa));

	/* Algorithm choice -- AEAD only on ESP, AUTH-only on AH, COMP
	 * on IPCOMP; otherwise paired CRYPT + AUTH_TRUNC for ESP. */
	if (proto == IPPROTO_AH) {
		off = append_auth_trunc(buf, off, sizeof(buf));
	} else if (proto == IPPROTO_COMP) {
		off = append_comp(buf, off, sizeof(buf));
	} else {
		/* IPPROTO_ESP -- AEAD or paired CRYPT+AUTH_TRUNC. */
		if (rand32() & 1) {
			off = append_aead(buf, off, sizeof(buf));
		} else {
			off = append_crypt(buf, off, sizeof(buf));
			if (off)
				off = append_auth_trunc(buf, off, sizeof(buf));
		}
	}
	if (!off)
		return -EIO;

	off = append_encap_maybe(buf, off, sizeof(buf));
	if (!off)
		return -EIO;

	off = append_replay_maybe(buf, off, sizeof(buf), &sa->flags);
	if (!off)
		return -EIO;

	off = append_marks_and_if(buf, off, sizeof(buf));
	if (!off)
		return -EIO;

	off = append_iptfs_and_extras(buf, off, sizeof(buf));
	if (!off)
		return -EIO;

	nlh->nlmsg_len = (__u32)off;
	rc = xfrm_send_recv(fd, buf, off);
	if (rc != 0) {
		if (is_structural_reject(rc))
			latch_unsupported(rc);
		return rc;
	}

	memset(&entry, 0, sizeof(entry));
	entry.family = family;
	entry.proto  = proto;
	entry.daddr  = sa->id.daddr;
	entry.spi    = spi;
	entry.reqid  = reqid;
	/* On sa_ring_push failure the slot still tracks the prior SA;
	 * the new SA reached the kernel but stays untracked here.  Do
	 * not retry inline -- the next push to this slot retries the
	 * DELSA naturally. */
	if (sa_ring_push(fd, &entry) != 0)
		return 0;
	return 0;
}

/*
 * Pick a (min, max) SPI range, rotating across happy-path and edge
 * cases the kernel scan loop and validation arms care about:
 *
 *   60% normal happy-path 0x100..0x1000-ish range
 *   10% min == max single-value scan
 *   10% min  > max EINVAL early-return arm
 *   10% min == 0 IPCOMP-distinguishing boundary
 *   10% max == ~0U top-of-range edge
 */
static void pick_spi_range(__u32 *out_min, __u32 *out_max)
{
	unsigned int r = rnd_modulo_u32(100U);
	__u32 a, b;

	if (r < 60U) {
		*out_min = 0x100U + rnd_modulo_u32(0x1000U);
		*out_max = *out_min + 0x100U + rnd_modulo_u32(0xff00U);
	} else if (r < 70U) {
		*out_min = *out_max = 0x100U + rnd_modulo_u32(0xfffffU);
	} else if (r < 80U) {
		a = 0x100U + rnd_modulo_u32(0xff00U);
		b = 0x100U + rnd_modulo_u32(0xff00U);
		if (a == b)
			b++;
		*out_min = (a > b ? a : b) + 1U;
		*out_max = (a < b ? a : b);
	} else if (r < 90U) {
		*out_min = 0U;
		*out_max = 0x100U + rnd_modulo_u32(0xff00U);
	} else {
		*out_min = rand32() | 0x80000000U;
		*out_max = ~0U;
	}
}

/*
 * Build XFRM_MSG_ALLOCSPI -- NEWSA-shaped shell asking the kernel to
 * pick a free SPI within [min, max].  No SA-ring push: the kernel-
 * allocated SPI value is returned in the response payload but the
 * grammar has no path to thread that back into the ring shape.
 */
int xfrm_emit_allocspi(int fd)
{
	unsigned char buf[XFRM_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct xfrm_userspi_info *spi;
	struct xfrm_usersa_info *sa;
	__u16 family = pick_family();
	__u8 mode = pick_mode();
	__u8 proto = pick_sa_proto();
	__u32 reqid = (rand32() & 0xff) + 1U;
	size_t off;
	int rc;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = XFRM_MSG_ALLOCSPI;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = xfrm_next_seq();

	spi = (struct xfrm_userspi_info *)NLMSG_DATA(nlh);
	sa = &spi->info;
	fill_selector(&sa->sel, family);
	sa->id.proto      = proto;
	sa->id.spi        = 0;	/* kernel allocates */
	fill_addresses(family, &sa->saddr, &sa->id.daddr);
	fill_lifetime(&sa->lft);
	sa->reqid         = reqid;
	sa->family        = family;
	sa->mode          = mode;
	sa->replay_window = (__u8)rnd_modulo_u32(64);
	sa->flags         = (__u8)(rand32() & 0x7f);
	pick_spi_range(&spi->min, &spi->max);

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*spi));

	if (proto == IPPROTO_AH) {
		off = append_auth_trunc(buf, off, sizeof(buf));
	} else if (proto == IPPROTO_COMP) {
		off = append_comp(buf, off, sizeof(buf));
	} else {
		if (rand32() & 1) {
			off = append_aead(buf, off, sizeof(buf));
		} else {
			off = append_crypt(buf, off, sizeof(buf));
			if (off)
				off = append_auth_trunc(buf, off, sizeof(buf));
		}
	}
	if (!off)
		return -EIO;

	off = append_encap_maybe(buf, off, sizeof(buf));
	if (!off)
		return -EIO;

	off = append_replay_maybe(buf, off, sizeof(buf), &sa->flags);
	if (!off)
		return -EIO;

	off = append_marks_and_if(buf, off, sizeof(buf));
	if (!off)
		return -EIO;

	off = append_iptfs_and_extras(buf, off, sizeof(buf));
	if (!off)
		return -EIO;

	nlh->nlmsg_len = (__u32)off;
	rc = xfrm_send_recv(fd, buf, off);
	if (rc != 0 && is_structural_reject(rc))
		latch_unsupported(rc);
	return rc;
}
