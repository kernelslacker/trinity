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

/*
 * Build XFRM_MSG_UPDSA targeting a ring SA.  Same shell with a fresh
 * random key + rotated attribute set.  No-op when ring is empty.
 */
int xfrm_emit_updsa(int fd)
{
	unsigned char buf[XFRM_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct xfrm_usersa_info *sa;
	struct xfrm_sa_track t;
	size_t off;

	if (!sa_ring_pick(&t, NULL))
		return 0;	/* nothing to update yet */

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = XFRM_MSG_UPDSA;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = xfrm_next_seq();

	sa = (struct xfrm_usersa_info *)NLMSG_DATA(nlh);
	fill_selector(&sa->sel, t.family);
	sa->id.proto      = t.proto;
	sa->id.spi        = t.spi;
	sa->id.daddr      = t.daddr;
	memset(&sa->saddr, 0, sizeof(sa->saddr));
	if (t.family == AF_INET)
		sa->saddr.a4 = (__be32)htonl(0x7f000001U);
	else {
		sa->saddr.a6[0] = htonl(0xfe800000U);
		sa->saddr.a6[3] = htonl(1U);
	}
	fill_lifetime(&sa->lft);
	sa->reqid         = t.reqid;
	sa->family        = t.family;
	sa->mode          = pick_mode();
	sa->replay_window = (__u8)rnd_modulo_u32(64);
	sa->flags         = (__u8)(rand32() & 0x7f);

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*sa));

	if (t.proto == IPPROTO_AH) {
		off = append_auth_trunc(buf, off, sizeof(buf));
	} else if (t.proto == IPPROTO_COMP) {
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
	return xfrm_send_recv(fd, buf, off);
}

/*
 * Build XFRM_MSG_NEWAE (asynchronous event) targeting a ring SA.
 * Userspace pushes a new replay state / lifetime view into the kernel
 * via this message; the parser walks XFRMA_REPLAY_VAL or
 * XFRMA_REPLAY_ESN_VAL plus optional XFRMA_LTIME_VAL based on the
 * XFRM_AE_RVAL / XFRM_AE_LVAL flag bits.
 */
int xfrm_emit_newae(int fd)
{
	unsigned char buf[XFRM_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct xfrm_aevent_id *ae;
	struct xfrm_sa_track t;
	__u8 ignored_flags = 0;
	size_t off, before_replay;

	if (!sa_ring_pick(&t, NULL))
		return 0;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = XFRM_MSG_NEWAE;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = xfrm_next_seq();

	ae = (struct xfrm_aevent_id *)NLMSG_DATA(nlh);
	ae->sa_id.daddr  = t.daddr;
	ae->sa_id.spi    = t.spi;
	ae->sa_id.family = t.family;
	ae->sa_id.proto  = t.proto;
	if (t.family == AF_INET)
		ae->saddr.a4 = (__be32)htonl(0x7f000001U);
	else {
		ae->saddr.a6[0] = htonl(0xfe800000U);
		ae->saddr.a6[3] = htonl(1U);
	}
	ae->reqid = t.reqid;
	/* RVAL is added after the replay attr append below, but only when
	 * append_replay_maybe actually emitted XFRMA_REPLAY_VAL or
	 * XFRMA_REPLAY_ESN_VAL.  Setting RVAL without a matching attr causes
	 * the kernel xfrm_new_ae() parser to return -EINVAL. */
	ae->flags = XFRM_AE_LVAL & (__u32)(rand32() & 0xff);

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ae));

	before_replay = off;
	off = append_replay_maybe(buf, off, sizeof(buf), &ignored_flags);
	if (!off)
		return -EIO;
	if (off > before_replay)
		ae->flags |= XFRM_AE_RVAL;

	if (ae->flags & XFRM_AE_LVAL) {
		struct xfrm_lifetime_cur cur;

		memset(&cur, 0, sizeof(cur));
		cur.bytes    = rand32();
		cur.packets  = rand32();
		cur.add_time = rand32();
		cur.use_time = rand32();
		off = xfrm_nla_put(buf, off, sizeof(buf), XFRMA_LTIME_VAL,
				   &cur, sizeof(cur));
		if (!off)
			return -EIO;
	}

	nlh->nlmsg_len = (__u32)off;
	return xfrm_send_recv(fd, buf, off);
}

int xfrm_emit_delsa_random(int fd)
{
	struct xfrm_sa_track t;
	unsigned int idx;
	int rc;

	if (!sa_ring_pick(&t, &idx))
		return 0;

	rc = xfrm_emit_delsa_for(fd, &t);
	if (rc == 0)
		sa_ring_drop(idx);
	return rc;
}

/*
 * Build XFRM_MSG_EXPIRE targeting a ring SA.  The kernel handler
 * (xfrm_add_sa_expire in net/xfrm/xfrm_user.c) looks up the SA by
 * (mark, daddr, spi, proto, family) from the embedded xfrm_usersa_info
 * shell, then calls km_state_expired() with the trailing ->hard byte;
 * hard==1 also tears the SA down via __xfrm_state_delete().  The lookup
 * uses XFRMA_MARK from the attrs (we don't emit it -- mark falls back
 * to 0, matching the most common NEWSA shape we install).  The
 * remaining xfrm_usersa_info fields are unread by the lookup; we still
 * fill them with self-consistent values so a future kernel that grew
 * additional validation on the expire path doesn't bounce us on shape.
 *
 * On hard==1 acceptance the kernel deletes the SA -- drop the ring
 * slot so subsequent UPDSA/NEWAE/DELSA on it don't bounce on ESRCH.
 * On soft (hard==0) the SA stays installed; the ring entry stays.
 */
int xfrm_emit_expire(int fd)
{
	unsigned char buf[512];
	struct nlmsghdr *nlh;
	struct xfrm_user_expire *ue;
	struct xfrm_usersa_info *sa;
	struct xfrm_sa_track t;
	unsigned int idx;
	__u8 hard;
	size_t off;
	int rc;

	if (!sa_ring_pick(&t, &idx))
		return 0;	/* nothing installed yet */

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = XFRM_MSG_EXPIRE;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = xfrm_next_seq();

	ue = (struct xfrm_user_expire *)NLMSG_DATA(nlh);
	sa = &ue->state;

	/* Lookup keys -- must match the SA the ring entry refers to. */
	sa->id.daddr = t.daddr;
	sa->id.spi   = t.spi;
	sa->id.proto = t.proto;
	sa->family   = t.family;

	/* Self-consistent fill for the rest of the shell.  None of these
	 * are read by xfrm_add_sa_expire today, but a future-kernel
	 * shape-validation arm would otherwise hit zeros. */
	fill_selector(&sa->sel, t.family);
	fill_addresses(t.family, &sa->saddr, &sa->id.daddr);
	sa->id.daddr = t.daddr;	/* restore lookup key after fill_addresses */
	fill_lifetime(&sa->lft);
	sa->reqid         = t.reqid;
	sa->mode          = pick_mode();
	sa->replay_window = (__u8)rnd_modulo_u32(64);
	sa->flags         = (__u8)(rand32() & 0x7f);

	/* Rotate hard 0/1 -- soft hits the kn->event(STATE_EXPIRED) path
	 * without teardown; hard additionally drives __xfrm_state_delete
	 * and audit_state_delete. */
	hard = (__u8)(rand32() & 1);
	ue->hard = hard;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ue));
	nlh->nlmsg_len = (__u32)off;

	rc = xfrm_send_recv(fd, buf, off);
	if (rc == 0 && hard)
		sa_ring_drop(idx);
	return rc;
}

/*
 * XFRM_MSG_MIGRATE_STATE + xfrm_user_migrate_state landed in v7.1;
 * the numeric value follows XFRM_MSG_GETDEFAULT in the enum sequence.
 * Old-host uapi headers lack both; provide a local shim so the emitter
 * compiles everywhere and only exercises the path at runtime on a
 * kernel that recognises the msg type (structural rejections latch
 * xfrm_unsupported below).
 */
#ifndef XFRM_MSG_MIGRATE_STATE
#define XFRM_MSG_MIGRATE_STATE 41
struct xfrm_user_migrate_state {
	struct xfrm_usersa_id id;
	xfrm_address_t new_daddr;
	xfrm_address_t new_saddr;
	struct xfrm_mark old_mark;
	struct xfrm_selector new_sel;
	__u32 new_reqid;
	__u32 flags;
	__u16 new_family;
	__u16 reserved;
};
#endif

/*
 * Build XFRM_MSG_MIGRATE_STATE (v7.1).  Body is xfrm_user_migrate_state
 * = xfrm_usersa_id + new_daddr/new_saddr + old_mark + new_sel + reqid +
 * flags + new_family.  When the SA ring is populated, target a real
 * entry so xfrm_migrate_state_find hits an installed SA; otherwise
 * synthesise a coherent (family, proto, daddr, spi) shell and let the
 * kernel bounce on ESRCH -- still walks the parser arms.  flags is
 * masked to the two known bits with a 1-in-8 unknown-bit rotation so
 * both KNOWN_FLAGS and reject-unknown-bits paths get coverage.
 */
int xfrm_emit_migrate_state(int fd)
{
	unsigned char buf[XFRM_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct xfrm_user_migrate_state *ums;
	struct xfrm_sa_track t;
	__u16 family;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = XFRM_MSG_MIGRATE_STATE;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = xfrm_next_seq();

	ums = (struct xfrm_user_migrate_state *)NLMSG_DATA(nlh);
	if (sa_ring_pick(&t, NULL)) {
		family              = t.family;
		ums->id.daddr       = t.daddr;
		ums->id.spi         = t.spi;
		ums->id.family      = family;
		ums->id.proto       = t.proto;
	} else {
		family              = pick_family();
		ums->id.family      = family;
		ums->id.proto       = pick_sa_proto();
		ums->id.spi         = htonl(0x100U + rnd_modulo_u32(0xff00U));
		fill_addresses(family, &ums->new_saddr, &ums->id.daddr);
	}
	fill_addresses(family, &ums->new_saddr, &ums->new_daddr);
	ums->old_mark.v         = rand32();
	ums->old_mark.m         = rand32();
	fill_selector(&ums->new_sel, family);
	ums->new_reqid          = (rand32() & 0xff) + 1U;
	ums->flags              = rand32() & 0x3U;
	if (rnd_modulo_u32(8) == 0)
		ums->flags |= 1U << (2 + rnd_modulo_u32(30));
	ums->new_family         = family;
	ums->reserved           = 0;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ums));
	nlh->nlmsg_len = (__u32)off;
	return xfrm_send_recv(fd, buf, off);
}
