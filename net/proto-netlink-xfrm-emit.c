/*
 * proto-netlink-xfrm-emit.c -- per-message-kind NETLINK_XFRM builders.
 * Each xfrm_emit_* function assembles one message (NEWSA / NEWAE /
 * NEWPOLICY / ...) plus its coherent attribute payload, sends it
 * through xfrm_send_recv, and -- on accept -- pushes any installed
 * SA / policy onto the per-process ring so later UPDSA / NEWAE /
 * DELSA / POLEXPIRE invocations target a real entry.
 */

#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <netinet/in.h>
#include <linux/netlink.h>

#include "compat.h"
#include "net.h"
#include "proto-netlink-xfrm-internal.h"
#include "random.h"
#include "utils.h"

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
 * Build XFRM_MSG_NEWPOLICY OUT direction with XFRMA_TMPL.  When the
 * SA ring has an entry, point the template at it (so the resolution
 * machinery has a concrete target); otherwise synthesise a template
 * with random reqid + spi + proto so the parser walks anyway.
 */
int xfrm_emit_newpolicy(int fd)
{
	unsigned char buf[XFRM_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct xfrm_userpolicy_info *pol;
	struct xfrm_user_tmpl tmpl;
	struct xfrm_sa_track t;
	__u16 family;
	size_t off;
	int rc;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = XFRM_MSG_NEWPOLICY;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = xfrm_next_seq();

	pol = (struct xfrm_userpolicy_info *)NLMSG_DATA(nlh);
	family = pick_family();
	fill_selector(&pol->sel, family);

	/* P2.10 family desync: 1-in-8 flip pol->sel.family so it disagrees
	 * with the outer family used by the XFRMA_TMPL we append below.
	 * Drives the xfrm_policy_construct family-mismatch arm
	 * (verify_newpolicy_info / copy_templates) which the coherent
	 * always-matched path would never reach. */
	if (rnd_modulo_u32(8) == 0)
		pol->sel.family = (family == AF_INET) ? AF_INET6 : AF_INET;

	fill_lifetime(&pol->lft);
	pol->priority = (__u32)(rand32() & 0xffff);
	pol->index    = 0;
	pol->dir      = XFRM_POLICY_OUT;
	pol->action   = XFRM_POLICY_ALLOW;
	pol->flags    = (__u8)(rand32() & 0x7);
	/* P3.13 reserved-bit OR: high bits 3-7 of pol->flags are reserved
	 * in the current UAPI.  OR in a random 3-bit pattern shifted into
	 * the reserved range so verify_policy_info's
	 * XFRM_POLICY_LOCALOK-and-friends mask check sees out-of-set bits. */
	pol->flags   |= (__u8)(rnd_modulo_u32(8) << 3);
	pol->share    = XFRM_SHARE_ANY;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*pol));

	memset(&tmpl, 0, sizeof(tmpl));
	if (sa_ring_pick(&t, NULL)) {
		tmpl.id.daddr = t.daddr;
		tmpl.id.spi   = t.spi;
		tmpl.id.proto = t.proto;
		tmpl.family   = t.family;
		tmpl.reqid    = t.reqid;
		if (t.family == AF_INET) {
			tmpl.saddr.a4 = (__be32)htonl(0x7f000001U);
		} else {
			tmpl.saddr.a6[0] = htonl(0xfe800000U);
			tmpl.saddr.a6[3] = htonl(1U);
		}
	} else {
		tmpl.id.proto = pick_sa_proto();
		tmpl.id.spi   = htonl(0x100U + rnd_modulo_u32(0xfff000U));
		tmpl.family   = family;
		tmpl.reqid    = (rand32() & 0xff) + 1U;
		fill_addresses(family, &tmpl.saddr, &tmpl.id.daddr);
	}
	tmpl.mode     = pick_mode();
	tmpl.share    = XFRM_SHARE_ANY;
	tmpl.optional = (__u8)(rand32() & 1);
	tmpl.aalgos   = (__u32)~0U;
	tmpl.ealgos   = (__u32)~0U;
	tmpl.calgos   = (__u32)~0U;

	off = xfrm_nla_put(buf, off, sizeof(buf), XFRMA_TMPL,
			   &tmpl, sizeof(tmpl));
	if (!off)
		return -EIO;

	off = append_marks_and_if(buf, off, sizeof(buf));
	if (!off)
		return -EIO;

	nlh->nlmsg_len = (__u32)off;
	rc = xfrm_send_recv(fd, buf, off);
	if (rc == 0) {
		struct xfrm_policy_track entry = {
			.sel    = pol->sel,
			.dir    = pol->dir,
			.family = family,
			.used   = true,
		};
		policy_ring_push(&entry);
	}
	return rc;
}

int xfrm_emit_delpolicy(int fd)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct xfrm_userpolicy_id *pid;
	__u16 family = pick_family();
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = XFRM_MSG_DELPOLICY;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = xfrm_next_seq();

	pid = (struct xfrm_userpolicy_id *)NLMSG_DATA(nlh);
	fill_selector(&pid->sel, family);
	pid->dir = XFRM_POLICY_OUT;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*pid));
	nlh->nlmsg_len = (__u32)off;
	return xfrm_send_recv(fd, buf, off);
}

int xfrm_emit_flushsa(int fd)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct xfrm_usersa_flush *uf;
	static const __u8 proto_choices[] = {
		IPPROTO_ESP, IPPROTO_AH, IPPROTO_COMP, IPSEC_PROTO_ANY,
	};
	size_t off;
	int rc;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = XFRM_MSG_FLUSHSA;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = xfrm_next_seq();

	uf = (struct xfrm_usersa_flush *)NLMSG_DATA(nlh);
	uf->proto = RAND_ARRAY(proto_choices);

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*uf));
	nlh->nlmsg_len = (__u32)off;
	rc = xfrm_send_recv(fd, buf, off);

	/* Whether or not the kernel accepts (a partial-proto flush may
	 * leave some entries), drain the ring -- the next UPDSA / NEWAE
	 * / DELSA on a stale entry would just bounce off ESRCH anyway. */
	if (rc == 0)
		sa_ring_drain();
	return rc;
}

int xfrm_emit_flushpolicy(int fd)
{
	unsigned char buf[64];
	struct nlmsghdr *nlh;
	size_t off = NLMSG_HDRLEN;
	int rc;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = XFRM_MSG_FLUSHPOLICY;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = xfrm_next_seq();
	nlh->nlmsg_len   = (__u32)off;
	rc = xfrm_send_recv(fd, buf, off);

	/* Whether or not the kernel accepts (a partial flush may leave
	 * some entries), drain the policy ring -- the next POLEXPIRE on
	 * a stale entry would just bounce off ESRCH anyway. */
	if (rc == 0)
		policy_ring_drain();
	return rc;
}

/*
 * Build XFRM_MSG_MIGRATE coherently: a xfrm_userpolicy_id body
 * (selector + dir, index=0 to take the match-by-selector path) plus a
 * required XFRMA_MIGRATE attribute carrying 1-3 xfrm_user_migrate
 * slots.  Per-tmpl old_family == new_family here so the per-template
 * family validation arm sees the coherent shape; the random-body path
 * in xfrm_types[] still covers garbage payloads.
 */
int xfrm_emit_migrate(int fd)
{
	unsigned char buf[XFRM_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct xfrm_userpolicy_id *id;
	struct xfrm_user_migrate mig[3];
	__u16 family = pick_family();
	__u8 dir = (__u8)rnd_modulo_u32(3);
	unsigned int n_slots = 1 + rnd_modulo_u32(3);
	size_t off, addr_bytes;
	unsigned int i;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = XFRM_MSG_MIGRATE;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = xfrm_next_seq();

	id = (struct xfrm_userpolicy_id *)NLMSG_DATA(nlh);
	fill_selector(&id->sel, family);

	/* P2.11 family desync: 1-in-8 flip id->sel.family so the body
	 * selector disagrees with the per-template old_family / new_family
	 * we emit in the XFRMA_MIGRATE attribute below.  Drives the
	 * xfrm_migrate_check / copy_to_user_migrate family-mismatch arms
	 * the coherent always-matched path would never reach. */
	if (rnd_modulo_u32(8) == 0)
		id->sel.family = (family == AF_INET) ? AF_INET6 : AF_INET;

	id->index = 0;
	id->dir   = dir;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*id));

	addr_bytes = (family == AF_INET6) ? 16 : 4;
	memset(mig, 0, sizeof(mig));
	for (i = 0; i < n_slots; i++) {
		generate_rand_bytes((unsigned char *)&mig[i].old_daddr, addr_bytes);
		generate_rand_bytes((unsigned char *)&mig[i].old_saddr, addr_bytes);
		generate_rand_bytes((unsigned char *)&mig[i].new_daddr, addr_bytes);
		generate_rand_bytes((unsigned char *)&mig[i].new_saddr, addr_bytes);
		mig[i].proto      = pick_sa_proto();
		mig[i].mode       = pick_mode();
		/* P3.13 reserved-bit OR: xfrm_user_migrate.reserved is a
		 * must-be-zero pad in the UAPI.  Plant a low 3-bit random
		 * value so the validator-side zero check (if any) actually
		 * fires; old kernels ignored it, newer ones may reject. */
		mig[i].reserved   = (__u8)rnd_modulo_u32(8);
		mig[i].reqid      = (rand32() & 0xff) + 1U;
		mig[i].old_family = family;
		mig[i].new_family = family;
	}

	off = xfrm_nla_put(buf, off, sizeof(buf), XFRMA_MIGRATE, mig,
			   n_slots * sizeof(struct xfrm_user_migrate));
	if (!off)
		return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return xfrm_send_recv(fd, buf, off);
}

/*
 * Build XFRM_MSG_POLEXPIRE.  Body is xfrm_user_polexpire = embedded
 * xfrm_userpolicy_info shell + trailing __u8 hard.  The kernel handler
 * (xfrm_add_pol_expire in net/xfrm/xfrm_user.c) looks up the policy by
 * (sel, dir) from the embedded shell, then calls km_policy_expired() with
 * the trailing ->hard byte; hard==1 also tears the policy down via
 * xfrm_policy_delete().  Pick from the policy ring when one exists so the
 * lookup hits a real installed policy; otherwise synthesise (sel, dir)
 * with random values and let the kernel bounce on ESRCH -- still walks
 * the parser arms.
 */
int xfrm_emit_polexpire(int fd)
{
	unsigned char buf[XFRM_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct xfrm_user_polexpire *upe;
	struct xfrm_userpolicy_info *pol;
	struct xfrm_policy_track t;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = XFRM_MSG_POLEXPIRE;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = xfrm_next_seq();

	upe = (struct xfrm_user_polexpire *)NLMSG_DATA(nlh);
	pol = &upe->pol;

	if (policy_ring_pick(&t, NULL)) {
		pol->sel = t.sel;
		pol->dir = t.dir;
	} else {
		fill_selector(&pol->sel, pick_family());
		pol->dir = (__u8)rnd_modulo_u32(3);	/* IN / OUT / FWD */
	}
	fill_lifetime(&pol->lft);
	pol->priority = (__u32)(rand32() & 0xffff);
	pol->index    = 0;	/* kernel matches by sel+dir */
	pol->action   = XFRM_POLICY_ALLOW;
	pol->flags    = (__u8)(rand32() & 0x7);
	pol->share    = XFRM_SHARE_ANY;

	/* Rotate hard 0/1 -- soft hits the km_policy_expired notification
	 * path without teardown; hard additionally drives xfrm_policy_delete
	 * and the audit_policy_delete arm. */
	upe->hard = (__u8)(rand32() & 1);

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*upe));
	nlh->nlmsg_len = (__u32)off;
	return xfrm_send_recv(fd, buf, off);
}

/*
 * Build XFRM_MSG_ACQUIRE.  Body is xfrm_user_acquire = embedded id /
 * saddr / selector / userpolicy_info plus aalgos/ealgos/calgos algo
 * bitmasks and a seq.  Mandatory XFRMA_TMPL attribute carries one
 * xfrm_user_tmpl (xfrm_add_acquire walks per-tmpl and dispatches
 * km_query for each).  Optional XFRMA_MARK / XFRMA_SET_MARK_MASK /
 * XFRMA_IF_ID / XFRMA_OFFLOAD_DEV / XFRMA_SA_EXTRA_FLAGS via the
 * shared append_marks_and_if helper so the same attribute-walk arms
 * as NEWSA / NEWPOLICY get exercised.
 *
 * Reaches xfrm_add_acquire -> verify_newpolicy_info ->
 * verify_sec_ctx_len -> xfrm_policy_construct -> km_query in
 * net/xfrm/xfrm_user.c.  The selector / policy / template fields are
 * coherent enough to make it past the shape validators; payload byte
 * variation comes from the embedded fuzz on aalgos/ealgos/calgos and
 * randomised id.proto / mode / addresses.
 */
int xfrm_emit_acquire(int fd)
{
	unsigned char buf[XFRM_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct xfrm_user_acquire *ua;
	struct xfrm_user_tmpl tmpl;
	struct xfrm_sa_track t;
	__u16 family;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = XFRM_MSG_ACQUIRE;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = xfrm_next_seq();

	ua = (struct xfrm_user_acquire *)NLMSG_DATA(nlh);
	family = pick_family();

	fill_addresses(family, &ua->saddr, &ua->id.daddr);
	ua->id.spi   = htonl(0x100U + rnd_modulo_u32(0xfff000U));
	ua->id.proto = pick_sa_proto();

	fill_selector(&ua->sel, family);

	fill_selector(&ua->policy.sel, family);
	fill_lifetime(&ua->policy.lft);
	ua->policy.priority = (__u32)(rand32() & 0xffff);
	ua->policy.index    = 0;
	ua->policy.dir      = XFRM_POLICY_OUT;
	ua->policy.action   = XFRM_POLICY_ALLOW;
	ua->policy.flags    = (__u8)(rand32() & 0x7);
	ua->policy.share    = XFRM_SHARE_ANY;

	/* Bias toward all-bits-set (the canonical "any algo" wildcard the
	 * IKE daemons use) but keep a fully random arm so reserved-bit
	 * handling in km_query / per-template dispatch gets exercised. */
	ua->aalgos = (rand32() & 1) ? (__u32)~0U : rand32();
	ua->ealgos = (rand32() & 1) ? (__u32)~0U : rand32();
	ua->calgos = (rand32() & 1) ? (__u32)~0U : rand32();
	ua->seq    = rand32();

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ua));

	/* XFRMA_TMPL is mandatory: xfrm_add_acquire dereferences
	 * nla_data(attrs[XFRMA_TMPL]) inside its per-template loop and
	 * xfrm_policy_construct rejects a zero xfrm_nr.  Mirror the
	 * NEWPOLICY emitter -- target a ring SA when one exists, else
	 * synthesise a coherent template. */
	memset(&tmpl, 0, sizeof(tmpl));
	if (sa_ring_pick(&t, NULL)) {
		tmpl.id.daddr = t.daddr;
		tmpl.id.spi   = t.spi;
		tmpl.id.proto = t.proto;
		tmpl.family   = t.family;
		tmpl.reqid    = t.reqid;
		if (t.family == AF_INET) {
			tmpl.saddr.a4 = (__be32)htonl(0x7f000001U);
		} else {
			tmpl.saddr.a6[0] = htonl(0xfe800000U);
			tmpl.saddr.a6[3] = htonl(1U);
		}
	} else {
		tmpl.id.proto = pick_sa_proto();
		tmpl.id.spi   = htonl(0x100U + rnd_modulo_u32(0xfff000U));
		tmpl.family   = family;
		tmpl.reqid    = (rand32() & 0xff) + 1U;
		fill_addresses(family, &tmpl.saddr, &tmpl.id.daddr);
	}
	tmpl.mode     = pick_mode();
	tmpl.share    = XFRM_SHARE_ANY;
	tmpl.optional = (__u8)(rand32() & 1);
	tmpl.aalgos   = (__u32)~0U;
	tmpl.ealgos   = (__u32)~0U;
	tmpl.calgos   = (__u32)~0U;

	off = xfrm_nla_put(buf, off, sizeof(buf), XFRMA_TMPL,
			   &tmpl, sizeof(tmpl));
	if (!off)
		return -EIO;

	off = append_marks_and_if(buf, off, sizeof(buf));
	if (!off)
		return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return xfrm_send_recv(fd, buf, off);
}

/*
 * SETDEFAULT/GETDEFAULT body bytes are small enums (0..2).  Bias the
 * rotation toward valid values but keep low-probability edge bytes so
 * any future reserved-bit handling on the kernel side gets exercised.
 */
static __u8 pick_default_byte(void)
{
	unsigned int r = rnd_modulo_u32(100);

	if (r < 75)
		return r % 3;		/* UNSPEC / BLOCK / ACCEPT */
	if (r < 90)
		return 0xff;		/* top-byte edge */
	return rand32() & 0xff;		/* full-byte fuzz */
}

int xfrm_emit_setdefault(int fd)
{
	unsigned char buf[64];
	struct nlmsghdr *nlh;
	struct xfrm_userpolicy_default *upd;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = XFRM_MSG_SETDEFAULT;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = xfrm_next_seq();

	upd = (struct xfrm_userpolicy_default *)NLMSG_DATA(nlh);
	upd->in  = pick_default_byte();
	upd->fwd = pick_default_byte();
	upd->out = pick_default_byte();

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*upd));
	nlh->nlmsg_len = (__u32)off;
	return xfrm_send_recv(fd, buf, off);
}

int xfrm_emit_getdefault(int fd)
{
	unsigned char buf[64];
	struct nlmsghdr *nlh;
	struct xfrm_userpolicy_default *upd;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = XFRM_MSG_GETDEFAULT;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = xfrm_next_seq();

	upd = (struct xfrm_userpolicy_default *)NLMSG_DATA(nlh);
	upd->in  = pick_default_byte();
	upd->fwd = pick_default_byte();
	upd->out = pick_default_byte();

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*upd));
	nlh->nlmsg_len = (__u32)off;
	return xfrm_send_recv(fd, buf, off);
}
