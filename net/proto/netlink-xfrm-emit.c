/*
 * netlink-xfrm-emit.c -- per-message-kind NETLINK_XFRM builders.
 * Each xfrm_emit_* function assembles one message (NEWSA / NEWAE /
 * NEWPOLICY / ...) plus its coherent attribute payload, sends it
 * through xfrm_send_recv, and -- on accept -- pushes any installed
 * SA / policy onto the per-process ring so later UPDSA / NEWAE /
 * DELSA / POLEXPIRE invocations target a real entry.
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
 * XFRM_MSG_MIGRATE_STATE + xfrm_user_migrate_state landed in v7.1;
 * the numeric value follows XFRM_MSG_GETDEFAULT in the enum sequence.
 * Old-host uapi headers lack both; provide a local shim so the emitter
 * compiles everywhere and only exercises the path at runtime on a
 * kernel that recognises the msg type (structural rejections latch
 * xfrm_unsupported below).
 */
#ifndef XFRM_MSG_MIGRATE_STATE
#define XFRM_MSG_MIGRATE_STATE 42
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
