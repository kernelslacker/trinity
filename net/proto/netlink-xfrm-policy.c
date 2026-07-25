/*
 * netlink-xfrm-policy.c -- NETLINK_XFRM policy-family message builders.
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
