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
