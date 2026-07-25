/*
 * nat-t-churn-cleanup - nat_keepalive construct-error and teardown
 * driver for the nat_t_churn childop.  Carved out of
 * childops/net/xfrm/nat-t-churn.c so the NEWSA-that-arms-a-worker plus
 * matching-DELSA cycle -- which is the primary driver for the kernel's
 * xfrm_nat_keepalive_init construct-error cleanup and
 * xfrm_nat_keepalive_fini teardown paths -- compiles as its own TU
 * alongside the shared SA assemblers and the traffic drivers.
 *
 * Pure relocation: every function body and constant table is
 * byte-for-byte the same as the original.  The only linkage change is
 * widening nat_keepalive_err_cycle from file-static to external so the
 * top-level dispatch in nat-t-churn.c can reach it across the TU
 * boundary; build_newsa_keepalive keeps file-static linkage because it
 * has no cross-TU callers.  The interval rotation table stays with the
 * two functions that consume it.
 */

#include "nat-t-churn-internal.h"

/* Keepalive interval rotation (seconds).  0 disables the keepalive
 * worker entirely; non-zero + XFRMA_SA_DIR=OUT + XFRMA_ENCAP arms the
 * per-net keepalive worker on the SA at construct time.  Small values
 * exercise the worker's arming/rearming path; a large value exercises
 * the same setup arithmetic without ever actually firing during the
 * op's 1s lifetime. */
static const __u32 nat_keepalive_intervals[] = {
	1U, 2U, 5U, 60U, 0xffffU,
};

/*
 * Build XFRM_MSG_NEWSA carrying the standard NAT-T attribute set plus
 * XFRMA_SA_DIR and XFRMA_NAT_KEEPALIVE_INTERVAL.  The kernel accepts
 * the SA only when the (direction, encap-present, interval) triple is
 * mutually consistent -- OUT + encap + non-zero interval arms the
 * per-net keepalive worker; IN with a non-zero interval or an
 * encap-less SA with a non-zero interval is rejected by
 * xfrm_nat_keepalive_init after the SA shell has already been
 * partly-constructed, driving the construct-error teardown path.
 *
 * Every combination is emitted intentionally so the rejection paths
 * get roughly equal cycles alongside the accepted (OUT + encap +
 * interval) baseline.
 */
static int build_newsa_keepalive(struct nl_ctx *ctx, __be32 spi, __u8 mode,
				 enum nat_t_encap_choice encap_choice,
				 __u8 sa_dir, __u32 interval,
				 const struct nat_t_alg *auth,
				 const struct nat_t_alg *crypt)
{
	unsigned char buf[NAT_T_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct xfrm_usersa_info *sa;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = XFRM_MSG_NEWSA;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	sa = (struct xfrm_usersa_info *)NLMSG_DATA(nlh);
	nat_t_fill_selector(&sa->sel);
	sa->id.daddr.a4   = NAT_T_DADDR_BE;
	sa->id.spi        = spi;
	sa->id.proto      = IPPROTO_ESP;
	sa->saddr.a4      = NAT_T_SADDR_BE;
	nat_t_fill_lifetime(&sa->lft);
	sa->reqid         = 1;
	sa->family        = AF_INET;
	sa->mode          = mode;
	/* Kernel rejects OUT SAs whose replay_window is non-zero once
	 * XFRMA_SA_DIR is present; pair the two so the accepted path
	 * doesn't fall over on that unrelated check. */
	sa->replay_window = (sa_dir == XFRM_SA_DIR_OUT) ? 0 : 32;
	sa->flags         = 0;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*sa));

	off = nat_t_append_auth_trunc(buf, off, sizeof(buf), auth);
	if (!off)
		return -EIO;

	off = nat_t_append_crypt(buf, off, sizeof(buf), crypt);
	if (!off)
		return -EIO;

	if (encap_choice != NAT_T_ENCAP_OMIT) {
		__u16 et = (encap_choice == NAT_T_ENCAP_NON_IKE)
				? UDP_ENCAP_ESPINUDP_NON_IKE
				: UDP_ENCAP_ESPINUDP;
		off = nat_t_append_encap(buf, off, sizeof(buf), et);
		if (!off)
			return -EIO;
	}

	off = nla_put_u8(buf, off, sizeof(buf), XFRMA_SA_DIR, sa_dir);
	if (!off)
		return -EIO;

	off = nla_put_u32(buf, off, sizeof(buf),
			  XFRMA_NAT_KEEPALIVE_INTERVAL, interval);
	if (!off)
		return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * Drive one full nat_keepalive setup->teardown cycle over one SA:
 * pick a (direction, encap-present, interval) triple, dispatch NEWSA
 * (accepted or rejected depending on the triple's coherence), then
 * DELSA on the same SPI so a successful install runs the teardown side
 * of xfrm_nat_keepalive_fini and a failing install has already walked
 * the construct-error cleanup path.  Consistent-triple iterations
 * (OUT + encap + interval>0) additionally short-race the worker
 * arming with the DELSA so the delete lands while the worker's per-net
 * accounting is still transient.
 */
void nat_keepalive_err_cycle(struct nl_ctx *ctx)
{
	__be32 spi;
	__u8 mode, sa_dir;
	__u32 interval;
	enum nat_t_encap_choice encap_choice;
	const struct nat_t_alg *auth, *crypt;
	int rc;

	mode  = (rand32() & 1U) ? XFRM_MODE_TUNNEL : XFRM_MODE_TRANSPORT;
	auth  = &nat_t_auth_algs[rnd_modulo_u32(nat_t_auth_algs_n)];
	crypt = &nat_t_crypt_algs[rnd_modulo_u32(nat_t_crypt_algs_n)];
	spi   = htonl((rand32() % XFRM_SPI_RANGE) + XFRM_SPI_MIN);

	/* Rotate every triple corner deliberately -- the point of this
	 * cycle is to exercise both the arming path and the two error
	 * shapes (IN + interval; no-encap + interval), not to bias
	 * toward one. */
	sa_dir       = (rand32() & 1U) ? XFRM_SA_DIR_OUT : XFRM_SA_DIR_IN;
	interval     = ONE_IN(3) ? 0U : RAND_ARRAY(nat_keepalive_intervals);
	encap_choice = ONE_IN(3) ? NAT_T_ENCAP_OMIT
				 : ((rand32() & 1U) ? NAT_T_ENCAP_NON_IKE
						    : NAT_T_ENCAP_ESPINUDP);

	rc = build_newsa_keepalive(ctx, spi, mode, encap_choice, sa_dir,
				   interval, auth, crypt);
	if (rc == 0)
		__atomic_add_fetch(&shm->stats.nat_t_churn.sa_added,
				   1, __ATOMIC_RELAXED);

	if (nat_t_build_delsa(ctx, spi) == 0)
		__atomic_add_fetch(&shm->stats.nat_t_churn.sa_deleted,
				   1, __ATOMIC_RELAXED);
}
