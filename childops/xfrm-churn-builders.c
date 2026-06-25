/*
 * xfrm-churn-builders - netlink message builders for the xfrm_churn
 * childop.  Carved out of childops/xfrm-churn.c so the heavy
 * message-assembly code (build_sa_msg / build_sa_id_msg /
 * build_newpolicy / build_delpolicy / build_allocspi and their
 * attribute / selector / lifetime helpers) compiles as its own TU
 * in parallel with the rest of the module.
 *
 * Pure relocation: every function body is byte-for-byte the same as
 * the original.  The only linkage change is widening file-static
 * functions that the xfrm-churn.c phase drivers now reach across the
 * TU boundary; append_algo_attrs() keeps file-static linkage because
 * it has no cross-TU callers.
 *
 * All entry points consume the shared types / constants / UAPI shims
 * declared in childops/xfrm-churn-internal.h; nothing here touches
 * shm or per-child latch state.
 */

#include "xfrm-churn-internal.h"

/* Build the SA selector matching 127.0.0.1 -> 127.0.0.2 UDP, both
 * sides /32.  Same shape used for the policy selector so the SPD
 * lookup at output time finds our SA cleanly. */
void xfrm_churn_fill_selector(struct xfrm_selector *sel, __u8 proto)
{
	memset(sel, 0, sizeof(*sel));
	sel->saddr.a4    = XFRM_SADDR_BE;
	sel->daddr.a4    = XFRM_DADDR_BE;
	sel->family      = AF_INET;
	sel->prefixlen_s = 32;
	sel->prefixlen_d = 32;
	sel->proto       = proto;	/* 0 = any */
}

void xfrm_churn_fill_lifetime(struct xfrm_lifetime_cfg *lft)
{
	memset(lft, 0, sizeof(*lft));
	lft->soft_byte_limit            = (__u64)~0ULL;
	lft->hard_byte_limit            = (__u64)~0ULL;
	lft->soft_packet_limit          = (__u64)~0ULL;
	lft->hard_packet_limit          = (__u64)~0ULL;
	lft->soft_add_expires_seconds   = 0;
	lft->hard_add_expires_seconds   = 0;
	lft->soft_use_expires_seconds   = 0;
	lft->hard_use_expires_seconds   = 0;
}

/*
 * Append the algorithm key material attribute(s) appropriate for the
 * given algo definition.  AEAD goes in XFRMA_ALG_AEAD with a single
 * combined key + ICV length.  Classic ESP CBC pairs XFRMA_ALG_CRYPT
 * (enc) + XFRMA_ALG_AUTH (HMAC).  ESP-NULL is the same shape with a
 * zero-length cipher_null key.  AH-only carries XFRMA_ALG_AUTH.
 * IPCOMP carries XFRMA_ALG_COMP.  Returns the new offset, or 0 on
 * buffer overflow (caller must check).
 */
static size_t append_algo_attrs(unsigned char *buf, size_t off, size_t cap,
				const struct xfrm_algo_def *def)
{
	unsigned char keymat[64];
	unsigned int enc_key_bytes  = def->enc_key_bits / 8;
	unsigned int auth_key_bytes = def->auth_key_bits / 8;

	if (def->kind == XFRM_ALG_AEAD) {
		struct xfrm_algo_aead *aead;
		unsigned char abuf[sizeof(*aead) + sizeof(keymat)];

		if (enc_key_bytes > sizeof(keymat))
			enc_key_bytes = sizeof(keymat);

		generate_rand_bytes(keymat, enc_key_bytes);

		memset(abuf, 0, sizeof(abuf));
		aead = (struct xfrm_algo_aead *)abuf;
		strncpy(aead->alg_name, def->enc_name,
			sizeof(aead->alg_name) - 1);
		aead->alg_key_len = def->enc_key_bits;
		aead->alg_icv_len = def->aead_icv_bits;
		memcpy(aead->alg_key, keymat, enc_key_bytes);

		return nla_put(buf, off, cap, XFRMA_ALG_AEAD, abuf,
			       sizeof(*aead) + enc_key_bytes);
	}

	if (def->enc_name) {
		struct xfrm_algo *enc;
		unsigned char ebuf[sizeof(*enc) + sizeof(keymat)];

		if (enc_key_bytes > sizeof(keymat))
			enc_key_bytes = sizeof(keymat);

		if (enc_key_bytes)
			generate_rand_bytes(keymat, enc_key_bytes);

		memset(ebuf, 0, sizeof(ebuf));
		enc = (struct xfrm_algo *)ebuf;
		strncpy(enc->alg_name, def->enc_name,
			sizeof(enc->alg_name) - 1);
		enc->alg_key_len = def->enc_key_bits;
		if (enc_key_bytes)
			memcpy(enc->alg_key, keymat, enc_key_bytes);

		off = nla_put(buf, off, cap,
			      def->kind == XFRM_ALG_COMP ? XFRMA_ALG_COMP
							 : XFRMA_ALG_CRYPT,
			      ebuf, sizeof(*enc) + enc_key_bytes);
		if (!off)
			return 0;
	}

	if (def->auth_name) {
		struct xfrm_algo_auth *au;
		unsigned char abuf[sizeof(*au) + sizeof(keymat)];

		if (auth_key_bytes > sizeof(keymat))
			auth_key_bytes = sizeof(keymat);

		if (auth_key_bytes)
			generate_rand_bytes(keymat, auth_key_bytes);

		memset(abuf, 0, sizeof(abuf));
		au = (struct xfrm_algo_auth *)abuf;
		strncpy(au->alg_name, def->auth_name,
			sizeof(au->alg_name) - 1);
		au->alg_key_len   = def->auth_key_bits;
		au->alg_trunc_len = def->auth_trunc_bits;
		if (auth_key_bytes)
			memcpy(au->alg_key, keymat, auth_key_bytes);

		off = nla_put(buf, off, cap, XFRMA_ALG_AUTH, abuf,
			      sizeof(*au) + auth_key_bytes);
		if (!off)
			return 0;
	}

	return off;
}

/*
 * Build and dispatch a NEWSA or UPDSA netlink request: a
 * fully-populated xfrm_usersa_info plus one or more XFRMA_ALG_*
 * attributes appropriate for the algo, plus XFRMA_SA_DIR.  The SA
 * shell, attribute set, and ack/wait loop are identical across both
 * opcodes; only the netlink opcode itself differs.
 *
 * NEWSA path: fresh install.  reqid + spi + proto are captured by
 * the caller for the matching policy template and the later UPDSA /
 * DELSA.
 *
 * UPDSA path: rebuild the same SA shell with a fresh random key (and
 * same SPI by default).  Drives the UPDSA-vs-encrypt rekey race —
 * the in-flight encrypt may still be holding the old key.
 */
int build_sa_msg(struct nl_ctx *ctx, __u16 msg_type,
		 const struct xfrm_algo_def *def,
		 __u32 reqid, __be32 spi, __u8 mode, __u32 seq)
{
	unsigned char buf[XFRM_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct xfrm_usersa_info *sa;
	size_t off;
	__u8 sa_dir;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = msg_type;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	sa_dir = ONE_IN(2) ? XFRM_SA_DIR_OUT : XFRM_SA_DIR_IN;

	sa = (struct xfrm_usersa_info *)NLMSG_DATA(nlh);
	xfrm_churn_fill_selector(&sa->sel, IPPROTO_UDP);
	sa->id.daddr.a4    = XFRM_DADDR_BE;
	sa->id.spi         = spi;
	sa->id.proto       = def->proto;
	sa->saddr.a4       = XFRM_SADDR_BE;
	xfrm_churn_fill_lifetime(&sa->lft);
	sa->seq            = seq;	/* link onto byseq when seq != 0; preserves linkage across rekey */
	sa->reqid          = reqid;
	sa->family         = AF_INET;
	sa->mode           = mode;
	/* Kernel rejects OUT SAs with a nonzero replay_window once
	 * XFRMA_SA_DIR is present — keep the two coupled so the
	 * validation actually runs. */
	sa->replay_window  = (sa_dir == XFRM_SA_DIR_OUT) ? 0 : 32;
	sa->flags          = 0;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*sa));

	off = append_algo_attrs(buf, off, sizeof(buf), def);
	if (!off)
		return -EIO;

	off = nla_put_u8(buf, off, sizeof(buf), XFRMA_SA_DIR, sa_dir);
	if (!off)
		return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv_retry(ctx, buf, off);
}

/*
 * Build and dispatch a netlink request keyed on xfrm_usersa_id
 * (daddr + spi + proto + family).  Shared between DELSA and GETSA —
 * both carry the same payload, only the netlink opcode differs.
 * v4-only; install_ah_esn_async_sa keeps its own inline DELSA for v6.
 *
 * DELSA path: races the in-flight encrypt still draining from the
 * post-UPDSA sendto burst; the SA refcount UAF window opens here.
 *
 * GETSA path: drives the __xfrm_state_lookup byspi walker on the
 * netlink-visible read path — one of the lookup-side readers upstream
 * commit 14acf9652e56 calls out (KASAN tag "Read in
 * __xfrm_state_lookup").  Reply carries a full xfrm_usersa_info; we
 * don't parse it — the bug window is the kernel-side hash walk, not
 * the userland decode.
 */
int build_sa_id_msg(struct nl_ctx *ctx, __u16 msg_type,
		    __u8 proto, __be32 spi)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct xfrm_usersa_id *uid;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = msg_type;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	uid = (struct xfrm_usersa_id *)NLMSG_DATA(nlh);
	uid->daddr.a4 = XFRM_DADDR_BE;
	uid->spi      = spi;
	uid->family   = AF_INET;
	uid->proto    = proto;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*uid));
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * XFRM_MSG_NEWPOLICY OUT direction with XFRMA_TMPL pointing at the
 * SA we just installed.  Selector matches the inner UDP traffic so
 * the SPD lookup at xfrm_output time resolves to our SA bundle.
 */
int build_newpolicy(struct nl_ctx *ctx, const struct xfrm_algo_def *def,
		    __u32 reqid, __be32 spi, __u8 mode)
{
	unsigned char buf[XFRM_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct xfrm_userpolicy_info *pol;
	struct xfrm_user_tmpl tmpl;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = XFRM_MSG_NEWPOLICY;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	pol = (struct xfrm_userpolicy_info *)NLMSG_DATA(nlh);
	xfrm_churn_fill_selector(&pol->sel, IPPROTO_UDP);
	xfrm_churn_fill_lifetime(&pol->lft);
	pol->priority = 1024;
	pol->index    = 0;
	pol->dir      = XFRM_POLICY_OUT;
	pol->action   = XFRM_POLICY_ALLOW;
	pol->flags    = 0;
	pol->share    = XFRM_SHARE_ANY;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*pol));

	memset(&tmpl, 0, sizeof(tmpl));
	tmpl.id.daddr.a4 = XFRM_DADDR_BE;
	tmpl.id.spi      = spi;
	tmpl.id.proto    = def->proto;
	tmpl.family      = AF_INET;
	tmpl.saddr.a4    = XFRM_SADDR_BE;
	tmpl.reqid       = reqid;
	tmpl.mode        = mode;
	tmpl.share       = XFRM_SHARE_ANY;
	tmpl.optional    = 0;
	tmpl.aalgos      = (__u32)~0U;
	tmpl.ealgos      = (__u32)~0U;
	tmpl.calgos      = (__u32)~0U;

	off = nla_put(buf, off, sizeof(buf), XFRMA_TMPL, &tmpl, sizeof(tmpl));
	if (!off)
		return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv_retry(ctx, buf, off);
}

/*
 * XFRM_MSG_DELPOLICY OUT via xfrm_userpolicy_id.  Races the in-flight
 * skbs still draining from the post-UPDSA sendto burst.
 */
int build_delpolicy(struct nl_ctx *ctx)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct xfrm_userpolicy_id *pid;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = XFRM_MSG_DELPOLICY;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	pid = (struct xfrm_userpolicy_id *)NLMSG_DATA(nlh);
	xfrm_churn_fill_selector(&pid->sel, IPPROTO_UDP);
	pid->dir = XFRM_POLICY_OUT;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*pid));
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * Rotate sa->km.seq across edge values + a couple of random sizes.
 * The kernel only links an SA onto byseq when (x->km.seq != 0); the
 * lookup walker (__xfrm_find_acq_byseq) is reachable from
 * xfrm_alloc_userspi when the in-flight SA-acquire rotation happens
 * to share a saddr/seq tuple, and the byseq unhash path runs from
 * __xfrm_state_delete on every linked SA.  Rotating across {0, 1, 2,
 * a small random, a large random, U32_MAX} keeps zero in the mix
 * (skip-link control) while ensuring the byseq table is non-empty
 * across most invocations.  Returning the value lets the caller use
 * the same seq in any follow-up GETSA-by-seq request.
 */
__u32 pick_sa_seq(void)
{
	switch (rand32() % 6U) {
	case 0:  return 0U;
	case 1:  return 1U;
	case 2:  return 2U;
	case 3:  return (rand32() & 0xffU) + 1U;
	case 4:  return rand32();
	default: return ~0U;
	}
}

/*
 * XFRM_MSG_ALLOCSPI: ask the kernel to pick a fresh SPI for a
 * half-built SA carrying daddr + proto + reqid.  Walks
 * __xfrm_find_acq_byseq + xfrm_state_lookup_byspi while scanning the
 * SPI window, then inserts the resulting larval SA onto byspi — one
 * of two writers (alongside NEWSA) that hits the byspi insert side
 * upstream commit 14acf9652e56 fingerprints.  min/max bracket the
 * same [0x100, 0xffffff] range used elsewhere in this op.
 */
int build_allocspi(struct nl_ctx *ctx, const struct xfrm_algo_def *def,
		   __u32 reqid, __u8 mode, __u32 seq)
{
	unsigned char buf[XFRM_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct xfrm_userspi_info *spi_info;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = XFRM_MSG_ALLOCSPI;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	spi_info = (struct xfrm_userspi_info *)NLMSG_DATA(nlh);
	xfrm_churn_fill_selector(&spi_info->info.sel, IPPROTO_UDP);
	spi_info->info.id.daddr.a4 = XFRM_DADDR_BE;
	spi_info->info.id.spi      = 0;	/* kernel picks */
	spi_info->info.id.proto    = def->proto;
	spi_info->info.saddr.a4    = XFRM_SADDR_BE;
	xfrm_churn_fill_lifetime(&spi_info->info.lft);
	spi_info->info.seq    = seq;
	spi_info->info.reqid  = reqid;
	spi_info->info.family = AF_INET;
	spi_info->info.mode   = mode;
	spi_info->info.replay_window = 32;
	spi_info->info.flags  = 0;
	spi_info->min = XFRM_SPI_MIN;
	spi_info->max = XFRM_SPI_MIN + XFRM_SPI_RANGE - 1U;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*spi_info));
	nlh->nlmsg_len = (__u32)off;
	/* ALLOCSPI returns a longer reply than send_recv's 1KB rbuf can
	 * always carry; nl_send_recv treats a non-error reply as -EIO.
	 * That's still acceptable as a counter signal — the kernel-side
	 * walk has already happened by the time the reply is composed. */
	return nl_send_recv_retry(ctx, buf, off);
}
