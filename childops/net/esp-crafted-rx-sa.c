/*
 * esp-crafted-rx: inbound ESP SA install / delete.  Split out so the
 * netlink-XFRM message construction lives beside the DELSA teardown
 * and does not crowd the packet-emit dispatcher.  cipher_null +
 * digest_null keys keep any ciphertext accepted so the burst reaches
 * the inner-parse seam.
 */

#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "childops-netlink.h"

#include "childops/net/esp-crafted-rx-internal.h"

/*
 * Install an inbound ESP SA with cipher_null + digest_null so any
 * ciphertext survives ICV verify and decrypt.  reqid, spi and v6
 * are captured by the caller so the packet-emit loop can stamp
 * matching SPIs on the outer frames and later DELSA can look the
 * SA up.  Returns 0 on netlink-ack success, negated errno on
 * kernel rejection, -EIO on local encode failure.
 */
int install_null_esp_sa(struct nl_ctx *ctx, __be32 spi, __u32 reqid,
			bool v6)
{
	unsigned char buf[1024];
	unsigned char ebuf[sizeof(struct xfrm_algo)];
	unsigned char abuf[sizeof(struct xfrm_algo_auth)];
	struct nlmsghdr *nlh;
	struct xfrm_usersa_info *sa;
	struct xfrm_algo *enc;
	struct xfrm_algo_auth *au;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = XFRM_MSG_NEWSA;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	sa = (struct xfrm_usersa_info *)NLMSG_DATA(nlh);

	if (v6) {
		sa->sel.saddr.a6[3] = (__be32)__builtin_bswap32(1U);
		sa->sel.daddr.a6[3] = (__be32)__builtin_bswap32(1U);
		sa->sel.family      = AF_INET6;
		sa->sel.prefixlen_s = 128;
		sa->sel.prefixlen_d = 128;
		sa->id.daddr.a6[3]  = (__be32)__builtin_bswap32(1U);
		sa->saddr.a6[3]     = (__be32)__builtin_bswap32(1U);
		sa->family          = AF_INET6;
	} else {
		sa->sel.saddr.a4    = ESPRX_V4_SADDR_BE;
		sa->sel.daddr.a4    = ESPRX_V4_DADDR_BE;
		sa->sel.family      = AF_INET;
		sa->sel.prefixlen_s = 32;
		sa->sel.prefixlen_d = 32;
		sa->id.daddr.a4     = ESPRX_V4_DADDR_BE;
		sa->saddr.a4        = ESPRX_V4_SADDR_BE;
		sa->family          = AF_INET;
	}

	sa->id.spi        = spi;
	sa->id.proto      = IPPROTO_ESP;

	sa->lft.soft_byte_limit   = (__u64)~0ULL;
	sa->lft.hard_byte_limit   = (__u64)~0ULL;
	sa->lft.soft_packet_limit = (__u64)~0ULL;
	sa->lft.hard_packet_limit = (__u64)~0ULL;

	sa->reqid         = reqid;
	sa->mode          = XFRM_MODE_TRANSPORT;
	sa->replay_window = 32;
	sa->flags         = 0;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*sa));

	/* XFRMA_ALG_CRYPT: ecb(cipher_null), zero-length key.  Kernel
	 * accepts a bare header with no key bytes for the null cipher. */
	memset(ebuf, 0, sizeof(ebuf));
	enc = (struct xfrm_algo *)ebuf;
	strncpy(enc->alg_name, "ecb(cipher_null)", sizeof(enc->alg_name) - 1);
	enc->alg_key_len = 0;
	off = nla_put(buf, off, sizeof(buf), XFRMA_ALG_CRYPT, ebuf, sizeof(*enc));
	if (!off)
		return -EIO;

	/* XFRMA_ALG_AUTH: digest_null, zero-length key + zero trunc.  Any
	 * ciphertext will verify.  Paired with cipher_null the SA accepts
	 * arbitrary ESP payload and the inner-parse seam is reachable. */
	memset(abuf, 0, sizeof(abuf));
	au = (struct xfrm_algo_auth *)abuf;
	strncpy(au->alg_name, "digest_null", sizeof(au->alg_name) - 1);
	au->alg_key_len   = 0;
	au->alg_trunc_len = 0;
	off = nla_put(buf, off, sizeof(buf), XFRMA_ALG_AUTH, abuf, sizeof(*au));
	if (!off)
		return -EIO;

	off = nla_put_u8(buf, off, sizeof(buf), XFRMA_SA_DIR, XFRM_SA_DIR_IN);
	if (!off)
		return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * Tear the SA down on the way out so the SAD does not accumulate
 * across iterations.  Netns destruction on grandchild exit would reap
 * anything left behind, but an explicit DELSA moves the DELSA counter
 * and exercises xfrm_state_delete on the success path.  Failure is
 * benign -- the netns teardown will take care of it.
 */
int delete_esp_sa(struct nl_ctx *ctx, __be32 spi, bool v6)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct xfrm_usersa_id *uid;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = XFRM_MSG_DELSA;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	uid = (struct xfrm_usersa_id *)NLMSG_DATA(nlh);
	if (v6) {
		uid->daddr.a6[3] = (__be32)__builtin_bswap32(1U);
		uid->family      = AF_INET6;
	} else {
		uid->daddr.a4    = ESPRX_V4_DADDR_BE;
		uid->family      = AF_INET;
	}
	uid->spi   = spi;
	uid->proto = IPPROTO_ESP;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*uid));
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}
