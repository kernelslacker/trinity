/*
 * xfrm-churn-ah-esn - AH+ESN+async-hash sub-mode for the xfrm_churn
 * childop.  Carved out of childops/net/xfrm/xfrm-churn.c so the
 * install_ah_esn_async_sa driver and its async-friendly auth algo
 * rotation table compile as their own TU alongside the netlink
 * builders and inner-traffic drivers.
 *
 * Pure relocation: every function body is byte-for-byte the same as
 * the original.  install_ah_esn_async_sa widens from file-static to
 * external linkage so the xfrm-churn.c teardown phase can reach it
 * across the TU boundary; the ah_esn_async_algos[] table, the
 * per-child ns_unsupported_xfrm_ah_esn latch and the IPv6-loopback
 * constant stay file-static because they have no cross-TU callers.
 */

#include "xfrm-churn-internal.h"

/*
 * Async-friendly auth algorithm names cycled by install_ah_esn_async_sa.
 * "hmac(sha256-generic)" deliberately forces the synchronous software
 * fallback as a control; the others may resolve to an async backend
 * depending on which crypto driver the kernel allocator picks.
 * authenc(...) is included for its async-friendly combined-mode
 * lineage even though AH only consumes the auth half — the kernel
 * still walks the async-hash post-callback path during driver lookup.
 * Upstream commit ec54093e6a8f fixed a wrong-ICV-layout bug in that
 * post-callback when XFRM_STATE_ESN was set; the (AH, ESN, async-algo)
 * trifecta is what reaches it.
 */
struct ah_esn_async_alg {
	const char	*name;
	unsigned int	trunc_bits;
};

static const struct ah_esn_async_alg ah_esn_async_algos[] = {
	{ "hmac(sha256-generic)",            128 },
	{ "hmac(sha256)",                    128 },
	{ "authenc(hmac(sha256),cbc(aes))",  128 },
	{ "hmac(sha384)",                    192 },
	{ "hmac(sha512)",                    256 },
};

/* Latched on the first NEWSA failure that signals the kernel doesn't
 * have AH+ESN+the async-hash auth modules built — paid once per child. */
static bool ns_unsupported_xfrm_ah_esn;

/* IPv6 loopback (::1) — both ends of the v6 variant of the SA stay on lo. */
static const __be32 v6_loopback_be[4] = {
	0, 0, 0, (__be32)__builtin_bswap32(1U)
};

/*
 * Install an AH SA with XFRM_STATE_ESN + a replay-window attribute and
 * an async-friendly auth algorithm name, drive the inner UDP through
 * it (v4 only — the udp socket is AF_INET), then DELSA.  The trifecta
 * (AH, ESN, async-algo) is what walks the kernel codepath upstream
 * commit ec54093e6a8f patches: the async-hash post-callback's ICV
 * layout was wrong when ESN was set.  Routed via a separate sub-mode
 * because the existing xfrm_algos[] rotation doesn't combine all three
 * at once.
 */
void install_ah_esn_async_sa(struct nl_ctx *ctx, int udp,
			     struct childdata *child)
{
	unsigned char buf[XFRM_BUF_BYTES];
	unsigned char abuf[sizeof(struct xfrm_algo_auth) + 32];
	unsigned char ebuf[sizeof(struct xfrm_replay_state_esn) + sizeof(__u32)];
	unsigned char dbuf[256];
	struct nlmsghdr *nlh;
	struct xfrm_usersa_info *sa;
	struct xfrm_algo_auth *au;
	struct xfrm_replay_state_esn *esn;
	struct xfrm_usersa_id *uid;
	const struct ah_esn_async_alg *alg;
	struct timespec t0;
	__u32 reqid;
	__be32 spi;
	bool v6;
	size_t off;
	int rc;
	unsigned int sent;

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op latch slot.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the latch
	 * store entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (ns_unsupported_xfrm_ah_esn)
		return;

	__atomic_add_fetch(&shm->stats.xfrm_ah_esn.async_runs, 1,
			   __ATOMIC_RELAXED);

	alg   = &RAND_ARRAY(ah_esn_async_algos);
	reqid = (rand32() % XFRM_REQID_RANGE) + 1U;
	spi   = htonl((rand32() % XFRM_SPI_RANGE) + XFRM_SPI_MIN);
	v6    = ONE_IN(2);

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = XFRM_MSG_NEWSA;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	sa = (struct xfrm_usersa_info *)NLMSG_DATA(nlh);
	if (v6) {
		memcpy(sa->sel.saddr.a6, v6_loopback_be, sizeof(v6_loopback_be));
		memcpy(sa->sel.daddr.a6, v6_loopback_be, sizeof(v6_loopback_be));
		sa->sel.family      = AF_INET6;
		sa->sel.prefixlen_s = 128;
		sa->sel.prefixlen_d = 128;
		sa->sel.proto       = IPPROTO_UDP;
		memcpy(sa->id.daddr.a6, v6_loopback_be, sizeof(v6_loopback_be));
		memcpy(sa->saddr.a6,    v6_loopback_be, sizeof(v6_loopback_be));
		sa->family          = AF_INET6;
	} else {
		xfrm_churn_fill_selector(&sa->sel, IPPROTO_UDP);
		sa->id.daddr.a4 = XFRM_DADDR_BE;
		sa->saddr.a4    = XFRM_SADDR_BE;
		sa->family      = AF_INET;
	}
	sa->id.spi        = spi;
	sa->id.proto      = IPPROTO_AH;
	xfrm_churn_fill_lifetime(&sa->lft);
	sa->reqid         = reqid;
	sa->mode          = XFRM_MODE_TRANSPORT;
	sa->replay_window = 32;
	sa->flags         = XFRM_STATE_ESN;	/* the trifecta's middle leg */

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*sa));

	memset(abuf, 0, sizeof(abuf));
	au = (struct xfrm_algo_auth *)abuf;
	strncpy(au->alg_name, alg->name, sizeof(au->alg_name) - 1);
	au->alg_key_len   = 256;
	au->alg_trunc_len = alg->trunc_bits;
	generate_rand_bytes((unsigned char *)au->alg_key, 32);
	off = nla_put(buf, off, sizeof(buf), XFRMA_ALG_AUTH, abuf,
		      sizeof(*au) + 32);
	if (!off)
		return;

	memset(ebuf, 0, sizeof(ebuf));
	esn = (struct xfrm_replay_state_esn *)ebuf;
	esn->bmp_len       = 1;	/* 32 bits = one __u32 word */
	esn->replay_window = 32;
	off = nla_put(buf, off, sizeof(buf), XFRMA_REPLAY_ESN_VAL, ebuf,
		      sizeof(*esn) + sizeof(__u32));
	if (!off)
		return;

	nlh->nlmsg_len = (__u32)off;
	rc = nl_send_recv_retry(ctx, buf, off);
	if (rc != 0) {
		__atomic_add_fetch(&shm->stats.xfrm_ah_esn.setup_fail, 1,
				   __ATOMIC_RELAXED);
		if (rc == -EOPNOTSUPP || rc == -ENOPROTOOPT || rc == -ENOENT) {
			ns_unsupported_xfrm_ah_esn = true;
			if (valid_op)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_NS_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		return;
	}
	__atomic_add_fetch(&shm->stats.xfrm_ah_esn.setup_ok, 1,
			   __ATOMIC_RELAXED);

	/* Drive the inner UDP through the AH SA so the async-hash
	 * post-callback (the codepath ec54093e6a8f patches) actually
	 * gets walked.  AF_INET only — the udp fd is a v4 DGRAM; the
	 * v6 variant exercises the install + parser side and relies on
	 * netns teardown for cleanup of the data plane. */
	if (udp >= 0 && !v6) {
		(void)clock_gettime(CLOCK_MONOTONIC, &t0);
		sent = drive_inner_traffic(udp, XFRM_PACKET_FLOOR, &t0);
		if (sent)
			__atomic_add_fetch(&shm->stats.xfrm_churn.esp_sent,
					   sent, __ATOMIC_RELAXED);
	}

	/* DELSA racing the in-flight encrypt — the post-callback ICV
	 * write window the bug-class lives in.  Inline because the
	 * shared build_sa_id_msg() hardcodes AF_INET in xfrm_usersa_id
	 * and would miss a v6 SA on lookup. */
	memset(dbuf, 0, sizeof(dbuf));
	nlh = (struct nlmsghdr *)dbuf;
	nlh->nlmsg_type  = XFRM_MSG_DELSA;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	uid = (struct xfrm_usersa_id *)NLMSG_DATA(nlh);
	if (v6)
		memcpy(uid->daddr.a6, v6_loopback_be, sizeof(v6_loopback_be));
	else
		uid->daddr.a4 = XFRM_DADDR_BE;
	uid->spi    = spi;
	uid->family = v6 ? AF_INET6 : AF_INET;
	uid->proto  = IPPROTO_AH;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*uid));
	nlh->nlmsg_len = (__u32)off;
	if (nl_send_recv(ctx, dbuf, off) == 0)
		__atomic_add_fetch(&shm->stats.xfrm_ah_esn.delsa_races, 1,
				   __ATOMIC_RELAXED);
}
