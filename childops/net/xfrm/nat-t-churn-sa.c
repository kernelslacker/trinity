/*
 * nat-t-churn-sa - SA attribute assemblers for the nat_t_churn
 * childop.  Carved out of childops/net/xfrm/nat-t-churn.c so the
 * netlink-attribute assembly code (selector + lifetime fills, auth /
 * crypt / encap / replay-ESN appenders, and the algorithm-rotation
 * constants they consume) compiles as its own TU alongside the
 * higher-level SA new/delete builders and the traffic drivers.
 *
 * Pure relocation: every function body and constant table is
 * byte-for-byte the same as the original.  The only linkage change is
 * widening the appenders / fill helpers / nat_t_pick_seq_hi and the algo
 * rotation tables from file-static to external so the SA new/delete
 * builders and the top-level dispatch in nat-t-churn.c can reach them
 * across the TU boundary.
 */

#include "nat-t-churn-internal.h"

const struct nat_t_alg nat_t_auth_algs[] = {
	{ "hmac(sha256)",	256,	128 },
	{ "hmac(sha384)",	384,	192 },
	{ "hmac(sha1)",		160,	96  },
	{ "xcbc(aes)",		128,	96  },
	{ "hmac(not-a-real-hash)", 256,	128 },
};

const struct nat_t_alg nat_t_crypt_algs[] = {
	{ "cbc(aes)",			128,	0 },
	{ "cbc(des3_ede)",		192,	0 },
	{ "rfc4106(gcm(aes))",		160,	0 },
	{ "cbc(not-a-real-cipher)",	128,	0 },
};

/* Replay window size rotation.  0 disables replay protection
 * entirely; 32 / 64 / 256 are the standard sizes the kernel handles
 * via the legacy bitmap or the XFRMA_REPLAY_ESN_VAL bmp[] tail. */
const __u8 nat_t_replay_windows[] = { 0, 32, 64, 64 /*XFRM_REPLAY_ESN_MAX is large; cap at 64 for the bmp_len sizing*/ };

/* seq_hi edge values exercised when XFRM_STATE_ESN is set. */
const __u32 nat_t_esn_seq_hi_edges[] = {
	0x00000000U,
	0x00000001U,
	0xfffffffeU,
	0xffffffffU,
};

/* Explicit table sizes so cross-TU callers can spin an index via
 * rnd_modulo_u32() without needing sizeof visibility on the extern
 * declarations.  Kept in lockstep with the arrays above by placement. */
const size_t nat_t_auth_algs_n = ARRAY_SIZE(nat_t_auth_algs);
const size_t nat_t_crypt_algs_n = ARRAY_SIZE(nat_t_crypt_algs);
const size_t nat_t_replay_windows_n = ARRAY_SIZE(nat_t_replay_windows);
const size_t nat_t_esn_seq_hi_edges_n = ARRAY_SIZE(nat_t_esn_seq_hi_edges);

void nat_t_fill_selector(struct xfrm_selector *sel)
{
	memset(sel, 0, sizeof(*sel));
	sel->saddr.a4    = NAT_T_SADDR_BE;
	sel->daddr.a4    = NAT_T_DADDR_BE;
	sel->family      = AF_INET;
	sel->prefixlen_s = 32;
	sel->prefixlen_d = 32;
	sel->proto       = IPPROTO_UDP;
}

void nat_t_fill_lifetime(struct xfrm_lifetime_cfg *lft)
{
	memset(lft, 0, sizeof(*lft));
	lft->soft_byte_limit   = (__u64)~0ULL;
	lft->hard_byte_limit   = (__u64)~0ULL;
	lft->soft_packet_limit = (__u64)~0ULL;
	lft->hard_packet_limit = (__u64)~0ULL;
}

/*
 * Append XFRMA_ALG_AUTH_TRUNC carrying a random key of the requested
 * size.  Returns the new offset, or 0 on buffer overflow.
 */
size_t nat_t_append_auth_trunc(unsigned char *buf, size_t off, size_t cap,
			 const struct nat_t_alg *a)
{
	unsigned char abuf[sizeof(struct xfrm_algo_auth) + 64];
	struct xfrm_algo_auth *au = (struct xfrm_algo_auth *)abuf;
	unsigned int kbytes = a->key_bits / 8;

	if (kbytes > 64)
		kbytes = 64;

	memset(abuf, 0, sizeof(abuf));
	strncpy(au->alg_name, a->name, sizeof(au->alg_name) - 1);
	au->alg_key_len   = a->key_bits;
	au->alg_trunc_len = a->trunc_bits;
	if (kbytes)
		generate_rand_bytes((unsigned char *)au->alg_key, kbytes);

	return nla_put(buf, off, cap, XFRMA_ALG_AUTH_TRUNC, abuf,
		       sizeof(*au) + kbytes);
}

size_t nat_t_append_crypt(unsigned char *buf, size_t off, size_t cap,
		    const struct nat_t_alg *a)
{
	unsigned char ebuf[sizeof(struct xfrm_algo) + 64];
	struct xfrm_algo *enc = (struct xfrm_algo *)ebuf;
	unsigned int kbytes = a->key_bits / 8;

	if (kbytes > 64)
		kbytes = 64;

	memset(ebuf, 0, sizeof(ebuf));
	strncpy(enc->alg_name, a->name, sizeof(enc->alg_name) - 1);
	enc->alg_key_len = a->key_bits;
	if (kbytes)
		generate_rand_bytes((unsigned char *)enc->alg_key, kbytes);

	return nla_put(buf, off, cap, XFRMA_ALG_CRYPT, ebuf,
		       sizeof(*enc) + kbytes);
}

size_t nat_t_append_encap(unsigned char *buf, size_t off, size_t cap,
		    __u16 encap_type)
{
	struct xfrm_encap_tmpl tmpl;

	memset(&tmpl, 0, sizeof(tmpl));
	tmpl.encap_type  = encap_type;
	tmpl.encap_sport = htons(NAT_T_ENCAP_PORT);
	tmpl.encap_dport = htons(NAT_T_ENCAP_PORT);
	tmpl.encap_oa.a4 = NAT_T_SADDR_BE;

	return nla_put(buf, off, cap, XFRMA_ENCAP, &tmpl, sizeof(tmpl));
}

/*
 * Append XFRMA_REPLAY_ESN_VAL carrying a freshly-rolled seq_hi.  The
 * bmp[] tail is sized from replay_window (in bits); a window of 32
 * needs a single __u32 word, 64 needs two, etc.  bmp_len is the word
 * count.  Returns the new offset, or 0 on buffer overflow.
 */
size_t nat_t_append_replay_esn(unsigned char *buf, size_t off, size_t cap,
			 __u32 replay_window, __u32 seq_hi)
{
	unsigned char rbuf[sizeof(struct xfrm_replay_state_esn) + 32];
	struct xfrm_replay_state_esn *esn =
		(struct xfrm_replay_state_esn *)rbuf;
	unsigned int words;

	if (replay_window == 0)
		replay_window = 32;
	words = (replay_window + 31U) / 32U;
	if (words > 8U)
		words = 8U;	/* 8 * 32 = 256 bits cap, fits in rbuf tail */

	memset(rbuf, 0, sizeof(rbuf));
	esn->bmp_len       = words;
	esn->oseq          = 0;
	esn->seq           = 0;
	esn->oseq_hi       = 0;
	esn->seq_hi        = seq_hi;
	esn->replay_window = replay_window;

	return nla_put(buf, off, cap, XFRMA_REPLAY_ESN_VAL, rbuf,
		       sizeof(*esn) + words * sizeof(__u32));
}

__u32 nat_t_pick_seq_hi(void)
{
	if ((rand32() & 1U) == 0)
		return rand32();
	return RAND_ARRAY(nat_t_esn_seq_hi_edges);
}
