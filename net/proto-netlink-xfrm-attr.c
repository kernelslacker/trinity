/*
 * proto-netlink-xfrm-attr.c -- attribute appenders, algorithm name
 * rotation tables, and address / selector / lifetime helpers for the
 * NETLINK_XFRM grammar.  The message builders in
 * proto-netlink-xfrm-emit.c reach these through the externs in
 * include/proto-netlink-xfrm-internal.h.
 */

#include <stdbool.h>
#include <string.h>

#include "compat.h"
#include "proto-netlink-xfrm-internal.h"
#include "random.h"

/*
 * Algorithm rotation tables.  Names include deliberately-mistyped
 * entries so the kernel-side request_module / crypto_alloc_*() failure
 * arms get coverage too -- a fuzzer that only ever submits well-formed
 * algorithm names never reaches the rejection paths.
 */
static const char * const auth_trunc_names[] = {
	"hmac(sha256)",
	"hmac(sha384)",
	"hmac(sha1)",
	"hmac(sha512)",
	"aes-xcbc-mac",
	"hmac(sha22)",			/* deliberately invalid -- exercises
					 * crypto_alloc_ahash() rejection arm */
};

static const char * const crypt_names[] = {
	"cbc(aes)",
	"cbc(des3_ede)",
	"ecb(cipher_null)",
	"rfc3686(ctr(aes))",
	"cbc(garbage)",			/* deliberately invalid */
};

static const char * const aead_names[] = {
	"rfc4106(gcm(aes))",
	"rfc4543(gcm(aes))",
	"rfc7539esp(chacha20,poly1305)",
	"rfc4309(ccm(aes))",
	"gcm(no-such-cipher)",		/* deliberately invalid */
};

static const char * const comp_names[] = {
	"deflate",
	"lzs",
	"lzjh",
	"frobnicate",			/* deliberately invalid */
};

/*
 * Append paired XFRMA_ALG_AUTH_TRUNC + XFRMA_ALG_CRYPT attributes.
 * AUTH_TRUNC is the modern variant of XFRMA_ALG_AUTH and carries the
 * trunc_len field separately -- the kernel parser treats them as
 * mutually exclusive but interesting parser arms exist on either path.
 */
size_t append_auth_trunc(unsigned char *buf, size_t off, size_t cap)
{
	struct xfrm_algo_auth *au;
	unsigned char abuf[sizeof(*au) + 64];
	const char *name = RAND_ARRAY(auth_trunc_names);
	unsigned int key_bits = 128 + ((rand32() & 3) * 64);	/* 128/192/256/320 */
	unsigned int key_bytes = key_bits / 8;

	if (key_bytes > 64)
		key_bytes = 64;

	memset(abuf, 0, sizeof(abuf));
	au = (struct xfrm_algo_auth *)abuf;
	strncpy(au->alg_name, name, sizeof(au->alg_name) - 1);
	au->alg_key_len   = key_bits;
	/* Trunc length: rotate the common suite values plus a few edge
	 * cases (0 = invalid, key_bits + 8 = oversized, key_bits / 2 =
	 * mid-truncation).  Drives the trunc_len validation arm in
	 * xfrm_alg_auth_len() / esp_init_authenc(). */
	{
		static const unsigned int trunc_choices[] = {
			96, 128, 160, 192, 256,
			0,			/* invalid -- exercises rejection */
		};
		au->alg_trunc_len = RAND_ARRAY(trunc_choices);
		if ((rand32() & 7) == 0)
			au->alg_trunc_len = key_bits + 8;	/* oversized */
	}
	generate_rand_bytes((unsigned char *)au->alg_key, key_bytes);

	return xfrm_nla_put(buf, off, cap, XFRMA_ALG_AUTH_TRUNC,
			    abuf, sizeof(*au) + key_bytes);
}

size_t append_crypt(unsigned char *buf, size_t off, size_t cap)
{
	struct xfrm_algo *enc;
	unsigned char ebuf[sizeof(*enc) + 64];
	const char *name = RAND_ARRAY(crypt_names);
	unsigned int key_bits = 128 + ((rand32() & 3) * 64);
	unsigned int key_bytes = key_bits / 8;

	if (key_bytes > 64)
		key_bytes = 64;

	memset(ebuf, 0, sizeof(ebuf));
	enc = (struct xfrm_algo *)ebuf;
	strncpy(enc->alg_name, name, sizeof(enc->alg_name) - 1);
	enc->alg_key_len = key_bits;
	generate_rand_bytes((unsigned char *)enc->alg_key, key_bytes);

	return xfrm_nla_put(buf, off, cap, XFRMA_ALG_CRYPT,
			    ebuf, sizeof(*enc) + key_bytes);
}

size_t append_aead(unsigned char *buf, size_t off, size_t cap)
{
	struct xfrm_algo_aead *aead;
	unsigned char abuf[sizeof(*aead) + 64];
	const char *name = RAND_ARRAY(aead_names);
	unsigned int key_bits = 160 + ((rand32() & 3) * 32);	/* 160/192/224/256 */
	unsigned int key_bytes = key_bits / 8;
	static const unsigned int icv_choices[] = { 64, 96, 128, 160, 192 };

	if (key_bytes > 64)
		key_bytes = 64;

	memset(abuf, 0, sizeof(abuf));
	aead = (struct xfrm_algo_aead *)abuf;
	strncpy(aead->alg_name, name, sizeof(aead->alg_name) - 1);
	aead->alg_key_len = key_bits;
	aead->alg_icv_len = RAND_ARRAY(icv_choices);
	generate_rand_bytes((unsigned char *)aead->alg_key, key_bytes);

	return xfrm_nla_put(buf, off, cap, XFRMA_ALG_AEAD,
			    abuf, sizeof(*aead) + key_bytes);
}

size_t append_comp(unsigned char *buf, size_t off, size_t cap)
{
	struct xfrm_algo *comp;
	unsigned char cbuf[sizeof(*comp) + 8];
	const char *name = RAND_ARRAY(comp_names);

	memset(cbuf, 0, sizeof(cbuf));
	comp = (struct xfrm_algo *)cbuf;
	strncpy(comp->alg_name, name, sizeof(comp->alg_name) - 1);
	comp->alg_key_len = 0;

	return xfrm_nla_put(buf, off, cap, XFRMA_ALG_COMP, cbuf, sizeof(*comp));
}

/*
 * UDP encapsulation: rotates ESPINUDP / ESPINUDP_NON_IKE / L2TP plus
 * the always-allowed "no encap" case (we just don't emit the attr).
 * Source / destination ports rotate across the IPsec-NAT well-known
 * ports (4500, 500) plus an ephemeral-range pick.
 */
size_t append_encap_maybe(unsigned char *buf, size_t off, size_t cap)
{
	struct xfrm_encap_tmpl encap;
	static const __u16 encap_types[] = {
		UDP_ENCAP_ESPINUDP,
		UDP_ENCAP_ESPINUDP_NON_IKE,
		UDP_ENCAP_L2TPINUDP,
	};
	static const __u16 ports[] = {
		4500, 500, 1701, 0,
	};

	if ((rand32() & 1) == 0)
		return off;	/* skip half the time -- "no encap" path */

	memset(&encap, 0, sizeof(encap));
	encap.encap_type  = RAND_ARRAY(encap_types);
	encap.encap_sport = htons(RAND_ARRAY(ports) +
				  (rand32() & 1U ? 1024 + (rand32() & 0xfff) : 0));
	encap.encap_dport = htons(RAND_ARRAY(ports));
	encap.encap_oa.a4 = (__be32)htonl(0x7f000001U);

	return xfrm_nla_put(buf, off, cap, XFRMA_ENCAP, &encap, sizeof(encap));
}

/*
 * Replay state: rotate between the legacy 32-bit XFRMA_REPLAY_VAL and
 * the extended-sequence-number XFRMA_REPLAY_ESN_VAL.  ESN deeply fuzzes
 * seq_hi / oseq_hi across the wrap edges (0, 1, 0xfffffffe, 0xffffffff,
 * random) and bmp_len / replay_window across edge values that drive
 * the bmp[] sizing arithmetic.
 */
size_t append_replay_maybe(unsigned char *buf, size_t off, size_t cap,
				  __u8 *flags_out)
{
	if ((rand32() & 3) == 0) {
		struct xfrm_replay_state legacy;

		memset(&legacy, 0, sizeof(legacy));
		legacy.oseq   = rand32();
		legacy.seq    = rand32();
		legacy.bitmap = rand32();
		return xfrm_nla_put(buf, off, cap, XFRMA_REPLAY_VAL,
				    &legacy, sizeof(legacy));
	}

	if ((rand32() & 1) == 0) {
		/* Extended sequence numbers -- mark XFRM_STATE_ESN on the
		 * containing SA so the kernel parser actually walks the
		 * ESN replay arm. */
		static const __u32 hi_choices[] = {
			0, 1, 0xFFFFFFFEU, 0xFFFFFFFFU,
		};
		static const __u32 win_choices[] = {
			32, 64, 128, 256, 1024, 4096,
		};
		struct xfrm_replay_state_esn *esn;
		unsigned char ebuf[sizeof(*esn) + 128 * sizeof(__u32)];
		__u32 win = RAND_ARRAY(win_choices);
		__u32 bmp_len = (win + 31) / 32;

		if (bmp_len > 128)
			bmp_len = 128;

		memset(ebuf, 0, sizeof(ebuf));
		esn = (struct xfrm_replay_state_esn *)ebuf;
		esn->bmp_len       = bmp_len;
		esn->oseq          = rand32();
		esn->seq           = rand32();
		esn->oseq_hi       = (rand32() & 1)
			? RAND_ARRAY(hi_choices)
			: rand32();
		esn->seq_hi        = (rand32() & 1)
			? RAND_ARRAY(hi_choices)
			: rand32();
		esn->replay_window = win;

		if (flags_out)
			*flags_out |= XFRM_STATE_ESN;

		return xfrm_nla_put(buf, off, cap, XFRMA_REPLAY_ESN_VAL,
				    ebuf,
				    sizeof(*esn) + bmp_len * sizeof(__u32));
	}

	return off;	/* leave replay state default */
}

/*
 * Independent XFRMA_SET_MARK / XFRMA_SET_MARK_MASK / XFRMA_IF_ID /
 * XFRMA_OFFLOAD_DEV / XFRMA_SA_EXTRA_FLAGS rotation.  Each rolls a
 * coin to decide whether to emit the attribute, and all five may
 * coexist on a single NEWSA so the parser walks combined-attribute
 * arms.
 */
size_t append_marks_and_if(unsigned char *buf, size_t off, size_t cap)
{
	if ((rand32() & 1) == 0) {
		__u32 mark = rand32();

		off = xfrm_nla_put(buf, off, cap, XFRMA_SET_MARK,
				   &mark, sizeof(mark));
		if (!off)
			return 0;
	}
	if ((rand32() & 1) == 0) {
		__u32 mask = rand32();

		off = xfrm_nla_put(buf, off, cap, XFRMA_SET_MARK_MASK,
				   &mask, sizeof(mask));
		if (!off)
			return 0;
	}
	if ((rand32() & 3) == 0) {
		__u32 if_id = (rand32() & 0xff) + 1;	/* nonzero, smallish */

		off = xfrm_nla_put(buf, off, cap, XFRMA_IF_ID,
				   &if_id, sizeof(if_id));
		if (!off)
			return 0;
	}
	if ((rand32() & 7) == 0) {
		struct xfrm_user_offload off_attr;

		memset(&off_attr, 0, sizeof(off_attr));
		off_attr.ifindex = (int)(rand32() & 0x7);
		off_attr.flags   = (__u8)(rand32() & 0x3);
		off = xfrm_nla_put(buf, off, cap, XFRMA_OFFLOAD_DEV,
				   &off_attr, sizeof(off_attr));
		if (!off)
			return 0;
	}
	if ((rand32() & 3) == 0) {
		__u32 extra = rand32() & 0x7;

		off = xfrm_nla_put(buf, off, cap, XFRMA_SA_EXTRA_FLAGS,
				   &extra, sizeof(extra));
		if (!off)
			return 0;
	}
	return off;
}

/*
 * Selector + family + addresses.  AF_INET / AF_INET6 chosen by the
 * caller; the AF_INET path uses 127.0.0.0/8 endpoints, AF_INET6 uses
 * ::1 -based endpoints; prefixlen rotates across boundary values
 * including the kernel-side range edges (0 / 32 / 33 for AF_INET, 0 /
 * 128 / 129 for AF_INET6) so the family-specific validation arms get
 * exercised.
 */
void fill_addresses(__u16 family, xfrm_address_t *saddr,
			   xfrm_address_t *daddr)
{
	memset(saddr, 0, sizeof(*saddr));
	memset(daddr, 0, sizeof(*daddr));

	if (family == AF_INET) {
		saddr->a4 = (__be32)htonl(0x7f000001U + (rand32() & 0xff));
		daddr->a4 = (__be32)htonl(0x7f000002U + (rand32() & 0xff));
	} else {
		/* fe80::1 / fe80::2 plus low-byte rotation */
		saddr->a6[0] = htonl(0xfe800000U);
		saddr->a6[3] = htonl(1U + (rand32() & 0xff));
		daddr->a6[0] = htonl(0xfe800000U);
		daddr->a6[3] = htonl(2U + (rand32() & 0xff));
	}
}

__u8 pick_prefixlen(__u16 family)
{
	if (family == AF_INET) {
		static const __u8 choices[] = { 0, 8, 16, 24, 32, 33 };

		return RAND_ARRAY(choices);
	} else {
		static const __u8 choices[] = { 0, 32, 64, 96, 128, 129 };

		return RAND_ARRAY(choices);
	}
}

__u8 pick_proto(void)
{
	static const __u8 choices[] = {
		0,			/* "any" */
		IPPROTO_UDP, IPPROTO_TCP, IPPROTO_ICMP, IPPROTO_ICMPV6,
	};

	return RAND_ARRAY(choices);
}

__u8 pick_mode(void)
{
	static const __u8 choices[] = {
		XFRM_MODE_TRANSPORT,
		XFRM_MODE_TUNNEL,
		XFRM_MODE_BEET,
		XFRM_MODE_ROUTEOPTIMIZATION,
		XFRM_MODE_IN_TRIGGER,
	};

	return RAND_ARRAY(choices);
}

__u8 pick_sa_proto(void)
{
	static const __u8 choices[] = {
		IPPROTO_ESP, IPPROTO_AH, IPPROTO_COMP,
	};

	return RAND_ARRAY(choices);
}

__u16 pick_family(void)
{
	return (rand32() & 1) ? AF_INET : AF_INET6;
}

void fill_selector(struct xfrm_selector *sel, __u16 family)
{
	memset(sel, 0, sizeof(*sel));
	fill_addresses(family, &sel->saddr, &sel->daddr);
	sel->family       = family;
	sel->prefixlen_s  = pick_prefixlen(family);
	sel->prefixlen_d  = pick_prefixlen(family);
	sel->proto        = pick_proto();
	if (sel->proto == IPPROTO_UDP || sel->proto == IPPROTO_TCP) {
		sel->sport      = htons((__u16)(rand32() & 0xffff));
		sel->sport_mask = htons((__u16)(rand32() & 0xffff));
		sel->dport      = htons((__u16)(rand32() & 0xffff));
		sel->dport_mask = htons((__u16)(rand32() & 0xffff));
	}
}

/*
 * Lifetime: rotate soft / hard byte and packet limits through
 * boundary values (0 = unlimited shorthand on some paths, 1, small,
 * large, ~0).  add_expires / use_expires rotate similarly so the
 * lifetime parser walks each comparison arm.
 */
void fill_lifetime(struct xfrm_lifetime_cfg *lft)
{
	static const __u64 byte_choices[] = {
		0, 1, 1024, 1U << 20, 1U << 30, ~0ULL,
	};
	static const __u64 pkt_choices[] = {
		0, 1, 64, 1024, 1U << 20, ~0ULL,
	};
	static const __u64 sec_choices[] = {
		0, 1, 60, 3600, 86400, ~0ULL,
	};

	lft->soft_byte_limit          = RAND_ARRAY(byte_choices);
	lft->hard_byte_limit          = RAND_ARRAY(byte_choices);
	lft->soft_packet_limit        = RAND_ARRAY(pkt_choices);
	lft->hard_packet_limit        = RAND_ARRAY(pkt_choices);
	lft->soft_add_expires_seconds = RAND_ARRAY(sec_choices);
	lft->hard_add_expires_seconds = RAND_ARRAY(sec_choices);
	lft->soft_use_expires_seconds = RAND_ARRAY(sec_choices);
	lft->hard_use_expires_seconds = RAND_ARRAY(sec_choices);
}
