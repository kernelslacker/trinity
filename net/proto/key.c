#include <sys/socket.h>
#include <stdbool.h>
#include <linux/pfkeyv2.h>
#include <linux/ipsec.h>
#include <string.h>
#include "net.h"
#include "random.h"
#include "rnd.h"

#define PFKEY_BUF_SZ	1024U

static void key_gen_sockaddr(__unused__ struct socket_triplet *triplet, struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr *sa;

	sa = zmalloc_tracked(sizeof(struct sockaddr));
	sa->sa_family = AF_KEY;

	*addr = sa;
	*addrlen = sizeof(struct sockaddr);
}

/*
 * PF_KEYv2 extension TLVs (rfc2367 §2.3) are padded to an 8-byte
 * boundary and every sadb_*_len field is expressed in 64-bit units.
 * pfkey_put_ext() stamps the standard sadb_ext header at buf+*off,
 * zeroes the padded body, and advances *off so callers can chain TLVs
 * without recomputing offsets.  Returns NULL if the buffer would
 * overflow, which lets the caller drop the optional extension instead
 * of corrupting an adjacent TLV.
 */
static __u16 pfkey_padlen8(__u16 len)
{
	return (__u16)((len + 7U) & ~7U);
}

static void *pfkey_put_ext(unsigned char *buf, size_t *off, __u16 ext_type,
			   __u16 inner_len)
{
	__u16 padded = pfkey_padlen8(inner_len);
	struct sadb_ext *e;

	if (*off + padded > PFKEY_BUF_SZ)
		return NULL;
	e = (struct sadb_ext *)(buf + *off);
	memset(e, 0, padded);
	e->sadb_ext_len  = (__u16)(padded / 8U);
	e->sadb_ext_type = ext_type;
	*off += padded;
	return e;
}

static void pfkey_fill_addr(struct sadb_address *a, bool v6)
{
	/* sadb_address is followed by an embedded sockaddr (padded to 8B
	 * by pfkey_put_ext).  Fill a routable-looking but unbound family
	 * so the kernel walks parse_ipsecrequests / xfrm_state_lookup
	 * before bouncing on the missing SA. */
	void *sa_after = a + 1;

	a->sadb_address_proto     = IPPROTO_AH;
	a->sadb_address_prefixlen = (__u8)(v6 ? 128 : 32);

	if (v6) {
		struct sockaddr_in6 *s6 = sa_after;

		s6->sin6_family = AF_INET6;
		s6->sin6_port   = htons((uint16_t)rnd_modulo_u32(0xffffU));
		generate_rand_bytes((unsigned char *)&s6->sin6_addr,
				    sizeof(s6->sin6_addr));
	} else {
		struct sockaddr_in *s4 = sa_after;

		s4->sin_family = AF_INET;
		s4->sin_port   = htons((uint16_t)rnd_modulo_u32(0xffffU));
		s4->sin_addr.s_addr = (__be32)rnd_u32();
	}
}

static void pfkey_append_addr(unsigned char *buf, size_t *off, __u16 ext_type)
{
	bool v6 = ONE_IN(3);
	size_t sa_sz = v6 ? sizeof(struct sockaddr_in6)
			  : sizeof(struct sockaddr_in);
	__u16 inner = (__u16)(sizeof(struct sadb_address) + sa_sz);
	struct sadb_address *a = pfkey_put_ext(buf, off, ext_type, inner);

	if (a == NULL)
		return;
	pfkey_fill_addr(a, v6);
}

static void pfkey_append_sa(unsigned char *buf, size_t *off)
{
	static const __u8 auths[] = {
		SADB_AALG_NONE, SADB_AALG_MD5HMAC, SADB_AALG_SHA1HMAC,
		SADB_X_AALG_SHA2_256HMAC, SADB_X_AALG_SHA2_512HMAC,
		SADB_X_AALG_AES_XCBC_MAC,
	};
	static const __u8 encs[] = {
		SADB_EALG_NONE, SADB_EALG_NULL,
		SADB_X_EALG_AESCBC, SADB_X_EALG_AESCTR,
		SADB_X_EALG_AES_GCM_ICV16, SADB_X_EALG_CAMELLIACBC,
	};
	static const __u8 states[] = {
		SADB_SASTATE_LARVAL, SADB_SASTATE_MATURE,
		SADB_SASTATE_DYING,  SADB_SASTATE_DEAD,
	};
	struct sadb_sa *sa = pfkey_put_ext(buf, off, SADB_EXT_SA,
					   sizeof(struct sadb_sa));

	if (sa == NULL)
		return;
	sa->sadb_sa_spi     = (__be32)rnd_u32();
	sa->sadb_sa_replay  = (__u8)rnd_modulo_u32(32);
	sa->sadb_sa_state   = RAND_ARRAY(states);
	sa->sadb_sa_auth    = RAND_ARRAY(auths);
	sa->sadb_sa_encrypt = RAND_ARRAY(encs);
	sa->sadb_sa_flags   = rnd_u32();
}

static void pfkey_append_lifetime(unsigned char *buf, size_t *off, __u16 et)
{
	struct sadb_lifetime *lt = pfkey_put_ext(buf, off, et,
						 sizeof(struct sadb_lifetime));

	if (lt == NULL)
		return;
	lt->sadb_lifetime_allocations = rnd_u32();
	lt->sadb_lifetime_bytes       = (__u64)rnd_u32() << 10;
	lt->sadb_lifetime_addtime     = rnd_u32() & 0xffffU;
	lt->sadb_lifetime_usetime     = rnd_u32() & 0xffffU;
}

static void pfkey_append_key(unsigned char *buf, size_t *off, __u16 et)
{
	/* Coherent key sizes spanning HMAC-MD5 through AES-256-GCM /
	 * SHA-512.  Trailing material is padded to the 8-byte ext
	 * boundary by pfkey_put_ext via the inner-length round-up. */
	static const __u16 bits_table[] = {
		64, 128, 160, 192, 256, 384, 512,
	};
	__u16 bits = bits_table[rnd_modulo_u32(ARRAY_SIZE(bits_table))];
	__u16 key_bytes = (__u16)((bits + 7U) / 8U);
	__u16 inner = (__u16)(sizeof(struct sadb_key) + key_bytes);
	struct sadb_key *k = pfkey_put_ext(buf, off, et, inner);

	if (k == NULL)
		return;
	k->sadb_key_bits = bits;
	generate_rand_bytes((unsigned char *)(k + 1), key_bytes);
}

static void pfkey_append_spirange(unsigned char *buf, size_t *off)
{
	struct sadb_spirange *sr = pfkey_put_ext(buf, off, SADB_EXT_SPIRANGE,
						 sizeof(struct sadb_spirange));
	__u32 a, b;

	if (sr == NULL)
		return;
	a = rnd_u32();
	b = rnd_u32();
	sr->sadb_spirange_min = a < b ? a : b;
	sr->sadb_spirange_max = a < b ? b : a;
}

static void pfkey_append_x_sa2(unsigned char *buf, size_t *off)
{
	static const __u8 modes[] = {
		IPSEC_MODE_ANY, IPSEC_MODE_TRANSPORT,
		IPSEC_MODE_TUNNEL, IPSEC_MODE_BEET,
	};
	struct sadb_x_sa2 *s2 = pfkey_put_ext(buf, off, SADB_X_EXT_SA2,
					      sizeof(struct sadb_x_sa2));

	if (s2 == NULL)
		return;
	s2->sadb_x_sa2_mode     = RAND_ARRAY(modes);
	s2->sadb_x_sa2_sequence = rnd_u32();
	s2->sadb_x_sa2_reqid    = rnd_u32();
}

static void pfkey_append_x_policy(unsigned char *buf, size_t *off)
{
	/* Bare policy header (no trailing ipsecrequests).  Handlers that
	 * require the request tail bail in parse_ipsecrequests, but the
	 * TLV walker has already chewed through the rest of the chain. */
	static const __u16 types[] = {
		IPSEC_POLICY_DISCARD, IPSEC_POLICY_NONE, IPSEC_POLICY_IPSEC,
		IPSEC_POLICY_ENTRUST, IPSEC_POLICY_BYPASS,
	};
	static const __u8 dirs[] = {
		IPSEC_DIR_INBOUND, IPSEC_DIR_OUTBOUND, IPSEC_DIR_FWD,
	};
	struct sadb_x_policy *p = pfkey_put_ext(buf, off, SADB_X_EXT_POLICY,
						sizeof(struct sadb_x_policy));

	if (p == NULL)
		return;
	p->sadb_x_policy_type     = RAND_ARRAY(types);
	p->sadb_x_policy_dir      = RAND_ARRAY(dirs);
	p->sadb_x_policy_id       = rnd_u32();
	p->sadb_x_policy_priority = rnd_u32();
}

static void pfkey_append_nat_t_type(unsigned char *buf, size_t *off)
{
	struct sadb_x_nat_t_type *t =
		pfkey_put_ext(buf, off, SADB_X_EXT_NAT_T_TYPE,
			      sizeof(struct sadb_x_nat_t_type));

	if (t == NULL)
		return;
	t->sadb_x_nat_t_type_type = (__u8)rnd_modulo_u32(4);
}

static void pfkey_append_nat_t_port(unsigned char *buf, size_t *off, __u16 et)
{
	struct sadb_x_nat_t_port *p =
		pfkey_put_ext(buf, off, et,
			      sizeof(struct sadb_x_nat_t_port));

	if (p == NULL)
		return;
	p->sadb_x_nat_t_port_port = htons((uint16_t)rnd_modulo_u32(0xffffU));
}

static void key_gen_msg(__unused__ struct socket_triplet *triplet, void **buf, size_t *len)
{
	static const __u8 types[] = {
		SADB_GETSPI, SADB_UPDATE, SADB_ADD, SADB_DELETE,
		SADB_GET, SADB_REGISTER, SADB_FLUSH, SADB_DUMP,
		SADB_X_PROMISC, SADB_X_SPDADD, SADB_X_SPDFLUSH,
	};
	static const __u8 satypes[] = {
		SADB_SATYPE_AH, SADB_SATYPE_ESP, SADB_X_SATYPE_IPCOMP,
	};
	unsigned char *msgbuf = zmalloc(PFKEY_BUF_SZ);
	struct sadb_msg *msg = (struct sadb_msg *)msgbuf;
	__u8 type = RAND_ARRAY(types);
	size_t off = sizeof(struct sadb_msg);

	msg->sadb_msg_version = PF_KEY_V2;
	msg->sadb_msg_type    = type;
	msg->sadb_msg_satype  = RAND_ARRAY(satypes);
	msg->sadb_msg_seq     = rnd_u32();
	msg->sadb_msg_pid     = 0;

	/* Type-driven extension TLV chains.  Each arm emits the baseline
	 * extensions the kernel-side message validator (pfkey_add /
	 * pfkey_get / pfkey_spdadd in net/key/af_key.c) actually expects,
	 * then opportunistically tacks on optional TLVs (lifetimes,
	 * NAT-T, x_sa2) so the grammar exercises both the happy path and
	 * the ragged-tail TLV walker.  Unknown / disallowed combinations
	 * are intentional — that's where the parser does interesting
	 * work before rejecting. */
	switch (type) {
	case SADB_ADD:
	case SADB_UPDATE:
		pfkey_append_sa(msgbuf, &off);
		pfkey_append_addr(msgbuf, &off, SADB_EXT_ADDRESS_SRC);
		pfkey_append_addr(msgbuf, &off, SADB_EXT_ADDRESS_DST);
		pfkey_append_key(msgbuf, &off, SADB_EXT_KEY_AUTH);
		if (ONE_IN(2))
			pfkey_append_key(msgbuf, &off, SADB_EXT_KEY_ENCRYPT);
		if (ONE_IN(2))
			pfkey_append_lifetime(msgbuf, &off, SADB_EXT_LIFETIME_HARD);
		if (ONE_IN(2))
			pfkey_append_lifetime(msgbuf, &off, SADB_EXT_LIFETIME_SOFT);
		if (ONE_IN(3))
			pfkey_append_x_sa2(msgbuf, &off);
		if (ONE_IN(4))
			pfkey_append_nat_t_type(msgbuf, &off);
		if (ONE_IN(4))
			pfkey_append_nat_t_port(msgbuf, &off, SADB_X_EXT_NAT_T_SPORT);
		if (ONE_IN(4))
			pfkey_append_nat_t_port(msgbuf, &off, SADB_X_EXT_NAT_T_DPORT);
		break;
	case SADB_GET:
	case SADB_DELETE:
		pfkey_append_sa(msgbuf, &off);
		pfkey_append_addr(msgbuf, &off, SADB_EXT_ADDRESS_SRC);
		pfkey_append_addr(msgbuf, &off, SADB_EXT_ADDRESS_DST);
		break;
	case SADB_GETSPI:
		pfkey_append_addr(msgbuf, &off, SADB_EXT_ADDRESS_SRC);
		pfkey_append_addr(msgbuf, &off, SADB_EXT_ADDRESS_DST);
		pfkey_append_spirange(msgbuf, &off);
		if (ONE_IN(3))
			pfkey_append_x_sa2(msgbuf, &off);
		break;
	case SADB_X_SPDADD:
		pfkey_append_x_policy(msgbuf, &off);
		pfkey_append_addr(msgbuf, &off, SADB_EXT_ADDRESS_SRC);
		pfkey_append_addr(msgbuf, &off, SADB_EXT_ADDRESS_DST);
		if (ONE_IN(2))
			pfkey_append_lifetime(msgbuf, &off, SADB_EXT_LIFETIME_HARD);
		break;
	default:
		/* SADB_REGISTER, SADB_FLUSH, SADB_DUMP, SADB_X_PROMISC,
		 * SADB_X_SPDFLUSH — bare sadb_msg, no extensions. */
		break;
	}

	msg->sadb_msg_len = (__u16)(off / 8U);

	*buf = msgbuf;
	*len = off;
}

static struct socket_triplet key_triplets[] = {
	{ .family = PF_KEY, .protocol = PF_KEY_V2, .type = SOCK_RAW },
};

const struct netproto proto_key = {
	.name = "key",
	.gen_sockaddr = key_gen_sockaddr,
	.gen_msg = key_gen_msg,
	.valid_triplets = key_triplets,
	.nr_triplets = ARRAY_SIZE(key_triplets),
};
