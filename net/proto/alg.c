#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <linux/rtnetlink.h>
#include "arch.h"
#include "random.h"
#include "net.h"
#include "proto-alg-dict.h"
#include "rnd.h"
#include "sanitise.h"	/* get_random_key_serial */

#ifdef USE_IF_ALG
#include <linux/if_alg.h>

#include "kernel/crypto.h"
#include "kernel/if_alg.h"
#include "kernel/socket.h"
static const char *hashes[] = {
	"md4", "md5",
	"sha1", "sha224", "sha256", "sha384", "sha512",
	"sha3-224", "sha3-256", "sha3-384", "sha3-512",
	"hmac(md5)", "hmac(sha1)",
	"hmac(sha224)", "hmac(sha256)", "hmac(sha384)", "hmac(sha512)",
	"hmac(sha3-256)",
	"rmd160",
	"streebog256", "streebog512",
	"wp256", "wp384", "wp512",
	"blake2b-160", "blake2b-256", "blake2b-384", "blake2b-512",
	"crc32", "crc32c", "xxhash64",
	"digest_null",
	"cmac(aes)", "xcbc(aes)", "cbcmac(aes)",
	"sm3",
};

static const char *aead_algos[] = {
	"aegis128",
	"gcm(aes)",
	"gcm(sm4)",
	"ccm(aes)",
	"ccm(sm4)",
	"rfc4106(gcm(aes))",
	"rfc4106(gcm(sm4))",
	"rfc4309(ccm(aes))",
	"rfc4309(ccm(sm4))",
	"rfc4543(gcm(aes))",
	"rfc4543(gcm(sm4))",
	"rfc7539(chacha20,poly1305)",
	"rfc7539esp(chacha20,poly1305)",
	"authenc(hmac(sha1),cbc(aes))",
	"authenc(hmac(sha1),cbc(des3_ede))",
	"authenc(hmac(sha224),cbc(aes))",
	"authenc(hmac(sha256),cbc(aes))",
	"authenc(hmac(sha384),cbc(aes))",
	"authenc(hmac(sha512),cbc(aes))",
	"authencesn(hmac(sha1),cbc(aes))",
	"authencesn(hmac(sha1),cbc(des3_ede))",
	"authencesn(hmac(sha256),cbc(aes))",
	"authencesn(hmac(sha512),cbc(aes))",
	"krb5enc(hmac(sha1),cts(cbc(aes)))",
	"krb5enc(cmac(camellia),cts(cbc(camellia)))",
	"essiv(authenc(hmac(sha256),cbc(aes)),sha256)",
};

static const char *rng_algos[] = {
	"stdrng",
	"drbg_nopr_ctr_aes128",
	"drbg_nopr_ctr_aes192",
	"drbg_nopr_ctr_aes256",
	"drbg_nopr_hmac_sha256",
	"drbg_nopr_hmac_sha384",
	"drbg_nopr_hmac_sha512",
	"drbg_nopr_sha256",
	"drbg_nopr_sha384",
	"drbg_nopr_sha512",
	"drbg_pr_ctr_aes128",
	"drbg_pr_ctr_aes192",
	"drbg_pr_ctr_aes256",
	"drbg_pr_hmac_sha256",
	"drbg_pr_hmac_sha384",
	"drbg_pr_hmac_sha512",
	"drbg_pr_sha256",
	"drbg_pr_sha384",
	"drbg_pr_sha512",
	"jitterentropy_rng",
};

static const char *skcipher_algos[] = {
	"arc4",
	"cipher_null",
	"ecb(cipher_null)",
	"cbc(aes)",
	"cbc(anubis)",
	"cbc(aria)",
	"cbc(blowfish)",
	"cbc(camellia)",
	"cbc(cast5)",
	"cbc(cast6)",
	"cbc(des)",
	"cbc(des3_ede)",
	"cbc(seed)",
	"cbc(serpent)",
	"cbc(sm4)",
	"cbc(twofish)",
	"ecb(aes)",
	"ecb(anubis)",
	"ecb(arc4)",
	"ecb(aria)",
	"ecb(blowfish)",
	"ecb(camellia)",
	"ecb(cast5)",
	"ecb(cast6)",
	"ecb(des)",
	"ecb(des3_ede)",
	"ecb(seed)",
	"ecb(serpent)",
	"ecb(sm4)",
	"ecb(twofish)",
	"ctr(aes)",
	"ctr(aria)",
	"ctr(blowfish)",
	"ctr(camellia)",
	"ctr(cast5)",
	"ctr(cast6)",
	"ctr(des3_ede)",
	"ctr(serpent)",
	"ctr(sm4)",
	"ctr(twofish)",
	"xts(aes)",
	"xts(aria)",
	"xts(camellia)",
	"xts(serpent)",
	"xts(sm4)",
	"xts(twofish)",
	"lrw(aes)",
	"lrw(camellia)",
	"lrw(serpent)",
	"lrw(twofish)",
	"cts(cbc(aes))",
	"cts(cbc(camellia))",
	"cts(cbc(serpent))",
	"pcbc(aes)",
	"rfc3686(ctr(aes))",
	"essiv(cbc(aes),sha256)",
	"xctr(aes)",
	"hctr2(aes)",
	"hctr2(aria)",
	"hctr2(camellia)",
	"adiantum(xchacha12,aes)",
	"adiantum(xchacha20,aes)",
	"chacha20",
	"xchacha20",
	"xchacha12",
};

static const char *akcipher_algos[] = {
	"rsa",
	"pkcs1pad(rsa,sha224)",
	"pkcs1pad(rsa,sha256)",
	"pkcs1pad(rsa,sha384)",
	"pkcs1pad(rsa,sha512)",
};

static const char *kpp_algos[] = {
	"dh",
	"ecdh-nist-p192",
	"ecdh-nist-p256",
	"ecdh-nist-p384",
	"ffdhe2048",
	"ffdhe3072",
	"ffdhe4096",
	"ffdhe6144",
	"ffdhe8192",
};

static const char *sig_algos[] = {
	"ecdsa-nist-p192",
	"ecdsa-nist-p256",
	"ecdsa-nist-p384",
	"ecdsa-nist-p521",
	"ecrdsa",
	"mldsa44",
	"mldsa65",
	"mldsa87",
};

/*
 * Static-fallback accessor consumed by net/alg-dict.c.  The dict
 * merges these entries with whatever it parses from /proc/crypto, so
 * containers/locked-down envs with an empty /proc/crypto still get a
 * working algorithm list.  Keep these arrays in lockstep with upstream
 * crypto/ — see Q2.30 refresh against linux 7.1-rc1.
 */
void alg_static_fallback_get(enum alg_dict_type type,
			     const char *const **arr, unsigned int *count)
{
	switch (type) {
	case ALG_DICT_AEAD:
		*arr = aead_algos;	*count = ARRAY_SIZE(aead_algos);	break;
	case ALG_DICT_HASH:
		*arr = hashes;		*count = ARRAY_SIZE(hashes);		break;
	case ALG_DICT_RNG:
		*arr = rng_algos;	*count = ARRAY_SIZE(rng_algos);		break;
	case ALG_DICT_SKCIPHER:
		*arr = skcipher_algos;	*count = ARRAY_SIZE(skcipher_algos);	break;
	case ALG_DICT_AKCIPHER:
		*arr = akcipher_algos;	*count = ARRAY_SIZE(akcipher_algos);	break;
	case ALG_DICT_KPP:
		*arr = kpp_algos;	*count = ARRAY_SIZE(kpp_algos);		break;
	case ALG_DICT_SIG:
		*arr = sig_algos;	*count = ARRAY_SIZE(sig_algos);		break;
	default:
		*arr = NULL;		*count = 0;				break;
	}
}

static void alg_gen_sockaddr(__unused__ struct socket_triplet *triplet, struct sockaddr **addr, socklen_t *addrlen)
{
	static const struct {
		enum alg_dict_type type;
		const char *str;
	} types[] = {
		{ ALG_DICT_AEAD,	"aead"		},
		{ ALG_DICT_HASH,	"hash"		},
		{ ALG_DICT_RNG,		"rng"		},
		{ ALG_DICT_SKCIPHER,	"skcipher"	},
		{ ALG_DICT_AKCIPHER,	"akcipher"	},
		{ ALG_DICT_KPP,		"kpp"		},
		{ ALG_DICT_SIG,		"sig"		},
	};
	struct sockaddr_alg *alg;
	unsigned int idx;

	alg = zmalloc_tracked(sizeof(struct sockaddr_alg));

	alg->salg_family = PF_ALG;

	idx = rnd_modulo_u32(ARRAY_SIZE(types));
	pick_alg(types[idx].type, types[idx].str, alg);

	/* alg_bind() refuses any salg_feat or salg_mask bit but
	 * CRYPTO_ALG_KERN_DRIVER_ONLY with -EINVAL, before the algorithm
	 * lookup: one draw in eight keeps random words, for the refusal. */
	if (ONE_IN(8)) {
		alg->salg_feat = rand32();
		alg->salg_mask = rand32();
	} else {
		alg->salg_feat = RAND_BOOL() ? CRYPTO_ALG_KERN_DRIVER_ONLY : 0;
		alg->salg_mask = RAND_BOOL() ? CRYPTO_ALG_KERN_DRIVER_ONLY : 0;
	}

	*addr = (struct sockaddr *) alg;
	*addrlen = sizeof(struct sockaddr_alg);
}

#define ALG_SET_IV		2
#define ALG_SET_OP		3
#define ALG_SET_AEAD_ASSOCLEN	4
#define ALG_SET_AEAD_AUTHSIZE	5
#define ALG_SET_DRBG_ENTROPY	6

static const unsigned int alg_opts[] = {
	ALG_SET_KEY, ALG_SET_IV, ALG_SET_OP,
	ALG_SET_AEAD_ASSOCLEN, ALG_SET_AEAD_AUTHSIZE,
	ALG_SET_DRBG_ENTROPY,
	ALG_SET_KEY_BY_KEY_SERIAL,
};

static struct socket_triplet alg_triplet[] = {
	{ .family = PF_ALG, .protocol = 0, .type = SOCK_SEQPACKET },
};

/*
 * Boundary keylens for ALG_SET_KEY.  Mixes valid sizes (16/24/32/64 for
 * AES/Camellia/HMAC ranges), exact off-by-ones around common per-cipher
 * max-key declarations (16,32,64,256,1024), and oversize values: the
 * userspace buffer is one page, so any keylen > KEY_BUF_BYTES is a
 * deliberate over-claim.  alg_setkey() sock_kmalloc()s keylen bytes
 * before it copies, so a keylen past net.core.optmem_max (128 KiB by
 * default) fails ENOMEM there, the allocation bound the oversize values
 * probe, and a smaller one is copied in full, reading on past the
 * buffer into whatever is mapped after it.
 */
static const unsigned int alg_boundary_keylens[] = {
	0, 1, 7,
	15, 16, 17,			/* AES-128 boundary */
	23, 24, 25,			/* AES-192 boundary */
	31, 32, 33,			/* AES-256 / chacha20 boundary */
	47, 48,
	63, 64, 65,			/* common HMAC block size */
	127, 128, 129,
	255, 256, 257,			/* skcipher MAX_KEY_SIZE on many algs */
	1023, 1024, 1025,		/* per-alg upper declared */
	4095, 4096, 4097,		/* one-page edge */
	65535, 65536,
	0x10000000, 0x7fffffff, 0xffffffff,
};

/*
 * ALG_SET_AEAD_AUTHSIZE encodes the authsize in `optlen`; `optval` is
 * ignored.  Boundary set covers 0, the GCM/CCM legal sizes (4,8,12,13,
 * 14,15,16), off-by-ones, and unbounded values.
 */
static const unsigned int alg_boundary_authsizes[] = {
	0, 1, 2, 3, 4, 5, 7, 8, 9,
	11, 12, 13, 14, 15, 16, 17,
	24, 31, 32, 33,
	63, 64, 65,
	128, 256, 0xffff, 0x10000, 0x7fffffff, 0xffffffff,
};

/*
 * An authenc-family key (authenc, authencesn, essiv over authenc,
 * krb5enc): crypto_authenc_extractkeys() and its krb5enc twin take an
 * rtattr of type CRYPTO_AUTHENC_KEYA_PARAM whose payload is just the
 * big-endian cipher key length, then the authentication key and the
 * cipher key, so random bytes never set one.  The cipher key is 16, 24
 * or 32 bytes (AES and Camellia take each, 3DES 24) and the
 * authentication key 16 to 64 (an hmac takes any, a cmac its cipher's).
 * One key in eight claims more cipher key than follows, which the
 * parse refuses.  Returns the key's length, 0 if it does not fit.
 */
static unsigned int build_authenc_key(unsigned char *buf, unsigned int cap)
{
	static const unsigned int enclens[] = { 16, 24, 32 };
	static const unsigned int authlens[] = { 16, 20, 24, 32, 64 };
	struct rtattr rta = {
		.rta_len = RTA_LENGTH(sizeof(uint32_t)),
		.rta_type = CRYPTO_AUTHENC_KEYA_PARAM,
	};
	unsigned int enclen = RAND_ARRAY(enclens);
	unsigned int authlen = RAND_ARRAY(authlens);
	unsigned int len = rta.rta_len + authlen + enclen;
	uint32_t claim;

	if (len > cap)
		return 0;
	claim = htonl(ONE_IN(8) ? authlen + enclen + 1 : enclen);
	memcpy(buf, &rta, sizeof(rta));
	memcpy(buf + RTA_LENGTH(0), &claim, sizeof(claim));
	generate_rand_bytes(buf + rta.rta_len, authlen + enclen);
	return len;
}

static void alg_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	unsigned int len, fill;

	so->level = SOL_ALG;
	so->optname = RAND_ARRAY(alg_opts);

	switch (so->optname) {
	case ALG_SET_KEY:
		/*
		 * The builder cannot see what the socket is bound to, so one
		 * key in four is the blob an authenc-family transform takes.
		 * Otherwise pick a keylen from the boundary table.  Fill is
		 * clamped to the caller-provided page-sized buffer; optlen
		 * may deliberately over-claim (see alg_boundary_keylens[]).
		 */
		if (ONE_IN(4)) {
			len = build_authenc_key((unsigned char *) so->optval,
						page_size);
			if (len != 0) {
				so->optlen = len;
				break;
			}
		}
		len = alg_boundary_keylens[
			rnd_modulo_u32(ARRAY_SIZE(alg_boundary_keylens))];
		fill = len < page_size ? len : page_size;
		generate_rand_bytes((unsigned char *) so->optval, fill);
		so->optlen = len;
		break;

	case ALG_SET_AEAD_AUTHSIZE:
		/* The authsize is encoded in optlen; the kernel ignores optval. */
		so->optlen = alg_boundary_authsizes[
			rnd_modulo_u32(ARRAY_SIZE(alg_boundary_authsizes))];
		break;

	case ALG_SET_DRBG_ENTROPY:
		len = rnd_modulo_u32(512) + 1;
		fill = len < page_size ? len : page_size;
		generate_rand_bytes((unsigned char *) so->optval, fill);
		so->optlen = len;
		break;

	case ALG_SET_KEY_BY_KEY_SERIAL:
		/* alg_setkey_by_key_serial() looks the serial up as a key,
		 * and the zeroed optval's 0 names none. */
		*(int32_t *) so->optval = get_random_key_serial();
		so->optlen = sizeof(int32_t);
		break;

	default:
		/*
		 * ALG_SET_IV / ALG_SET_OP / ALG_SET_AEAD_ASSOCLEN are sendmsg
		 * cmsg controls, not setsockopt optnames — the kernel rejects
		 * them here with -ENOPROTOOPT regardless of the payload, so
		 * leave the stub-sized optlen in place.
		 */
		so->optlen = sizeof(unsigned int);
		break;
	}
}

/*
 * Set up the AF_ALG lifecycle on fd:
 * 1. bind() with a random algorithm type and name
 * 2. setsockopt(ALG_SET_KEY) to set a key on the parent fd
 * 3. accept() to get a child fd for crypto operations
 * 4. Close the child fd — we just want to exercise the kernel path
 */
#define KEY_BUF_BYTES 4096

static void alg_socket_setup(int fd)
{
	static const struct {
		enum alg_dict_type type;
		const char *str;
	} setup_types[] = {
		{ ALG_DICT_HASH,	"hash"		},
		{ ALG_DICT_SKCIPHER,	"skcipher"	},
		{ ALG_DICT_AEAD,	"aead"		},
		{ ALG_DICT_RNG,		"rng"		},
	};
	struct sockaddr_alg sa;
	unsigned char key[KEY_BUF_BYTES];
	int child_fd;
	unsigned int keylen, idx, fill;

	memset(&sa, 0, sizeof(sa));
	sa.salg_family = AF_ALG;

	idx = rnd_modulo_u32(ARRAY_SIZE(setup_types));
	pick_alg(setup_types[idx].type, setup_types[idx].str, &sa);

	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) == -1)
		return;

	/*
	 * An authenc-family transform, named here, takes its key as a
	 * blob seven times in eight.  Otherwise pick a keylen: keep the
	 * existing valid-key path (16..47) the majority of the time so the
	 * lifecycle coverage doesn't regress; the remaining slice rotates
	 * through alg_boundary_keylens[] to stress the per-alg setkey
	 * validators and the over-claim path.
	 */
	keylen = 0;
	if ((strstr((const char *) sa.salg_name, "authenc") != NULL ||
	     strstr((const char *) sa.salg_name, "krb5enc") != NULL) &&
	    !ONE_IN(8))
		keylen = build_authenc_key(key, sizeof(key));
	if (keylen == 0) {
		if (rnd_modulo_u32(10) < 7) {
			keylen = rnd_modulo_u32(32) + 16;	/* 16..47 valid */
		} else {
			keylen = alg_boundary_keylens[
				rnd_modulo_u32(ARRAY_SIZE(alg_boundary_keylens))];
		}
		fill = keylen < sizeof(key) ? keylen : sizeof(key);
		generate_rand_bytes(key, fill);
	}
	(void) setsockopt(fd, SOL_ALG, ALG_SET_KEY, key, keylen);

	/*
	 * AEAD authsize boundary: ALG_SET_AEAD_AUTHSIZE reads the value
	 * from optlen, optval is unused.  Only fire on AEAD sockets, and
	 * only sometimes — most algorithms accept a small fixed set, so
	 * boundary values yield -EINVAL most of the time; the point is
	 * the rare path where validation lets one through.
	 */
	if (setup_types[idx].type == ALG_DICT_AEAD &&
	    rnd_modulo_u32(4) == 0) {
		unsigned int authsize = alg_boundary_authsizes[
			rnd_modulo_u32(ARRAY_SIZE(alg_boundary_authsizes))];
		(void) setsockopt(fd, SOL_ALG, ALG_SET_AEAD_AUTHSIZE,
				  NULL, authsize);
	}

	/* accept() gives us a child fd for actual crypto I/O */
	child_fd = accept4(fd, NULL, NULL, SOCK_CLOEXEC);
	if (child_fd == -1)
		return;

	/* The child fd is where sendmsg/recvmsg would happen.
	 * We close it here — the fuzzer will exercise the parent
	 * fd via random setsockopt/sendmsg calls independently. */
	close(child_fd);
}

const struct netproto proto_alg = {
	.name = "alg",
	.socket_setup = alg_socket_setup,
	.setsockopt = alg_setsockopt,
	.gen_sockaddr = alg_gen_sockaddr,
	.valid_triplets = alg_triplet,
	.nr_triplets = ARRAY_SIZE(alg_triplet),
};
#endif
