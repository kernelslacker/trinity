#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "random.h"
#include "net.h"
#include "compat.h"
#include "proto-alg-dict.h"

#ifdef USE_IF_ALG
#include <linux/if_alg.h>

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
 * Static-fallback accessor consumed by net/proto-alg-dict.c.  The dict
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

static void alg_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
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

	alg = zmalloc(sizeof(struct sockaddr_alg));

	alg->salg_family = PF_ALG;

	idx = rand() % ARRAY_SIZE(types);
	pick_alg(types[idx].type, types[idx].str, alg);

	alg->salg_feat = rand32();
	alg->salg_mask = rand32();

	*addr = (struct sockaddr *) alg;
	*addrlen = sizeof(struct sockaddr_alg);
}

#define SOL_ALG 279

#define ALG_SET_KEY		1
#define ALG_SET_IV		2
#define ALG_SET_OP		3
#define ALG_SET_AEAD_ASSOCLEN	4
#define ALG_SET_AEAD_AUTHSIZE	5
#define ALG_SET_DRBG_ENTROPY	6

static const unsigned int alg_opts[] = {
	ALG_SET_KEY, ALG_SET_IV, ALG_SET_OP,
	ALG_SET_AEAD_ASSOCLEN, ALG_SET_AEAD_AUTHSIZE,
	ALG_SET_DRBG_ENTROPY,
};

static struct socket_triplet alg_triplet[] = {
	{ .family = PF_ALG, .protocol = 0, .type = SOCK_SEQPACKET },
};

static void alg_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	so->level = SOL_ALG;
	so->optname = RAND_ARRAY(alg_opts);
}

/*
 * Set up the AF_ALG lifecycle on fd:
 * 1. bind() with a random algorithm type and name
 * 2. setsockopt(ALG_SET_KEY) to set a key on the parent fd
 * 3. accept() to get a child fd for crypto operations
 * 4. Close the child fd — we just want to exercise the kernel path
 */
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
	unsigned char key[64];
	int child_fd;
	unsigned int keylen, idx;

	memset(&sa, 0, sizeof(sa));
	sa.salg_family = AF_ALG;

	idx = rand() % ARRAY_SIZE(setup_types);
	pick_alg(setup_types[idx].type, setup_types[idx].str, &sa);

	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) == -1)
		return;

	/* Set a key — required for skcipher/aead, harmless for hash */
	keylen = (rand() % 32) + 16;	/* 16..47 bytes */
	generate_rand_bytes(key, keylen);
	(void) setsockopt(fd, SOL_ALG, ALG_SET_KEY, key, keylen);

	/* accept() gives us a child fd for actual crypto I/O */
	child_fd = accept(fd, NULL, NULL);
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
