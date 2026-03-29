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

#ifdef USE_IF_ALG
#include <linux/if_alg.h>

static const char *hashes[] = {
	"md5", "sha1", "sha256", "sha384", "sha512",
	"blake2b-256", "blake2b-512", "sm3",
};

static const char *algos[] = {
	"__cbc-cast5-avx",
	"__cbc-cast6-avx",
	"__cbc-serpent-avx",
	"__cbc-serpent-avx2",
	"__cbc-serpent-sse2",
	"__cbc-twofish-avx",
	"__driver-cbc-aes-aesni",
	"__driver-cbc-camellia-aesni",
	"__driver-cbc-camellia-aesni-avx2",
	"__driver-cbc-cast5-avx",
	"__driver-cbc-cast6-avx",
	"__driver-cbc-serpent-avx",
	"__driver-cbc-serpent-avx2",
	"__driver-cbc-serpent-sse2",
	"__driver-cbc-twofish-avx",
	"__driver-ecb-aes-aesni",
	"__driver-ecb-camellia-aesni",
	"__driver-ecb-camellia-aesni-avx2",
	"__driver-ecb-cast5-avx",
	"__driver-ecb-cast6-avx",
	"__driver-ecb-serpent-avx",
	"__driver-ecb-serpent-avx2",
	"__driver-ecb-serpent-sse2",
	"__driver-ecb-twofish-avx",
	"__driver-gcm-aes-aesni",
	"__ghash-pclmulqdqni",
	"ansi_cprng",
	"authenc(hmac(md5),ecb(cipher_null))",
	"authenc(hmac(sha1),cbc(aes))",
	"authenc(hmac(sha1),cbc(des))",
	"authenc(hmac(sha1),cbc(des3_ede))",
	"authenc(hmac(sha1),ctr(aes))",
	"authenc(hmac(sha1),ecb(cipher_null))",
	"authenc(hmac(sha224),cbc(des))",
	"authenc(hmac(sha224),cbc(des3_ede))",
	"authenc(hmac(sha256),cbc(aes))",
	"authenc(hmac(sha256),cbc(des))",
	"authenc(hmac(sha256),cbc(des3_ede))",
	"authenc(hmac(sha256),ctr(aes))",
	"authenc(hmac(sha384),cbc(des))",
	"authenc(hmac(sha384),cbc(des3_ede))",
	"authenc(hmac(sha384),ctr(aes))",
	"authenc(hmac(sha512),cbc(aes))",
	"authenc(hmac(sha512),cbc(des))",
	"authenc(hmac(sha512),cbc(des3_ede))",
	"authenc(hmac(sha512),ctr(aes))",
	"cbc(aes)",
	"cbc(anubis)",
	"cbc(blowfish)",
	"cbc(camellia)",
	"cbc(cast5)",
	"cbc(cast6)",
	"cbc(des)",
	"cbc(des3_ede)",
	"cbc(serpent)",
	"cbc(twofish)",
	"ccm(aes)",
	"chacha20",
	"cmac(aes)",
	"cmac(des3_ede)",
	"compress_null",
	"crc32",
	"crc32c",
	"crct10dif",
	"cryptd(__driver-cbc-aes-aesni)",
	"cryptd(__driver-cbc-camellia-aesni)",
	"cryptd(__driver-cbc-camellia-aesni-avx2)",
	"cryptd(__driver-cbc-serpent-avx2)",
	"cryptd(__driver-ecb-aes-aesni)",
	"cryptd(__driver-ecb-camellia-aesni)",
	"cryptd(__driver-ecb-camellia-aesni-avx2)",
	"cryptd(__driver-ecb-cast5-avx)",
	"cryptd(__driver-ecb-cast6-avx)",
	"cryptd(__driver-ecb-serpent-avx)",
	"cryptd(__driver-ecb-serpent-avx2)",
	"cryptd(__driver-ecb-serpent-sse2)",
	"cryptd(__driver-ecb-twofish-avx)",
	"cryptd(__driver-gcm-aes-aesni)",
	"cryptd(__ghash-pclmulqdqni)",
	"ctr(aes)",
	"ctr(blowfish)",
	"ctr(camellia)",
	"ctr(cast5)",
	"ctr(cast6)",
	"ctr(des)",
	"ctr(des3_ede)",
	"ctr(serpent)",
	"ctr(twofish)",
	"cts(cbc(aes))",
	"deflate",
	"digest_null",
	"drbg_nopr_ctr_aes128",
	"drbg_nopr_ctr_aes192",
	"drbg_nopr_ctr_aes256",
	"drbg_nopr_hmac_sha1",
	"drbg_nopr_hmac_sha256",
	"drbg_nopr_hmac_sha384",
	"drbg_nopr_hmac_sha512",
	"drbg_nopr_sha1",
	"drbg_nopr_sha256",
	"drbg_nopr_sha384",
	"drbg_nopr_sha512",
	"drbg_pr_ctr_aes128",
	"drbg_pr_ctr_aes192",
	"drbg_pr_ctr_aes256",
	"drbg_pr_hmac_sha1",
	"drbg_pr_hmac_sha256",
	"drbg_pr_hmac_sha384",
	"drbg_pr_hmac_sha512",
	"drbg_pr_sha1",
	"drbg_pr_sha256",
	"drbg_pr_sha384",
	"drbg_pr_sha512",
	"ecb(__aes-aesni)",
	"ecb(aes)",
	"ecb(anubis)",
	"ecb(arc4)",
	"ecb(blowfish)",
	"ecb(camellia)",
	"ecb(cast5)",
	"ecb(cast6)",
	"ecb(cipher_null)",
	"ecb(des)",
	"ecb(des3_ede)",
	"ecb(fcrypt)",
	"ecb(khazad)",
	"ecb(seed)",
	"ecb(serpent)",
	"ecb(tea)",
	"ecb(tnepres)",
	"ecb(twofish)",
	"ecb(xeta)",
	"ecb(xtea)",
	"gcm(aes)",
	"ghash",
	"hmac(crc32)",
	"hmac(md5)",
	"hmac(rmd128)",
	"hmac(rmd160)",
	"hmac(sha1)",
	"hmac(sha224)",
	"hmac(sha256)",
	"hmac(sha384)",
	"hmac(sha512)",
	"jitterentropy_rng",
	"kw(aes)",
	"lrw(aes)",
	"lrw(camellia)",
	"lrw(cast6)",
	"lrw(serpent)",
	"lrw(twofish)",
	"lz4",
	"lz4hc",
	"lzo",
	"md4",
	"md5",
	"michael_mic",
	"ofb(aes)",
	"pcbc(fcrypt)",
	"poly1305",
	"rfc3686(ctr(aes))",
	"rfc4106(gcm(aes))",
	"rfc4309(ccm(aes))",
	"rfc4543(gcm(aes))",
	"rfc7539(chacha20,poly1305)",
	"rfc7539esp(chacha20,poly1305)",
	"rmd128",
	"rmd160",
	"rmd256",
	"rmd320",
	"rsa",
	"salsa20",
	"sha1",
	"sha224",
	"sha256",
	"sha384",
	"sha512",
	"tgr128",
	"tgr160",
	"tgr192",
	"vmac(aes)",
	"wp256",
	"wp384",
	"wp512",
	"xcbc(aes)",
	"xts(aes)",
	"xts(camellia)",
	"xts(cast6)",
	"xts(serpent)",
	"xts(twofish)",
	"zlib",
};

static void alg_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_alg *alg;
	const char **algs = algos;
	unsigned int type;
	const char *types[] = { "aead", "hash", "rng", "skcipher", "akcipher", "kpp", };
	unsigned int algo;

	alg = zmalloc(sizeof(struct sockaddr_alg));

	alg->salg_family = PF_ALG;

	type = rand() % ARRAY_SIZE(types);
	strcpy((char *)alg->salg_type, types[type]);

	switch (type) {
	// aead
	case 0:	algo = rand() % ARRAY_SIZE(algos);
		break;
	// hash
	case 1:	algo = rand() % ARRAY_SIZE(hashes);
		algs = hashes;
		break;
	// rng
	case 2:	algo = rand() % ARRAY_SIZE(algos);
		break;
	// skcipher
	case 3:	algo = rand() % ARRAY_SIZE(algos);
		break;
	// akcipher
	case 4:	algo = rand() % ARRAY_SIZE(algos);
		break;
	// kpp
	case 5:	algo = rand() % ARRAY_SIZE(algos);
		break;
	default: unreachable();
	}
	strcpy((char *)alg->salg_name, algs[algo]);

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
	struct sockaddr_alg sa;
	unsigned char key[64];
	int child_fd;
	unsigned int keylen;
	const char *hash_types[] = { "hash", "skcipher", "aead", "rng" };
	const char *hash_algos[] = { "sha1", "sha256", "md5", "sha512" };
	const char *skcipher_algos[] = { "cbc(aes)", "ecb(aes)", "ctr(aes)" };
	const char *type;
	unsigned int type_idx;

	memset(&sa, 0, sizeof(sa));
	sa.salg_family = AF_ALG;

	type_idx = rand() % ARRAY_SIZE(hash_types);
	type = hash_types[type_idx];
	strncpy((char *)sa.salg_type, type, sizeof(sa.salg_type) - 1);

	/* Pick an algorithm appropriate for the type */
	switch (type_idx) {
	case 0: /* hash */
		strncpy((char *)sa.salg_name,
			hash_algos[rand() % ARRAY_SIZE(hash_algos)],
			sizeof(sa.salg_name) - 1);
		break;
	case 1: /* skcipher */
		strncpy((char *)sa.salg_name,
			skcipher_algos[rand() % ARRAY_SIZE(skcipher_algos)],
			sizeof(sa.salg_name) - 1);
		break;
	default:
		strncpy((char *)sa.salg_name,
			hash_algos[rand() % ARRAY_SIZE(hash_algos)],
			sizeof(sa.salg_name) - 1);
		break;
	}

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
