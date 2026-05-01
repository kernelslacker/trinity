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
	"cbc(aes)",
	"cbc(des)",
	"cbc(des3_ede)",
	"cbc(camellia)",
	"ecb(aes)",
	"ecb(des)",
	"ecb(des3_ede)",
	"ecb(camellia)",
	"ctr(aes)",
	"ctr(camellia)",
	"xts(aes)",
	"lrw(aes)",
	"cts(cbc(aes))",
	"chacha20",
	"xchacha20",
	"xchacha12",
	"cbc(sm4)",
	"ecb(sm4)",
	"ctr(sm4)",
};

static const char *akcipher_algos[] = {
	"rsa",
};

static const char *kpp_algos[] = {
	"dh",
	"ecdh-nist-p192",
	"ecdh-nist-p256",
};

static void alg_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_alg *alg;
	const char **algs = NULL;
	unsigned int type;
	const char *types[] = { "aead", "hash", "rng", "skcipher", "akcipher", "kpp", };
	unsigned int algo;

	alg = zmalloc(sizeof(struct sockaddr_alg));

	alg->salg_family = PF_ALG;

	type = rand() % ARRAY_SIZE(types);
	strcpy((char *)alg->salg_type, types[type]);

	switch (type) {
	// aead
	case 0:	algs = aead_algos;
		algo = rand() % ARRAY_SIZE(aead_algos);
		break;
	// hash
	case 1:	algs = hashes;
		algo = rand() % ARRAY_SIZE(hashes);
		break;
	// rng
	case 2:	algs = rng_algos;
		algo = rand() % ARRAY_SIZE(rng_algos);
		break;
	// skcipher
	case 3:	algs = skcipher_algos;
		algo = rand() % ARRAY_SIZE(skcipher_algos);
		break;
	// akcipher
	case 4:	algs = akcipher_algos;
		algo = rand() % ARRAY_SIZE(akcipher_algos);
		break;
	// kpp
	case 5:	algs = kpp_algos;
		algo = rand() % ARRAY_SIZE(kpp_algos);
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
	const char *setup_skcipher_algos[] = { "cbc(aes)", "ecb(aes)", "ctr(aes)" };
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
			setup_skcipher_algos[rand() % ARRAY_SIZE(setup_skcipher_algos)],
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
