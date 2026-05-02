/*
 * socket_family_chain - coherent multi-step chain through a single
 * protocol family inside one childop.
 *
 * Random per-syscall fuzzing rolls a fresh family/level/optname for each
 * call.  The conditional probability of a five-call sequence landing on
 * the same family with semantically coherent arguments at every step is
 * effectively zero, so deep paths that demand a coherent protocol-family
 * lifecycle stay cold.  This childop walks one such lifecycle end-to-end
 * with the same fd flowing through every step.
 *
 * v1: AF_ALG only.  socket() -> bind(salg_type/salg_name) ->
 * setsockopt(ALG_SET_KEY) -> [aead only] setsockopt(ALG_SET_AEAD_AUTHSIZE)
 * -> accept() -> sendmsg() -> recv() -> close.  The bound parent_fd and
 * accepted child_fd are private to one invocation and never enter the
 * global socket pool — coherence is the entire point.
 *
 * Cleanup follows the canonical childop convention (see iouring-recipes.c
 * recipe_provide_buffers): per-resource flag, single goto out, only the
 * resources that were acquired get torn down.  An alarm bounds the whole
 * invocation in case any step blocks.
 *
 * If the kernel rebuffs the chain repeatedly with ESRCH/EPERM/ENOPROTOOPT
 * (CRYPTO_USER_API absent or AF_ALG bind path locked down), a per-shm
 * latch flips so siblings stop probing.
 */

#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#ifdef USE_IF_ALG
#include <linux/if_alg.h>
#endif

#include "child.h"
#include "compat.h"
#include "proto-alg-dict.h"
#include "random.h"
#include "shm.h"
#include "stats.h"
#include "trinity.h"
#include "utils.h"

#ifndef SOL_ALG
#define SOL_ALG			279
#endif
#ifndef ALG_SET_KEY
#define ALG_SET_KEY		1
#endif
#ifndef ALG_SET_AEAD_AUTHSIZE
#define ALG_SET_AEAD_AUTHSIZE	5
#endif

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL		0x4000
#endif

#define INNER_MIN	1
#define INNER_MAX	4
#define ERR_BURST_LIMIT	5

#ifdef USE_IF_ALG

/*
 * The salg_type strings we exercise.  This is a strict subset of the
 * dict's ALG_DICT_* enum — sig is intentionally excluded; the AF_ALG
 * sig path isn't part of the v1 chain.
 */
enum sfc_type_idx {
	SFC_TYPE_AEAD = 0,
	SFC_TYPE_HASH,
	SFC_TYPE_RNG,
	SFC_TYPE_SKCIPHER,
	SFC_TYPE_AKCIPHER,
	SFC_TYPE_KPP,
	SFC_NR_TYPES,
};

static const char * const sfc_types[SFC_NR_TYPES] = {
	[SFC_TYPE_AEAD]     = "aead",
	[SFC_TYPE_HASH]     = "hash",
	[SFC_TYPE_RNG]      = "rng",
	[SFC_TYPE_SKCIPHER] = "skcipher",
	[SFC_TYPE_AKCIPHER] = "akcipher",
	[SFC_TYPE_KPP]      = "kpp",
};

static const enum alg_dict_type sfc_to_dict[SFC_NR_TYPES] = {
	[SFC_TYPE_AEAD]     = ALG_DICT_AEAD,
	[SFC_TYPE_HASH]     = ALG_DICT_HASH,
	[SFC_TYPE_RNG]      = ALG_DICT_RNG,
	[SFC_TYPE_SKCIPHER] = ALG_DICT_SKCIPHER,
	[SFC_TYPE_AKCIPHER] = ALG_DICT_AKCIPHER,
	[SFC_TYPE_KPP]      = ALG_DICT_KPP,
};

/* The Copy Fail-shaped name we want to land on with elevated probability. */
#define AUTHENCESN_NAME	"authencesn(hmac(sha256),cbc(aes))"

/*
 * One coherent AF_ALG chain.  Returns false on a clean kernel-not-supported
 * path so the outer cycle can latch the unsupported flag; returns true on
 * everything else (including chain steps that legitimately fail late).
 */
static bool run_one_chain(unsigned int *err_burst)
{
	struct sockaddr_alg sa;
	unsigned char key[64];
	unsigned char *sndbuf = NULL;
	unsigned char *rcvbuf = NULL;
	struct iovec iov;
	struct msghdr msg;
	enum sfc_type_idx type;
	int parent_fd = -1;
	int child_fd = -1;
	unsigned int keylen;
	unsigned int sndlen;
	unsigned int rcvlen;
	bool forced_authencesn = false;
	bool ok = false;

	parent_fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (parent_fd < 0) {
		if (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT)
			(*err_burst)++;
		goto out;
	}

	memset(&sa, 0, sizeof(sa));
	sa.salg_family = AF_ALG;

	if (ONE_IN(8)) {
		/* The Copy Fail-shaped path: aead/authencesn-with-extended-sn. */
		strncpy((char *)sa.salg_type, "aead",
			sizeof(sa.salg_type) - 1);
		strncpy((char *)sa.salg_name, AUTHENCESN_NAME,
			sizeof(sa.salg_name) - 1);
		type = SFC_TYPE_AEAD;
		forced_authencesn = true;
		__atomic_add_fetch(
			&shm->stats.socket_family_chain_authencesn_attempts, 1,
			__ATOMIC_RELAXED);
	} else {
		type = (enum sfc_type_idx)(rand() % SFC_NR_TYPES);
		pick_alg(sfc_to_dict[type], sfc_types[type], &sa);
	}

	if (bind(parent_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		if (errno == ENOENT || errno == ESRCH ||
		    errno == EPERM || errno == ENOPROTOOPT)
			(*err_burst)++;
		goto out;
	}

	keylen = (rand() % 3 == 0) ? 16 : ((rand() & 1) ? 32 : 64);
	generate_rand_bytes(key, keylen);
	if (setsockopt(parent_fd, SOL_ALG, ALG_SET_KEY,
		       key, keylen) < 0) {
		if (errno == EPERM || errno == ENOPROTOOPT)
			(*err_burst)++;
		/* Some algos (rng, akcipher) reject ALG_SET_KEY — keep
		 * walking the chain anyway; accept() may still succeed. */
	}

	if (type == SFC_TYPE_AEAD) {
		unsigned int authsize = (rand() & 1) ? 12 : 16;

		(void) setsockopt(parent_fd, SOL_ALG,
				  ALG_SET_AEAD_AUTHSIZE,
				  &authsize, sizeof(authsize));
	}

	child_fd = accept(parent_fd, NULL, NULL);
	if (child_fd < 0) {
		if (errno == EPERM || errno == ENOPROTOOPT)
			(*err_burst)++;
		goto out;
	}

	/* From here on we've reached the actual data path the bug class
	 * lives in.  Any per-step failure is interesting but not a kernel-
	 * absent signal, so don't bump err_burst. */

	sndlen = 16 + (rand() % (256 - 16 + 1));
	sndbuf = zmalloc(sndlen);
	generate_rand_bytes(sndbuf, sndlen);

	iov.iov_base = sndbuf;
	iov.iov_len  = sndlen;
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov    = &iov;
	msg.msg_iovlen = 1;

	(void) sendmsg(child_fd, &msg, MSG_NOSIGNAL);

	rcvlen = 16 + (rand() % (256 - 16 + 1));
	rcvbuf = zmalloc(rcvlen);
	(void) recv(child_fd, rcvbuf, rcvlen, 0);

	*err_burst = 0;
	ok = true;
out:
	if (child_fd >= 0)
		close(child_fd);
	if (parent_fd >= 0)
		close(parent_fd);
	if (sndbuf)
		free(sndbuf);
	if (rcvbuf)
		free(rcvbuf);

	(void) forced_authencesn;
	return ok;
}

bool socket_family_chain(struct childdata *child __unused__)
{
	unsigned int inner;
	unsigned int cycles;
	unsigned int err_burst = 0;
	bool any_completed = false;

	__atomic_add_fetch(&shm->stats.socket_family_chain_runs, 1,
			   __ATOMIC_RELAXED);

	if (__atomic_load_n(&shm->socket_family_chain_unsupported,
			    __ATOMIC_RELAXED))
		return true;

	/*
	 * Bound the entire invocation.  child.c arms alarm(1) for every
	 * non-syscall op; the inner cycle does up to 4 full setup chains
	 * and each step (bind, setsockopt, accept) can briefly block on
	 * crypto module init under load.  Two seconds is comfortable for
	 * the worst case and short enough that a stuck op still yields
	 * the slot promptly.
	 */
	alarm(2);

	cycles = INNER_MIN + (rand() % (INNER_MAX - INNER_MIN + 1));
	for (inner = 0; inner < cycles; inner++) {
		if (run_one_chain(&err_burst))
			any_completed = true;

		if (err_burst > ERR_BURST_LIMIT) {
			__atomic_store_n(
				&shm->socket_family_chain_unsupported, true,
				__ATOMIC_RELAXED);
			break;
		}
	}

	if (any_completed)
		__atomic_add_fetch(&shm->stats.socket_family_chain_completed,
				   1, __ATOMIC_RELAXED);
	else
		__atomic_add_fetch(&shm->stats.socket_family_chain_failed,
				   1, __ATOMIC_RELAXED);

	alarm(0);
	return true;
}

#else /* !USE_IF_ALG */

bool socket_family_chain(struct childdata *child __unused__)
{
	__atomic_add_fetch(&shm->stats.socket_family_chain_runs, 1,
			   __ATOMIC_RELAXED);
	__atomic_store_n(&shm->socket_family_chain_unsupported, true,
			 __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.socket_family_chain_failed, 1,
			   __ATOMIC_RELAXED);
	return true;
}

#endif /* USE_IF_ALG */
