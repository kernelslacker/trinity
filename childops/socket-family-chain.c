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
 * v1 (84b298906961): AF_ALG only.  socket() -> bind(salg_type/salg_name)
 * -> setsockopt(ALG_SET_KEY) -> [aead only] setsockopt(ALG_SET_AEAD_AUTHSIZE)
 * -> accept() -> sendmsg() -> recv() -> close.  The bound parent_fd and
 * accepted child_fd are private to one invocation and never enter the
 * global socket pool — coherence is the entire point.
 *
 * v3 (ef5622b4ac38): added a splice(tagged_fd -> pipe -> child_fd) data
 * leg substitution to the AF_ALG path so the chain reaches alg_sendpage
 * via splice_read_to_pipe instead of only the userspace-buffer sendmsg
 * route.
 *
 * v2 (this file): the AF_ALG-only walker now lives in run_alg_chain()
 * unchanged.  The outer driver dispatches between run_alg_chain() and
 * the table-driven run_grammar_chain() (net/socket-family-grammar.c)
 * which handles arbitrary AF_* families via per-family grammar entries.
 * SFG_AF_ALG_BIAS_PCT keeps a fixed share of invocations on the AF_ALG
 * path so v1's authencesn-shaped probing load isn't diluted as the
 * grammar registry grows.  When the registry is empty the dispatcher
 * falls back to run_alg_chain() for every cycle, so behaviour is
 * identical to v1+v3 until per-family grammars land.
 *
 * Cleanup follows the canonical childop convention (see iouring-recipes.c
 * recipe_provide_buffers): per-resource flag, single goto out, only the
 * resources that were acquired get torn down.  child.c arms alarm(1)
 * around every non-syscall op, which bounds the whole invocation in
 * case any step blocks.
 *
 * If the AF_ALG path is rebuffed repeatedly with ESRCH/EPERM/ENOPROTOOPT
 * (CRYPTO_USER_API absent or AF_ALG bind path locked down), a per-shm
 * latch flips so siblings stop probing.  Per-family latches under
 * shm->sfg_unsupported[] handle the same recovery story for the
 * grammar-registry families.
 */

#include <errno.h>
#include <fcntl.h>
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
#include "files.h"
#include "proto-alg-dict.h"
#include "random.h"
#include "shm.h"
#include "socket-family-grammar.h"
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

#define INNER_MIN		1
#define INNER_MAX_ALG		4	/* AF_ALG arm preserves v1's 1..4 */
#define INNER_MAX_GRAMMAR	3	/* grammar walks are longer; cap at 3 */
#define ERR_BURST_LIMIT		5

/*
 * Probability (out of 100) that a cycle drives the AF_ALG-specific
 * walker (run_alg_chain).  The remaining 75% draws a random entry from
 * the grammar registry and runs it via run_grammar_chain().  When the
 * registry is empty (framework commit, before any per-family grammar
 * lands) the grammar arm has nothing to pick and the cycle falls back
 * to run_alg_chain — behaviour is identical to v1+v3.
 *
 * 25% keeps the AF_ALG path's authencesn-shaped probing load steady
 * after the grammar table fills out, so the existing CVE-bait isn't
 * diluted by the new families.
 */
#define SFG_AF_ALG_BIAS_PCT	25

/*
 * Probability (out of 100) that the data leg is replaced by a splice
 * sequence pulling from a page-cache-backed source fd through a pipe
 * into the AF_ALG child socket.  The remaining ~70% keeps the natural
 * sendmsg(buffer) path that already lands the bug class we care about.
 */
#define SPLICE_SUBST_PCT	30

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
static bool run_alg_chain(unsigned int *err_burst)
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
	int splice_pfd[2] = { -1, -1 };
	unsigned int keylen;
	unsigned int sndlen;
	unsigned int rcvlen;
	bool forced_authencesn = false;
	bool used_splice = false;
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
	/* 1-in-RAND_NEGATIVE_RATIO sub the curated 16/32/64 keylen for a
	 * curated edge value — exercises __sys_setsockopt's optlen < 0
	 * rejection (cast to int) which the curated mix never reaches. */
	if (setsockopt(parent_fd, SOL_ALG, ALG_SET_KEY,
		       key, (socklen_t)RAND_NEGATIVE_OR(keylen)) < 0) {
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

	/*
	 * Data leg.  ~SPLICE_SUBST_PCT% of the time, replace the sendmsg
	 * buffer path with splice(tagged_fd -> pipe -> child_fd) using a
	 * page-cache-backed source fd from the OBJ_FD_PAGECACHE pool.  The
	 * pipe pair is owned by run_alg_chain() — splice_pfd[] is initialised
	 * to {-1, -1} and torn down in the unified out: block, matching the
	 * per-resource flag-and-cleanup pattern in iouring-recipes.c.
	 *
	 * On any setup failure (no fd available, pipe2 ENFILE, the input
	 * splice returning <= 0 because the AF_ALG sink isn't accepting yet,
	 * etc.) we fall through to the sendmsg path so the chain still
	 * exercises the bug-class data path it was built for.
	 */
	if ((rand() % 100) < SPLICE_SUBST_PCT) {
		int tagged_fd = get_rand_pagecache_fd();

		if (tagged_fd >= 0 && pipe2(splice_pfd, O_CLOEXEC) == 0) {
			ssize_t in_n;

			__atomic_add_fetch(
				&shm->stats.socket_family_chain_splice_attempts,
				1, __ATOMIC_RELAXED);

			in_n = splice(tagged_fd, NULL, splice_pfd[1], NULL,
				      sndlen,
				      SPLICE_F_NONBLOCK | SPLICE_F_MOVE);
			if (in_n > 0) {
				(void) splice(splice_pfd[0], NULL, child_fd,
					      NULL, (size_t) in_n,
					      SPLICE_F_NONBLOCK | SPLICE_F_MOVE);
				used_splice = true;
			}
		}
	}

	if (!used_splice) {
		sndbuf = zmalloc(sndlen);
		generate_rand_bytes(sndbuf, sndlen);

		iov.iov_base = sndbuf;
		iov.iov_len  = sndlen;
		memset(&msg, 0, sizeof(msg));
		msg.msg_iov    = &iov;
		msg.msg_iovlen = 1;

		(void) sendmsg(child_fd, &msg, MSG_NOSIGNAL);
	}

	rcvlen = 16 + (rand() % (256 - 16 + 1));
	rcvbuf = zmalloc(rcvlen);
	(void) recv(child_fd, rcvbuf, rcvlen, 0);

	*err_burst = 0;
	ok = true;
out:
	if (splice_pfd[0] >= 0)
		close(splice_pfd[0]);
	if (splice_pfd[1] >= 0)
		close(splice_pfd[1]);
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

/*
 * Pick the per-cycle arm.  Returns true to drive the AF_ALG-specific
 * walker, false to draw from the grammar registry.  When the grammar
 * registry has no active entry the caller treats a "false" decision as
 * a fall-through to the AF_ALG arm so behaviour stays identical to v1+v3
 * until per-family grammars land.
 */
static bool pick_alg_arm(void)
{
	return (rand() % 100) < SFG_AF_ALG_BIAS_PCT;
}

bool socket_family_chain(struct childdata *child __unused__)
{
	unsigned int inner;
	unsigned int cycles;
	unsigned int alg_err_burst = 0;
	unsigned int gram_err_burst = 0;
	bool any_completed = false;
	bool use_alg;
	const struct socket_family_grammar *sfg;

	__atomic_add_fetch(&shm->stats.socket_family_chain_runs, 1,
			   __ATOMIC_RELAXED);

	/*
	 * Decide arm + cycle count once per invocation so kcov locality
	 * doesn't get diluted by per-cycle arm flipping.  Grammar walks
	 * cap at INNER_MAX_GRAMMAR (3) because each walk is heavier than
	 * a v1 AF_ALG chain; AF_ALG keeps INNER_MAX_ALG (4) for parity
	 * with v1.
	 */
	use_alg = pick_alg_arm();
	if (!use_alg) {
		sfg = sfg_pick_random_active();
		if (sfg == NULL) {
			/* Empty registry or every entry latched off — fall
			 * back to the AF_ALG arm so the slot still does
			 * useful work. */
			use_alg = true;
		}
	} else {
		sfg = NULL;
	}

	if (use_alg) {
		if (__atomic_load_n(&shm->socket_family_chain_unsupported,
				    __ATOMIC_RELAXED)) {
			return true;
		}
		cycles = INNER_MIN +
			 (rand() % (INNER_MAX_ALG - INNER_MIN + 1));
	} else {
		cycles = INNER_MIN +
			 (rand() % (INNER_MAX_GRAMMAR - INNER_MIN + 1));
	}

	for (inner = 0; inner < cycles; inner++) {
		if (use_alg) {
			if (run_alg_chain(&alg_err_burst))
				any_completed = true;

			if (alg_err_burst > ERR_BURST_LIMIT) {
				__atomic_store_n(
					&shm->socket_family_chain_unsupported,
					true, __ATOMIC_RELAXED);
				break;
			}
		} else {
			if (run_grammar_chain(sfg, &gram_err_burst))
				any_completed = true;

			if (gram_err_burst > ERR_BURST_LIMIT) {
				sfg_mark_unsupported(sfg->family);
				break;
			}
		}
	}

	if (any_completed)
		__atomic_add_fetch(&shm->stats.socket_family_chain_completed,
				   1, __ATOMIC_RELAXED);
	else
		__atomic_add_fetch(&shm->stats.socket_family_chain_failed,
				   1, __ATOMIC_RELAXED);

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
