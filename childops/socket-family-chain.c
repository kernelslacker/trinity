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
#include "rnd.h"
#include "shm.h"
#include "socket-family-grammar.h"
#include "stats.h"
#include "trinity.h"
#include "utils.h"

#ifndef ALG_SET_AEAD_AUTHSIZE
#define ALG_SET_AEAD_AUTHSIZE	5
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
 * Per-invocation state shared across the alg_chain_iter_* helpers below.
 * parent_fd / child_fd / splice_pfd default to -1 via the orchestrator's
 * designated initialiser so the teardown helper can close them
 * unconditionally regardless of which earlier phase bailed; sndbuf /
 * rcvbuf default to NULL so the per-buffer free gates skip work the data
 * leg never allocated.  sa + type are filled in by setup and consumed by
 * arm (bind + the AEAD-only authsize branch).
 */
struct alg_chain_iter_ctx {
	struct sockaddr_alg	sa;
	unsigned char		*sndbuf;
	unsigned char		*rcvbuf;
	enum sfc_type_idx	type;
	int			parent_fd;
	int			child_fd;
	int			splice_pfd[2];
};

/*
 * Phase 1: open the AF_ALG parent socket and fill sa with either the
 * authencesn-shaped Copy Fail-bait (1-in-8) or a random pick from the
 * curated dictionary.  socket() failures with EAFNOSUPPORT /
 * EPROTONOSUPPORT bump err_burst so the caller can latch the AF_ALG-
 * unsupported gate after ERR_BURST_LIMIT consecutive misses.  Returns
 * 0 on success or -1 if the iteration should bail to the orchestrator's
 * out: teardown path.
 */
static int alg_chain_iter_setup(struct alg_chain_iter_ctx *ictx,
				unsigned int *err_burst)
{
	ictx->parent_fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (ictx->parent_fd < 0) {
		if (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT)
			(*err_burst)++;
		return -1;
	}

	memset(&ictx->sa, 0, sizeof(ictx->sa));
	ictx->sa.salg_family = AF_ALG;

	if (ONE_IN(8)) {
		/* The Copy Fail-shaped path: aead/authencesn-with-extended-sn. */
		strncpy((char *)ictx->sa.salg_type, "aead",
			sizeof(ictx->sa.salg_type) - 1);
		strncpy((char *)ictx->sa.salg_name, AUTHENCESN_NAME,
			sizeof(ictx->sa.salg_name) - 1);
		ictx->type = SFC_TYPE_AEAD;
		__atomic_add_fetch(
			&shm->stats.socket_family_chain_authencesn_attempts, 1,
			__ATOMIC_RELAXED);
	} else {
		ictx->type = (enum sfc_type_idx)rnd_modulo_u32(SFC_NR_TYPES);
		pick_alg(sfc_to_dict[ictx->type], sfc_types[ictx->type],
			 &ictx->sa);
	}
	return 0;
}

/*
 * Phase 2: bind sa onto parent_fd, push a random key via ALG_SET_KEY
 * (with the curated 1-in-RAND_NEGATIVE_RATIO negative-optlen spike),
 * issue the AEAD-only ALG_SET_AEAD_AUTHSIZE side trip, and accept the
 * child_fd that the data leg will run against.  bind() / accept()
 * failures with EPERM / ENOPROTOOPT bump err_burst — see the bind
 * comment for why ENOENT/ESRCH are NOT counted.  ALG_SET_KEY failures
 * for algos that reject it (rng, akcipher) are tolerated and the chain
 * walks on; the post-AUTHSIZE accept() may still succeed.  Returns 0
 * on success or -1 if the iteration should bail to the orchestrator's
 * out: teardown path.
 */
static int alg_chain_iter_arm(struct alg_chain_iter_ctx *ictx,
			      unsigned int *err_burst)
{
	unsigned char key[64];
	unsigned int keylen;

	if (bind(ictx->parent_fd, (struct sockaddr *)&ictx->sa,
		 sizeof(ictx->sa)) < 0) {
		/*
		 * Only count errors that suggest the kernel doesn't support
		 * AF_ALG at all (ENOPROTOOPT) or rejects on privilege
		 * (EPERM).  ENOENT/ESRCH are expected per-alg churn:
		 * pick_alg draws from a curated dictionary and not every
		 * name is built on every kernel (e.g. sig algorithms gated
		 * behind extra config).  Latching on those disabled the op
		 * fleet-wide after one unlucky child drew a run of missing
		 * names in a row.
		 */
		if (errno == EPERM || errno == ENOPROTOOPT)
			(*err_burst)++;
		return -1;
	}

	keylen = (rnd_modulo_u32(3) == 0) ? 16 : ((rnd_u32() & 1) ? 32 : 64);
	generate_rand_bytes(key, keylen);
	/* 1-in-RAND_NEGATIVE_RATIO sub the curated 16/32/64 keylen for a
	 * curated edge value — exercises __sys_setsockopt's optlen < 0
	 * rejection (cast to int) which the curated mix never reaches. */
	if (setsockopt(ictx->parent_fd, SOL_ALG, ALG_SET_KEY,
		       key, (socklen_t)RAND_NEGATIVE_OR(keylen)) < 0) {
		if (errno == EPERM || errno == ENOPROTOOPT)
			(*err_burst)++;
		/* Some algos (rng, akcipher) reject ALG_SET_KEY — keep
		 * walking the chain anyway; accept() may still succeed. */
	}

	if (ictx->type == SFC_TYPE_AEAD) {
		unsigned int authsize = (rnd_u32() & 1) ? 12 : 16;

		(void) setsockopt(ictx->parent_fd, SOL_ALG,
				  ALG_SET_AEAD_AUTHSIZE,
				  &authsize, sizeof(authsize));
	}

	ictx->child_fd = accept(ictx->parent_fd, NULL, NULL);
	if (ictx->child_fd < 0) {
		if (errno == EPERM || errno == ENOPROTOOPT)
			(*err_burst)++;
		return -1;
	}
	return 0;
}

/*
 * Phase 3: drive the data leg.  Past the accept() we've reached the
 * actual data path the bug class lives in, so per-step failure here
 * isn't a kernel-absent signal — no err_burst bumps in this phase.
 * ~SPLICE_SUBST_PCT% of the time the sendmsg(buffer) leg is replaced
 * by splice(tagged_fd -> pipe -> child_fd) pulling from a page-cache
 * fd in the OBJ_FD_PAGECACHE pool so the chain reaches alg_sendpage
 * via splice_read_to_pipe; on any setup failure (no fd, pipe2 ENFILE,
 * splice <= 0) we fall through to sendmsg so the data path still
 * runs.  The pipe pair lives in ictx->splice_pfd (default {-1, -1})
 * and the optional sndbuf lives in ictx->sndbuf (default NULL); both
 * are torn down by the teardown helper regardless of which leg ran.
 */
static void alg_chain_iter_drive(struct alg_chain_iter_ctx *ictx)
{
	struct iovec iov;
	struct msghdr msg;
	unsigned int sndlen;
	bool used_splice = false;

	sndlen = 16 + rnd_modulo_u32(256 - 16 + 1);

	if (rnd_modulo_u32(100) < SPLICE_SUBST_PCT) {
		int tagged_fd = get_rand_pagecache_fd();

		if (tagged_fd >= 0 && pipe2(ictx->splice_pfd, O_CLOEXEC) == 0) {
			ssize_t in_n;

			__atomic_add_fetch(
				&shm->stats.socket_family_chain_splice_attempts,
				1, __ATOMIC_RELAXED);

			in_n = splice(tagged_fd, NULL, ictx->splice_pfd[1],
				      NULL, sndlen,
				      SPLICE_F_NONBLOCK | SPLICE_F_MOVE);
			if (in_n > 0) {
				(void) splice(ictx->splice_pfd[0], NULL,
					      ictx->child_fd, NULL,
					      (size_t) in_n,
					      SPLICE_F_NONBLOCK | SPLICE_F_MOVE);
				used_splice = true;
			}
		}
	}

	if (!used_splice) {
		ictx->sndbuf = zmalloc(sndlen);
		generate_rand_bytes(ictx->sndbuf, sndlen);

		iov.iov_base = ictx->sndbuf;
		iov.iov_len  = sndlen;
		memset(&msg, 0, sizeof(msg));
		msg.msg_iov    = &iov;
		msg.msg_iovlen = 1;

		(void) sendmsg(ictx->child_fd, &msg, MSG_NOSIGNAL);
	}
}

/*
 * Phase 4: roll an rcvlen, allocate the receive buffer into ictx, and
 * drain the child_fd once.  Like drive, this is past the kernel-not-
 * supported gates so the recv result is discarded and err_burst stays
 * untouched here — the orchestrator clears it as part of the success
 * book-keeping after this phase returns.  ictx->rcvbuf defaults to
 * NULL so the teardown helper's free gate skips work if a bail above
 * skipped this phase entirely.
 */
static void alg_chain_iter_verify(struct alg_chain_iter_ctx *ictx)
{
	unsigned int rcvlen;

	rcvlen = 16 + rnd_modulo_u32(256 - 16 + 1);
	ictx->rcvbuf = zmalloc(rcvlen);
	(void) recv(ictx->child_fd, ictx->rcvbuf, rcvlen, 0);
}

/*
 * Phase 5: close whichever fds we managed to open and free whichever
 * buffers we managed to allocate.  Runs on every exit path — both the
 * success path after verify and any early-bail goto out from setup or
 * arm.  All fd fields default to -1 and buffer fields to NULL via the
 * orchestrator's designated initialiser so the guards skip work that
 * was never set up.  Order mirrors the pre-extraction layout: splice
 * pipe ends first, then child_fd / parent_fd, then sndbuf / rcvbuf.
 */
static void alg_chain_iter_teardown(struct alg_chain_iter_ctx *ictx)
{
	if (ictx->splice_pfd[0] >= 0)
		close(ictx->splice_pfd[0]);
	if (ictx->splice_pfd[1] >= 0)
		close(ictx->splice_pfd[1]);
	if (ictx->child_fd >= 0)
		close(ictx->child_fd);
	if (ictx->parent_fd >= 0)
		close(ictx->parent_fd);
	if (ictx->sndbuf)
		free(ictx->sndbuf);
	if (ictx->rcvbuf)
		free(ictx->rcvbuf);
}

/*
 * One coherent AF_ALG chain.  Returns false on a clean kernel-not-supported
 * path so the outer cycle can latch the unsupported flag; returns true on
 * everything else (including chain steps that legitimately fail late).
 */
static bool run_alg_chain(unsigned int *err_burst)
{
	struct alg_chain_iter_ctx ictx = {
		.parent_fd = -1,
		.child_fd = -1,
		.splice_pfd = { -1, -1 },
	};
	bool ok = false;

	if (alg_chain_iter_setup(&ictx, err_burst) != 0)
		goto out;

	if (alg_chain_iter_arm(&ictx, err_burst) != 0)
		goto out;

	alg_chain_iter_drive(&ictx);
	alg_chain_iter_verify(&ictx);

	*err_burst = 0;
	ok = true;
out:
	alg_chain_iter_teardown(&ictx);
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
	return rnd_modulo_u32(100) < SFG_AF_ALG_BIAS_PCT;
}

bool socket_family_chain(struct childdata *child)
{
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);
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
			 rnd_modulo_u32(INNER_MAX_ALG - INNER_MIN + 1);
	} else {
		cycles = INNER_MIN +
			 rnd_modulo_u32(INNER_MAX_GRAMMAR - INNER_MIN + 1);
	}

	for (inner = 0; inner < cycles; inner++) {
		if (use_alg) {
			if (run_alg_chain(&alg_err_burst)) {
				any_completed = true;
				if (valid_op) {
					__atomic_add_fetch(
						&shm->stats.childop_setup_accepted[op],
						1, __ATOMIC_RELAXED);
					__atomic_add_fetch(
						&shm->stats.childop_data_path[op],
						1, __ATOMIC_RELAXED);
				}
			}

			if (alg_err_burst > ERR_BURST_LIMIT) {
				__atomic_store_n(
					&shm->socket_family_chain_unsupported,
					true, __ATOMIC_RELAXED);
				if (valid_op)
					__atomic_store_n(
						&shm->stats.childop_latch_reason[op],
						CHILDOP_LATCH_UNSUPPORTED,
						__ATOMIC_RELAXED);
				break;
			}
		} else {
			if (run_grammar_chain(sfg, &gram_err_burst)) {
				any_completed = true;
				if (valid_op) {
					__atomic_add_fetch(
						&shm->stats.childop_setup_accepted[op],
						1, __ATOMIC_RELAXED);
					__atomic_add_fetch(
						&shm->stats.childop_data_path[op],
						1, __ATOMIC_RELAXED);
				}
			}

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

bool socket_family_chain(struct childdata *child)
{
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	__atomic_add_fetch(&shm->stats.socket_family_chain_runs, 1,
			   __ATOMIC_RELAXED);
	__atomic_store_n(&shm->socket_family_chain_unsupported, true,
			 __ATOMIC_RELAXED);
	if (valid_op)
		__atomic_store_n(&shm->stats.childop_latch_reason[op],
				 CHILDOP_LATCH_UNSUPPORTED, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.socket_family_chain_failed, 1,
			   __ATOMIC_RELAXED);
	return true;
}

#endif /* USE_IF_ALG */
