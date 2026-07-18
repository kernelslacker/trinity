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
 * global socket pool -- coherence is the entire point.
 *
 * v3 (ef5622b4ac38): added a splice(tagged_fd -> pipe -> child_fd) data
 * leg substitution to the AF_ALG path so the chain reached alg_sendpage
 * via splice_read_to_pipe instead of only the userspace-buffer sendmsg
 * route.
 *
 * v4 (this file): the AF_ALG-specific walker retires -- grammar_alg in
 * sfg_registry[] covers every AF_ALG lifecycle shape v1+v3 did, plus
 * the P1 sequence hash / P2 illegal-op set / P4 per-order feedback
 * every other family already gets.  The authencesn 1-in-8 Copy Fail
 * bait ported into grammar_alg's ALG_BIND phase keeps the CVE-shaped
 * probing load steady after run_alg_chain went away.  This dispatcher
 * now unconditionally drives run_grammar_chain() against a randomly
 * picked entry from the grammar registry -- one path, one accounting
 * story, no AF_ALG special case.
 *
 * If the picked grammar is rebuffed repeatedly (per-family err_burst
 * exceeds threshold) sfg_mark_unsupported() flips the shm->sfg_unsupported
 * latch for that family so siblings stop probing it.  af_alg-specific
 * unreachability (CRYPTO_USER_API absent / bind path locked down) is
 * handled by grammar_alg.can_run latching PF_ALG on the same shared
 * latch table.
 *
 * The af-alg-recvmsg-churn childop stays as the precision-recipe arm
 * (the BOTH-not-either split): grammar_alg drives breadth / composition
 * / hostile orderings; recvmsg-churn keeps the exact upstream C-repro
 * shapes hot on every iter.  Neither subsumes the other.
 *
 * Cleanup follows the canonical childop convention (see iouring-recipes.c
 * recipe_provide_buffers): child.c arms alarm(1) around every non-syscall
 * op, which bounds the whole invocation in case any step blocks.
 */

#include <stdbool.h>
#include <stdint.h>

#include "child.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "socket-family-grammar.h"
#include "stats.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/socket.h"
#define INNER_MIN		1
#define INNER_MAX_GRAMMAR	3	/* grammar walks are longer than v1's
					 * AF_ALG chains; cap at 3 to keep the
					 * per-invocation wall time bounded */
#define ERR_BURST_LIMIT		5

bool socket_family_chain(struct childdata *child)
{
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);
	const struct socket_family_grammar *sfg;
	unsigned int inner, cycles;
	unsigned int gram_err_burst = 0;
	bool any_completed = false;

	__atomic_add_fetch(&shm->stats.socket_family_chain.runs, 1,
			   __ATOMIC_RELAXED);

	sfg = sfg_pick_random_active();
	if (sfg == NULL) {
		/* Empty registry or every entry latched off.  Nothing to
		 * drive -- book as a failed invocation. */
		__atomic_add_fetch(&shm->stats.socket_family_chain.failed, 1,
				   __ATOMIC_RELAXED);
		return true;
	}

	cycles = INNER_MIN + rnd_modulo_u32(INNER_MAX_GRAMMAR - INNER_MIN + 1);

	for (inner = 0; inner < cycles; inner++) {
		if (run_grammar_chain(sfg, &gram_err_burst)) {
			any_completed = true;
			if (valid_op) {
				__atomic_add_fetch(
					&shm->stats.childop.setup_accepted[op],
					1, __ATOMIC_RELAXED);
				__atomic_add_fetch(
					&shm->stats.childop.data_path[op],
					1, __ATOMIC_RELAXED);
			}
		}

		if (gram_err_burst > ERR_BURST_LIMIT) {
			sfg_mark_unsupported(sfg->family);
			break;
		}
	}

	if (any_completed)
		__atomic_add_fetch(&shm->stats.socket_family_chain.completed,
				   1, __ATOMIC_RELAXED);
	else
		__atomic_add_fetch(&shm->stats.socket_family_chain.failed, 1,
				   __ATOMIC_RELAXED);

	return true;
}
