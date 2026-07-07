/*
 * Per-family grammar table dispatcher.  Generalises the v1
 * socket_family_chain childop (84b298906961, AF_ALG only) and v3's
 * splice-substitution data leg (ef5622b4ac38) into a table-driven
 * walker that drives arbitrary AF_* families through coherent
 * setsockopt/bind/listen/accept/sendmsg sequences using one struct
 * socket_family_grammar entry per family.
 *
 * The registry below is empty by default — when no grammar is
 * registered the outer dispatcher in childops/net/socket-family-chain.c
 * falls back to run_alg_chain (the v1 path) so behaviour is identical
 * to v1+v3.  Per-family grammars are added incrementally, each adding
 * one entry to sfg_registry[] alongside its definition in
 * net/proto-<family>.c.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "arch.h"		/* page_size */
#include "child.h"
#include "deferred-free.h"
#include "files.h"		/* get_rand_pagecache_fd */
#include "kcov.h"
#include "net.h"
#include "random.h"
#include "shm.h"
#include "socket-family-grammar.h"
#include "trinity.h"
#include "utils.h"
		/* keep last — matches net/proto-*.c order */
#include "rnd.h"
#include "xdp-umem-track.h"

#ifdef USE_IF_ALG
#include <linux/if_alg.h>
#include "proto-alg-dict.h"

#include "kernel/fcntl.h"
#include "kernel/splice.h"
#include "kernel/socket.h"
#ifndef ALG_SET_IV
#define ALG_SET_IV		2
#endif
#ifndef ALG_SET_OP
#define ALG_SET_OP		3
#endif
#ifndef ALG_SET_AEAD_ASSOCLEN
#define ALG_SET_AEAD_ASSOCLEN	4
#endif
#ifndef ALG_SET_AEAD_AUTHSIZE
#define ALG_SET_AEAD_AUTHSIZE	5
#endif
#ifndef ALG_OP_DECRYPT
#define ALG_OP_DECRYPT		0
#endif
#ifndef ALG_OP_ENCRYPT
#define ALG_OP_ENCRYPT		1
#endif

/* Copy Fail-shaped AEAD name that the retired standalone AF_ALG walker
 * biased at 1-in-8.  Ported here so the CVE-bait probing load stays
 * steady after run_alg_chain retirement.  Kept as a define rather than
 * lifted to a shared header — this is the only site that emits it. */
#define AUTHENCESN_NAME	"authencesn(hmac(sha256),cbc(aes))"

/*
 * Probability (out of 100) that the ALG_SEND_MORE phase substitutes a
 * single splice(tagged_fd -> pipe -> child_fd) pull-from-pagecache for
 * the default N × sendmsg(MSG_MORE) buffer sends.  Re-added from the
 * retired v3 run_alg_chain data leg (ef5622b4ac38 / 1c7259d88947): the
 * splice path reaches alg_sendpage via splice_read_to_pipe, coverage
 * the buffer-sendmsg walk never lands.  Rate matches v3.  On any setup
 * miss (no pagecache fd, pipe2 ENFILE, splice returning <= 0 in
 * either leg) the phase falls through to the buffer sends so the data
 * leg still runs — mirrors alg_chain_iter_drive's discipline.  The
 * pipe pair lives in ctx->fam.alg.splice_pfd (already reserved and
 * initialised to {-1, -1} by the run_grammar_chain designated init)
 * and is torn down unconditionally by the out: label's close gate.
 */
#define SFG_ALG_SPLICE_SUBST_PCT	30
#endif

/*
 * Registry filled in by per-family commits.  The trailing NULL is a
 * sentinel that lets the framework commit land before any family
 * does — sfg_pick_random_active() skips NULL entries.  When a family
 * is added it goes ABOVE the sentinel so ARRAY_SIZE() still spans
 * every real slot.
 */
static const struct socket_family_grammar * const sfg_registry[] = {
	&grammar_inet,
#ifdef USE_IF_ALG
	&grammar_alg,
#endif
#ifdef USE_IPV6
	&grammar_inet6,
#endif
	&grammar_mptcp,
	&grammar_kcm,
	&grammar_rxrpc,
	&grammar_qrtr,
#ifdef USE_RDS
	&grammar_rds,
#endif
#ifdef USE_MCTP
	&grammar_mctp,
#endif
	&grammar_llc,
	&grammar_mpls,
	&grammar_unix,
	&grammar_netlink,
	&grammar_xfrm,
	&grammar_packet,
#ifdef USE_XDP
	&grammar_xdp,
#endif

	/* Dormant stubs — sfg_always_false keeps them inert on this
	 * kernel build, but the slot is held so a user with the right
	 * CONFIG (or a future commit upgrading the stub to a real
	 * grammar) drops in without changing the registry array. */
#ifdef USE_BLUETOOTH
	&grammar_bluetooth_stub,
#endif
#ifdef USE_CAIF
	&grammar_caif_stub,
#endif
#ifdef USE_VSOCK
	&grammar_vsock_stub,
#endif
	&grammar_can_stub,
	&grammar_phonet_stub,
	&grammar_smc_stub,
	&grammar_tipc_stub,

	NULL,
};

const struct socket_family_grammar *sfg_pick_random_active(void)
{
	const struct socket_family_grammar *active[ARRAY_SIZE(sfg_registry)];
	unsigned int i, nr_active = 0;

	for (i = 0; i < ARRAY_SIZE(sfg_registry); i++) {
		const struct socket_family_grammar *sfg = sfg_registry[i];

		if (sfg == NULL)
			continue;
		if (sfg->family <= 0 || sfg->family >= TRINITY_PF_MAX)
			continue;
		if (__atomic_load_n(&shm->sfg_unsupported[sfg->family],
				    __ATOMIC_RELAXED))
			continue;
		if (sfg->can_run != NULL && !sfg->can_run())
			continue;

		active[nr_active++] = sfg;
	}

	if (nr_active == 0)
		return NULL;

	return active[rnd_modulo_u32(nr_active)];
}

bool sfg_can_run_default(int family)
{
	int fd;

	if (family <= 0 || family >= TRINITY_PF_MAX)
		return false;

	if (__atomic_load_n(&shm->sfg_unsupported[family], __ATOMIC_RELAXED))
		return false;

	/* SOCK_STREAM is the most universally supported type for the
	 * IP-style families; AF_PACKET / AF_NETLINK / AF_ALG override
	 * can_run because their natural type is different. */
	fd = socket(family, SOCK_STREAM, 0);
	if (fd < 0) {
		__atomic_store_n(&shm->sfg_unsupported[family], true,
				 __ATOMIC_RELAXED);
		return false;
	}
	close(fd);
	return true;
}

void sfg_mark_unsupported(int family)
{
	if (family <= 0 || family >= TRINITY_PF_MAX)
		return;
	__atomic_store_n(&shm->sfg_unsupported[family], true,
			 __ATOMIC_RELAXED);
}

bool sfg_always_false(void)
{
	return false;
}

const char *sfg_illegal_name(enum sfg_illegal_op op)
{
	switch (op) {
	case SFG_ILLEGAL_NONE:			return "none";
	case SFG_ILLEGAL_ACCEPT_NON_LISTENER:	return "accept-non-listener";
	case SFG_ILLEGAL_BIND_AFTER_LISTEN:	return "bind-after-listen";
	case SFG_ILLEGAL_SEND_BEFORE_BIND:	return "send-before-bind";
	case SFG_ILLEGAL_DOUBLE_SHUTDOWN:	return "double-shutdown";
	case SFG_ILLEGAL_ALG_SEND_BEFORE_SETKEY:
		return "alg-send-before-setkey";
	case SFG_ILLEGAL_ALG_RECV_ON_EMPTY_TSGL:
		return "alg-recv-on-empty-tsgl";
	case SFG_ILLEGAL_ALG_ACCEPT_BEFORE_BIND:
		return "alg-accept-before-bind";
	case SFG_ILLEGAL_ALG_SETKEY_AFTER_ACCEPT:
		return "alg-setkey-after-accept";
	case SFG_ILLEGAL_ALG_OP_DIRECTION_MISMATCH:
		return "alg-op-direction-mismatch";
	case SFG_ILLEGAL_ALG_DOUBLE_ACCEPT:	return "alg-double-accept";
	case SFG_ILLEGAL_ALG_SET_AEAD_ON_NON_AEAD:
		return "alg-set-aead-on-non-aead";
	}
	return "unknown";
}

const char *sfg_conn_state_name(enum sfg_conn_state st)
{
	switch (st) {
	case SFG_CONN_INIT:		return "INIT";
	case SFG_CONN_CREATED:		return "CREATED";
	case SFG_CONN_BOUND:		return "BOUND";
	case SFG_CONN_LISTENING:	return "LISTENING";
	case SFG_CONN_ACCEPTED:		return "ACCEPTED";
	}
	return "UNKNOWN";
}

void sfg_publish_illegal(enum sfg_illegal_op op, enum sfg_conn_state at,
			 int family, int fd)
{
	struct childdata *child = this_child();

	if (child != NULL) {
		child->last_sfg_illegal.op = op;
		child->last_sfg_illegal.at = at;
		child->last_sfg_illegal.family = family;
	}

	output(2, "sfg illegal: %s fd=%d family=%d state=%s\n",
	       sfg_illegal_name(op), fd, family, sfg_conn_state_name(at));
}

void sfg_default_pick_triplet(int family, struct socket_triplet *out)
{
	const struct netproto *proto;

	out->family = family;
	out->type = SOCK_STREAM;
	out->protocol = 0;

	if (family <= 0 || family >= TRINITY_PF_MAX)
		return;

	proto = net_protocols[family].proto;
	if (proto == NULL || proto->valid_triplets == NULL ||
	    proto->nr_triplets == 0)
		return;

	*out = proto->valid_triplets[rnd_modulo_u32(proto->nr_triplets)];
}

int sfg_default_bind(int fd, struct socket_triplet *triplet,
		     struct socket_ctx *ctx)
{
	const struct netproto *proto;
	struct sockaddr *addr = NULL;
	socklen_t addrlen = 0;

	if (ctx->family == 0 || ctx->family >= TRINITY_PF_MAX)
		return -1;

	proto = net_protocols[ctx->family].proto;
	if (proto == NULL || proto->gen_sockaddr == NULL)
		return -1;

	proto->gen_sockaddr(triplet, &addr, &addrlen);
	if (addr == NULL)
		return -1;

	if (bind(fd, addr, addrlen) < 0) {
		tracked_free_now(addr);
		return -1;
	}

	/* Hand ownership to the ctx — the driver's teardown will
	 * tracked_free_now() this pointer on the out: path so later
	 * legs can reference it without regenerating (and without
	 * this helper needing to know when they're done with it). */
	ctx->bound_addr = addr;
	return 0;
}

bool sfg_default_needs_listen_accept(struct socket_triplet *triplet)
{
	return triplet->type == SOCK_STREAM ||
	       triplet->type == SOCK_SEQPACKET;
}

void sfg_default_walk_setsockopts(int fd, struct socket_triplet *triplet,
				  unsigned int n)
{
	const struct netproto *proto;
	void *scratch;
	unsigned int i;

	if (triplet->family == 0 || triplet->family >= TRINITY_PF_MAX)
		return;

	proto = net_protocols[triplet->family].proto;
	if (proto == NULL || proto->setsockopt == NULL)
		return;

	scratch = zmalloc(page_size);

	for (i = 0; i < n; i++) {
		struct sockopt so = { 0, 0, 0, 0 };

		memset(scratch, 0, page_size);
		so.optval = (unsigned long) scratch;
		so.optlen = sockoptlen(0);
		proto->setsockopt(&so, triplet);
		/* Defensive clamp: the per-proto callback is contracted to
		 * keep optlen within the optval allocation (page_size), but
		 * a regressed callback could pass a larger value to the
		 * kernel and leak heap bytes past the buffer.  Refuse it. */
		if (so.optlen > page_size)
			so.optlen = page_size;
		(void) setsockopt(fd, so.level, so.optname,
				  (const void *) so.optval, so.optlen);
	}

	free(scratch);
}

void sfg_default_data_leg(int data_fd,
			  const struct socket_family_grammar *sfg,
			  struct socket_triplet *triplet)
{
	const struct netproto *proto;
	void *payload = NULL;
	size_t payload_len = 0;
	struct iovec iov;
	struct msghdr msg;
	unsigned char rcvbuf[256];
	unsigned char cmsgbuf[CMSG_SPACE(256)];

	if (triplet->family == 0 || triplet->family >= TRINITY_PF_MAX)
		return;

	proto = net_protocols[triplet->family].proto;
	if (proto != NULL && proto->gen_msg != NULL) {
		proto->gen_msg(triplet, &payload, &payload_len);
	} else {
		payload_len = 16 + (rnd_modulo_u32(64));
		payload = zmalloc(payload_len);
		generate_rand_bytes(payload, payload_len);
	}

	memset(&msg, 0, sizeof(msg));
	iov.iov_base = payload;
	iov.iov_len  = payload_len;
	msg.msg_iov    = &iov;
	msg.msg_iovlen = 1;

	if (sfg->gen_cmsg != NULL) {
		memset(cmsgbuf, 0, sizeof(cmsgbuf));
		sfg->gen_cmsg(data_fd, triplet, &msg, cmsgbuf, sizeof(cmsgbuf));
	}

	(void) sendmsg(data_fd, &msg, MSG_NOSIGNAL | MSG_DONTWAIT);
	(void) recv(data_fd, rcvbuf, sizeof(rcvbuf), MSG_DONTWAIT);

	if (payload != NULL)
		free(payload);
}

/*
 * Framework-default phase ordering — the single sequence the pre-P1
 * driver hardcoded.  Consulted for every family that does not opt in
 * to phase_orders, and for triplets a family's phase_orders_apply gate
 * declines (e.g. inet's UDP path).  LISTEN/ACCEPT stay in the ordering
 * unconditionally: their case bodies self-gate via needs_listen_accept
 * so non-STREAM triplets skip them cleanly without a second ordering.
 */
static const struct sfg_phase_order sfg_default_order = {
	{ SFG_PHASE_SOCKET, SFG_PHASE_PRE_CFG, SFG_PHASE_WALK,
	  SFG_PHASE_BIND, SFG_PHASE_POST_CFG,
	  SFG_PHASE_LISTEN, SFG_PHASE_ACCEPT, SFG_PHASE_DATA,
	  SFG_PHASE_END },
};

/*
 * P4 arm id: one grammar "arm" is a (family, order-index) pair.
 * Several executed sequence hashes can map to one arm (via needs_la
 * gating and mid-walk bails), so reward is stored per hash-slot and
 * rolled up to the arm at pick time.  Packing family in the high bits
 * and the order-index in the low byte lets the rollup side (here) and
 * the credit side (sfg_seq_credit) derive the identical id.  order-
 * index is < SFG_MAX_PHASES and family is a small AF_* constant, so
 * the low byte never overflows.
 */
static inline uint32_t sfg_arm_id(int family, unsigned int order_idx)
{
	return ((uint32_t)family << 8) | (order_idx & 0xffu);
}

/* P4 tilt strength: 1-in-N picks consult the reward arms; the other
 * N-1 stay uniform.  ε = 1/8 keeps the uniform pick strongly dominant
 * so the feedback tilt never collapses into a greedy coverage-chaser. */
#define SFG_P4_EPSILON_DENOM	8u

static const struct sfg_phase_order *
sfg_pick_phase_order(const struct socket_family_grammar *sfg,
		     const struct socket_triplet *triplet)
{
	unsigned int count, idx, slot, best_idx = 0;
	uint64_t best_r = 0, best_a = 0;
	bool have = false;

	if (sfg->phase_orders == NULL || sfg->nr_phase_orders == 0)
		return &sfg_default_order;
	if (sfg->phase_orders_apply != NULL &&
	    !sfg->phase_orders_apply(triplet))
		return &sfg_default_order;

	/*
	 * P4 feedback tilt.  With the dominant probability keep the
	 * uniform pick; with probability 1/SFG_P4_EPSILON_DENOM roll up
	 * each candidate arm's mean reward over the ring and pick the
	 * best.  Cold start (no credited slot for any arm of this family)
	 * falls through to the uniform pick.
	 */
	if (!ONE_IN(SFG_P4_EPSILON_DENOM))
		return &sfg->phase_orders[rnd_modulo_u32(sfg->nr_phase_orders)];

	count = __atomic_load_n(&shm->sfg_seq_count, __ATOMIC_ACQUIRE);
	if (count > SFG_SEQ_HASH_CAP)		/* clamp: shm may be corrupted */
		count = SFG_SEQ_HASH_CAP;
	for (idx = 0; idx < sfg->nr_phase_orders; idx++) {
		uint32_t arm = sfg_arm_id(triplet->family, idx);
		uint64_t r = 0, a = 0;

		for (slot = 0; slot < count; slot++) {
			uint32_t at = __atomic_load_n(
				&shm->sfg_seq_attempts[slot], __ATOMIC_RELAXED);

			if (at == 0)
				continue;
			if (__atomic_load_n(&shm->sfg_seq_arm[slot],
					    __ATOMIC_RELAXED) != arm)
				continue;
			r += __atomic_load_n(&shm->sfg_seq_reward[slot],
					     __ATOMIC_RELAXED);
			a += at;
		}
		if (a == 0)
			continue;
		/* mean r/a > best_r/best_a, cross-multiplied to stay integer. */
		if (!have || r * best_a > best_r * a) {
			best_r = r;
			best_a = a;
			best_idx = idx;
			have = true;
		}
	}

	if (have) {
		__atomic_add_fetch(&shm->stats.socket_family_grammar_feedback_picks,
				   1, __ATOMIC_RELAXED);
		return &sfg->phase_orders[best_idx];
	}
	return &sfg->phase_orders[rnd_modulo_u32(sfg->nr_phase_orders)];
}

/*
 * Injector: with low probability, splice EXACTLY ONE precondition-
 * violating step into an otherwise-coherent plan.  Kept rare so the
 * bulk of walks stay coherent and the P1 sequence-variety metric
 * stays interpretable; a tighter rate would swamp the variety signal
 * with illegal-step noise.  Only fires on the inet/TCP arm today
 * (mirrors P1's inet_phase_orders_apply scope); other families opt
 * in as their grammar tables land.
 */
#define SFG_ILLEGAL_RATE	16

static enum sfg_illegal_op sfg_pick_illegal_op(int family)
{
	static const enum sfg_illegal_op inet_ops[] = {
		SFG_ILLEGAL_ACCEPT_NON_LISTENER,
		SFG_ILLEGAL_BIND_AFTER_LISTEN,
		SFG_ILLEGAL_SEND_BEFORE_BIND,
		SFG_ILLEGAL_DOUBLE_SHUTDOWN,
	};
#ifdef USE_IF_ALG
	static const enum sfg_illegal_op alg_ops[] = {
		SFG_ILLEGAL_ALG_SEND_BEFORE_SETKEY,
		SFG_ILLEGAL_ALG_RECV_ON_EMPTY_TSGL,
		SFG_ILLEGAL_ALG_ACCEPT_BEFORE_BIND,
		SFG_ILLEGAL_ALG_SETKEY_AFTER_ACCEPT,
		SFG_ILLEGAL_ALG_OP_DIRECTION_MISMATCH,
		SFG_ILLEGAL_ALG_DOUBLE_ACCEPT,
		SFG_ILLEGAL_ALG_SET_AEAD_ON_NON_AEAD,
	};

	if (family == PF_ALG)
		return alg_ops[rnd_modulo_u32(ARRAY_SIZE(alg_ops))];
#endif
	(void)family;
	return inet_ops[rnd_modulo_u32(ARRAY_SIZE(inet_ops))];
}

/*
 * Find the first index of `step` in the ordering, stopping at the
 * SFG_PHASE_END terminator.  Returns -1 if the step is absent (or
 * the ordering is malformed / unterminated within SFG_MAX_PHASES).
 */
static int sfg_find_step(const struct sfg_phase_order *o, unsigned char step)
{
	unsigned int i;

	for (i = 0; i < SFG_MAX_PHASES; i++) {
		if (o->steps[i] == step)
			return (int) i;
		if (o->steps[i] == SFG_PHASE_END)
			return -1;
	}
	return -1;
}

/*
 * Insert `n` step bytes at position `pos`, shifting the rest of the
 * ordering (including the SFG_PHASE_END terminator) right by `n`.
 * Returns false if the resulting ordering would leave no room for
 * the terminator inside SFG_MAX_PHASES.
 */
static bool sfg_insert_steps(struct sfg_phase_order *o, unsigned int pos,
			     const unsigned char *seq, unsigned int n)
{
	unsigned int len = 0;

	while (len < SFG_MAX_PHASES && o->steps[len] != SFG_PHASE_END)
		len++;
	if (len + n >= SFG_MAX_PHASES)
		return false;

	memmove(&o->steps[pos + n], &o->steps[pos],
		(len + 1 - pos) * sizeof(o->steps[0]));
	memcpy(&o->steps[pos], seq, n * sizeof(o->steps[0]));
	return true;
}

/*
 * Splice one illegal step into a legal ordering.  Copies the picked
 * legal order into *out and mutates it in place per the chosen op:
 *
 *   ACCEPT_NON_LISTENER: ILLEGAL inserted immediately BEFORE LISTEN,
 *      so it fires on a BOUND fd that never listen()ed.
 *   BIND_AFTER_LISTEN:   ILLEGAL inserted immediately AFTER LISTEN,
 *      so it fires bind() on a LISTENING fd.
 *   DOUBLE_SHUTDOWN:     ILLEGAL inserted immediately AFTER DATA, so
 *      it fires the double shutdown() on the ACCEPTED child_fd (or
 *      the LISTENING parent_fd if accept never took) once the
 *      coherent walk is otherwise complete.
 *   SEND_BEFORE_BIND:    ILLEGAL + a second DATA inserted immediately
 *      BEFORE BIND.  ILLEGAL publishes the label; the following DATA
 *      step fires sendmsg on the still-CREATED parent_fd (the DATA
 *      case's data_fd fallback resolves to parent_fd when not
 *      ACCEPTED).  The trailing legal DATA leg is untouched.
 *
 * Returns true on successful splice, false if the target step is
 * missing from the input ordering or the insertion would overflow.
 * On false the caller leaves the picked legal ordering unmutated so
 * the walk falls back to a coherent plan.
 */
#ifdef USE_IF_ALG
/*
 * AF_ALG illegal orderings build a fresh hostile plan rather than
 * splicing into a legal one — the AF_ALG preconditions we violate
 * (SETKEY-before-send, non-empty tsgl-before-recv, bind-before-accept)
 * are baked into the LEGAL orderings themselves, so a pure insertion
 * can't achieve "reach ACCEPTED without SETKEY" or "reach RECV without
 * SEND_MORE" shapes.  Overwriting the picked ordering with a bespoke
 * short plan is cleaner than teaching the splicer to remove steps.
 * Every plan starts SOCKET, terminates on SFG_PHASE_ILLEGAL, and stays
 * well inside SFG_MAX_PHASES.
 */
static bool sfg_build_illegal_order_alg(struct sfg_phase_order *out,
					enum sfg_illegal_op op)
{
	static const unsigned char socket_illegal[] = {
		SFG_PHASE_SOCKET, SFG_PHASE_ILLEGAL, SFG_PHASE_END };
	static const unsigned char bind_illegal[] = {
		SFG_PHASE_SOCKET, SFG_PHASE_ALG_BIND,
		SFG_PHASE_ILLEGAL, SFG_PHASE_END };
	static const unsigned char accept_illegal[] = {
		SFG_PHASE_SOCKET, SFG_PHASE_ALG_BIND,
		SFG_PHASE_ALG_ACCEPT, SFG_PHASE_ILLEGAL,
		SFG_PHASE_END };
	static const unsigned char setkey_accept_illegal[] = {
		SFG_PHASE_SOCKET, SFG_PHASE_ALG_BIND,
		SFG_PHASE_ALG_SETKEY, SFG_PHASE_ALG_ACCEPT,
		SFG_PHASE_ILLEGAL, SFG_PHASE_END };
	const unsigned char *src;
	size_t srclen;

	switch (op) {
	case SFG_ILLEGAL_ALG_ACCEPT_BEFORE_BIND:
		src = socket_illegal;
		srclen = sizeof(socket_illegal);
		break;
	case SFG_ILLEGAL_ALG_SET_AEAD_ON_NON_AEAD:
		/* Fires the SET_AEAD_AUTHSIZE setsockopt after BIND but
		 * before SETKEY, so ctx->fam.alg.type reflects the drawn
		 * algorithm without being masked by later steps. */
		src = bind_illegal;
		srclen = sizeof(bind_illegal);
		break;
	case SFG_ILLEGAL_ALG_SEND_BEFORE_SETKEY:
	case SFG_ILLEGAL_ALG_SETKEY_AFTER_ACCEPT:
	case SFG_ILLEGAL_ALG_DOUBLE_ACCEPT:
		src = accept_illegal;
		srclen = sizeof(accept_illegal);
		break;
	case SFG_ILLEGAL_ALG_RECV_ON_EMPTY_TSGL:
	case SFG_ILLEGAL_ALG_OP_DIRECTION_MISMATCH:
		src = setkey_accept_illegal;
		srclen = sizeof(setkey_accept_illegal);
		break;
	default:
		return false;
	}
	if (srclen > sizeof(out->steps))
		return false;
	memset(out->steps, 0, sizeof(out->steps));
	memcpy(out->steps, src, srclen);
	return true;
}
#endif /* USE_IF_ALG */

static bool sfg_splice_illegal(struct sfg_phase_order *out,
			       const struct sfg_phase_order *in,
			       enum sfg_illegal_op op)
{
	unsigned char seq[2] = { SFG_PHASE_ILLEGAL, 0 };
	unsigned int nseq = 1;
	int pos;

#ifdef USE_IF_ALG
	switch (op) {
	case SFG_ILLEGAL_ALG_SEND_BEFORE_SETKEY:
	case SFG_ILLEGAL_ALG_RECV_ON_EMPTY_TSGL:
	case SFG_ILLEGAL_ALG_ACCEPT_BEFORE_BIND:
	case SFG_ILLEGAL_ALG_SETKEY_AFTER_ACCEPT:
	case SFG_ILLEGAL_ALG_OP_DIRECTION_MISMATCH:
	case SFG_ILLEGAL_ALG_DOUBLE_ACCEPT:
	case SFG_ILLEGAL_ALG_SET_AEAD_ON_NON_AEAD:
		(void)in;
		return sfg_build_illegal_order_alg(out, op);
	default:
		break;
	}
#endif

	*out = *in;

	switch (op) {
	case SFG_ILLEGAL_ACCEPT_NON_LISTENER:
		pos = sfg_find_step(out, SFG_PHASE_LISTEN);
		break;
	case SFG_ILLEGAL_BIND_AFTER_LISTEN:
		pos = sfg_find_step(out, SFG_PHASE_LISTEN);
		if (pos >= 0)
			pos++;
		break;
	case SFG_ILLEGAL_DOUBLE_SHUTDOWN:
		pos = sfg_find_step(out, SFG_PHASE_DATA);
		if (pos >= 0)
			pos++;
		break;
	case SFG_ILLEGAL_SEND_BEFORE_BIND:
		pos = sfg_find_step(out, SFG_PHASE_BIND);
		seq[1] = SFG_PHASE_DATA;
		nseq = 2;
		break;
	default:
		return false;
	}
	if (pos < 0)
		return false;
	return sfg_insert_steps(out, (unsigned int) pos, seq, nseq);
}

/*
 * SFG_PHASE_ILLEGAL handler.  The ONE place in the executor that
 * deliberately bypasses the guard rails the legal phases self-gate
 * with (ACCEPT only when LISTENING; DATA falls back to parent_fd;
 * LISTEN gates on needs_la) — the whole point is to fire the raw
 * illegal syscall against the current fd regardless of conn_state so
 * the kernel path that would normally be unreachable from a coherent
 * walk gets exercised.
 *
 * Publishes labels on both channels (childdata slot + on-wire
 * breadcrumb) IMMEDIATELY BEFORE firing so an oops inside the illegal
 * syscall carries an unambiguous forensic tail on netconsole / logview
 * and lands in the post-mortem summary block via last_sfg_illegal.
 *
 * For SEND_BEFORE_BIND the handler is publish-only: the extra DATA
 * step the splicer put immediately after this pseudo-step fires the
 * actual sendmsg() on the unbound parent_fd (that ordering-only case
 * is what makes SEND_BEFORE_BIND fit the same "one label per walk"
 * contract as the three handler-issued ops).
 */
static void sfg_do_illegal_step(struct socket_ctx *ctx,
				struct socket_triplet *triplet,
				enum sfg_illegal_op op)
{
	int fd;

	/* Route each op to the fd whose kernel path a real crash would
	 * land on: DOUBLE_SHUTDOWN + the AF_ALG op-fd ops target the
	 * accepted child_fd (falling back to parent_fd if accept never
	 * took); every other op targets the parent_fd (pre-LISTEN accept
	 * / at-LISTEN bind / pre-BIND send / AF_ALG parent-side ops). */
	switch (op) {
	case SFG_ILLEGAL_DOUBLE_SHUTDOWN:
#ifdef USE_IF_ALG
	case SFG_ILLEGAL_ALG_SEND_BEFORE_SETKEY:
	case SFG_ILLEGAL_ALG_RECV_ON_EMPTY_TSGL:
	case SFG_ILLEGAL_ALG_OP_DIRECTION_MISMATCH:
#endif
		fd = (ctx->child_fd >= 0) ? ctx->child_fd : ctx->parent_fd;
		break;
	default:
		fd = ctx->parent_fd;
		break;
	}

	ctx->illegal_op = op;
	ctx->illegal_at = ctx->conn_state;
	sfg_publish_illegal(op, ctx->conn_state, ctx->family, fd);

	switch (op) {
	case SFG_ILLEGAL_ACCEPT_NON_LISTENER:
		/* accept() on a BOUND-not-LISTENING fd: the guard case in
		 * the legal SFG_PHASE_ACCEPT arm gates on conn_state ==
		 * LISTENING, so no coherent walk ever reaches this kernel
		 * path.  Discard any fd that unexpectedly escapes. */
	{
		int a = accept(fd, NULL, NULL);

		if (a >= 0)
			close(a);
		break;
	}
	case SFG_ILLEGAL_BIND_AFTER_LISTEN: {
		const struct netproto *proto;
		struct sockaddr *addr = NULL;
		socklen_t addrlen = 0;

		if (ctx->family <= 0 || ctx->family >= TRINITY_PF_MAX)
			break;
		proto = net_protocols[ctx->family].proto;
		if (proto == NULL || proto->gen_sockaddr == NULL)
			break;
		/* Fresh sockaddr rather than reusing ctx->bound_addr so a
		 * downstream free path never sees the same pointer twice. */
		proto->gen_sockaddr(triplet, &addr, &addrlen);
		if (addr != NULL) {
			(void) bind(fd, addr, addrlen);
			tracked_free_now(addr);
		}
		break;
	}
	case SFG_ILLEGAL_DOUBLE_SHUTDOWN:
		(void) shutdown(fd, SHUT_RDWR);
		(void) shutdown(fd, SHUT_RDWR);
		break;
	case SFG_ILLEGAL_SEND_BEFORE_BIND:
		/* Publish-only.  The trailing SFG_PHASE_DATA step the
		 * splicer inserted immediately after this pseudo-step
		 * issues the sendmsg on the still-CREATED parent_fd. */
		break;
#ifdef USE_IF_ALG
	case SFG_ILLEGAL_ALG_ACCEPT_BEFORE_BIND:
	case SFG_ILLEGAL_ALG_DOUBLE_ACCEPT: {
		/* accept() on the parent fd.  For ACCEPT_BEFORE_BIND the
		 * parent is CREATED-not-BOUND (af_alg_accept: ask->type is
		 * NULL); for DOUBLE_ACCEPT the parent already yielded one
		 * op fd and a second accept() creates two op sockets
		 * sharing one alg_sock (the refcount edge). */
		int a = accept(fd, NULL, NULL);

		if (a >= 0)
			close(a);
		break;
	}
	case SFG_ILLEGAL_ALG_SEND_BEFORE_SETKEY: {
		/* sendmsg on the ACCEPTED-but-unkeyed op fd.  skcipher /
		 * aead reject unkeyed operations at the ctx->more / setkey
		 * gate in af_alg_sendmsg. */
		unsigned char buf[16];
		struct iovec iov;
		struct msghdr mh;

		generate_rand_bytes(buf, sizeof(buf));
		memset(&mh, 0, sizeof(mh));
		iov.iov_base = buf;
		iov.iov_len = sizeof(buf);
		mh.msg_iov = &iov;
		mh.msg_iovlen = 1;
		(void) sendmsg(fd, &mh, MSG_DONTWAIT);
		break;
	}
	case SFG_ILLEGAL_ALG_RECV_ON_EMPTY_TSGL: {
		/* The documented af_alg_pull_tsgl OOB trigger: recv() on
		 * an ACCEPTED op fd with no accumulated tsgl (walker
		 * skipped SEND_MORE for this walk).  Highest-value member
		 * of the AF_ALG illegal set — exactly the shape upstream
		 * CI has a C reproducer for. */
		unsigned char buf[64];

		(void) recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
		break;
	}
	case SFG_ILLEGAL_ALG_SETKEY_AFTER_ACCEPT: {
		/* setsockopt(ALG_SET_KEY) on the parent AFTER the op fd
		 * exists — races af_alg_release_parent refcount
		 * assumptions.  Always fires on ctx->parent_fd (not fd)
		 * because the target is the parent regardless of which fd
		 * the fd-picker returned. */
		unsigned char key[32];

		if (ctx->parent_fd < 0)
			break;
		generate_rand_bytes(key, sizeof(key));
		(void) setsockopt(ctx->parent_fd, SOL_ALG, ALG_SET_KEY,
				  key, sizeof(key));
		break;
	}
	case SFG_ILLEGAL_ALG_OP_DIRECTION_MISMATCH: {
		/* sendmsg with ALG_SET_OP=DECRYPT cmsg + random plaintext
		 * -shaped payload.  Feeds aead_recvmsg's length math a
		 * data-vs-authsize mismatch and stresses
		 * crypto_aead_decrypt's -EBADMSG path. */
		unsigned char cbuf[CMSG_SPACE(sizeof(uint32_t))];
		unsigned char payload[64];
		struct iovec iov;
		struct msghdr mh;
		struct cmsghdr *cmsg;
		uint32_t decrypt_op = ALG_OP_DECRYPT;

		memset(cbuf, 0, sizeof(cbuf));
		memset(&mh, 0, sizeof(mh));
		mh.msg_control = cbuf;
		mh.msg_controllen = sizeof(cbuf);
		cmsg = CMSG_FIRSTHDR(&mh);
		cmsg->cmsg_level = SOL_ALG;
		cmsg->cmsg_type = ALG_SET_OP;
		cmsg->cmsg_len = CMSG_LEN(sizeof(decrypt_op));
		memcpy(CMSG_DATA(cmsg), &decrypt_op, sizeof(decrypt_op));

		generate_rand_bytes(payload, sizeof(payload));
		iov.iov_base = payload;
		iov.iov_len = sizeof(payload);
		mh.msg_iov = &iov;
		mh.msg_iovlen = 1;
		(void) sendmsg(fd, &mh, MSG_DONTWAIT);
		break;
	}
	case SFG_ILLEGAL_ALG_SET_AEAD_ON_NON_AEAD: {
		/* ALG_SET_AEAD_AUTHSIZE on a BOUND-but-non-AEAD parent:
		 * the type ->setauthsize hook is NULL.  Fires
		 * unconditionally — a coincidental AEAD draw at bind
		 * would leave this a legal-shape syscall, but the
		 * published label still names the intent so the wire
		 * story is unambiguous. */
		unsigned int authsize;

		if (ctx->parent_fd < 0)
			break;
		authsize = alg_boundary_authsizes[
			rnd_modulo_u32(alg_boundary_authsizes_count)];
		(void) setsockopt(ctx->parent_fd, SOL_ALG,
				  ALG_SET_AEAD_AUTHSIZE, NULL, authsize);
		break;
	}
#endif
	default:
		break;
	}
}

/*
 * FNV-1a step-ID hash.  Streamed per-step from the executor loop so
 * a walk that bails mid-sequence hashes only the steps that actually
 * ran — the truncated hash is a distinct sequence in its own right,
 * which is the right variety signal for the P1 metric.
 */
#define SFG_FNV1A_OFFSET	0x811c9dc5u
#define SFG_FNV1A_PRIME		0x01000193u

static inline uint32_t sfg_fnv1a_step(uint32_t h, unsigned char step)
{
	h ^= step;
	h *= SFG_FNV1A_PRIME;
	return h;
}

/* Returned by sfg_seq_record when the ring is full and the hash was
 * not already present -- the caller has no slot to attach per-sequence
 * data to and skips the attempt. */
#define SFG_SEQ_SLOT_NONE	((unsigned int)-1)

/*
 * Record a per-walk sequence hash in shm's bounded ring.  Linear scan
 * to skip duplicates; CAS on sfg_seq_count reserves a fresh slot and
 * bumps stats.socket_family_grammar_distinct_seq exactly once per new
 * sequence observed fleet-wide.  Saturates silently once the ring
 * fills (SFG_SEQ_HASH_CAP entries); the variety-signal use case does
 * not need a full inventory.
 *
 * Returns the ring slot holding this hash -- the index found on a
 * duplicate, or the freshly CAS-reserved slot on a first sighting --
 * so a caller can attach per-sequence data (the P4 reward arms) keyed
 * by the same slot.  Returns SFG_SEQ_SLOT_NONE when the ring is full.
 */
static unsigned int sfg_seq_record(uint32_t h)
{
	unsigned int count, i, slot;

	count = __atomic_load_n(&shm->sfg_seq_count, __ATOMIC_ACQUIRE);
	for (;;) {
		if (count > SFG_SEQ_HASH_CAP)	/* clamp: shm may be corrupted */
			count = SFG_SEQ_HASH_CAP;
		for (i = 0; i < count; i++) {
			if (__atomic_load_n(&shm->sfg_seq_hashes[i],
					    __ATOMIC_RELAXED) == h)
				return i;
		}
		if (count >= SFG_SEQ_HASH_CAP)
			return SFG_SEQ_SLOT_NONE;
		slot = count;
		if (__atomic_compare_exchange_n(&shm->sfg_seq_count,
						&count, slot + 1,
						false,
						__ATOMIC_ACQ_REL,
						__ATOMIC_ACQUIRE)) {
			__atomic_store_n(&shm->sfg_seq_hashes[slot], h,
					 __ATOMIC_RELEASE);
			__atomic_add_fetch(
				&shm->stats.socket_family_grammar_distinct_seq,
				1, __ATOMIC_RELAXED);
			return slot;
		}
		/* CAS lost: `count` now holds the witnessed slot count;
		 * re-scan (the winning writer may have written OUR hash). */
	}
}

/* Halve reward+attempts for a slot once its attempt count reaches this
 * cap, so a barren-but-historically-lucky arm releases instead of
 * winning forever on a stale lifetime mean (coverage is non-stationary,
 * mirroring the strategy bandit's EMA decay discipline). */
#define SFG_P4_ATTEMPTS_CAP	1024u

/*
 * Credit one legal walk's new-edge reward to its ring slot.  Stamps the
 * owning arm on the slot's first credit (attempts 0 -> 1), accumulates
 * reward + attempts, and decays both by half on reaching the cap to
 * keep the rolled-up mean recent.  Concurrent crediting from sibling
 * children is atomic on the accumulate; the coarse cap-halve races
 * benignly -- a lost increment is noise in a heuristic tilt.
 */
static void sfg_seq_credit(unsigned int slot, uint32_t arm_id,
			   uint32_t reward)
{
	if (__atomic_load_n(&shm->sfg_seq_attempts[slot],
			    __ATOMIC_RELAXED) == 0)
		__atomic_store_n(&shm->sfg_seq_arm[slot], arm_id,
				 __ATOMIC_RELAXED);

	__atomic_add_fetch(&shm->sfg_seq_reward[slot], reward,
			   __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.socket_family_grammar_reward, reward,
			   __ATOMIC_RELAXED);

	if (__atomic_add_fetch(&shm->sfg_seq_attempts[slot], 1,
			       __ATOMIC_RELAXED) >= SFG_P4_ATTEMPTS_CAP) {
		__atomic_store_n(&shm->sfg_seq_reward[slot],
			__atomic_load_n(&shm->sfg_seq_reward[slot],
					__ATOMIC_RELAXED) / 2,
			__ATOMIC_RELAXED);
		__atomic_store_n(&shm->sfg_seq_attempts[slot],
			__atomic_load_n(&shm->sfg_seq_attempts[slot],
					__ATOMIC_RELAXED) / 2,
			__ATOMIC_RELAXED);
	}
}

#ifdef USE_IF_ALG
/*
 * AF_ALG phase handlers for grammar_alg (see net/proto/alg.c).  These
 * run as ctx-aware executor case bodies rather than sfg-> callbacks
 * because the stateless (fd, triplet) callback signature can't thread
 * key_set / alg type / staged authsize+assoclen across phases — every
 * handler reads or writes ctx->fam.alg.  The AEAD-only phases self-gate
 * on ctx->fam.alg.type so a non-AEAD algorithm draw at ALG_BIND
 * degenerates cleanly on the full-AEAD ordering.
 *
 * Return true from bind/accept helpers on success; false signals bail
 * to the executor loop so late phases don't run against an unopened fd.
 */

static const struct {
	enum sfg_alg_type sfg;
	enum alg_dict_type dict;
	const char *str;
} sfg_alg_types[] = {
	{ SFG_ALG_TYPE_HASH,	 ALG_DICT_HASH,	    "hash"     },
	{ SFG_ALG_TYPE_SKCIPHER, ALG_DICT_SKCIPHER, "skcipher" },
	{ SFG_ALG_TYPE_AEAD,	 ALG_DICT_AEAD,	    "aead"     },
	{ SFG_ALG_TYPE_RNG,	 ALG_DICT_RNG,	    "rng"      },
};

static bool sfg_alg_do_bind(struct socket_ctx *ctx, unsigned int *err_burst)
{
	struct sockaddr_alg *sa = &ctx->fam.alg.sa;
	unsigned int idx;

	if (ctx->conn_state != SFG_CONN_CREATED || ctx->parent_fd < 0)
		return false;

	memset(sa, 0, sizeof(*sa));
	sa->salg_family = AF_ALG;

	if (ONE_IN(8)) {
		/* Copy Fail-shaped bait ported from the retired
		 * run_alg_chain arm: aead/authencesn-with-extended-sn.
		 * Kept on its own 1-in-8 gate so the CVE-bait probing
		 * load stays steady after the standalone AF_ALG walker
		 * went away. */
		strncpy((char *)sa->salg_type, "aead",
			sizeof(sa->salg_type) - 1);
		strncpy((char *)sa->salg_name, AUTHENCESN_NAME,
			sizeof(sa->salg_name) - 1);
		ctx->fam.alg.type = SFG_ALG_TYPE_AEAD;
		__atomic_add_fetch(
			&shm->stats.socket_family_chain_authencesn_attempts,
			1, __ATOMIC_RELAXED);
	} else {
		idx = rnd_modulo_u32(ARRAY_SIZE(sfg_alg_types));
		ctx->fam.alg.type = sfg_alg_types[idx].sfg;
		pick_alg(sfg_alg_types[idx].dict, sfg_alg_types[idx].str, sa);
	}

	if (bind(ctx->parent_fd, (struct sockaddr *)sa, sizeof(*sa)) < 0) {
		/* ENOENT/ESRCH are expected per-alg churn (curated dict
		 * covers algos not built on every kernel); only latch on
		 * signals the AF_ALG surface is unreachable. */
		if (errno == EPERM || errno == ENOPROTOOPT)
			(*err_burst)++;
		return false;
	}
	ctx->conn_state = SFG_CONN_BOUND;
	return true;
}

static void sfg_alg_do_setkey(struct socket_ctx *ctx)
{
	unsigned char keybuf[4096];
	unsigned int keylen, fill;

	if (ctx->conn_state != SFG_CONN_BOUND || ctx->parent_fd < 0)
		return;

	/* 70% curated valid 16..47, 30% boundary — same weighting as
	 * alg_socket_setup so grammar walks don't regress key-length
	 * coverage the per-syscall path already delivers. */
	if (rnd_modulo_u32(10) < 7)
		keylen = 16 + rnd_modulo_u32(32);
	else
		keylen = alg_boundary_keylens[
			rnd_modulo_u32(alg_boundary_keylens_count)];
	fill = keylen < sizeof(keybuf) ? keylen : sizeof(keybuf);
	generate_rand_bytes(keybuf, fill);
	if (setsockopt(ctx->parent_fd, SOL_ALG, ALG_SET_KEY, keybuf,
		       (socklen_t)keylen) == 0)
		ctx->fam.alg.key_set = true;
	/* rng/akcipher reject ALG_SET_KEY — tolerated; the walk continues
	 * to ACCEPT which may still succeed. */
}

static void sfg_alg_do_set_aead(struct socket_ctx *ctx)
{
	static const unsigned int assoclens[] = { 0, 1, 16, 64, 4096, 65536 };
	unsigned int authsize;

	if (ctx->conn_state != SFG_CONN_BOUND || ctx->parent_fd < 0)
		return;
	/* AEAD-only self-gate: SET_AEAD_AUTHSIZE on a non-aead alg has
	 * type->setauthsize == NULL and returns -ENOPROTOOPT, so firing
	 * it there is noise not coverage. */
	if (ctx->fam.alg.type != SFG_ALG_TYPE_AEAD)
		return;

	authsize = alg_boundary_authsizes[
		rnd_modulo_u32(alg_boundary_authsizes_count)];
	(void) setsockopt(ctx->parent_fd, SOL_ALG, ALG_SET_AEAD_AUTHSIZE,
			  NULL, authsize);
	ctx->fam.alg.authsize = authsize;
	ctx->fam.alg.assoclen = assoclens[rnd_modulo_u32(ARRAY_SIZE(assoclens))];
}

static bool sfg_alg_do_accept(struct socket_ctx *ctx, unsigned int *err_burst)
{
	if (ctx->conn_state != SFG_CONN_BOUND || ctx->parent_fd < 0)
		return false;

	ctx->child_fd = accept(ctx->parent_fd, NULL, NULL);
	if (ctx->child_fd < 0) {
		if (errno == EPERM || errno == ENOPROTOOPT)
			(*err_burst)++;
		return false;
	}
	ctx->conn_state = SFG_CONN_ACCEPTED;
	return true;
}

/*
 * Push ALG_SET_OP (+ optional ALG_SET_IV + optional
 * ALG_SET_AEAD_ASSOCLEN) as a cmsg batch on an empty-payload
 * sendmsg(MSG_MORE).  Empty-payload MSG_MORE opens the tsgl without
 * committing bytes; the following SEND_MORE case appends the actual
 * plaintext segments.  Assoclen is echoed from the value SET_AEAD
 * staged so aead_recvmsg's assoc-vs-data length math sees a matched
 * pair rather than a random draw.
 */
static void sfg_alg_do_cmsg(struct socket_ctx *ctx)
{
	unsigned char cbuf[CMSG_SPACE(sizeof(uint32_t)) +
			   CMSG_SPACE(sizeof(uint32_t) + 32) +
			   CMSG_SPACE(sizeof(uint32_t))];
	struct msghdr mh;
	struct cmsghdr *cmsg;
	uint32_t op, assoclen;
	unsigned char iv_bytes[32];
	uint32_t iv_hdr;
	unsigned int ivlen = 0;
	size_t off = 0;
	bool want_iv = RAND_BOOL();

	if (ctx->conn_state != SFG_CONN_ACCEPTED || ctx->child_fd < 0)
		return;

	memset(cbuf, 0, sizeof(cbuf));
	memset(&mh, 0, sizeof(mh));

	/* ALG_SET_OP always present. */
	op = RAND_BOOL() ? ALG_OP_ENCRYPT : ALG_OP_DECRYPT;
	cmsg = (struct cmsghdr *)(cbuf + off);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(sizeof(op));
	memcpy(CMSG_DATA(cmsg), &op, sizeof(op));
	off += CMSG_SPACE(sizeof(op));

	/* ALG_SET_IV: kernel format is af_alg_iv = {u32 ivlen; u8 iv[]}. */
	if (want_iv) {
		ivlen = 8 + rnd_modulo_u32(25);		/* 8..32 */
		iv_hdr = ivlen;
		generate_rand_bytes(iv_bytes, ivlen);
		cmsg = (struct cmsghdr *)(cbuf + off);
		cmsg->cmsg_level = SOL_ALG;
		cmsg->cmsg_type = ALG_SET_IV;
		cmsg->cmsg_len = CMSG_LEN(sizeof(iv_hdr) + ivlen);
		memcpy(CMSG_DATA(cmsg), &iv_hdr, sizeof(iv_hdr));
		memcpy(CMSG_DATA(cmsg) + sizeof(iv_hdr), iv_bytes, ivlen);
		off += CMSG_SPACE(sizeof(iv_hdr) + ivlen);
	}

	/* ALG_SET_AEAD_ASSOCLEN: only on AEAD; echoes the value SET_AEAD
	 * staged so aead_recvmsg's assoc-vs-data length math is coherent
	 * (the > sent-length case is exactly the memcpy_sglist GPF shape). */
	if (ctx->fam.alg.type == SFG_ALG_TYPE_AEAD) {
		assoclen = ctx->fam.alg.assoclen;
		cmsg = (struct cmsghdr *)(cbuf + off);
		cmsg->cmsg_level = SOL_ALG;
		cmsg->cmsg_type = ALG_SET_AEAD_ASSOCLEN;
		cmsg->cmsg_len = CMSG_LEN(sizeof(assoclen));
		memcpy(CMSG_DATA(cmsg), &assoclen, sizeof(assoclen));
		off += CMSG_SPACE(sizeof(assoclen));
	}

	mh.msg_control = cbuf;
	mh.msg_controllen = off;
	(void) sendmsg(ctx->child_fd, &mh, MSG_DONTWAIT | MSG_MORE);
}

/*
 * ~SFG_ALG_SPLICE_SUBST_PCT% of the time replace the buffer-sends leg
 * with a splice(tagged_fd -> pipe -> child_fd) pull from a page-cache
 * fd in the OBJ_FD_PAGECACHE pool so the walk reaches alg_sendpage
 * via splice_read_to_pipe -- coverage the buffer-sendmsg path never
 * lands.  Returns true when the splice pair completed and the caller
 * should skip the buffer sends; returns false on any setup miss so
 * the caller falls through.  Bumps socket_family_chain_splice_attempts
 * (retained from the retired run_alg_chain path -- one accounting
 * story for AF_ALG splice attempts, no new stats field) on every
 * attempt regardless of eventual outcome.
 */
static bool sfg_alg_try_splice_send(struct socket_ctx *ctx)
{
	unsigned int sndlen;
	int tagged_fd;
	ssize_t in_n;

	if (rnd_modulo_u32(100) >= SFG_ALG_SPLICE_SUBST_PCT)
		return false;

	tagged_fd = get_rand_pagecache_fd();
	if (tagged_fd < 0)
		return false;

	if (pipe2(ctx->fam.alg.splice_pfd, O_CLOEXEC) < 0)
		return false;

	__atomic_add_fetch(&shm->stats.socket_family_chain_splice_attempts, 1,
			   __ATOMIC_RELAXED);

	sndlen = 16 + rnd_modulo_u32(256 - 16 + 1);
	in_n = splice(tagged_fd, NULL, ctx->fam.alg.splice_pfd[1], NULL,
		      sndlen, SPLICE_F_NONBLOCK | SPLICE_F_MOVE);
	if (in_n <= 0)
		return false;

	(void) splice(ctx->fam.alg.splice_pfd[0], NULL, ctx->child_fd, NULL,
		      (size_t) in_n, SPLICE_F_NONBLOCK | SPLICE_F_MOVE);
	return true;
}

/*
 * N × sendmsg(MSG_MORE) with page-straddling segment sizes.  Drives
 * af_alg_sendmsg's cross-call path: tsgl accumulation across calls,
 * SG-list realloc as the accumulated length crosses the per-tsgl entry
 * cap, page-spanning where a segment's tail lands on a different page
 * from the next segment's head.  Terminal ALG_RECV closes the request
 * with a non-MSG_MORE flush.
 *
 * ~SFG_ALG_SPLICE_SUBST_PCT% of invocations first try a single splice
 * pair via sfg_alg_try_splice_send; on success the buffer-send loop
 * is skipped (the splice already fed the request), on any miss the
 * loop runs so the data leg still lands.
 */
static void sfg_alg_do_send_more(struct socket_ctx *ctx)
{
	static const unsigned int seg_sizes[] = {
		1, 4095, 4096, 4097, 8192, 2048, 4096 - 1, 4096 + 1,
	};
	unsigned int n = 2 + rnd_modulo_u32(7);		/* 2..8 */
	unsigned int cap = page_size * 3;
	unsigned char *scratch;
	unsigned int i;

	if (ctx->conn_state != SFG_CONN_ACCEPTED || ctx->child_fd < 0)
		return;

	if (sfg_alg_try_splice_send(ctx))
		return;

	scratch = zmalloc(cap);
	for (i = 0; i < n; i++) {
		unsigned int seglen = seg_sizes[
			rnd_modulo_u32(ARRAY_SIZE(seg_sizes))];
		struct iovec iov;
		struct msghdr mh;

		if (seglen > cap)
			seglen = cap;
		generate_rand_bytes(scratch, seglen);
		iov.iov_base = scratch;
		iov.iov_len  = seglen;
		memset(&mh, 0, sizeof(mh));
		mh.msg_iov = &iov;
		mh.msg_iovlen = 1;
		(void) sendmsg(ctx->child_fd, &mh, MSG_DONTWAIT | MSG_MORE);
	}
	free(scratch);
}

static void sfg_alg_do_recv(struct socket_ctx *ctx)
{
	unsigned char *rcvbuf;
	unsigned int rcvlen;

	if (ctx->conn_state != SFG_CONN_ACCEPTED || ctx->child_fd < 0)
		return;

	rcvlen = 16 + rnd_modulo_u32(4096);
	rcvbuf = zmalloc(rcvlen);
	(void) recv(ctx->child_fd, rcvbuf, rcvlen, MSG_DONTWAIT);
	free(rcvbuf);
}
#endif /* USE_IF_ALG */

/*
 * Drive one coherent grammar walk end to end.  The picker resolves a
 * per-family sfg_phase_order table entry and this loop drives each
 * step in turn against the shared socket_ctx.  Invariants every entry
 * in a legal phase_orders table satisfies (see the phase_orders field
 * in socket-family-grammar.h): SOCKET first; BIND before LISTEN;
 * LISTEN before ACCEPT; DATA only after a live connection; pre-bind
 * cfg pre-bind; post-bind cfg post-bind.  The executor TRUSTS the
 * table and does not re-validate — a family that puts a hostile
 * ordering into its table is telling the framework to run it.
 *
 * The illegal-step injector is the ONE controlled break in that
 * invariant model: with probability ONE_IN(SFG_ILLEGAL_RATE) it copies
 * the picked legal ordering into a stack-local scratch and splices
 * exactly one SFG_PHASE_ILLEGAL pseudo-step into it (see
 * sfg_splice_illegal / sfg_do_illegal_step above).  Legal table
 * entries STILL satisfy every invariant; the invariant break is
 * confined to a single, explicitly-labeled, opt-in path — never a
 * silent reorder.  The illegal handler is the only executor site that
 * deliberately bypasses the legal-phase guards; every non-illegal
 * step in the mutated ordering still self-gates via conn_state, so at
 * most one precondition-violating syscall fires per walk.
 */
bool run_grammar_chain(const struct socket_family_grammar *sfg,
		       unsigned int *err_burst)
{
	struct socket_triplet triplet = { 0, 0, 0 };
	struct socket_ctx ctx = {
		.parent_fd = -1,
		.child_fd = -1,
		.family = 0,
		.bound_addr = NULL,
		.conn_state = SFG_CONN_INIT,
		.illegal_op = SFG_ILLEGAL_NONE,
		.illegal_at = SFG_CONN_INIT,
#ifdef USE_IF_ALG
		/* splice_pfd defaults to {-1,-1} so the teardown gate
		 * can close guarded on >= 0.  All other fam.alg fields
		 * are zeroed by the partial designated initialiser. */
		.fam.alg.splice_pfd = { -1, -1 },
#endif
	};
	const struct sfg_phase_order *order;
	struct sfg_phase_order scratch_order;
	struct childdata *child = this_child();
	enum sfg_illegal_op illegal_op = SFG_ILLEGAL_NONE;
	int arm_idx = -1;
	unsigned int i;
	int data_fd;
	bool ok = false;
	bool bail = false;
	unsigned long kcov_cursor = 0;
	bool p4_sampling = false;
	unsigned long p4_edges = 0;
	unsigned int n_setsockopts;
	uint32_t seq_hash = SFG_FNV1A_OFFSET;
	unsigned int seq_len = 0;
	bool (*needs_la)(struct socket_triplet *);

	__atomic_add_fetch(&shm->stats.socket_family_grammar_runs, 1,
			   __ATOMIC_RELAXED);

	if (sfg->can_run != NULL && !sfg->can_run()) {
		sfg_mark_unsupported(sfg->family);
		(*err_burst)++;
		goto out;
	}

	if (sfg->pick_triplet != NULL)
		sfg->pick_triplet(&triplet);
	else
		sfg_default_pick_triplet(sfg->family, &triplet);
	ctx.family = triplet.family;

	n_setsockopts = 2 + (rnd_modulo_u32(5));	/* 2..6 coordinated calls */
	order = sfg_pick_phase_order(sfg, &triplet);
	/* Capture the picked legal arm (family, order-index) before any
	 * illegal splice repoints `order` at the scratch copy.  P4 credits
	 * the legal arm only, and only when the pick landed on a real
	 * phase_orders entry rather than the fixed default order. */
	if (sfg->phase_orders != NULL && order != &sfg_default_order)
		arm_idx = (int)(order - sfg->phase_orders);
	needs_la = sfg->needs_listen_accept != NULL ? sfg->needs_listen_accept
						    : sfg_default_needs_listen_accept;

	/* Illegal-step injection: only splice on the family/type arm the
	 * family's phase_orders_apply gate covers (matches P1 scope so
	 * an inet UDP walk on the default order never gets an ILLEGAL
	 * step even if the dice roll fires).  The ONE_IN gate keeps the
	 * rate rare so the P1 sequence-variety metric stays interpretable
	 * and the bulk of walks stay coherent. */
	if (sfg->phase_orders_apply != NULL &&
	    sfg->phase_orders_apply(&triplet) &&
	    ONE_IN(SFG_ILLEGAL_RATE)) {
		enum sfg_illegal_op op = sfg_pick_illegal_op(triplet.family);

		if (sfg_splice_illegal(&scratch_order, order, op)) {
			illegal_op = op;
			order = &scratch_order;
		}
	}

	/* Snapshot the child's live PC-trace position so the executor
	 * loop below can be scored by a read-only novelty probe over the
	 * PCs the loop appends.  The outer childop-attribution bracket
	 * (opened by the childop dispatcher) already owns the trace and
	 * is the authoritative writer of bucket_seen / dedup /
	 * generation; a nested inner bracket would nested-reject and
	 * leave the per-walk grammar reward silently dead, so instead
	 * this path samples the outer bracket's live trace without
	 * mutating any shm counter.  Paired with kcov_sample_new_edges
	 * after the loop. */
	if (child != NULL) {
		kcov_cursor = kcov_trace_pos(&child->kcov);
		p4_sampling = true;
	}

	for (i = 0; i < SFG_MAX_PHASES && !bail; i++) {
		enum sfg_phase step = order->steps[i];

		if (step == SFG_PHASE_END)
			break;

		seq_hash = sfg_fnv1a_step(seq_hash, (unsigned char)step);
		seq_len++;

		switch (step) {
		case SFG_PHASE_SOCKET:
			ctx.parent_fd = socket(triplet.family, triplet.type,
					       triplet.protocol);
			if (ctx.parent_fd < 0) {
				if (errno == EAFNOSUPPORT ||
				    errno == EPROTONOSUPPORT)
					sfg_mark_unsupported(sfg->family);
				(*err_burst)++;
				bail = true;
				break;
			}
			ctx.conn_state = SFG_CONN_CREATED;
			break;

		case SFG_PHASE_PRE_CFG:
			if (sfg->configure_pre_bind != NULL)
				sfg->configure_pre_bind(ctx.parent_fd,
							&triplet);
			break;

		case SFG_PHASE_WALK:
			if (sfg->walk_setsockopts != NULL)
				sfg->walk_setsockopts(ctx.parent_fd, &triplet,
						      n_setsockopts);
			else
				sfg_default_walk_setsockopts(ctx.parent_fd,
							     &triplet,
							     n_setsockopts);
			break;

		case SFG_PHASE_BIND:
			if (sfg->bind_or_connect != NULL) {
				if (sfg->bind_or_connect(ctx.parent_fd,
							 &triplet) < 0) {
					(*err_burst)++;
					bail = true;
					break;
				}
			} else {
				if (sfg_default_bind(ctx.parent_fd, &triplet,
						     &ctx) < 0) {
					(*err_burst)++;
					bail = true;
					break;
				}
			}
			ctx.conn_state = SFG_CONN_BOUND;
			break;

		case SFG_PHASE_POST_CFG:
			if (sfg->configure_post_bind != NULL)
				sfg->configure_post_bind(ctx.parent_fd,
							 &triplet);
			break;

		case SFG_PHASE_LISTEN:
			if (needs_la(&triplet)) {
				if (listen(ctx.parent_fd, 4) == 0)
					ctx.conn_state = SFG_CONN_LISTENING;
			}
			break;

		case SFG_PHASE_ACCEPT:
			if (ctx.conn_state == SFG_CONN_LISTENING) {
				ctx.child_fd = accept(ctx.parent_fd, NULL,
						      NULL);
				if (ctx.child_fd >= 0)
					ctx.conn_state = SFG_CONN_ACCEPTED;
			}
			break;

		case SFG_PHASE_DATA:
			data_fd = (ctx.conn_state == SFG_CONN_ACCEPTED)
					? ctx.child_fd : ctx.parent_fd;
			if (sfg->data_leg != NULL)
				sfg->data_leg(ctx.parent_fd, data_fd,
					      &triplet);
			else
				sfg_default_data_leg(data_fd, sfg, &triplet);
			ok = true;
			break;

		case SFG_PHASE_ILLEGAL:
			/* Never present in a legal ordering; only the
			 * injector splices it in.  illegal_op is
			 * SFG_ILLEGAL_NONE unless the injector fired, in
			 * which case the handler bypasses guards and
			 * publishes labels on both forensic channels
			 * before firing (or right before the trailing
			 * DATA step for SEND_BEFORE_BIND). */
			if (illegal_op != SFG_ILLEGAL_NONE)
				sfg_do_illegal_step(&ctx, &triplet,
						    illegal_op);
			break;

#ifdef USE_IF_ALG
		case SFG_PHASE_ALG_BIND:
			if (!sfg_alg_do_bind(&ctx, err_burst))
				bail = true;
			break;
		case SFG_PHASE_ALG_SETKEY:
			sfg_alg_do_setkey(&ctx);
			break;
		case SFG_PHASE_ALG_SET_AEAD:
			sfg_alg_do_set_aead(&ctx);
			break;
		case SFG_PHASE_ALG_ACCEPT:
			if (!sfg_alg_do_accept(&ctx, err_burst))
				bail = true;
			break;
		case SFG_PHASE_ALG_CMSG:
			sfg_alg_do_cmsg(&ctx);
			break;
		case SFG_PHASE_ALG_SEND_MORE:
			sfg_alg_do_send_more(&ctx);
			break;
		case SFG_PHASE_ALG_RECV:
			sfg_alg_do_recv(&ctx);
			/* AF_ALG orderings terminate on RECV — mark ok
			 * so the completed counter tracks legal walks
			 * that reached the data leg cleanly, mirroring
			 * SFG_PHASE_DATA on the inet-shaped orderings. */
			ok = true;
			break;
#else
		case SFG_PHASE_ALG_BIND:
		case SFG_PHASE_ALG_SETKEY:
		case SFG_PHASE_ALG_SET_AEAD:
		case SFG_PHASE_ALG_ACCEPT:
		case SFG_PHASE_ALG_CMSG:
		case SFG_PHASE_ALG_SEND_MORE:
		case SFG_PHASE_ALG_RECV:
			/* AF_ALG unavailable at build time; grammar_alg
			 * isn't registered so these IDs cannot appear in
			 * any ordering.  Skip silently for the enum
			 * exhaustiveness check. */
			break;
#endif

		case SFG_PHASE_END:
		default:
			break;
		}
	}

	if (p4_sampling)
		p4_edges = kcov_sample_new_edges(&child->kcov, &kcov_cursor);

	if (ok) {
		__atomic_add_fetch(&shm->stats.socket_family_grammar_completed,
				   1, __ATOMIC_RELAXED);
		*err_burst = 0;
	}

	if (seq_len > 0) {
		unsigned int slot = sfg_seq_record(seq_hash);

		/* Credit the legal arm's productivity: only a legal walk
		 * (no illegal splice) that owned its bracket and landed on a
		 * real phase_orders arm contributes reward. */
		if (p4_sampling && illegal_op == SFG_ILLEGAL_NONE &&
		    arm_idx >= 0 && slot != SFG_SEQ_SLOT_NONE)
			sfg_seq_credit(slot,
				       sfg_arm_id(triplet.family,
						  (unsigned int)arm_idx),
				       (uint32_t)p4_edges);
	}
out:
#ifdef USE_IF_ALG
	if (ctx.fam.alg.splice_pfd[0] >= 0)
		close(ctx.fam.alg.splice_pfd[0]);
	if (ctx.fam.alg.splice_pfd[1] >= 0)
		close(ctx.fam.alg.splice_pfd[1]);
#endif
	if (ctx.child_fd >= 0) {
		xdp_umem_release(ctx.child_fd);
		close(ctx.child_fd);
	}
	if (ctx.parent_fd >= 0) {
		xdp_umem_release(ctx.parent_fd);
		close(ctx.parent_fd);
	}
	if (ctx.bound_addr != NULL)
		tracked_free_now(ctx.bound_addr);
	return ok;
}
