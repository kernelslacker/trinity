/*
 * Per-family grammar table dispatcher.  Generalises the v1
 * socket_family_chain childop (296466cb1845 ("[childops] add socket-family-chain childop (AF_ALG)")) and v3's
 * splice-substitution data leg (6adbd3a6bbf2 ("[childops] socket-family-chain: splice-substitution data leg")) into a table-driven
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
#include "socket-family-grammar-internal.h"
#include "trinity.h"
#include "utils.h"
		/* keep last — matches net/proto-*.c order */
#include "rnd.h"
#include "xdp-umem-track.h"
#include "net/netlink/rtnl-ack-oracle.h"

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
		/*
		 * This path does a bare sendmsg() and never calls
		 * proto->post_send, so rtnl_oracle_drain() will not run.
		 * Cancel any pending sample: undo the NLM_F_ACK annotation
		 * and roll the counter back so the budget slot is not wasted
		 * on a path where draining is impossible.
		 */
		rtnl_oracle_abort();
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
		__atomic_add_fetch(&shm->stats.socket_family_grammar.feedback_picks,
				   1, __ATOMIC_RELAXED);
		return &sfg->phase_orders[best_idx];
	}
	return &sfg->phase_orders[rnd_modulo_u32(sfg->nr_phase_orders)];
}

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

	__atomic_add_fetch(&shm->stats.socket_family_grammar.runs, 1,
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

		default:
			break;
		}
	}

	if (p4_sampling)
		p4_edges = kcov_sample_new_edges(&child->kcov, &kcov_cursor);

	if (ok) {
		__atomic_add_fetch(&shm->stats.socket_family_grammar.completed,
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
