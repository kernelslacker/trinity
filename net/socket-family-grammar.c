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
#include <stdint.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "arch.h"		/* page_size */
#include "child.h"
#include "deferred-free.h"
#include "net.h"
#include "random.h"
#include "shm.h"
#include "socket-family-grammar.h"
#include "trinity.h"
#include "utils.h"
#include "compat.h"		/* keep last — matches net/proto-*.c order */
#include "rnd.h"
#include "xdp-umem-track.h"

/*
 * Registry filled in by per-family commits.  The trailing NULL is a
 * sentinel that lets the framework commit land before any family
 * does — sfg_pick_random_active() skips NULL entries.  When a family
 * is added it goes ABOVE the sentinel so ARRAY_SIZE() still spans
 * every real slot.
 */
static const struct socket_family_grammar * const sfg_registry[] = {
	&grammar_inet,
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

static const struct sfg_phase_order *
sfg_pick_phase_order(const struct socket_family_grammar *sfg,
		     const struct socket_triplet *triplet)
{
	if (sfg->phase_orders == NULL || sfg->nr_phase_orders == 0)
		return &sfg_default_order;
	if (sfg->phase_orders_apply != NULL &&
	    !sfg->phase_orders_apply(triplet))
		return &sfg_default_order;
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

static enum sfg_illegal_op sfg_pick_illegal_op(void)
{
	static const enum sfg_illegal_op ops[] = {
		SFG_ILLEGAL_ACCEPT_NON_LISTENER,
		SFG_ILLEGAL_BIND_AFTER_LISTEN,
		SFG_ILLEGAL_SEND_BEFORE_BIND,
		SFG_ILLEGAL_DOUBLE_SHUTDOWN,
	};

	return ops[rnd_modulo_u32(ARRAY_SIZE(ops))];
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
static bool sfg_splice_illegal(struct sfg_phase_order *out,
			       const struct sfg_phase_order *in,
			       enum sfg_illegal_op op)
{
	unsigned char seq[2] = { SFG_PHASE_ILLEGAL, 0 };
	unsigned int nseq = 1;
	int pos;

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

	/* DOUBLE_SHUTDOWN: prefer the ACCEPTED child_fd (that's the fd
	 * a real double-shutdown crash would land on); every other op
	 * targets the parent_fd (pre-LISTEN accept / at-LISTEN bind /
	 * pre-BIND send). */
	if (op == SFG_ILLEGAL_DOUBLE_SHUTDOWN && ctx->child_fd >= 0)
		fd = ctx->child_fd;
	else
		fd = ctx->parent_fd;

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

/*
 * Record a per-walk sequence hash in shm's bounded ring.  Linear scan
 * to skip duplicates; CAS on sfg_seq_count reserves a fresh slot and
 * bumps stats.socket_family_grammar_distinct_seq exactly once per new
 * sequence observed fleet-wide.  Saturates silently once the ring
 * fills (SFG_SEQ_HASH_CAP entries); the variety-signal use case does
 * not need a full inventory.
 */
static void sfg_seq_record(uint32_t h)
{
	unsigned int count, i, slot;

	count = __atomic_load_n(&shm->sfg_seq_count, __ATOMIC_ACQUIRE);
	for (;;) {
		for (i = 0; i < count; i++) {
			if (__atomic_load_n(&shm->sfg_seq_hashes[i],
					    __ATOMIC_RELAXED) == h)
				return;
		}
		if (count >= SFG_SEQ_HASH_CAP)
			return;
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
			return;
		}
		/* CAS lost: `count` now holds the witnessed slot count;
		 * re-scan (the winning writer may have written OUR hash). */
	}
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
	};
	const struct sfg_phase_order *order;
	struct sfg_phase_order scratch_order;
	enum sfg_illegal_op illegal_op = SFG_ILLEGAL_NONE;
	unsigned int i;
	int data_fd;
	bool ok = false;
	bool bail = false;
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
		enum sfg_illegal_op op = sfg_pick_illegal_op();

		if (sfg_splice_illegal(&scratch_order, order, op)) {
			illegal_op = op;
			order = &scratch_order;
		}
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

		case SFG_PHASE_END:
		default:
			break;
		}
	}

	if (ok) {
		__atomic_add_fetch(&shm->stats.socket_family_grammar_completed,
				   1, __ATOMIC_RELAXED);
		*err_burst = 0;
	}

	if (seq_len > 0)
		sfg_seq_record(seq_hash);
out:
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
