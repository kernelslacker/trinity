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
	};
	const struct sfg_phase_order *order;
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
