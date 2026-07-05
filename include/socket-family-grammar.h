#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <sys/socket.h>

#include "syscall.h"	/* socket_triplet */

struct msghdr;

/*
 * Connection-phase tag for socket_ctx below.  Set by run_grammar_chain
 * as it walks the shared socket/bind/listen/accept legs, and read by
 * downstream legs (currently just the data-leg fd pick) to decide which
 * fd to run against.  Replaces the bare `bool listening` the pre-ctx
 * driver carried in its stack frame, so families that grow additional
 * phases (e.g. connect(), a second accept()) can extend the enum
 * without a fresh boolean per phase.
 */
enum sfg_conn_state {
	SFG_CONN_INIT = 0,	/* nothing opened yet */
	SFG_CONN_CREATED,	/* parent_fd is a live socket() */
	SFG_CONN_BOUND,		/* bind_or_connect leg succeeded */
	SFG_CONN_LISTENING,	/* listen() succeeded, accept() not yet */
	SFG_CONN_ACCEPTED,	/* accept() produced a live child_fd */
};

/*
 * Per-invocation state for run_grammar_chain.  Generalises the AF_ALG-
 * only alg_chain_iter_ctx (childops/net/socket-family-chain.c) so any
 * family the grammar table drives can carry its fds, bound address and
 * lifecycle position through the chain without loose locals.
 *
 * Field defaults must match the -1 / NULL / SFG_CONN_INIT initialisation
 * the driver uses so the teardown gates skip work any early bail
 * skipped: parent_fd/child_fd default to -1 (close guarded on >= 0),
 * bound_addr defaults to NULL (tracked_free_now guarded on non-NULL),
 * conn_state defaults to SFG_CONN_INIT.
 *
 * The AF_ALG childop keeps its own alg_chain_iter_ctx for the AF_ALG-
 * specific extras (sockaddr_alg body, sndbuf/rcvbuf, type enum, splice
 * pipe fds); folding it onto this struct is a follow-up, not this
 * commit's scope.
 */
struct socket_ctx {
	int parent_fd;			/* -1 until socket() opens it */
	int child_fd;			/* -1 until accept() opens it */
	int family;			/* AF_* from the picked triplet */
	struct sockaddr *bound_addr;	/* addr the bind leg used, or NULL */
	enum sfg_conn_state conn_state;	/* how far the chain has walked */
};

/*
 * Per-family grammar entry — an outer driver (run_grammar_chain in
 * net/socket-family-grammar.c) walks one of these end-to-end inside
 * a single childop, with the same fd flowing through every step.
 *
 * Generalises the v1 socket_family_chain childop (84b298906961) which
 * walked a hardcoded AF_ALG lifecycle, plus v3's splice-substitution
 * data leg (ef5622b4ac38) which stays inside the AF_ALG-specific
 * path (run_alg_chain).  The grammar table drives arbitrary AF_*
 * families through coherent setsockopt/bind/listen/accept/sendmsg
 * sequences without rebuilding the dispatcher per family.
 *
 * Fields are nullable on purpose.  A minimal entry (family/name/can_run)
 * already gets a coherent walk because the defaults reuse the per-family
 * netproto callbacks already in net/proto-*.c.  Each non-NULL field
 * overrides the default with family-specific shape — e.g. ordered
 * setsockopt sequences known to hit sequence-dependent paths.
 */
struct socket_family_grammar {
	int family;			/* AF_INET, AF_UNIX, ... */
	const char *name;		/* short tag for stats / debug */

	/* one-shot probe; the helper sfg_can_run_default() caches the
	 * verdict in the per-family shm latch keyed by family. */
	bool (*can_run)(void);

	/* Triplet picker.  NULL => sfg_default_pick_triplet() draws from
	 * net_protocols[family].proto->valid_triplets. */
	void (*pick_triplet)(struct socket_triplet *out);

	/* setsockopts before bind.  NULL ok. */
	void (*configure_pre_bind)(int fd, struct socket_triplet *triplet);

	/* bind() / connect().  NULL => sfg_default_bind() uses
	 * net_protocols[family].proto->gen_sockaddr + bind().  Returns
	 * 0 on success, -1 on failure. */
	int (*bind_or_connect)(int fd, struct socket_triplet *triplet);

	/* setsockopts after bind.  NULL ok. */
	void (*configure_post_bind)(int fd, struct socket_triplet *triplet);

	/* True when the listen()+accept() phase should run.
	 * NULL => sfg_default_needs_listen_accept() checks
	 * triplet->type == SOCK_STREAM || SOCK_SEQPACKET. */
	bool (*needs_listen_accept)(struct socket_triplet *triplet);

	/* Coherent setsockopt walk: fire n options on fd in order.
	 * NULL => sfg_default_walk_setsockopts() fans through
	 * proto->setsockopt n times.  Family-specific overrides fire
	 * ORDERED sequences targeting sequence-dependent paths. */
	void (*walk_setsockopts)(int fd, struct socket_triplet *triplet,
				 unsigned int n);

	/* cmsg grammar for the data leg.  NULL ok — falls back to no
	 * cmsg.  Caller passes a scratch cmsgbuf the callback can write
	 * into and link onto msg->msg_control. */
	void (*gen_cmsg)(int fd, struct socket_triplet *triplet,
			 struct msghdr *msg, void *cmsgbuf, size_t cmsgbuflen);

	/* Optional override for the data leg.  NULL =>
	 * sfg_default_data_leg() emits sendmsg with proto->gen_msg-produced
	 * payload + this entry's gen_cmsg, then non-blocking recv. */
	void (*data_leg)(int parent_fd, int child_fd,
			 struct socket_triplet *triplet);
};

/* Registry helpers (see net/socket-family-grammar.c). */
const struct socket_family_grammar *sfg_pick_random_active(void);
bool sfg_can_run_default(int family);
void sfg_mark_unsupported(int family);

/* Default callbacks the grammar entries can plug into the table. */
bool sfg_always_false(void);
void sfg_default_pick_triplet(int family, struct socket_triplet *out);
/*
 * Default bind path.  On success stashes the sockaddr it fabricated
 * (via net_protocols[family].proto->gen_sockaddr) into ctx->bound_addr
 * so the caller's teardown frees it exactly once.  Returns 0 on success,
 * -1 on failure — the caller ignores ctx->bound_addr on failure (it
 * stays NULL).
 */
int sfg_default_bind(int fd, struct socket_triplet *triplet,
		     struct socket_ctx *ctx);
bool sfg_default_needs_listen_accept(struct socket_triplet *triplet);
void sfg_default_walk_setsockopts(int fd, struct socket_triplet *triplet,
				  unsigned int n);
void sfg_default_data_leg(int data_fd,
			  const struct socket_family_grammar *sfg,
			  struct socket_triplet *triplet);

/*
 * Drive one coherent grammar walk.  Returns true if the walk reached
 * the data leg cleanly, false on early kernel-not-supported failures
 * (the helper bumps *err_burst on those, and outer callers latch the
 * family via sfg_mark_unsupported() once the burst exceeds threshold).
 */
bool run_grammar_chain(const struct socket_family_grammar *sfg,
		       unsigned int *err_burst);

/*
 * Per-family extern declarations.  The registry array in
 * net/socket-family-grammar.c grows in lockstep with this list as
 * each grammar lands.
 */
extern const struct socket_family_grammar grammar_inet;
#ifdef USE_IPV6
extern const struct socket_family_grammar grammar_inet6;
#endif
extern const struct socket_family_grammar grammar_mptcp;
extern const struct socket_family_grammar grammar_kcm;
extern const struct socket_family_grammar grammar_rxrpc;
extern const struct socket_family_grammar grammar_qrtr;
#ifdef USE_RDS
extern const struct socket_family_grammar grammar_rds;
#endif
#ifdef USE_MCTP
extern const struct socket_family_grammar grammar_mctp;
#endif
extern const struct socket_family_grammar grammar_llc;
extern const struct socket_family_grammar grammar_mpls;
extern const struct socket_family_grammar grammar_unix;
extern const struct socket_family_grammar grammar_netlink;
extern const struct socket_family_grammar grammar_xfrm;
extern const struct socket_family_grammar grammar_packet;
#ifdef USE_XDP
extern const struct socket_family_grammar grammar_xdp;
#endif

/*
 * Stub entries — registered with can_run=sfg_always_false so they
 * never run on this kernel build, but keep their slot in the
 * registry so a user with the matching CONFIG can pick them up
 * without registering anything new.  Each is upgraded to a real
 * grammar as families are filled in.
 */
#ifdef USE_BLUETOOTH
extern const struct socket_family_grammar grammar_bluetooth_stub;
#endif
#ifdef USE_CAIF
extern const struct socket_family_grammar grammar_caif_stub;
#endif
#ifdef USE_VSOCK
extern const struct socket_family_grammar grammar_vsock_stub;
#endif
extern const struct socket_family_grammar grammar_can_stub;
extern const struct socket_family_grammar grammar_phonet_stub;
extern const struct socket_family_grammar grammar_smc_stub;
extern const struct socket_family_grammar grammar_tipc_stub;
