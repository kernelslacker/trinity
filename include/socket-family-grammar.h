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
 * Phase-ID vocabulary for run_grammar_chain's data-driven executor.
 * A grammar entry (or the framework default) supplies a table of legal
 * orderings; the executor picks one per walk and drives the callbacks
 * in that order.  SFG_PHASE_END is the trailing sentinel so a single
 * fixed-size step buffer per ordering suffices without a separate
 * length field.
 *
 * Values are kept stable (small positive integers) so the per-walk
 * sequence hash is comparable across runs.
 */
enum sfg_phase {
	SFG_PHASE_END      = 0,	/* sentinel — terminates an ordering */
	SFG_PHASE_SOCKET   = 1,	/* socket()			  -> CREATED */
	SFG_PHASE_PRE_CFG  = 2,	/* configure_pre_bind		  (no-op ok) */
	SFG_PHASE_WALK     = 3,	/* walk_setsockopts		  (no-op ok) */
	SFG_PHASE_BIND     = 4,	/* bind_or_connect		  -> BOUND */
	SFG_PHASE_POST_CFG = 5,	/* configure_post_bind		  (no-op ok) */
	SFG_PHASE_LISTEN   = 6,	/* listen() (needs_la-gated)	  -> LISTENING */
	SFG_PHASE_ACCEPT   = 7,	/* accept() if LISTENING	  -> ACCEPTED */
	SFG_PHASE_DATA     = 8,	/* data_leg on child_fd || parent_fd */
	SFG_PHASE_ILLEGAL  = 9,	/* forced precondition-violating step;
				 * bypasses the guard rails legal phases
				 * use — the ONLY path allowed to fire an
				 * illegal syscall against ctx.parent_fd /
				 * ctx.child_fd regardless of conn_state.
				 * Never appears in a legal ordering; the
				 * injector splices exactly one per walk. */
};

/*
 * Precondition-violation vocabulary for the SFG_PHASE_ILLEGAL path.
 * Each value names the invariant the forced step deliberately breaks
 * so a kernel oops that fires inside the illegal syscall can be
 * attributed to a specific violated precondition instead of a
 * mystery-ordered walk.  SFG_ILLEGAL_NONE is the zero-init sentinel
 * a coherent (label-free) walk carries end-to-end.
 *
 * The four current members are inet/TCP-scoped:
 *   ACCEPT_NON_LISTENER   accept() on a fd that never listen()ed
 *   BIND_AFTER_LISTEN     second bind() while LISTENING
 *   SEND_BEFORE_BIND      sendmsg() on a CREATED (unbound) fd
 *   DOUBLE_SHUTDOWN       shutdown(fd, RDWR) issued twice back-to-back
 *
 * Per-family follow-ons the framework will fold in as other grammars
 * opt in: LISTEN_ON_CONNECTED (connect-based families),
 * SETSOCKOPT_AFTER_LISTEN (pre-listen-only opts), DATA_AFTER_SHUTDOWN.
 */
enum sfg_illegal_op {
	SFG_ILLEGAL_NONE = 0,
	SFG_ILLEGAL_ACCEPT_NON_LISTENER,
	SFG_ILLEGAL_BIND_AFTER_LISTEN,
	SFG_ILLEGAL_SEND_BEFORE_BIND,
	SFG_ILLEGAL_DOUBLE_SHUTDOWN,
};

/*
 * Bounded ordering: an ordered list of enum sfg_phase step IDs, with a
 * trailing SFG_PHASE_END.  Fixed capacity keeps the table static-const
 * and hashable byte-wise for the variety metric.  Capacity comfortably
 * fits every current legal permutation (8 real phases + terminator).
 */
#define SFG_MAX_PHASES 12
struct sfg_phase_order {
	unsigned char steps[SFG_MAX_PHASES];
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
	/*
	 * Labels for the SFG_PHASE_ILLEGAL path.  illegal_op is
	 * SFG_ILLEGAL_NONE on a fully coherent walk (the common case)
	 * and gets stamped by the illegal-step handler immediately
	 * before issuing the raw illegal syscall; illegal_at snapshots
	 * conn_state at the same instant so a downstream reader can tell
	 * which precondition was actually violated (e.g. an
	 * ACCEPT_NON_LISTENER stamped illegal_at=SFG_CONN_BOUND is a
	 * bind-but-no-listen fd, while SFG_CONN_CREATED is a raw fresh
	 * socket).  Consumed by post-mortem rendering + the on-wire
	 * breadcrumb; never read back by the executor itself.
	 */
	enum sfg_illegal_op illegal_op;
	enum sfg_conn_state illegal_at;
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

	/*
	 * Table of LEGAL phase orderings the executor may pick from per
	 * walk.  NULL / zero-length falls back to the single default
	 * ordering the framework uses when no family opts in.  Every entry
	 * in the table MUST satisfy the invariants documented above
	 * run_grammar_chain (socket first; bind before listen; listen
	 * before accept; data leg only after a live connection; pre-bind
	 * cfg stays pre-bind; post-bind cfg stays post-bind) — the
	 * executor trusts the table and does not re-validate.
	 *
	 * phase_orders_apply gates the table to triplets that actually
	 * support the alternate orderings (e.g. inet uses the table only
	 * for SOCK_STREAM triplets; UDP/DGRAM fall back to the default).
	 * NULL means "table applies to every triplet this family emits".
	 */
	const struct sfg_phase_order *phase_orders;
	unsigned int nr_phase_orders;
	bool (*phase_orders_apply)(const struct socket_triplet *triplet);
};

/* Registry helpers (see net/socket-family-grammar.c). */
const struct socket_family_grammar *sfg_pick_random_active(void);
bool sfg_can_run_default(int family);
void sfg_mark_unsupported(int family);

/*
 * Stable short tag for enum sfg_illegal_op.  Used by both the on-wire
 * breadcrumb (netconsole capture) and the post-mortem render so a
 * single string table backs both channels.  Never returns NULL — an
 * unknown value renders as "unknown".
 */
const char *sfg_illegal_name(enum sfg_illegal_op op);

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
