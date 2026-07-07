#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <sys/socket.h>

#include "syscall.h"	/* socket_triplet */

#ifdef USE_IF_ALG
#include <linux/if_alg.h>	/* sockaddr_alg in the socket_ctx union arm */
#endif

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

	/*
	 * AF_ALG lifecycle phases — the inet-shaped BIND/ACCEPT/DATA vocab
	 * does not map cleanly onto AF_ALG (bind carries salg_type/name,
	 * not an IP address; accept is NOT LISTEN-gated — it produces the
	 * operation fd from a bound parent; the data leg is a MSG_MORE-
	 * segmented cmsg-driven send/recv against the op fd).  Handled by
	 * the executor's ctx-aware case bodies in net/socket-family-grammar.c,
	 * not by the stateless (fd, triplet) sfg-> callback table.  Values
	 * kept stable so sfg_fnv1a_step's per-walk sequence hash stays
	 * comparable across runs.
	 */
	SFG_PHASE_ALG_BIND      = 10,	/* bind(salg_type,salg_name) -> BOUND */
	SFG_PHASE_ALG_SETKEY    = 11,	/* setsockopt(ALG_SET_KEY) on parent */
	SFG_PHASE_ALG_SET_AEAD  = 12,	/* setsockopt(ALG_SET_AEAD_AUTHSIZE) +
					 * stage assoclen for the CMSG phase */
	SFG_PHASE_ALG_ACCEPT    = 13,	/* accept() -> op fd -> ACCEPTED */
	SFG_PHASE_ALG_CMSG      = 14,	/* sendmsg(cmsg: ALG_SET_OP [+ IV]
					 * [+ AEAD_ASSOCLEN]), empty payload */
	SFG_PHASE_ALG_SEND_MORE = 15,	/* N × sendmsg(MSG_MORE) tsgl-growing */
	SFG_PHASE_ALG_RECV      = 16,	/* recvmsg() flush (no MSG_MORE) */
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

	/*
	 * AF_ALG-scoped precondition violations for grammar_alg's walk.
	 * Same discipline as the inet ops above: one hostile step per
	 * otherwise-coherent plan, sfg_publish_illegal stamps the label
	 * on both channels before the raw syscall lands.  The picker in
	 * sfg_pick_illegal_op gates on triplet.family so an inet walk
	 * never draws an AF_ALG op and vice versa.
	 *
	 *   ALG_SEND_BEFORE_SETKEY    sendmsg on an ACCEPTED-but-unkeyed
	 *                             op fd (skcipher/aead reject unkeyed
	 *                             ->encrypt; hits the ctx->more/setkey
	 *                             gate in af_alg_sendmsg)
	 *   ALG_RECV_ON_EMPTY_TSGL    the documented af_alg_pull_tsgl
	 *                             trigger — recv() with no accumulated
	 *                             request on a fresh ACCEPTED op fd
	 *                             (walker skips the SEND_MORE phase)
	 *   ALG_ACCEPT_BEFORE_BIND    accept() on an unbound parent
	 *                             (af_alg_accept: ask->type == NULL)
	 *   ALG_SETKEY_AFTER_ACCEPT   setsockopt(ALG_SET_KEY) on parent
	 *                             AFTER the op fd already exists
	 *                             (races af_alg_release_parent refcount
	 *                             assumptions)
	 *   ALG_OP_DIRECTION_MISMATCH ALG_SET_OP=DECRYPT cmsg with data
	 *                             shaped for encrypt (aead_recvmsg
	 *                             length math / crypto_aead_decrypt
	 *                             -EBADMSG path)
	 *   ALG_DOUBLE_ACCEPT         second accept() on the same parent
	 *                             (two op sockets sharing one alg_sock)
	 *   ALG_SET_AEAD_ON_NON_AEAD  ALG_SET_AEAD_AUTHSIZE on a
	 *                             skcipher/hash socket (type
	 *                             ->setauthsize is NULL)
	 */
	SFG_ILLEGAL_ALG_SEND_BEFORE_SETKEY,
	SFG_ILLEGAL_ALG_RECV_ON_EMPTY_TSGL,
	SFG_ILLEGAL_ALG_ACCEPT_BEFORE_BIND,
	SFG_ILLEGAL_ALG_SETKEY_AFTER_ACCEPT,
	SFG_ILLEGAL_ALG_OP_DIRECTION_MISMATCH,
	SFG_ILLEGAL_ALG_DOUBLE_ACCEPT,
	SFG_ILLEGAL_ALG_SET_AEAD_ON_NON_AEAD,
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

#ifdef USE_IF_ALG
/*
 * Algorithm family group for the grammar_alg walk.  Gates AEAD-only
 * phases (SET_AEAD, assoclen cmsg) and picks the salg_type string +
 * dict bucket at ALG_BIND.  Strict subset of the sfc_type_idx enum in
 * childops/net/socket-family-chain.c — the four buckets the grammar
 * actually drives (akcipher/kpp/sig lifecycles diverge and don't
 * benefit from the send/recv walk yet).
 */
enum sfg_alg_type {
	SFG_ALG_TYPE_HASH = 0,
	SFG_ALG_TYPE_SKCIPHER,
	SFG_ALG_TYPE_AEAD,
	SFG_ALG_TYPE_RNG,
	SFG_ALG_TYPE_NR,
};

/*
 * AF_ALG-specific extras for the grammar_alg walker.  Lives in
 * socket_ctx.fam.alg so the ctx-aware AF_ALG phase handlers can thread
 * key-set state, chosen alg type, and the authsize/assoclen values
 * SET_AEAD picked and the CMSG phase must echo.  Splice pipe fds are
 * reserved here so the follow-on run_alg_chain retirement (§6) can
 * fold the splice data leg without touching the ctx shape again.
 */
struct sfg_alg_extras {
	struct sockaddr_alg sa;
	enum sfg_alg_type type;
	bool key_set;
	unsigned int authsize;
	unsigned int assoclen;
	int splice_pfd[2];
};
#endif

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
 * The `fam` union carries family-specific extras.  Today only AF_ALG
 * (grammar_alg) needs any: sockaddr_alg body, alg type, key-set flag,
 * authsize/assoclen staged at SET_AEAD, and reserved splice pipe fds.
 * Other families that grow extras add a sibling arm.  splice_pfd
 * defaults to {-1, -1} — initialised alongside parent_fd/child_fd so
 * the teardown gate can close guarded on >= 0.
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
#ifdef USE_IF_ALG
	union {
		struct sfg_alg_extras alg;
	} fam;
#endif
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

/*
 * Stable short tag for enum sfg_conn_state.  Same shape as
 * sfg_illegal_name — one string table, both channels use it.  Never
 * returns NULL.
 */
const char *sfg_conn_state_name(enum sfg_conn_state st);

/*
 * Publish a socket-grammar illegal-step label on both channels the
 * post-mortem walker reads:
 *   1. this_child()->last_sfg_illegal is stamped so a kernel oops
 *      caught by the parent's health path renders the label alongside
 *      the chronicle dump.
 *   2. output(2, "sfg illegal: %s fd=%d family=%d state=%s\n", ...) is
 *      emitted so netconsole / logview capture the label on the wire
 *      before the illegal syscall lands -- the last line on the wire
 *      names the violated precondition if the kernel oopses inside
 *      the illegal path.
 *
 * Must be called IMMEDIATELY BEFORE the raw illegal syscall so the
 * wire order (breadcrumb, then syscall entry, then oops) is what
 * bandicoot/kdump post-mortem sees.  Safe to call outside a child
 * (this_child()==NULL): the childdata stamp is skipped, the wire
 * output still fires.
 */
void sfg_publish_illegal(enum sfg_illegal_op op, enum sfg_conn_state at,
			 int family, int fd);

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
#ifdef USE_IF_ALG
extern const struct socket_family_grammar grammar_alg;
#endif
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
