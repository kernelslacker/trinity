#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <sys/socket.h>

#include "syscall.h"	/* socket_triplet */

struct msghdr;

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
int sfg_default_bind(int fd, struct socket_triplet *triplet);
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
 * without registering anything new.  Each gets upgraded to a real
 * grammar in a later commit.
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
