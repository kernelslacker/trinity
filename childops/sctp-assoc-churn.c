/*
 * sctp_assoc_churn - SCTP multi-homing + ASCONF address rotation race
 * over a live association.
 *
 * SCTP carries a small, busy bug surface that flat per-syscall fuzzing
 * never reaches: associations only exist after a four-way INIT cookie
 * handshake completes, ASCONF chunks only emit when the local bound-
 * address-set changes *while an association is up*, and the path
 * manager only fires when a peer address actually transitions.  None
 * of those preconditions assemble themselves from independent random
 * setsockopts — the kernel quite reasonably refuses to act on path /
 * association state that doesn't exist yet, so single-syscall fuzzers
 * collect ENOPROTOOPT/ENOTCONN/EINVAL early-rejects on every attempt
 * and never enter net/sctp/sm_make_chunk.c, sm_sideeffect.c or
 * bind_addr.c past the front-door validators.
 *
 * The CVE class clustered here is the SCTP association-lifecycle race
 * family: CVE-2021-23133 sctp_destroy_sock vs path-list walk,
 * CVE-2022-20422 sctp_listen vs association-create, CVE-2023-1074
 * sctp_endpoint UAF, and the broader sctp_assoc_lookup / sctp_outq
 * race shape inside the ASCONF parameter parser.  Reaching any of
 * them needs the full sequence: socket -> bind -> bindx multi-addr
 * (ADD_IP) -> connectx multi-addr -> ESTABLISHED with cookie -> live
 * data -> bindx ADD/REM mid-flow (emits ASCONF on the wire) ->
 * optional peel-off -> shutdown.
 *
 * Sequence (per CV.48 spec):
 *   1. Server SCTP socket on 127.0.0.1; bind primary, sctp_bindx ADD
 *      with [127.0.0.2, 127.0.0.3] (multi-homed local).
 *   2. listen.
 *   3. Client SCTP socket; bind a different primary, bindx ADD with
 *      a second multi-homed set.
 *   4. SCTP_SOCKOPT_CONNECTX on the client with a packed array of
 *      server addresses — returns the assoc_id.  Server accepts (for
 *      SOCK_STREAM) or implicitly accepts on first ingress (for
 *      SOCK_SEQPACKET).
 *   5. send() a payload — drives the cookie-ack -> ESTABLISHED edge
 *      and exercises the data path against the just-installed assoc.
 *   6. sctp_bindx(SCTP_SOCKOPT_BINDX_ADD) on the client with a fresh
 *      loopback address.  The kernel calls
 *      sctp_send_asconf_add_ip() right after the bind succeeds, which
 *      formats and emits an ASCONF chunk for every up association on
 *      this sk — the targeted edge.
 *   7. send() during the ASCONF reply window — race the data-plane
 *      against ASCONF processing on the peer side.
 *   8. sctp_bindx(SCTP_SOCKOPT_BINDX_REM) to remove a path mid-flow —
 *      drives sctp_send_asconf_del_ip(), the REM_IP variant, against
 *      a path that may still have in-flight DATA chunks.
 *   9. Optional sctp_peeloff via getsockopt(SCTP_SOCKOPT_PEELOFF) on
 *      a SOCK_SEQPACKET socket — splits the assoc onto a fresh fd,
 *      stressing the assoc-detach / sk-clone path.
 *  10. shutdown / close.
 *
 * Self-bounding: one cycle per invocation, all sockets O_NONBLOCK so
 * a wedged peer can't pin us past child.c's SIGALRM(1s) safety net.
 * Loopback only (127.0.0.0/8) — no external traffic, no external
 * interfaces touched.  Falls back gracefully on hosts without
 * CONFIG_IP_SCTP (the very first socket() returns EPROTONOSUPPORT and
 * we latch ns_unsupported for the rest of the process so siblings
 * stop probing).
 *
 * Failure modes are all expected coverage and never propagated as
 * childop failure:
 *   - EPROTONOSUPPORT on socket(): no CONFIG_IP_SCTP.  Latched.
 *   - EADDRINUSE / EADDRNOTAVAIL on bind / bindx: another child is
 *     mid-cycle on the same loopback address, or the secondary
 *     loopback alias isn't configured (default loopback only owns
 *     127.0.0.1; binding to 127.0.0.2-4 still works because the
 *     loopback driver covers the whole 127.0.0.0/8 range).
 *   - EOPNOTSUPP on bindx ADD/REM during association: kernel built
 *     without ASCONF support (CONFIG_SCTP_ASCONF or ip_sctp ASCONF
 *     toggle off via /proc/sys/net/sctp/addip_enable=0).  Counted as
 *     a reject, not a failure.
 *   - EINVAL / ENOENT on peeloff: assoc already torn down.  Counted.
 */

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "child.h"
#include "compat.h"
#include "jitter.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"

/* Latched per-child: the very first IPPROTO_SCTP socket() returned
 * EPROTONOSUPPORT.  Kernel CONFIG_IP_SCTP is fixed for the life of
 * this process, so further attempts are pure waste. */
static bool ns_unsupported;

/* sctp_assoc_t is __s32 in <linux/sctp.h>, but trinity doesn't pull
 * that header in here (we drive everything through raw setsockopt to
 * avoid a libsctp link-time dependency).  Mirror the type explicitly
 * so the SCTP_SOCKOPT_CONNECTX return value parking and peeloff_arg
 * are typed identically to the kernel ABI. */
typedef int32_t sctp_assoc_t_compat;

/* getsockopt(SCTP_SOCKOPT_PEELOFF) input/output struct.  Same shape
 * as sctp_peeloff_arg_t in <linux/sctp.h>; defined locally so we
 * don't drag in the whole UAPI header.  Fields are documented by the
 * kernel's net/sctp/socket.c sctp_getsockopt_peeloff(). */
struct sctp_peeloff_arg_compat {
	sctp_assoc_t_compat	associd;
	int			sd;
};

/* Loopback address pool.  127.0.0.0/8 is all routed to the loopback
 * driver on Linux without any extra alias setup, so binding to
 * 127.0.0.2-4 succeeds out of the box on any kernel — they don't
 * need to be configured on lo.  Addr 0 (127.0.0.1) is the canonical
 * primary; the rest are the multi-homing fan-out. */
#define NR_LOOPBACK_ADDRS	5U
static const uint32_t loopback_pool[NR_LOOPBACK_ADDRS] = {
	0x7f000001U,	/* 127.0.0.1 */
	0x7f000002U,	/* 127.0.0.2 */
	0x7f000003U,	/* 127.0.0.3 */
	0x7f000004U,	/* 127.0.0.4 */
	0x7f000005U,	/* 127.0.0.5 */
};

/* Base inner-loop iteration count for the bindx churn.  Real value
 * gets ±50% jitter via JITTER_RANGE() and per-op multiplier scaling
 * via BUDGETED() so adapt_budget can grow it on productive runs.
 * Kept small because each iteration emits ASCONF chunks on the wire
 * which the kernel side has to format/sign/ack. */
#define CHURN_ITERS_BASE	3U

static void fill_sin(struct sockaddr_in *sa, uint32_t addr_h, uint16_t port_n)
{
	memset(sa, 0, sizeof(*sa));
	sa->sin_family = AF_INET;
	sa->sin_addr.s_addr = htonl(addr_h);
	sa->sin_port = port_n;
}

/*
 * Pack `count` addresses from loopback_pool[] starting at `start_idx`
 * (modulo wrap) into the caller-provided buffer, all sharing `port`.
 * Returns the total byte length (count * sizeof(struct sockaddr_in)).
 *
 * The kernel's sctp_setsockopt_bindx and sctp_setsockopt_connectx
 * walk the buffer reading sa_family on each entry to dispatch to the
 * right af->sockaddr_len.  IPv4-only here keeps the format trivial
 * (16 bytes per slot, no per-entry alignment padding).
 */
static int pack_addrs(struct sockaddr_in *buf, unsigned int cap,
		      unsigned int start_idx, unsigned int count,
		      uint16_t port_n)
{
	unsigned int i;

	if (count > cap)
		count = cap;
	if (count > NR_LOOPBACK_ADDRS)
		count = NR_LOOPBACK_ADDRS;

	for (i = 0; i < count; i++) {
		uint32_t a = loopback_pool[(start_idx + i) % NR_LOOPBACK_ADDRS];
		fill_sin(&buf[i], a, port_n);
	}
	return (int)(count * sizeof(struct sockaddr_in));
}

/*
 * Drive one short non-blocking send to push bytes through an SCTP
 * association.  No retry, no error handling — we don't care whether
 * the bytes land, just that the data path is exercised.  A succeeded
 * packets_sent stat tick distinguishes "association up + path
 * usable" from "no usable path / ASCONF mid-rotation rejecting".
 */
static void churn_send(int fd)
{
	unsigned char buf[128];
	ssize_t n;

	generate_rand_bytes(buf, sizeof(buf));
	n = send(fd, buf, 1U + ((unsigned int)rand() % sizeof(buf)),
		 MSG_DONTWAIT | MSG_NOSIGNAL);
	if (n > 0)
		__atomic_add_fetch(&shm->stats.sctp_assoc_churn_packets_sent,
				   1, __ATOMIC_RELAXED);
}

bool sctp_assoc_churn(struct childdata *child)
{
	/* sockaddr buffer space — sized for the whole pool plus a little
	 * head room.  Kept on the stack: each entry is 16 bytes so the
	 * whole pack-buffer fits in well under a kilobyte and there's
	 * nothing to free on the failure paths. */
	struct sockaddr_in addrs[NR_LOOPBACK_ADDRS];
	struct sockaddr_in srv_primary, cli_primary;
	socklen_t slen;
	int sock_type;
	int srv = -1;
	int cli = -1;
	int srv_acc = -1;
	int peeled = -1;
	int rc;
	int addr_len;
	uint16_t srv_port_n;
	uint16_t cli_port_n;
	sctp_assoc_t_compat assoc_id = 0;
	unsigned int iters;
	unsigned int i;
	unsigned int rot_idx;

	(void)child;

	__atomic_add_fetch(&shm->stats.sctp_assoc_churn_runs,
			   1, __ATOMIC_RELAXED);

	if (ns_unsupported)
		return true;

	/* Rotate the socket type per invocation so both the one-to-one
	 * (SOCK_STREAM) and one-to-many (SOCK_SEQPACKET) sk_prot tables
	 * inside net/sctp/socket.c get exercised.  The two share most of
	 * the assoc lifecycle code but split on accept / peeloff /
	 * implicit-assoc-on-sendmsg. */
	sock_type = (rand() & 1) ? SOCK_STREAM : SOCK_SEQPACKET;

	srv = socket(AF_INET, sock_type | SOCK_CLOEXEC, IPPROTO_SCTP);
	if (srv < 0) {
		if (errno == EPROTONOSUPPORT || errno == ESOCKTNOSUPPORT)
			ns_unsupported = true;
		__atomic_add_fetch(&shm->stats.sctp_assoc_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	/* Server: bind primary to 127.0.0.1:0 so the kernel picks an
	 * ephemeral port we can recover via getsockname.  bindx the rest
	 * of the multi-home set onto the same socket via the raw kernel
	 * sockopt — libsctp's sctp_bindx() is just a thin wrapper around
	 * this, so we skip the link-time dependency. */
	fill_sin(&srv_primary, loopback_pool[0], 0);
	if (bind(srv, (struct sockaddr *)&srv_primary,
		 sizeof(srv_primary)) < 0) {
		__atomic_add_fetch(&shm->stats.sctp_assoc_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}
	slen = sizeof(srv_primary);
	if (getsockname(srv, (struct sockaddr *)&srv_primary, &slen) < 0) {
		__atomic_add_fetch(&shm->stats.sctp_assoc_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}
	srv_port_n = srv_primary.sin_port;

	/* Multi-home the server: bindx ADD addrs[1..2] (127.0.0.2,
	 * 127.0.0.3) on the SAME port.  Pre-listen ADD doesn't trigger
	 * ASCONF (no association yet) — it goes through sctp_bindx_add
	 * only.  This is the structural setup that lets the post-
	 * association ADD/REM later actually emit ASCONF chunks. */
	addr_len = pack_addrs(addrs, NR_LOOPBACK_ADDRS, 1, 2, srv_port_n);
	rc = setsockopt(srv, IPPROTO_SCTP, SCTP_SOCKOPT_BINDX_ADD,
			addrs, (socklen_t)addr_len);
	if (rc == 0)
		__atomic_add_fetch(&shm->stats.sctp_assoc_churn_bindx_added,
				   1, __ATOMIC_RELAXED);
	else
		__atomic_add_fetch(&shm->stats.sctp_assoc_churn_bindx_rejected,
				   1, __ATOMIC_RELAXED);

	if (listen(srv, 4) < 0) {
		__atomic_add_fetch(&shm->stats.sctp_assoc_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}

	/* Client side: bind a separate primary so the assoc has
	 * unambiguous local-vs-remote endpoints, plus a second multi-
	 * home address for symmetry.  Also pinned to a known port via
	 * bind(0)+getsockname so the connectx path uses a stable
	 * 4-tuple. */
	cli = socket(AF_INET, sock_type | SOCK_CLOEXEC, IPPROTO_SCTP);
	if (cli < 0) {
		__atomic_add_fetch(&shm->stats.sctp_assoc_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}
	fill_sin(&cli_primary, loopback_pool[3], 0);
	if (bind(cli, (struct sockaddr *)&cli_primary,
		 sizeof(cli_primary)) < 0) {
		__atomic_add_fetch(&shm->stats.sctp_assoc_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}
	slen = sizeof(cli_primary);
	if (getsockname(cli, (struct sockaddr *)&cli_primary, &slen) < 0) {
		__atomic_add_fetch(&shm->stats.sctp_assoc_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}
	cli_port_n = cli_primary.sin_port;
	(void)cli_port_n;

	/* Non-blocking from here on so a wedged loopback can't pin us
	 * past SIGALRM(1s).  Connectx returning EINPROGRESS is fine —
	 * the assoc completes asynchronously and subsequent send()s
	 * either piggyback on the cookie or get queued. */
	(void)fcntl(cli, F_SETFL, O_NONBLOCK);
	(void)fcntl(srv, F_SETFL, O_NONBLOCK);

	/* SCTP_SOCKOPT_CONNECTX with the server's full multi-address
	 * set (3 addrs).  Kernel returns the new assoc_id as the
	 * setsockopt return value (positive) on success — that's
	 * non-standard but it's how the SCTP API was wired.  We grab it
	 * for the optional peeloff step later. */
	addr_len = pack_addrs(addrs, NR_LOOPBACK_ADDRS, 0, 3, srv_port_n);
	rc = setsockopt(cli, IPPROTO_SCTP, SCTP_SOCKOPT_CONNECTX,
			addrs, (socklen_t)addr_len);
	if (rc < 0 && errno != EINPROGRESS) {
		__atomic_add_fetch(&shm->stats.sctp_assoc_churn_connect_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}
	if (rc > 0)
		assoc_id = (sctp_assoc_t_compat)rc;
	__atomic_add_fetch(&shm->stats.sctp_assoc_churn_connected,
			   1, __ATOMIC_RELAXED);

	/* For SOCK_STREAM, accept() the inbound assoc on the server's
	 * accept queue so the server-side ESTABLISHED state actually
	 * exists when bindx ADD fires.  SOCK_SEQPACKET delivers all
	 * assocs through the parent socket, so accept() doesn't apply
	 * — the assoc materialises lazily on first ingress. */
	if (sock_type == SOCK_STREAM) {
		srv_acc = accept(srv, NULL, NULL);
		if (srv_acc >= 0) {
			(void)fcntl(srv_acc, F_SETFL, O_NONBLOCK);
			__atomic_add_fetch(
				&shm->stats.sctp_assoc_churn_accepted,
				1, __ATOMIC_RELAXED);
		}
		/* accept failure here is fine — the cookie may not have
		 * been ACKed yet, and SCTP doesn't queue on
		 * EINPROGRESS the same way TCP does.  Falling through to
		 * the bindx churn still exercises the client-side ASCONF
		 * emit path even if the server-side state machine
		 * hasn't caught up. */
	}

	/* Drive the data path before the first ASCONF so the assoc has
	 * actually transitioned to ESTABLISHED on both ends.  Otherwise
	 * the post-handshake bindx ADD races against the cookie itself,
	 * which isn't the bug class we're targeting. */
	churn_send(cli);
	if (srv_acc >= 0)
		churn_send(srv_acc);

	/* Churn loop: alternate ADD and REM of an extra address on the
	 * client.  Each ADD triggers sctp_send_asconf_add_ip(), each
	 * REM triggers sctp_send_asconf_del_ip(); both walk the assoc
	 * list under the bh-locked sk and emit ASCONF chunks on every
	 * up association.  The send() between each pair is the
	 * data-plane race window — DATA chunks may share the same
	 * sndbuf path as the ASCONF reply being processed. */
	iters = BUDGETED(CHILD_OP_SCTP_ASSOC_CHURN,
			 JITTER_RANGE(CHURN_ITERS_BASE));
	rot_idx = 4;	/* start with 127.0.0.5 — addrs 0..3 are already
			 * in use as the bound primaries / multi-home set. */
	for (i = 0; i < iters; i++) {
		/* a) ADD a fresh address mid-flow.  After this returns,
		 *    the ASCONF chunk is already on the wire (kernel
		 *    side runs sctp_send_asconf_add_ip synchronously
		 *    before the setsockopt returns to userspace). */
		addr_len = pack_addrs(addrs, NR_LOOPBACK_ADDRS,
				      rot_idx, 1, cli_port_n);
		rc = setsockopt(cli, IPPROTO_SCTP, SCTP_SOCKOPT_BINDX_ADD,
				addrs, (socklen_t)addr_len);
		if (rc == 0)
			__atomic_add_fetch(
				&shm->stats.sctp_assoc_churn_bindx_added,
				1, __ATOMIC_RELAXED);
		else
			__atomic_add_fetch(
				&shm->stats.sctp_assoc_churn_bindx_rejected,
				1, __ATOMIC_RELAXED);

		/* b) Send during the ASCONF reply window — race window
		 *    against ASCONF parameter parsing on the server. */
		churn_send(cli);
		if (srv_acc >= 0)
			churn_send(srv_acc);

		/* c) REM the address we just added.  Hits the
		 *    sctp_send_asconf_del_ip path; if the data send
		 *    above hasn't been ACKed yet, this races a path
		 *    deletion against in-flight DATA on that path. */
		rc = setsockopt(cli, IPPROTO_SCTP, SCTP_SOCKOPT_BINDX_REM,
				addrs, (socklen_t)addr_len);
		if (rc == 0)
			__atomic_add_fetch(
				&shm->stats.sctp_assoc_churn_bindx_removed,
				1, __ATOMIC_RELAXED);
		else
			__atomic_add_fetch(
				&shm->stats.sctp_assoc_churn_bindx_rejected,
				1, __ATOMIC_RELAXED);

		/* d) Walk the rotation forward — wraps inside the
		 *    pool so we never touch addresses outside
		 *    127.0.0.0/8. */
		rot_idx = (rot_idx + 1U) % NR_LOOPBACK_ADDRS;
	}

	/* Optional peel-off: split the assoc onto its own fd.  Only
	 * meaningful for SOCK_SEQPACKET (one-to-many style) — the
	 * SOCK_STREAM kernel-side already returns EINVAL for peeloff,
	 * which is itself an exercised reject edge so we still attempt
	 * it.  Requires a non-zero assoc_id from connectx; if we never
	 * got one (rare, EINPROGRESS path), skip. */
	if (assoc_id != 0) {
		struct sctp_peeloff_arg_compat parg;
		socklen_t plen = sizeof(parg);

		memset(&parg, 0, sizeof(parg));
		parg.associd = assoc_id;
		parg.sd = -1;
		rc = getsockopt(cli, IPPROTO_SCTP, SCTP_SOCKOPT_PEELOFF,
				&parg, &plen);
		if (rc == 0 && parg.sd >= 0) {
			peeled = parg.sd;
			__atomic_add_fetch(
				&shm->stats.sctp_assoc_churn_peeled_off,
				1, __ATOMIC_RELAXED);
		} else {
			__atomic_add_fetch(
				&shm->stats.sctp_assoc_churn_peeloff_rejected,
				1, __ATOMIC_RELAXED);
		}
	}

	(void)shutdown(cli, SHUT_RDWR);
	if (srv_acc >= 0)
		(void)shutdown(srv_acc, SHUT_RDWR);
	if (peeled >= 0)
		(void)shutdown(peeled, SHUT_RDWR);

out:
	if (peeled >= 0)
		close(peeled);
	if (srv_acc >= 0)
		close(srv_acc);
	if (cli >= 0)
		close(cli);
	if (srv >= 0)
		close(srv);
	__atomic_add_fetch(&shm->stats.sctp_assoc_churn_cycles,
			   1, __ATOMIC_RELAXED);
	return true;
}
