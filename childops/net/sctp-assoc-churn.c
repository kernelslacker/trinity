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
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>

#include "child.h"
#include "jitter.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"

#include "kernel/socket.h"
#include "kernel/sctp.h"
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

/* Per-invocation state shared across the extracted phase helpers.  Fd
 * fields default to -1 so the teardown path can close-or-skip
 * unconditionally regardless of which earlier phase bailed.  sock_type
 * is picked in setup_server and consumed downstream by setup_client
 * and connect; srv_port_n is the kernel-assigned ephemeral port the
 * connect helper packs into the CONNECTX address list.  child is the
 * caller's struct childdata so phase helpers can attribute per-childop
 * yield counters to child->op_type. */
struct sctp_assoc_churn_iter_ctx {
	int srv;
	int cli;
	int srv_acc;
	int peeled;
	int sock_type;
	uint16_t srv_port_n;
	uint16_t cli_port_n;
	sctp_assoc_t_compat assoc_id;
	struct childdata *child;
};

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
	n = send(fd, buf, 1U + rnd_modulo_u32(sizeof(buf)),
		 MSG_DONTWAIT | MSG_NOSIGNAL);
	if (n > 0)
		__atomic_add_fetch(&shm->stats.sctp_assoc_churn_packets_sent,
				   1, __ATOMIC_RELAXED);
}

/*
 * Phase 1: pick the per-invocation socket type (SOCK_STREAM vs
 * SOCK_SEQPACKET so both sk_prot tables in net/sctp/socket.c get
 * exercised across runs), open the server SCTP socket, bind the
 * primary to 127.0.0.1:0, recover the kernel-assigned ephemeral port
 * via getsockname, multi-home with bindx ADD on 127.0.0.2 +
 * 127.0.0.3 (pre-listen ADD doesn't fire ASCONF — no association
 * exists yet — but it's the structural setup that lets post-assoc
 * ADD/REM later actually emit ASCONF chunks), and finally listen.
 * Doubles as the support gate: EPROTONOSUPPORT / ESOCKTNOSUPPORT on
 * socket() latches ns_unsupported so siblings stop probing.  Returns
 * 0 on success or -1 if the iteration should bail to the out:
 * cleanup path.
 */
static int sctp_assoc_churn_iter_setup_server(struct sctp_assoc_churn_iter_ctx *ctx)
{
	struct sockaddr_in srv_primary;
	struct sockaddr_in addrs[NR_LOOPBACK_ADDRS];
	socklen_t slen;
	int addr_len;
	int rc;

	ctx->sock_type = (rnd_u32() & 1) ? SOCK_STREAM : SOCK_SEQPACKET;

	ctx->srv = socket(AF_INET, ctx->sock_type | SOCK_CLOEXEC, IPPROTO_SCTP);
	if (ctx->srv < 0) {
		if (errno == EPROTONOSUPPORT || errno == ESOCKTNOSUPPORT) {
			ns_unsupported = true;
			/* ctx->child->op_type lives in shared memory and can
			 * be scribbled by a poisoned-arena write from a
			 * sibling; bounds-check the snapshot before indexing
			 * the NR_CHILD_OP_TYPES-sized stats array, same
			 * pattern the child.c dispatch loop uses for the
			 * unguarded write that motivated this guard. */
			{
				const enum child_op_type op = ctx->child->op_type;
				if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
					__atomic_store_n(&shm->stats.childop.latch_reason[op],
							 CHILDOP_LATCH_NS_UNSUPPORTED,
							 __ATOMIC_RELAXED);
			}
		}
		__atomic_add_fetch(&shm->stats.sctp_assoc_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}

	fill_sin(&srv_primary, loopback_pool[0], 0);
	if (bind(ctx->srv, (struct sockaddr *)&srv_primary,
		 sizeof(srv_primary)) < 0) {
		__atomic_add_fetch(&shm->stats.sctp_assoc_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	slen = sizeof(srv_primary);
	if (getsockname(ctx->srv, (struct sockaddr *)&srv_primary, &slen) < 0) {
		__atomic_add_fetch(&shm->stats.sctp_assoc_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	ctx->srv_port_n = srv_primary.sin_port;

	addr_len = pack_addrs(addrs, NR_LOOPBACK_ADDRS, 1, 2, ctx->srv_port_n);
	rc = setsockopt(ctx->srv, IPPROTO_SCTP, SCTP_SOCKOPT_BINDX_ADD,
			addrs, (socklen_t)addr_len);
	if (rc == 0)
		__atomic_add_fetch(&shm->stats.sctp_assoc_churn_bindx_added,
				   1, __ATOMIC_RELAXED);
	else
		__atomic_add_fetch(&shm->stats.sctp_assoc_churn_bindx_rejected,
				   1, __ATOMIC_RELAXED);

	if (listen(ctx->srv, 4) < 0) {
		__atomic_add_fetch(&shm->stats.sctp_assoc_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	return 0;
}

/*
 * Phase 2: open the client SCTP socket, bind a separate primary
 * (127.0.0.4:0 — distinct from the server's primary so the assoc has
 * unambiguous local-vs-remote endpoints), recover the kernel-assigned
 * ephemeral port via getsockname, then flip both client and server
 * fds to O_NONBLOCK.  Non-blocking from here on so a wedged loopback
 * can't pin us past child.c's SIGALRM(1s) safety net — CONNECTX
 * returning EINPROGRESS later is fine and the assoc completes
 * asynchronously.  Returns 0 on success or -1 if the iteration should
 * bail to the out: cleanup path.
 */
static int sctp_assoc_churn_iter_setup_client(struct sctp_assoc_churn_iter_ctx *ctx)
{
	struct sockaddr_in cli_primary;
	socklen_t slen;

	ctx->cli = socket(AF_INET, ctx->sock_type | SOCK_CLOEXEC, IPPROTO_SCTP);
	if (ctx->cli < 0) {
		__atomic_add_fetch(&shm->stats.sctp_assoc_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	fill_sin(&cli_primary, loopback_pool[3], 0);
	if (bind(ctx->cli, (struct sockaddr *)&cli_primary,
		 sizeof(cli_primary)) < 0) {
		__atomic_add_fetch(&shm->stats.sctp_assoc_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	slen = sizeof(cli_primary);
	if (getsockname(ctx->cli, (struct sockaddr *)&cli_primary, &slen) < 0) {
		__atomic_add_fetch(&shm->stats.sctp_assoc_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	ctx->cli_port_n = cli_primary.sin_port;

	(void)fcntl(ctx->cli, F_SETFL, O_NONBLOCK);
	(void)fcntl(ctx->srv, F_SETFL, O_NONBLOCK);
	return 0;
}

/*
 * Phase 3: drive the association up.  CONNECTX with the server's
 * full multi-address set (3 addrs) on the client — the kernel
 * returns the new assoc_id as the setsockopt return value (positive)
 * on success, which we park in ctx for the optional peeloff step
 * later.  For SOCK_STREAM, accept() the inbound assoc on the
 * server's accept queue so server-side ESTABLISHED actually exists
 * when bindx ADD fires.  SOCK_SEQPACKET delivers all assocs through
 * the parent socket so accept() doesn't apply — the assoc
 * materialises lazily on first ingress.  Accept failure is fine: the
 * cookie may not have been ACKed yet, and SCTP doesn't queue on
 * EINPROGRESS the same way TCP does.  Finally drive the data path
 * before the first ASCONF so the assoc has actually transitioned to
 * ESTABLISHED on both ends — otherwise the post-handshake bindx ADD
 * races against the cookie itself, which isn't the bug class we're
 * targeting.  Returns 0 on success or -1 if the iteration should
 * bail to the out: cleanup path.
 */
static int sctp_assoc_churn_iter_connect(struct sctp_assoc_churn_iter_ctx *ctx)
{
	struct sockaddr_in addrs[NR_LOOPBACK_ADDRS];
	int addr_len;
	int rc;

	addr_len = pack_addrs(addrs, NR_LOOPBACK_ADDRS, 0, 3, ctx->srv_port_n);
	rc = setsockopt(ctx->cli, IPPROTO_SCTP, SCTP_SOCKOPT_CONNECTX,
			addrs, (socklen_t)addr_len);
	if (rc < 0 && errno != EINPROGRESS) {
		__atomic_add_fetch(&shm->stats.sctp_assoc_churn_connect_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	if (rc > 0)
		ctx->assoc_id = (sctp_assoc_t_compat)rc;
	__atomic_add_fetch(&shm->stats.sctp_assoc_churn_connected,
			   1, __ATOMIC_RELAXED);

	if (ctx->sock_type == SOCK_STREAM) {
		ctx->srv_acc = accept(ctx->srv, NULL, NULL);
		if (ctx->srv_acc >= 0) {
			(void)fcntl(ctx->srv_acc, F_SETFL, O_NONBLOCK);
			__atomic_add_fetch(
				&shm->stats.sctp_assoc_churn_accepted,
				1, __ATOMIC_RELAXED);
		}
	}

	churn_send(ctx->cli);
	if (ctx->srv_acc >= 0)
		churn_send(ctx->srv_acc);
	return 0;
}

/*
 * Phase 4: BUDGETED bindx ADD/REM churn against the live assoc.
 * Each iteration ADDs a fresh address on the client (kernel runs
 * sctp_send_asconf_add_ip synchronously and the ASCONF chunk is on
 * the wire before setsockopt returns), sends through the rotation
 * window to race DATA against ASCONF parameter parsing on the
 * server, then REMs the address (sctp_send_asconf_del_ip — if the
 * prior send hasn't been ACKed yet, this races a path deletion
 * against in-flight DATA on that path).  rot_idx walks the
 * loopback_pool starting at index 4 (127.0.0.5 — addrs 0..3 are
 * already in use as the bound primaries / multi-home set) and wraps
 * inside the pool so we never touch addresses outside 127.0.0.0/8.
 * Void return: every per-step bindx is best-effort and the
 * orchestrator has nothing to branch on.
 */
static void sctp_assoc_churn_iter_churn_loop(struct sctp_assoc_churn_iter_ctx *ctx)
{
	struct sockaddr_in addrs[NR_LOOPBACK_ADDRS];
	unsigned int iters, i, rot_idx;
	int addr_len;
	int rc;

	iters = BUDGETED(CHILD_OP_SCTP_ASSOC_CHURN,
			 JITTER_RANGE(CHURN_ITERS_BASE));
	rot_idx = 4;
	for (i = 0; i < iters; i++) {
		/* a) ADD a fresh address mid-flow.  After this returns,
		 *    the ASCONF chunk is already on the wire (kernel
		 *    side runs sctp_send_asconf_add_ip synchronously
		 *    before the setsockopt returns to userspace). */
		addr_len = pack_addrs(addrs, NR_LOOPBACK_ADDRS,
				      rot_idx, 1, ctx->cli_port_n);
		rc = setsockopt(ctx->cli, IPPROTO_SCTP, SCTP_SOCKOPT_BINDX_ADD,
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
		churn_send(ctx->cli);
		if (ctx->srv_acc >= 0)
			churn_send(ctx->srv_acc);

		/* c) REM the address we just added.  Hits the
		 *    sctp_send_asconf_del_ip path; if the data send
		 *    above hasn't been ACKed yet, this races a path
		 *    deletion against in-flight DATA on that path. */
		rc = setsockopt(ctx->cli, IPPROTO_SCTP, SCTP_SOCKOPT_BINDX_REM,
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
}

/*
 * Phase 5: optional peel-off then shutdown the live fds.  Peel-off
 * is only meaningful for SOCK_SEQPACKET (one-to-many style) — the
 * SOCK_STREAM kernel side already returns EINVAL for peeloff, which
 * is itself an exercised reject edge so we still attempt it.
 * Requires a non-zero assoc_id from CONNECTX; if we never got one
 * (rare, EINPROGRESS path), skip the getsockopt.  The trailing
 * shutdown(SHUT_RDWR) block lives here — peeled has to land after
 * the peeloff getsockopt, and cli / srv_acc shutdown only when we
 * reached this far so the existing early-bail goto out paths still
 * skip them.  Void return: peeloff outcome is purely a stat tick.
 */
static void sctp_assoc_churn_iter_peeloff(struct sctp_assoc_churn_iter_ctx *ctx)
{
	if (ctx->assoc_id != 0) {
		struct sctp_peeloff_arg_compat parg;
		socklen_t plen = sizeof(parg);
		int rc;

		memset(&parg, 0, sizeof(parg));
		parg.associd = ctx->assoc_id;
		parg.sd = -1;
		rc = getsockopt(ctx->cli, IPPROTO_SCTP, SCTP_SOCKOPT_PEELOFF,
				&parg, &plen);
		if (rc == 0 && parg.sd >= 0) {
			ctx->peeled = parg.sd;
			__atomic_add_fetch(
				&shm->stats.sctp_assoc_churn_peeled_off,
				1, __ATOMIC_RELAXED);
		} else {
			__atomic_add_fetch(
				&shm->stats.sctp_assoc_churn_peeloff_rejected,
				1, __ATOMIC_RELAXED);
		}
	}

	(void)shutdown(ctx->cli, SHUT_RDWR);
	if (ctx->srv_acc >= 0)
		(void)shutdown(ctx->srv_acc, SHUT_RDWR);
	if (ctx->peeled >= 0)
		(void)shutdown(ctx->peeled, SHUT_RDWR);
}

/*
 * Phase 6: close whichever fds we managed to open.  Runs on every
 * exit path — both the success path falling through to out: after
 * peeloff returns, and the early-bail goto out from any earlier
 * phase failure.  Order matches the original out: cleanup: peeled
 * first, then accepted server fd, then client, then listener.
 * Fields default to -1 via the orchestrator's designated initialiser
 * so the guards skip fds that were never opened.
 */
static void sctp_assoc_churn_iter_teardown(struct sctp_assoc_churn_iter_ctx *ctx)
{
	if (ctx->peeled >= 0)
		close(ctx->peeled);
	if (ctx->srv_acc >= 0)
		close(ctx->srv_acc);
	if (ctx->cli >= 0)
		close(ctx->cli);
	if (ctx->srv >= 0)
		close(ctx->srv);
}

bool sctp_assoc_churn(struct childdata *child)
{
	struct sctp_assoc_churn_iter_ctx ctx = {
		.srv = -1,
		.cli = -1,
		.srv_acc = -1,
		.peeled = -1,
		.child = child,
	};

	__atomic_add_fetch(&shm->stats.sctp_assoc_churn_runs,
			   1, __ATOMIC_RELAXED);

	if (ns_unsupported)
		return true;

	if (sctp_assoc_churn_iter_setup_server(&ctx) != 0)
		goto out;

	if (sctp_assoc_churn_iter_setup_client(&ctx) != 0)
		goto out;
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	if (sctp_assoc_churn_iter_connect(&ctx) != 0)
		goto out;

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	sctp_assoc_churn_iter_churn_loop(&ctx);

	sctp_assoc_churn_iter_peeloff(&ctx);

out:
	sctp_assoc_churn_iter_teardown(&ctx);
	__atomic_add_fetch(&shm->stats.sctp_assoc_churn_cycles,
			   1, __ATOMIC_RELAXED);
	return true;
}
