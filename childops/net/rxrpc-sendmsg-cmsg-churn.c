/*
 * rxrpc_sendmsg_cmsg_churn -- fuzz the AF_RXRPC sendmsg() control-message
 * surface (net/rxrpc/sendmsg.c rxrpc_sendmsg_cmsg).
 *
 * The rxrpc cmsg parser walks every CMSG_FIRSTHDR/CMSG_NXTHDR tuple in
 * msg_control and dispatches on cmsg_type:
 *
 *   RXRPC_USER_CALL_ID       64-bit user-supplied call cookie (anchors
 *                            an in-flight call to the userspace ABI)
 *   RXRPC_ABORT              4-byte abort code on a tracked call
 *   RXRPC_EXCLUSIVE_CALL     0-byte flag, makes a client call use a
 *                            dedicated rxrpc_connection
 *   RXRPC_UPGRADE_SERVICE    0-byte flag, asks for service-id upgrade
 *   RXRPC_TX_LENGTH          8-byte total tx length
 *   RXRPC_SET_CALL_TIMEOUT   variable-length per-call timeout block
 *   RXRPC_CHARGE_ACCEPT      server-side: charge a call slot for accept
 *   "ACCEPT" (alias)         legacy/synthetic; we send under the unused
 *                            RXRPC_ACK type-id so the kernel exercises
 *                            the unhandled / wrong-direction reject path
 *
 * Reachable bug class on this test kernel (CONFIG_AF_RXRPC=m,
 * CONFIG_AF_RXRPC_IPV6=y, CONFIG_AFS_FS=n): the rxrpc-only call lifecycle
 * surface -- rxrpc_destroy_all_calls ODEBUG when sendmsg() leaves a
 * partially-set-up call dangling in rx->calls; delete_node ODEBUG on the
 * peer/call timer trees when an ABORT/SET_CALL_TIMEOUT cmsg races the
 * teardown.  AFS-side bugs (afs_cell_purge, afs_dynroot_readdir) are
 * unreachable here -- AFS_FS is not built -- so this op stays scoped to
 * the raw-socket cmsg parser.
 *
 * Per-iteration shape:
 *   1. socket(AF_RXRPC, SOCK_DGRAM, PF_INET | PF_INET6).  EPROTONOSUPPORT
 *      / ENOPROTOOPT / EAFNOSUPPORT on the very first call latches
 *      ns_rxrpc_unsupported for the rest of the process and every
 *      subsequent invocation bails at the gate (mirrors the af_alg /
 *      mptcp_pm latch idiom).
 *   2. bind() to ephemeral local port via sockaddr_rxrpc with
 *      transport.sin{,6}_port = 0.  bind failure is counted but not
 *      latched -- a transient EADDRINUSE collision shouldn't disable
 *      the whole op.
 *   3. Coin-flip: connect() to a sockaddr_rxrpc whose transport endpoint
 *      is 127.0.0.1:<rotating> (or ::1 on the v6 side) so the per-iter
 *      mix exercises both connected and unconnected sendmsg paths.
 *   4. sendmsg() with msg_control carrying ONE cmsg drawn uniformly from
 *      the eight-element table.  Half the iters use the structurally
 *      valid attribute length for the chosen cmsg; the other half use a
 *      length perturbation (zero, one byte too short, one byte too long,
 *      or an arbitrary in-range scribble) so the parser's length-validate
 *      path runs.  user_call_id values mix a small in-range cookie and
 *      bogus high-bit values to exercise both lookup-hit and lookup-miss
 *      paths in the per-socket xarray.
 *
 * Self-bounding: one socket + bind + (maybe) connect + one sendmsg per
 * invocation, all inside child.c's SIGALRM(1s) cap.  No persistent state
 * across iters; each socket is closed before return.  Loopback-only
 * transport addresses, so nothing leaves the host even when the socket
 * is in connected state.  No netns plumbing -- the surface we want is
 * the cmsg parser, which is reached entirely from the AF_RXRPC socket-
 * layer dispatch.
 *
 * Header gating: <linux/rxrpc.h> is the UAPI header that exposes the
 * RXRPC_* cmsg type ids and struct sockaddr_rxrpc.  Sysroots without it
 * fall through to a stub that bumps runs+socket_failed and returns,
 * matching the tipc-link / mptcp-pm pattern.
 *
 * Failure modes treated as benign coverage:
 *   - EPROTONOSUPPORT / ENOPROTOOPT on socket(): kernel built without
 *     CONFIG_AF_RXRPC.  Latched ns_rxrpc_unsupported.
 *   - EINVAL / EBADMSG / ECONNABORTED on sendmsg(): expected for the
 *     malformed/wrong-direction cmsg shapes; counted as sendmsg_fail.
 *   - EADDRINUSE on bind(): another sibling grabbed the same ephemeral
 *     port.  Counted under socket_failed; the next iter rolls.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>

#include "child.h"
#include "shm.h"
#include "trinity.h"

#if defined(AF_RXRPC) && __has_include(<linux/rxrpc.h>)

#include <netinet/in.h>
#include <linux/rxrpc.h>

#include "random.h"
#include "utils.h"

#include "kernel/socket.h"
/*
 * Latched per-process: socket(AF_RXRPC, ...) returned an "unsupported"
 * errno once.  CONFIG_AF_RXRPC is fixed for the process lifetime so
 * further attempts are pure waste.
 */
static bool ns_rxrpc_unsupported;

/*
 * Eight cmsg slots fuzzed uniformly.  Slot indexes here are also the
 * histogram indexes the stats block reports.  Type ids match
 * <linux/rxrpc.h>; the "ACCEPT" alias has no dedicated cmsg type in
 * current UAPI -- we send under RXRPC_ACK (3, server-receive only) so
 * the kernel's "wrong direction / unhandled type" reject path runs.
 */
enum rxrpc_cmsg_slot {
	CMSG_SLOT_USER_CALL_ID = 0,
	CMSG_SLOT_ABORT,
	CMSG_SLOT_ACCEPT,
	CMSG_SLOT_EXCLUSIVE_CALL,
	CMSG_SLOT_UPGRADE_SERVICE,
	CMSG_SLOT_TX_LENGTH,
	CMSG_SLOT_SET_CALL_TIMEOUT,
	CMSG_SLOT_CHARGE_ACCEPT,
	NR_CMSG_SLOTS
};

struct cmsg_spec {
	int		type;		/* RXRPC_* cmsg type id */
	size_t		valid_len;	/* attribute length the kernel expects */
};

static const struct cmsg_spec cmsg_table[NR_CMSG_SLOTS] = {
	[CMSG_SLOT_USER_CALL_ID]	= { RXRPC_USER_CALL_ID,		sizeof(__u64) },
	[CMSG_SLOT_ABORT]		= { RXRPC_ABORT,		sizeof(__u32) },
	[CMSG_SLOT_ACCEPT]		= { RXRPC_ACK,			0 },
	[CMSG_SLOT_EXCLUSIVE_CALL]	= { RXRPC_EXCLUSIVE_CALL,	0 },
	[CMSG_SLOT_UPGRADE_SERVICE]	= { RXRPC_UPGRADE_SERVICE,	0 },
	[CMSG_SLOT_TX_LENGTH]		= { RXRPC_TX_LENGTH,		sizeof(__s64) },
	[CMSG_SLOT_SET_CALL_TIMEOUT]	= { RXRPC_SET_CALL_TIMEOUT,	3 * sizeof(__u32) },
	[CMSG_SLOT_CHARGE_ACCEPT]	= { RXRPC_CHARGE_ACCEPT,	sizeof(__u64) },
};

#define LOOPBACK_PEER_PORT_BASE	7000U	/* 127.0.0.1:7000.. as a fake peer */
#define NR_LOOPBACK_PEER_PORTS	8U

/*
 * Pick a payload length to send for the given slot.  Half the time we
 * send the structurally-valid length; the other half we perturb so the
 * parser's length-validate paths run.
 */
static size_t pick_payload_len(enum rxrpc_cmsg_slot slot)
{
	size_t valid = cmsg_table[slot].valid_len;

	if (RAND_BOOL())
		return valid;

	switch (rnd_modulo_u32(4U)) {
	case 0:		return 0;
	case 1:		return valid > 0 ? valid - 1U : 1U;
	case 2:		return valid + 1U;
	default:	return (size_t)rnd_modulo_u32(32U);
	}
}

/*
 * Fill an in-control cmsg payload of @len bytes targeted at @slot.  For
 * the slots whose semantics carry an embedded id (USER_CALL_ID,
 * CHARGE_ACCEPT) we mix small in-range cookies and bogus high-bit values
 * so the per-socket xarray sees both lookup-hit and lookup-miss shapes.
 */
static void fill_payload(enum rxrpc_cmsg_slot slot,
			 unsigned char *buf, size_t len)
{
	if (len == 0)
		return;
	memset(buf, 0, len);

	switch (slot) {
	case CMSG_SLOT_USER_CALL_ID:
	case CMSG_SLOT_CHARGE_ACCEPT:
		if (len >= sizeof(__u64)) {
			__u64 id;

			if (RAND_BOOL())
				id = (__u64)(rand32() & 0xffU);
			else
				id = ((__u64)rand32() << 32) | rand32();
			memcpy(buf, &id, sizeof(id));
		} else {
			generate_rand_bytes(buf, len);
		}
		break;

	case CMSG_SLOT_ABORT:
		if (len >= sizeof(__u32)) {
			__u32 code = rand32();
			memcpy(buf, &code, sizeof(code));
		} else {
			generate_rand_bytes(buf, len);
		}
		break;

	case CMSG_SLOT_TX_LENGTH:
		if (len >= sizeof(__s64)) {
			__s64 v = (__s64)(((__u64)rand32() << 32) | rand32());
			memcpy(buf, &v, sizeof(v));
		} else {
			generate_rand_bytes(buf, len);
		}
		break;

	default:
		generate_rand_bytes(buf, len);
		break;
	}
}

/*
 * Build & emit one sendmsg() carrying a single cmsg from @slot.  Returns
 * 0 on send success, -1 otherwise.  Caller bumps the per-slot histogram
 * regardless of outcome -- the histogram tracks attempted shape coverage
 * not kernel-side acceptance.
 */
static int send_one_cmsg(int fd, const struct sockaddr_rxrpc *peer,
			 bool have_peer, enum rxrpc_cmsg_slot slot)
{
	unsigned char ctrl[CMSG_SPACE(64)];
	unsigned char data[16];
	struct msghdr mh;
	struct cmsghdr *cmh;
	struct iovec iov;
	size_t payload_len;
	ssize_t n;

	memset(ctrl, 0, sizeof(ctrl));
	memset(&mh, 0, sizeof(mh));

	payload_len = pick_payload_len(slot);
	if (payload_len > 32U)
		payload_len = 32U;	/* keep inside ctrl[] */

	cmh = (struct cmsghdr *)ctrl;
	cmh->cmsg_level = SOL_RXRPC;
	cmh->cmsg_type  = cmsg_table[slot].type;
	cmh->cmsg_len   = CMSG_LEN(payload_len);
	fill_payload(slot, CMSG_DATA(cmh), payload_len);

	if (RAND_BOOL()) {
		generate_rand_bytes(data, sizeof(data));
		iov.iov_base = data;
		iov.iov_len  = 1U + rnd_modulo_u32(sizeof(data));
		mh.msg_iov    = &iov;
		mh.msg_iovlen = 1;
	}

	mh.msg_control    = ctrl;
	mh.msg_controllen = CMSG_SPACE(payload_len);

	if (have_peer) {
		mh.msg_name    = (void *)peer;
		mh.msg_namelen = sizeof(*peer);
	}

	n = sendmsg(fd, &mh, MSG_DONTWAIT | MSG_NOSIGNAL);
	return n >= 0 ? 0 : -1;
}

/*
 * Build a loopback sockaddr_rxrpc.  @v6 selects v4 vs v6 transport.
 * The transport port is rotated across NR_LOOPBACK_PEER_PORTS so multi-
 * child runs aren't all hammering the same imaginary peer.
 */
static void make_peer(struct sockaddr_rxrpc *srx, bool v6)
{
	memset(srx, 0, sizeof(*srx));
	srx->srx_family  = AF_RXRPC;
	srx->srx_service = 0;
	srx->transport_type = SOCK_DGRAM;

	if (v6) {
		struct in6_addr loop6 = IN6ADDR_LOOPBACK_INIT;

		srx->transport_len = sizeof(struct sockaddr_in6);
		srx->transport.sin6.sin6_family = AF_INET6;
		srx->transport.sin6.sin6_addr   = loop6;
		srx->transport.sin6.sin6_port =
			htons((uint16_t)(LOOPBACK_PEER_PORT_BASE +
					 rnd_modulo_u32(NR_LOOPBACK_PEER_PORTS)));
	} else {
		srx->transport_len = sizeof(struct sockaddr_in);
		srx->transport.sin.sin_family = AF_INET;
		srx->transport.sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		srx->transport.sin.sin_port =
			htons((uint16_t)(LOOPBACK_PEER_PORT_BASE +
					 rnd_modulo_u32(NR_LOOPBACK_PEER_PORTS)));
	}
}

bool rxrpc_sendmsg_cmsg_churn(struct childdata *child)
{
	struct sockaddr_rxrpc local;
	struct sockaddr_rxrpc peer;
	enum rxrpc_cmsg_slot slot;
	bool v6;
	bool have_peer;
	int fd;
	int rc;
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	__atomic_add_fetch(&shm->stats.rxrpc_sendmsg_cmsg_runs,
			   1, __ATOMIC_RELAXED);

	if (ns_rxrpc_unsupported)
		return true;

	v6 = RAND_BOOL();

	fd = socket(AF_RXRPC, SOCK_DGRAM | SOCK_CLOEXEC,
		    v6 ? PF_INET6 : PF_INET);
	if (fd < 0) {
		if (errno == EPROTONOSUPPORT || errno == EAFNOSUPPORT ||
		    errno == ENOPROTOOPT) {
			ns_rxrpc_unsupported = true;
			if (valid_op)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		__atomic_add_fetch(&shm->stats.rxrpc_sendmsg_cmsg_socket_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	memset(&local, 0, sizeof(local));
	local.srx_family  = AF_RXRPC;
	local.srx_service = 0;
	local.transport_type = SOCK_DGRAM;
	if (v6) {
		struct in6_addr loop6 = IN6ADDR_LOOPBACK_INIT;

		local.transport_len = sizeof(struct sockaddr_in6);
		local.transport.sin6.sin6_family = AF_INET6;
		local.transport.sin6.sin6_addr   = loop6;
		local.transport.sin6.sin6_port   = 0;
	} else {
		local.transport_len = sizeof(struct sockaddr_in);
		local.transport.sin.sin_family = AF_INET;
		local.transport.sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		local.transport.sin.sin_port = 0;
	}

	if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
		__atomic_add_fetch(&shm->stats.rxrpc_sendmsg_cmsg_socket_failed,
				   1, __ATOMIC_RELAXED);
		close(fd);
		return true;
	}

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	have_peer = RAND_BOOL();
	if (have_peer) {
		make_peer(&peer, v6);
		if (connect(fd, (struct sockaddr *)&peer, sizeof(peer)) < 0) {
			/* connect failures are fine: the unconnected
			 * sendmsg path with msg_name set is also part of
			 * the surface we want to exercise. */
		}
	} else {
		make_peer(&peer, v6);
	}

	slot = (enum rxrpc_cmsg_slot)rnd_modulo_u32((unsigned int)NR_CMSG_SLOTS);
	__atomic_add_fetch(&shm->stats.rxrpc_sendmsg_cmsg_sent[slot],
			   1, __ATOMIC_RELAXED);

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);

	rc = send_one_cmsg(fd, &peer, have_peer, slot);
	if (rc == 0)
		__atomic_add_fetch(&shm->stats.rxrpc_sendmsg_cmsg_sendmsg_ok,
				   1, __ATOMIC_RELAXED);
	else
		__atomic_add_fetch(&shm->stats.rxrpc_sendmsg_cmsg_sendmsg_fail,
				   1, __ATOMIC_RELAXED);

	close(fd);
	return true;
}

#else  /* !defined(AF_RXRPC) || !__has_include(<linux/rxrpc.h>) */

bool rxrpc_sendmsg_cmsg_churn(struct childdata *child)
{
	(void)child;
	__atomic_add_fetch(&shm->stats.rxrpc_sendmsg_cmsg_runs,
			   1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.rxrpc_sendmsg_cmsg_socket_failed,
			   1, __ATOMIC_RELAXED);
	return true;
}

#endif /* defined(AF_RXRPC) && __has_include(<linux/rxrpc.h>) */
