/*
 * SYSCALL_DEFINE3(getpeername, int, fd, struct sockaddr __user *, usockaddr, int __user *, usockaddr_len)
 */
#include <sys/syscall.h>
#include "sanitise.h"
#include "shm.h"
#include "sockname-recall.h"

/*
 * Oracle: getpeername(fd, addr, addrlen) writes the connected peer's
 * sockaddr for fd into *addr and the resulting length into *addrlen.
 * Only a call on the socket reconnects it, so for an already-connected
 * socket no sibling trinity child holds, two back-to-back calls for the
 * same fd must produce a byte-identical peer address (modulo families
 * with intentionally-volatile fields, see below).  sockname-recall.c
 * snapshots the result, re-issues the call and compares, for a socket of
 * the child's own pool only.
 *
 * Family-aware compare:
 *   - AF_UNIX: full sockaddr bytes (sun_family + sun_path) are stable, so
 *     a straight memcmp over first_len bytes is the right cross-check.
 *   - AF_INET: sin_family + sin_addr.s_addr are stable; sin_port is
 *     deliberately excluded.  The peer port the kernel reports back is
 *     the remote endpoint's port, which in normal use is fixed for the
 *     life of the connection -- but skipping it costs us nothing and
 *     defeats any ephemeral-source-port surprise leaking in via odd
 *     protocol corners (e.g. unconnected DGRAM sockets the syscall layer
 *     would reject before we get here, but better safe).
 *   - AF_INET6: sin6_family + sin6_addr (the 16-byte s6_addr) are stable;
 *     sin6_port, sin6_flowinfo and sin6_scope_id are deliberately
 *     excluded.  Flow label and scope-id can legitimately differ across
 *     re-reads on certain v6 socket types and we'd rather miss those than
 *     drown the channel in FPs.
 *   - All other families (AF_PACKET, AF_NETLINK, ...) are silently
 *     skipped: each has its own volatility profile and is left for a
 *     follow-up pass.
 */
static void post_getpeername(struct syscallrecord *rec)
{
	sockname_recall_post(rec, "getpeername", SYS_getpeername,
			     &shm->stats.oracle.getpeername_oracle_anomalies);
}

struct syscallentry syscall_getpeername = {
	.name = "getpeername",
	.num_args = 3,
	.argtype = { [0] = ARG_SOCKETINFO, [1] = ARG_SOCKADDR, [2] = ARG_SOCKADDRLEN },
	.argname = { [0] = "fd", [1] = "usockaddr", [2] = "usockaddr_len" },
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM | REEXEC_SANITISE_OK,
	.group = GROUP_NET,
	.sanitise = sockname_recall_sanitise,
	.post = post_getpeername,
	/* fd (a1): the re-call asks the socket the kernel did, which a
	 * RedQueen pin may have rewritten after the sanitiser drew its
	 * own. */
	.arg_snapshot_mask = (1u << 0),
};
