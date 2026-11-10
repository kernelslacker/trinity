/*
 * SYSCALL_DEFINE3(getsockname, int, fd, struct sockaddr __user *, usockaddr, int __user *, usockaddr_len)
 */
#include <sys/syscall.h>
#include "sanitise.h"
#include "shm.h"
#include "sockname-recall.h"

/*
 * Oracle: getsockname(fd, addr, addrlen) writes the bound local address
 * for fd into *addr and the resulting length into *addrlen.  Only a call
 * on the socket moves it, so for a socket no sibling trinity child holds,
 * two back-to-back calls for the same fd must produce a byte-identical
 * address (modulo families with intentionally-volatile fields, see
 * below).  sockname-recall.c snapshots the result, re-issues the call and
 * compares, for a socket of the child's own pool only.
 *
 * Family-aware compare:
 *   - AF_UNIX: full sockaddr bytes (sun_family + sun_path) are stable.
 *   - AF_INET: sin_family + sin_addr.s_addr are stable; sin_port is
 *     deliberately excluded -- a UDP DGRAM socket with an ephemeral
 *     autobind can legitimately surface a different port across the two
 *     re-reads in rare corner cases, and we'd rather miss those than
 *     drown the channel in autobind FPs.
 *   - AF_INET6: sin6_family + sin6_addr are stable: inet6_getname() reports
 *     the bound address, or the source address a connect() picked, which
 *     only another bind() or connect() moves.  sin6_port is excluded as
 *     for AF_INET, and sin6_flowinfo and sin6_scope_id with it.
 *   - All other families (AF_PACKET, AF_NETLINK, ...) are silently
 *     skipped: each has its own volatility profile and is left for a
 *     follow-up pass.
 */
static void post_getsockname(struct syscallrecord *rec)
{
	sockname_recall_post(rec, "getsockname", SYS_getsockname,
			     &shm->stats.oracle.getsockname_oracle_anomalies);
}

struct syscallentry syscall_getsockname = {
	.name = "getsockname",
	.num_args = 3,
	.argtype = { [0] = ARG_SOCKETINFO, [1] = ARG_SOCKADDR, [2] = ARG_SOCKADDRLEN },
	.argname = { [0] = "fd", [1] = "usockaddr", [2] = "usockaddr_len" },
	.flags = NEED_ALARM | REEXEC_SANITISE_OK,
	.group = GROUP_NET,
	.sanitise = sockname_recall_sanitise,
	.post = post_getsockname,
	/* fd (a1): the re-call asks the socket the kernel did, which a
	 * RedQueen pin may have rewritten after the sanitiser drew its
	 * own. */
	.arg_snapshot_mask = (1u << 0),
	.rettype = RET_ZERO_SUCCESS,
};
