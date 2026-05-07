/*
 * MPTCP (multipath TCP) per-protocol fuzzing helpers.
 *
 * Reachable via socket(AF_INET[6], SOCK_STREAM, IPPROTO_MPTCP).  In current
 * kernels, SOL_MPTCP options (MPTCP_INFO et al.) are getsockopt-only --
 * mptcp_setsockopt() at SOL_MPTCP returns -EOPNOTSUPP.  We still emit the
 * option grammar here because do_setsockopt() is shared between the
 * setsockopt and getsockopt sanitisers (see syscalls/getsockopt.c), so this
 * grammar exercises the SOL_MPTCP getsockopt dispatch path on real MPTCP
 * sockets.  Path-management lives behind the mptcp_pm genetlink family and
 * is intentionally not handled here.
 */

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include "arch.h"
#include "compat.h"
#include "net.h"
#include "random.h"
#include "socket-family-grammar.h"
#include "utils.h"

static const unsigned int mptcp_opts[] = {
	MPTCP_INFO,
	MPTCP_TCPINFO,
	MPTCP_SUBFLOW_ADDRS,
	MPTCP_FULL_INFO,
};

/*
 * mptcp_subflow_data is the userspace-controlled prefix the kernel reads off
 * the optval for MPTCP_TCPINFO / MPTCP_SUBFLOW_ADDRS / MPTCP_FULL_INFO.
 * Defined privately to avoid a hard dep on linux/mptcp.h at build time.
 */
struct mptcp_subflow_data_compat {
	unsigned int size_subflow_data;
	unsigned int num_subflows;
	unsigned int size_kernel;
	unsigned int size_user;
} __attribute__((aligned(8)));

void mptcp_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	unsigned char *p = (unsigned char *) so->optval;

	so->optname = RAND_ARRAY(mptcp_opts);

	switch (so->optname) {
	case MPTCP_INFO:
		/* struct mptcp_info has grown across kernel releases; a generous
		 * buffer covers older + newer versions without truncating.
		 */
		so->optlen = 256;
		generate_rand_bytes(p, so->optlen);
		break;

	case MPTCP_TCPINFO:
	case MPTCP_SUBFLOW_ADDRS:
	case MPTCP_FULL_INFO: {
		struct mptcp_subflow_data_compat *sd = (void *) p;

		so->optlen = sizeof(*sd) + (rand() % (page_size - sizeof(*sd)));
		generate_rand_bytes(p, so->optlen);

		/* Half the time, populate the subflow_data prefix with values
		 * that pass the kernel's size validation -- so the dispatcher
		 * proceeds past the early bounds check and reaches the per-opt
		 * handlers.  The other half stays fully random to exercise the
		 * validation path itself.
		 */
		if (RAND_BOOL()) {
			sd->size_subflow_data = sizeof(*sd);
			sd->num_subflows = 0;
			sd->size_kernel = 0;
			sd->size_user = rand() % 256;
		}
		break;
	}

	default:
		so->optlen = page_size;
		break;
	}
}

/*
 * grammar_mptcp — coherent walk for IPPROTO_MPTCP sockets driven by
 * the per-family grammar dispatcher (net/socket-family-grammar.c).
 *
 * MPTCP is not its own AF_*; it lives under AF_INET / AF_INET6 with
 * IPPROTO_MPTCP / SOCK_STREAM.  This entry sits next to the existing
 * MPTCP option helpers above so a single file owns the SOL_MPTCP
 * surface, paralleling the per-family colocation other grammars use.
 *
 * The walk pins the SOL_MPTCP dispatcher in BOTH directions inside
 * one childop:
 *
 *   1. TCP-level setsockopt churn (TCP_CONGESTION -> TCP_NODELAY ->
 *      TCP_CORK).  MPTCP sockets carry a TCP layer per subflow; these
 *      flow through the master's tcp_setsockopt and propagate to
 *      every active subflow via mptcp_setsockopt_first_sf_only /
 *      __mptcp_tcp_fallback paths the per-syscall fuzzer never lands
 *      on a real MPTCP socket.
 *
 *   2. SOL_MPTCP getsockopt fanout (MPTCP_INFO, MPTCP_FULL_INFO,
 *      MPTCP_TCPINFO, MPTCP_SUBFLOW_ADDRS).  At SOL_MPTCP the
 *      setsockopt direction returns -EOPNOTSUPP, so the dispatcher
 *      coverage we want is in getsockopt.  Mixing both directions on
 *      the same fd in the same coherent walk is the point — random
 *      per-syscall fuzzing pairs them on arbitrary fds, this pairs
 *      them on a confirmed-MPTCP fd whose subflow_data prefix
 *      validation (mptcp_get_sub_validate) is reachable.
 *
 * Triplet picking probes BOTH PF_INET and PF_INET6 once at startup
 * and caches each verdict.  pick_triplet only emits a family that
 * was confirmed to work at probe time, so the framework's socket()
 * inside run_grammar_chain never takes the EPROTONOSUPPORT branch
 * and never taints the per-family unsupported latch shared with
 * grammar_inet / grammar_inet6.  CONFIG_MPTCP=n latches mptcp_v4_state
 * to 0 in can_run, returning false there filters this grammar out at
 * sfg_pick_random_active() time before run_grammar_chain runs — so
 * the latch stays clean for the IP grammars.
 *
 * Subflow path-management (ADD_ADDR / REMOVE_ADDR via the mptcp_pm
 * genetlink family) is intentionally NOT handled here — that surface
 * has its own coherent driver in childops/mptcp-pm-churn.c which
 * already orchestrates the post-DEL race window.  This grammar is
 * orthogonal: socket-layer option-walk coverage only.
 */

/* Per-process probe cache.  -1 untested, 0 unsupported, 1 supported.
 * Each forked child runs its first selection-time probe independently;
 * subsequent picks in that child reuse the cache. */
static int mptcp_v4_state = -1;
static int mptcp_v6_state = -1;

static void mptcp_probe_one(int family, int *state)
{
	int fd;

	if (*state >= 0)
		return;

	fd = socket(family, SOCK_STREAM, IPPROTO_MPTCP);
	if (fd < 0) {
		*state = 0;
		return;
	}
	close(fd);
	*state = 1;
}

static bool mptcp_can_run(void)
{
	mptcp_probe_one(PF_INET, &mptcp_v4_state);
#ifdef USE_IPV6
	mptcp_probe_one(PF_INET6, &mptcp_v6_state);
#else
	mptcp_v6_state = 0;
#endif
	return mptcp_v4_state == 1 || mptcp_v6_state == 1;
}

static void mptcp_pick_triplet(struct socket_triplet *out)
{
	out->type = SOCK_STREAM;
	out->protocol = IPPROTO_MPTCP;

	if (mptcp_v4_state == 1 && mptcp_v6_state == 1)
		out->family = RAND_BOOL() ? PF_INET : PF_INET6;
	else if (mptcp_v4_state == 1)
		out->family = PF_INET;
	else
		out->family = PF_INET6;
}

static void mptcp_configure_pre_bind(int fd, struct socket_triplet *triplet)
{
	int flags;

	flags = fcntl(fd, F_GETFL, 0);
	if (flags >= 0)
		(void) fcntl(fd, F_SETFL, flags | O_NONBLOCK);

#ifdef USE_IPV6
	if (triplet->family == PF_INET6) {
		int v6only = RAND_BOOL();

		(void) setsockopt(fd, SOL_IPV6, IPV6_V6ONLY,
				  &v6only, sizeof(v6only));
	}
#else
	(void) triplet;
#endif
}

static const char * const mptcp_cc_algos[] = {
	"cubic", "reno", "bbr", "westwood", "vegas", "htcp",
	/* invalid algo to exercise tcp_set_congestion_control's
	 * autoload reject path on an MPTCP master socket. */
	"thereisnosuchthingaslunchmptcp",
};

static void mptcp_walk_setsockopts(int fd, struct socket_triplet *triplet,
				   unsigned int n)
{
	unsigned int step = 0;
	const char *cc;
	int one = 1;
	int zero = 0;
	socklen_t len;
	unsigned char buf[256];

	(void) triplet;

	if (step++ >= n)
		return;
	cc = mptcp_cc_algos[rand() % ARRAY_SIZE(mptcp_cc_algos)];
	(void) setsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, cc, strlen(cc));

	if (step++ >= n)
		return;
	(void) setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
			  RAND_BOOL() ? &one : &zero, sizeof(int));

	if (step++ >= n)
		return;
	(void) setsockopt(fd, IPPROTO_TCP, TCP_CORK,
			  RAND_BOOL() ? &one : &zero, sizeof(int));

	/* Remaining steps: rotate SOL_MPTCP getsockopt queries.  Buffers
	 * are sized to land both inside and outside the kernel's
	 * mptcp_get_sub_validate() bounds — the undersized arm exercises
	 * the early -EINVAL reject, the page-sized arm reaches the
	 * per-opt copyout. */
	while (step < n) {
		struct mptcp_subflow_data_compat sd;

		switch (step++ & 0x3) {
		case 0:
			len = sizeof(buf);
			(void) getsockopt(fd, SOL_MPTCP, MPTCP_INFO,
					  buf, &len);
			break;
		case 1:
			memset(&sd, 0, sizeof(sd));
			sd.size_subflow_data = sizeof(sd);
			len = sizeof(sd);
			(void) getsockopt(fd, SOL_MPTCP, MPTCP_FULL_INFO,
					  &sd, &len);
			break;
		case 2:
			/* Deliberately undersized — must hit the early
			 * size-validation reject in the dispatcher. */
			len = (socklen_t)(rand() % sizeof(struct mptcp_subflow_data_compat));
			(void) getsockopt(fd, SOL_MPTCP, MPTCP_TCPINFO,
					  buf, &len);
			break;
		case 3:
			len = sizeof(buf);
			(void) getsockopt(fd, SOL_MPTCP, MPTCP_SUBFLOW_ADDRS,
					  buf, &len);
			break;
		}
	}
}

const struct socket_family_grammar grammar_mptcp = {
	.family			= PF_INET,
	.name			= "mptcp",
	.can_run		= mptcp_can_run,
	.pick_triplet		= mptcp_pick_triplet,
	.configure_pre_bind	= mptcp_configure_pre_bind,
	.walk_setsockopts	= mptcp_walk_setsockopts,
	/* bind_or_connect / configure_post_bind / needs_listen_accept /
	 * data_leg / gen_cmsg use framework defaults — sfg_default_bind
	 * dispatches by triplet->family so a v6 triplet picks
	 * ipv6_gen_sockaddr; the default sendmsg+recv data leg under
	 * O_NONBLOCK with a non-accepted listener is a coherent no-op
	 * and the option-walk coverage is what this grammar is for. */
};
