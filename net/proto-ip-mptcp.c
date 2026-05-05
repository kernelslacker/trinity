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

#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include "arch.h"
#include "compat.h"
#include "net.h"
#include "random.h"

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
