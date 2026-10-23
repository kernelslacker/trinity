/*
 * MPTCP per-protocol fuzzing helpers: SOL_MPTCP optnames for sockets from
 * socket(AF_INET[6], SOCK_STREAM, IPPROTO_MPTCP).  SOL_MPTCP is
 * getsockopt-only (the kernel's mptcp_setsockopt() answers -ENOPROTOOPT);
 * do_setsockopt() also feeds the getsockopt sanitiser, so this grammar
 * reaches mptcp_getsockopt().  Path management is the mptcp_pm genl family.
 */

#include <sys/socket.h>
#include "arch.h"
#include "net.h"
#include "random.h"
#include "utils.h"
#include "rnd.h"

#include "kernel/mptcp.h"
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

		so->optlen = sizeof(*sd) + (rnd_modulo_u32(page_size - sizeof(*sd)));
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
			sd->size_user = rnd_modulo_u32(256);
		}
		break;
	}

	default:
		so->optlen = page_size;
		break;
	}
}
