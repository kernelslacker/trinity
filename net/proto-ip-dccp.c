#include <stdlib.h>
#include <linux/dccp.h>
#include "net.h"
#include "compat.h"
#include "random.h"

static const unsigned int dccp_opts[] = {
	DCCP_SOCKOPT_PACKET_SIZE, DCCP_SOCKOPT_SERVICE, DCCP_SOCKOPT_CHANGE_L, DCCP_SOCKOPT_CHANGE_R,
	DCCP_SOCKOPT_GET_CUR_MPS, DCCP_SOCKOPT_SERVER_TIMEWAIT, DCCP_SOCKOPT_SEND_CSCOV, DCCP_SOCKOPT_RECV_CSCOV,
	DCCP_SOCKOPT_AVAILABLE_CCIDS, DCCP_SOCKOPT_CCID, DCCP_SOCKOPT_TX_CCID, DCCP_SOCKOPT_RX_CCID,
	DCCP_SOCKOPT_QPOLICY_ID, DCCP_SOCKOPT_QPOLICY_TXQLEN, DCCP_SOCKOPT_CCID_RX_INFO, DCCP_SOCKOPT_CCID_TX_INFO
};

void dccp_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	unsigned int *optval32;
	unsigned char *optval8;
	unsigned int i, n;

	so->optname = RAND_ARRAY(dccp_opts);

	switch (so->optname) {
	case DCCP_SOCKOPT_SERVICE:
		/* __be32 service code, optionally followed by extra service
		 * codes — dccp_setsockopt_service() accepts up to
		 * DCCP_SERVICE_LIST_MAX_LEN entries. */
		optval32 = (unsigned int *) so->optval;
		n = RAND_RANGE(1, 4);
		for (i = 0; i < n; i++)
			optval32[i] = rand();
		so->optlen = n * sizeof(unsigned int);
		break;

	case DCCP_SOCKOPT_CCID:
	case DCCP_SOCKOPT_TX_CCID:
	case DCCP_SOCKOPT_RX_CCID:
		/* dccp_setsockopt_ccid() expects a u8 array of CCID numbers
		 * (1..DCCP_FEAT_MAX_SP_VALS bytes). */
		optval8 = (unsigned char *) so->optval;
		n = RAND_RANGE(1, 8);
		for (i = 0; i < n; i++)
			optval8[i] = rand();
		so->optlen = n;
		break;

	default:
		/* Plain int — covers SERVER_TIMEWAIT, *_CSCOV, QPOLICY_*, and
		 * the deprecated/get-only options that the kernel either
		 * rejects with -ENOPROTOOPT or short-circuits before touching
		 * the buffer. Still want a non-empty optlen so the dispatch
		 * code itself gets exercised. */
		optval32 = (unsigned int *) so->optval;
		*optval32 = rand();
		so->optlen = sizeof(unsigned int);
		break;
	}
}
