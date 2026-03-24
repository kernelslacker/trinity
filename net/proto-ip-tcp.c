#include <stdlib.h>
#include <string.h>
#include <linux/tcp.h>
#include "net.h"
#include "random.h"
#include "compat.h"

static const unsigned int tcp_opts[] = {
	TCP_NODELAY, TCP_MAXSEG, TCP_CORK, TCP_KEEPIDLE,
	TCP_KEEPINTVL, TCP_KEEPCNT, TCP_SYNCNT, TCP_LINGER2,
	TCP_DEFER_ACCEPT, TCP_WINDOW_CLAMP, TCP_INFO, TCP_QUICKACK,
	TCP_CONGESTION, TCP_MD5SIG, TCP_THIN_LINEAR_TIMEOUTS,
	TCP_THIN_DUPACK, TCP_USER_TIMEOUT, TCP_REPAIR, TCP_REPAIR_QUEUE,
	TCP_QUEUE_SEQ, TCP_REPAIR_OPTIONS, TCP_FASTOPEN, TCP_TIMESTAMP,
	TCP_NOTSENT_LOWAT, TCP_CC_INFO, TCP_SAVE_SYN, TCP_SAVED_SYN,
	TCP_REPAIR_WINDOW, TCP_FASTOPEN_CONNECT, TCP_ULP, TCP_MD5SIG_EXT,
	TCP_FASTOPEN_KEY, TCP_FASTOPEN_NO_COOKIE, TCP_ZEROCOPY_RECEIVE, TCP_INQ,
	TCP_TX_DELAY,
	TCP_AO_ADD_KEY, TCP_AO_DEL_KEY, TCP_AO_INFO, TCP_AO_GET_KEYS, TCP_AO_REPAIR,
	TCP_IS_MPTCP, TCP_RTO_MAX_MS, TCP_RTO_MIN_US, TCP_DELACK_MAX_US,
};

static const char *ulp_names[] = { "tls", "mptcp" };

static const char *cc_algos[] = { "cubic", "reno", "bbr", "dctcp", "vegas", "westwood" };

void tcp_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	char *ptr;
	const char *str;

	so->optname = RAND_ARRAY(tcp_opts);

	switch (so->optname) {
	case TCP_ULP:
		ptr = (char *) so->optval;
		str = RAND_ARRAY(ulp_names);
		so->optlen = strlen(str) + 1;
		memcpy(ptr, str, so->optlen);
		break;

	case TCP_CONGESTION:
		ptr = (char *) so->optval;
		str = RAND_ARRAY(cc_algos);
		so->optlen = strlen(str) + 1;
		memcpy(ptr, str, so->optlen);
		break;

	default:
		break;
	}
}
