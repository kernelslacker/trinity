#include "config.h"

#ifdef USE_NETROM
#include <stdlib.h>
#include <netrom/netrom.h>
#include "net.h"
#include "compat.h"
#include "random.h"
#include "utils.h"	// RAND_ARRAY

static void netrom_setsockopt(struct sockopt *so)
{
	const unsigned int netrom_opts[] = {
		NETROM_T1, NETROM_T2, NETROM_N2, NETROM_T4, NETROM_IDLE
	};

	so->level = SOL_NETROM;
	so->optname = RAND_ARRAY(netrom_opts);
}

struct netproto proto_netrom = {
	.name = "netrom",
//	.socket = netrom_rand_socket,
	.setsockopt = netrom_setsockopt,
};
#endif
