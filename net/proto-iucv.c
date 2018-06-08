#include <stdlib.h>
#include "net.h"
#include "compat.h"
#include "random.h"
#include "utils.h"	// RAND_ARRAY

static const unsigned int iucv_opts[] = {
	SO_IPRMDATA_MSG, SO_MSGLIMIT, SO_MSGSIZE
};

#define SOL_IUCV 277

static void iucv_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	so->level = SOL_IUCV;

	so->optname = RAND_ARRAY(iucv_opts);

	so->optlen = sizeof(int);
}

const struct netproto proto_iucv = {
	.name = "iucv",
//	.socket = iucv_rand_socket,
	.setsockopt = iucv_setsockopt,
};
