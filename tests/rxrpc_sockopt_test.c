/*
 * Self-check for the RxRPC option builder: rxrpc_setsockopt()
 * (net/rxrpc/af_rxrpc.c) refuses an RXRPC_MANAGE_RESPONSE value other
 * than 0 or 1 with -EINVAL, so the values drawn are ones it takes, and
 * some turn response management on.
 */

#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>		/* ahead of the linux/in.h linux/rxrpc.h takes */

#include "debug.h"		/* BUG */
#include "kernel/rxrpc.h"	/* RXRPC_MANAGE_RESPONSE */
#include "net.h"		/* proto_rxrpc, struct sockopt */

#define RXRPC_ROUNDS		2000
#define RXRPC_OPTVAL_LEN	4096

void rxrpc_sockopt_self_check(void);
void rxrpc_sockopt_self_check(void)
{
	struct socket_triplet rxrpc = {
		.family = PF_RXRPC, .type = SOCK_DGRAM, .protocol = PF_INET,
	};
	static unsigned char optval[RXRPC_OPTVAL_LEN];
	unsigned int i, drawn = 0, taken = 0, on = 0;

	for (i = 0; i < RXRPC_ROUNDS; i++) {
		struct sockopt so = { .optval = (unsigned long) optval };
		unsigned int val;

		memset(optval, 0, sizeof(optval));
		proto_rxrpc.setsockopt(&so, &rxrpc);
		if (so.optname != RXRPC_MANAGE_RESPONSE)
			continue;

		drawn++;
		memcpy(&val, optval, sizeof(val));
		if (so.optlen == sizeof(val) && val <= 1)
			taken++;
		if (val == 1)
			on++;
	}

	if (drawn == 0)
		BUG("rxrpc: no RXRPC_MANAGE_RESPONSE drawn");
	if (taken < drawn * 3 / 4 || on == 0)
		BUG("rxrpc: the RXRPC_MANAGE_RESPONSE values the kernel takes are rare");
}
