#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <stdlib.h>
#include "net.h"
#include "random.h"
#include "utils.h"	// RAND_ARRAY

#ifndef KCMPROTO_CONNECTED
#define KCMPROTO_CONNECTED 0
#define KCM_RECV_DISABLE 1
#define SOL_KCM 281
#endif

static void kcm_rand_socket(struct socket_triplet *st)
{
	st->protocol = KCMPROTO_CONNECTED;

	if (RAND_BOOL())
		st->type = SOCK_DGRAM;
	else
		st->type = SOCK_PACKET;
}

static const unsigned int kcm_opts[] = {
	KCM_RECV_DISABLE,
};

static void kcm_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	char *optval;

	so->level = SOL_KCM;

	optval = (char *) so->optval;

	so->optname = RAND_ARRAY(kcm_opts);
	so->optlen = sizeof(int);

	switch (so->optname) {
	case KCM_RECV_DISABLE:
		optval[0] = RAND_BOOL();
		break;
	default:
		break;
	}
}

const struct netproto proto_kcm = {
	.name = "kcm",
	.socket = kcm_rand_socket,
	.setsockopt = kcm_setsockopt,
};
