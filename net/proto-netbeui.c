#include "net.h"

static void netbeui_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	so->level = SOL_NETBEUI;
}

struct netproto proto_netbeui = {
	.name = "netbeui",
//	.socket = netbeui_rand_socket,
	.setsockopt = netbeui_setsockopt,
};
