#include "net.h"

static void netbeui_setsockopt(struct sockopt *so)
{
	so->level = SOL_NETBEUI;
}

struct netproto proto_netbeui = {
	.name = "netbeui",
//	.socket = netbeui_rand_socket,
	.setsockopt = netbeui_setsockopt,
};
