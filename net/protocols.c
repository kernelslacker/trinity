#include <sys/socket.h>
#include "net.h"

const struct protoptr net_protocols[PF_MAX] = {
	[PF_UNIX] = { .proto = &proto_unix },
	[PF_INET] = { .proto = &proto_ipv4 },
	[PF_AX25] = { .proto = &proto_ax25 },
	[PF_IPX] = { .proto = &proto_ipx },
	[PF_NETLINK] = { .proto = &proto_netlink },
};
