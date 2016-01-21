#include <sys/socket.h>
#include "config.h"
#include "net.h"

const struct protoptr net_protocols[PF_MAX] = {
	[PF_UNIX] = { .proto = &proto_unix },
	[PF_INET] = { .proto = &proto_ipv4 },
	[PF_AX25] = { .proto = &proto_ax25 },
	[PF_IPX] = { .proto = &proto_ipx },
#ifdef USE_APPLETALK
	[PF_APPLETALK] = { .proto = &proto_appletalk },
#endif
	[PF_NETLINK] = { .proto = &proto_netlink },
};
