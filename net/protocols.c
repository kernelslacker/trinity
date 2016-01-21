#include <sys/socket.h>
#include "net.h"

const struct protoptr net_protocols[PF_MAX] = {
	[PF_NETLINK] = { .proto = &proto_netlink },
};
