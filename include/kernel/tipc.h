#pragma once
#include <linux/tipc.h>

#ifndef TIPC_SERVICE_RANGE
#define TIPC_SERVICE_RANGE	1
#endif
#ifndef TIPC_MCAST_BROADCAST
#define TIPC_MCAST_BROADCAST	133
#endif
#ifndef TIPC_GROUP_JOIN
#define TIPC_GROUP_JOIN		135
#endif
#ifndef TIPC_GROUP_LEAVE
#define TIPC_GROUP_LEAVE	136
#endif
#ifndef TIPC_NODELAY
#define TIPC_NODELAY		138
#endif
#ifndef TIPC_GROUP_LOOPBACK
#define TIPC_GROUP_LOOPBACK	0x1
#endif
#ifndef TIPC_GROUP_MEMBER_EVTS
#define TIPC_GROUP_MEMBER_EVTS	0x2
#endif
