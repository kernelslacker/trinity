#pragma once

#include <netinet/in.h>

#ifndef IP_MULTICAST_ALL
#define IP_MULTICAST_ALL		49
#define IP_UNICAST_IF		50
#endif
#ifndef IP_LOCAL_PORT_RANGE
#define IP_LOCAL_PORT_RANGE	51
#endif
#ifndef IP_PROTOCOL
#define IP_PROTOCOL		51
#endif

#ifndef MCAST_EXCLUDE
#define MCAST_EXCLUDE   0
#define MCAST_INCLUDE   1
#endif
#ifndef MCAST_JOIN_GROUP
#define MCAST_JOIN_GROUP         42
#define MCAST_BLOCK_SOURCE       43
#define MCAST_UNBLOCK_SOURCE     44
#define MCAST_LEAVE_GROUP        45
#define MCAST_JOIN_SOURCE_GROUP  46
#define MCAST_LEAVE_SOURCE_GROUP 47
#define MCAST_MSFILTER           48
#endif
#ifndef IP_MULTICAST_ALL
#define IP_MULTICAST_ALL         49
#endif
#ifndef IP_UNICAST_IF
#define IP_UNICAST_IF            50
#endif

#ifndef IPPROTO_MH
#define IPPROTO_MH              135
#endif
#ifndef IPPROTO_BEETPH
#define IPPROTO_BEETPH          94
#endif
#ifndef IPPROTO_MPLS
#define IPPROTO_MPLS            137
#endif
#ifndef IPPROTO_ETHERNET
#define IPPROTO_ETHERNET        143
#endif
#ifndef IPPROTO_AG
#define IPPROTO_AG              3
#endif
#ifndef IPPROTO_NSH
#define IPPROTO_NSH             140
#endif
