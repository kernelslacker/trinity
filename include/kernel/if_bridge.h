#pragma once

/*
 * Wrapper around <linux/if_bridge.h> that ships #ifndef-guarded fallbacks
 * for IFLA_BRIDGE_* / BRIDGE_FLAGS_* / BRIDGE_VLAN_INFO_* / BR_STATE_*
 * symbols added after our installed uapi header.  Included only by its
 * real consumers -- never pulled into compat.h, so editing it doesn't
 * trigger a near-full-tree rebuild.
 */
#include <linux/if_bridge.h>

#ifndef IFLA_BRIDGE_FLAGS
#define IFLA_BRIDGE_FLAGS		0
#endif
#ifndef IFLA_BRIDGE_MODE
#define IFLA_BRIDGE_MODE		1
#endif
#ifndef IFLA_BRIDGE_VLAN_INFO
#define IFLA_BRIDGE_VLAN_INFO		2
#endif
#ifndef IFLA_BRIDGE_VLAN_TUNNEL_INFO
#define IFLA_BRIDGE_VLAN_TUNNEL_INFO	3
#endif
#ifndef IFLA_BRIDGE_MST
#define IFLA_BRIDGE_MST			6
#endif

#ifndef BRIDGE_FLAGS_MASTER
#define BRIDGE_FLAGS_MASTER		1
#endif
#ifndef BRIDGE_FLAGS_SELF
#define BRIDGE_FLAGS_SELF		2
#endif

#ifndef BRIDGE_VLAN_INFO_PVID
#define BRIDGE_VLAN_INFO_PVID		(1 << 1)
#endif
#ifndef BRIDGE_VLAN_INFO_UNTAGGED
#define BRIDGE_VLAN_INFO_UNTAGGED	(1 << 2)
#endif
#ifndef BRIDGE_VLAN_INFO_RANGE_BEGIN
#define BRIDGE_VLAN_INFO_RANGE_BEGIN	(1 << 3)
#endif
#ifndef BRIDGE_VLAN_INFO_RANGE_END
#define BRIDGE_VLAN_INFO_RANGE_END	(1 << 4)
#endif

#ifndef IFLA_BRIDGE_VLAN_TUNNEL_ID
#define IFLA_BRIDGE_VLAN_TUNNEL_ID	1
#endif
#ifndef IFLA_BRIDGE_VLAN_TUNNEL_VID
#define IFLA_BRIDGE_VLAN_TUNNEL_VID	2
#endif
#ifndef IFLA_BRIDGE_VLAN_TUNNEL_FLAGS
#define IFLA_BRIDGE_VLAN_TUNNEL_FLAGS	3
#endif

#ifndef IFLA_BRIDGE_MST_ENTRY
#define IFLA_BRIDGE_MST_ENTRY		1
#endif
#ifndef IFLA_BRIDGE_MST_ENTRY_MSTI
#define IFLA_BRIDGE_MST_ENTRY_MSTI	1
#endif
#ifndef IFLA_BRIDGE_MST_ENTRY_STATE
#define IFLA_BRIDGE_MST_ENTRY_STATE	2
#endif

#ifndef BR_STATE_FORWARDING
#define BR_STATE_FORWARDING		3
#endif
