#pragma once

/*
 * Wrapper around <linux/openvswitch.h> that ships #ifndef-guarded
 * fallbacks for the OVS_DP_* / OVS_VPORT_* / OVS_TUNNEL_* ids the
 * installed uapi header may be too old to know.  Including
 * <linux/openvswitch.h> here lets a .c pull "kernel/openvswitch.h"
 * once and get the real uapi enums plus the fallback shims for ids
 * the installed header is missing.
 *
 * Purely handler-local trinity values (recv timeout, buffer sizes,
 * dst-port range, jitter knobs) stay with their handler in the .c.
 */
#include <linux/openvswitch.h>

/*
 * uapi/linux/openvswitch.h is not always present on stripped sysroots.
 * Provide per-symbol fallback definitions of the OVS_* / OVS_TUNNEL_*
 * constants this childop emits.  IDs are stable in the UAPI so the
 * fallback values match what the kernel parser expects.
 */
#ifndef OVS_DATAPATH_VERSION
#define OVS_DATAPATH_VERSION	2
#endif
#ifndef OVS_VPORT_VERSION
#define OVS_VPORT_VERSION	0x1
#endif

#ifndef OVS_DP_CMD_NEW
#define OVS_DP_CMD_NEW		1
#endif

#ifndef OVS_DP_ATTR_NAME
#define OVS_DP_ATTR_NAME	1
#endif
#ifndef OVS_DP_ATTR_UPCALL_PID
#define OVS_DP_ATTR_UPCALL_PID	2
#endif

#ifndef OVS_VPORT_CMD_NEW
#define OVS_VPORT_CMD_NEW	1
#endif
#ifndef OVS_VPORT_CMD_DEL
#define OVS_VPORT_CMD_DEL	2
#endif

#ifndef OVS_VPORT_TYPE_GRE
#define OVS_VPORT_TYPE_GRE	3
#endif
#ifndef OVS_VPORT_TYPE_VXLAN
#define OVS_VPORT_TYPE_VXLAN	4
#endif
#ifndef OVS_VPORT_TYPE_GENEVE
#define OVS_VPORT_TYPE_GENEVE	5
#endif

#ifndef OVS_VPORT_ATTR_TYPE
#define OVS_VPORT_ATTR_TYPE	1
#endif
#ifndef OVS_VPORT_ATTR_NAME
#define OVS_VPORT_ATTR_NAME	2
#endif
#ifndef OVS_VPORT_ATTR_OPTIONS
#define OVS_VPORT_ATTR_OPTIONS	3
#endif
#ifndef OVS_VPORT_ATTR_UPCALL_PID
#define OVS_VPORT_ATTR_UPCALL_PID	4
#endif

#ifndef OVS_TUNNEL_ATTR_DST_PORT
#define OVS_TUNNEL_ATTR_DST_PORT	1
#endif

#ifndef OVS_PACKET_ATTR_UPCALL_PID
#define OVS_PACKET_ATTR_UPCALL_PID	12
#endif
