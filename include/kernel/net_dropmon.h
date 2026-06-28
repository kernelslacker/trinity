#pragma once

/*
 * Wrapper around <linux/net_dropmon.h> that ships #ifndef-guarded
 * fallbacks for NET_DM_ATTR_* / NET_DM_CMD_* ids on build hosts whose
 * installed uapi header predates a given enum addition.  The .c side
 * includes this from inside its `#if __has_include(<linux/net_dropmon.h>)`
 * gate, so the header itself can include <linux/net_dropmon.h>
 * unconditionally.
 */
#include <linux/net_dropmon.h>

/*
 * Per-symbol shims for NET_DM_CMD_* / NET_DM_ATTR_* ids.  Build hosts
 * whose <linux/net_dropmon.h> predates the packet-mode additions
 * (PACKET_ALERT, CONFIG_GET/_NEW, STATS_GET/_NEW, and the metadata
 * attrs that go with them) silently miss them from the validator
 * coverage; the fallback values match the upstream uapi enum ordering
 * so the wire-format ids the kernel parses match the ones the
 * generator emits.
 */
#ifndef NET_DM_CMD_ALERT
#define NET_DM_CMD_ALERT			1
#endif
#ifndef NET_DM_CMD_CONFIG
#define NET_DM_CMD_CONFIG			2
#endif
#ifndef NET_DM_CMD_START
#define NET_DM_CMD_START			3
#endif
#ifndef NET_DM_CMD_STOP
#define NET_DM_CMD_STOP				4
#endif
#ifndef NET_DM_CMD_PACKET_ALERT
#define NET_DM_CMD_PACKET_ALERT			5
#endif
#ifndef NET_DM_CMD_CONFIG_GET
#define NET_DM_CMD_CONFIG_GET			6
#endif
#ifndef NET_DM_CMD_CONFIG_NEW
#define NET_DM_CMD_CONFIG_NEW			7
#endif
#ifndef NET_DM_CMD_STATS_GET
#define NET_DM_CMD_STATS_GET			8
#endif
#ifndef NET_DM_CMD_STATS_NEW
#define NET_DM_CMD_STATS_NEW			9
#endif

#ifndef NET_DM_ATTR_ALERT_MODE
#define NET_DM_ATTR_ALERT_MODE			1
#endif
#ifndef NET_DM_ATTR_PC
#define NET_DM_ATTR_PC				2
#endif
#ifndef NET_DM_ATTR_SYMBOL
#define NET_DM_ATTR_SYMBOL			3
#endif
#ifndef NET_DM_ATTR_IN_PORT
#define NET_DM_ATTR_IN_PORT			4
#endif
#ifndef NET_DM_ATTR_TIMESTAMP
#define NET_DM_ATTR_TIMESTAMP			5
#endif
#ifndef NET_DM_ATTR_PROTO
#define NET_DM_ATTR_PROTO			6
#endif
#ifndef NET_DM_ATTR_PAYLOAD
#define NET_DM_ATTR_PAYLOAD			7
#endif
#ifndef NET_DM_ATTR_PAD
#define NET_DM_ATTR_PAD				8
#endif
#ifndef NET_DM_ATTR_TRUNC_LEN
#define NET_DM_ATTR_TRUNC_LEN			9
#endif
#ifndef NET_DM_ATTR_ORIG_LEN
#define NET_DM_ATTR_ORIG_LEN			10
#endif
#ifndef NET_DM_ATTR_QUEUE_LEN
#define NET_DM_ATTR_QUEUE_LEN			11
#endif
#ifndef NET_DM_ATTR_STATS
#define NET_DM_ATTR_STATS			12
#endif
#ifndef NET_DM_ATTR_HW_STATS
#define NET_DM_ATTR_HW_STATS			13
#endif
#ifndef NET_DM_ATTR_ORIGIN
#define NET_DM_ATTR_ORIGIN			14
#endif
#ifndef NET_DM_ATTR_HW_TRAP_GROUP_NAME
#define NET_DM_ATTR_HW_TRAP_GROUP_NAME		15
#endif
#ifndef NET_DM_ATTR_HW_TRAP_NAME
#define NET_DM_ATTR_HW_TRAP_NAME		16
#endif
#ifndef NET_DM_ATTR_HW_ENTRIES
#define NET_DM_ATTR_HW_ENTRIES			17
#endif
#ifndef NET_DM_ATTR_HW_ENTRY
#define NET_DM_ATTR_HW_ENTRY			18
#endif
#ifndef NET_DM_ATTR_HW_TRAP_COUNT
#define NET_DM_ATTR_HW_TRAP_COUNT		19
#endif
#ifndef NET_DM_ATTR_SW_DROPS
#define NET_DM_ATTR_SW_DROPS			20
#endif
#ifndef NET_DM_ATTR_HW_DROPS
#define NET_DM_ATTR_HW_DROPS			21
#endif
#ifndef NET_DM_ATTR_FLOW_ACTION_COOKIE
#define NET_DM_ATTR_FLOW_ACTION_COOKIE		22
#endif
#ifndef NET_DM_ATTR_REASON
#define NET_DM_ATTR_REASON			23
#endif
