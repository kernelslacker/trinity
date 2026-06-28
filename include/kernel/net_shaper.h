#pragma once

/*
 * Wrapper around <linux/net_shaper.h> that ships the #ifndef-guarded
 * fallbacks for NET_SHAPER_CMD_* / NET_SHAPER_A_* ids and the
 * NET_SHAPER_FAMILY_NAME / NET_SHAPER_FAMILY_VERSION macros.  The .c
 * side includes this from inside its `#if __has_include(<linux/
 * net_shaper.h>)` gate, so the header itself can include
 * <linux/net_shaper.h> unconditionally.
 */
#include <linux/net_shaper.h>

#ifndef NET_SHAPER_FAMILY_NAME
#define NET_SHAPER_FAMILY_NAME		"net-shaper"
#endif
#ifndef NET_SHAPER_FAMILY_VERSION
#define NET_SHAPER_FAMILY_VERSION	1
#endif

/*
 * Per-symbol shims for NET_SHAPER_CMD_* / NET_SHAPER_A_* ids.  Build
 * hosts whose <linux/net_shaper.h> predates the upstream uapi enums
 * silently miss the newer ids; the fallback values match the upstream
 * uapi enum ordering so the wire-format ids the kernel parses match
 * the ones the generator emits.
 */
#ifndef NET_SHAPER_CMD_GET
#define NET_SHAPER_CMD_GET		1
#endif
#ifndef NET_SHAPER_CMD_SET
#define NET_SHAPER_CMD_SET		2
#endif
#ifndef NET_SHAPER_CMD_DELETE
#define NET_SHAPER_CMD_DELETE		3
#endif
#ifndef NET_SHAPER_CMD_GROUP
#define NET_SHAPER_CMD_GROUP		4
#endif
#ifndef NET_SHAPER_CMD_CAP_GET
#define NET_SHAPER_CMD_CAP_GET		5
#endif

#ifndef NET_SHAPER_A_HANDLE
#define NET_SHAPER_A_HANDLE		1
#endif
#ifndef NET_SHAPER_A_METRIC
#define NET_SHAPER_A_METRIC		2
#endif
#ifndef NET_SHAPER_A_BW_MIN
#define NET_SHAPER_A_BW_MIN		3
#endif
#ifndef NET_SHAPER_A_BW_MAX
#define NET_SHAPER_A_BW_MAX		4
#endif
#ifndef NET_SHAPER_A_BURST
#define NET_SHAPER_A_BURST		5
#endif
#ifndef NET_SHAPER_A_PRIORITY
#define NET_SHAPER_A_PRIORITY		6
#endif
#ifndef NET_SHAPER_A_WEIGHT
#define NET_SHAPER_A_WEIGHT		7
#endif
#ifndef NET_SHAPER_A_IFINDEX
#define NET_SHAPER_A_IFINDEX		8
#endif
#ifndef NET_SHAPER_A_PARENT
#define NET_SHAPER_A_PARENT		9
#endif
#ifndef NET_SHAPER_A_LEAVES
#define NET_SHAPER_A_LEAVES		10
#endif

#ifndef NET_SHAPER_A_HANDLE_SCOPE
#define NET_SHAPER_A_HANDLE_SCOPE	1
#endif
#ifndef NET_SHAPER_A_HANDLE_ID
#define NET_SHAPER_A_HANDLE_ID		2
#endif

#ifndef NET_SHAPER_A_CAPS_IFINDEX
#define NET_SHAPER_A_CAPS_IFINDEX		1
#endif
#ifndef NET_SHAPER_A_CAPS_SCOPE
#define NET_SHAPER_A_CAPS_SCOPE			2
#endif
#ifndef NET_SHAPER_A_CAPS_SUPPORT_METRIC_BPS
#define NET_SHAPER_A_CAPS_SUPPORT_METRIC_BPS	3
#endif
#ifndef NET_SHAPER_A_CAPS_SUPPORT_METRIC_PPS
#define NET_SHAPER_A_CAPS_SUPPORT_METRIC_PPS	4
#endif
#ifndef NET_SHAPER_A_CAPS_SUPPORT_NESTING
#define NET_SHAPER_A_CAPS_SUPPORT_NESTING	5
#endif
#ifndef NET_SHAPER_A_CAPS_SUPPORT_BW_MIN
#define NET_SHAPER_A_CAPS_SUPPORT_BW_MIN	6
#endif
#ifndef NET_SHAPER_A_CAPS_SUPPORT_BW_MAX
#define NET_SHAPER_A_CAPS_SUPPORT_BW_MAX	7
#endif
#ifndef NET_SHAPER_A_CAPS_SUPPORT_BURST
#define NET_SHAPER_A_CAPS_SUPPORT_BURST		8
#endif
#ifndef NET_SHAPER_A_CAPS_SUPPORT_PRIORITY
#define NET_SHAPER_A_CAPS_SUPPORT_PRIORITY	9
#endif
#ifndef NET_SHAPER_A_CAPS_SUPPORT_WEIGHT
#define NET_SHAPER_A_CAPS_SUPPORT_WEIGHT	10
#endif
