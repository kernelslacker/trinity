#pragma once

/*
 * Wrapper around <linux/ncsi.h> that ships the #ifndef-guarded
 * fallbacks for NCSI_ATTR_* / NCSI_CMD_* ids.  The .c side includes
 * this from inside its `#if __has_include(<linux/ncsi.h>)` gate, so
 * the header itself can include <linux/ncsi.h> unconditionally.
 */
#include <linux/ncsi.h>

/*
 * Per-symbol shims for NCSI_ATTR_* / NCSI_CMD_* ids.  The NCSI uapi
 * has been stable since 4.20 (and again since the 5.1 PACKAGE_MASK /
 * CHANNEL_MASK additions); build hosts running older uapi silently
 * miss the mask-related ids from the validator coverage.  The fallback
 * values match the upstream enum ordering so the wire-format ids the
 * kernel parses match the ones the generator emits.
 */
#ifndef NCSI_ATTR_IFINDEX
#define NCSI_ATTR_IFINDEX		1
#endif
#ifndef NCSI_ATTR_PACKAGE_LIST
#define NCSI_ATTR_PACKAGE_LIST		2
#endif
#ifndef NCSI_ATTR_PACKAGE_ID
#define NCSI_ATTR_PACKAGE_ID		3
#endif
#ifndef NCSI_ATTR_CHANNEL_ID
#define NCSI_ATTR_CHANNEL_ID		4
#endif
#ifndef NCSI_ATTR_DATA
#define NCSI_ATTR_DATA			5
#endif
#ifndef NCSI_ATTR_MULTI_FLAG
#define NCSI_ATTR_MULTI_FLAG		6
#endif
#ifndef NCSI_ATTR_PACKAGE_MASK
#define NCSI_ATTR_PACKAGE_MASK		7
#endif
#ifndef NCSI_ATTR_CHANNEL_MASK
#define NCSI_ATTR_CHANNEL_MASK		8
#endif

#ifndef NCSI_CMD_PKG_INFO
#define NCSI_CMD_PKG_INFO		1
#endif
#ifndef NCSI_CMD_SET_INTERFACE
#define NCSI_CMD_SET_INTERFACE		2
#endif
#ifndef NCSI_CMD_CLEAR_INTERFACE
#define NCSI_CMD_CLEAR_INTERFACE	3
#endif
#ifndef NCSI_CMD_SEND_CMD
#define NCSI_CMD_SEND_CMD		4
#endif
#ifndef NCSI_CMD_SET_PACKAGE_MASK
#define NCSI_CMD_SET_PACKAGE_MASK	5
#endif
#ifndef NCSI_CMD_SET_CHANNEL_MASK
#define NCSI_CMD_SET_CHANNEL_MASK	6
#endif
