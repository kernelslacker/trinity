#pragma once

/*
 * Wrapper around <linux/sunrpc_netlink.h> that ships the #ifndef-guarded
 * fallbacks for SUNRPC_FAMILY_NAME / SUNRPC_FAMILY_VERSION and every
 * SUNRPC_CMD_* / SUNRPC_A_* id the grammar references.  Build hosts
 * whose installed uapi predates a given symbol silently miss it from
 * the validator coverage; the fallback values match the upstream uapi
 * enum ordering so the wire-format ids the kernel parses match the
 * ones the message generator emits.
 *
 * The .c side includes this from inside its `#if __has_include(
 * <linux/sunrpc_netlink.h>)` gate, so the header itself can include
 * <linux/sunrpc_netlink.h> unconditionally.
 */
#include <linux/sunrpc_netlink.h>

#ifndef SUNRPC_FAMILY_NAME
#define SUNRPC_FAMILY_NAME		"sunrpc"
#endif
#ifndef SUNRPC_FAMILY_VERSION
#define SUNRPC_FAMILY_VERSION		1
#endif

#ifndef SUNRPC_CMD_CACHE_NOTIFY
#define SUNRPC_CMD_CACHE_NOTIFY		1
#endif
#ifndef SUNRPC_CMD_IP_MAP_GET_REQS
#define SUNRPC_CMD_IP_MAP_GET_REQS	2
#endif
#ifndef SUNRPC_CMD_IP_MAP_SET_REQS
#define SUNRPC_CMD_IP_MAP_SET_REQS	3
#endif
#ifndef SUNRPC_CMD_UNIX_GID_GET_REQS
#define SUNRPC_CMD_UNIX_GID_GET_REQS	4
#endif
#ifndef SUNRPC_CMD_UNIX_GID_SET_REQS
#define SUNRPC_CMD_UNIX_GID_SET_REQS	5
#endif
#ifndef SUNRPC_CMD_CACHE_FLUSH
#define SUNRPC_CMD_CACHE_FLUSH		6
#endif

#ifndef SUNRPC_A_IP_MAP_REQS_REQUESTS
#define SUNRPC_A_IP_MAP_REQS_REQUESTS	1
#endif
