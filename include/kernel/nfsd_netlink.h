#pragma once

/*
 * Wrapper around <linux/nfsd_netlink.h> that ships the #ifndef-guarded
 * fallbacks for NFSD_FAMILY_NAME / NFSD_FAMILY_VERSION and every
 * NFSD_CMD_* / NFSD_A_* id the grammar references.  Build hosts whose
 * installed uapi predates a given symbol silently miss it from the
 * validator coverage; the fallback values match the upstream uapi
 * enum ordering so the wire-format ids the kernel parses match the
 * ones the message generator emits.
 *
 * The .c side includes this from inside its `#if __has_include(
 * <linux/nfsd_netlink.h>)` gate, so the header itself can include
 * <linux/nfsd_netlink.h> unconditionally.
 */
#include <linux/nfsd_netlink.h>

#ifndef NFSD_FAMILY_NAME
#define NFSD_FAMILY_NAME		"nfsd"
#endif
#ifndef NFSD_FAMILY_VERSION
#define NFSD_FAMILY_VERSION		1
#endif

#ifndef NFSD_CMD_RPC_STATUS_GET
#define NFSD_CMD_RPC_STATUS_GET		1
#endif
#ifndef NFSD_CMD_THREADS_SET
#define NFSD_CMD_THREADS_SET		2
#endif
#ifndef NFSD_CMD_THREADS_GET
#define NFSD_CMD_THREADS_GET		3
#endif
#ifndef NFSD_CMD_VERSION_SET
#define NFSD_CMD_VERSION_SET		4
#endif
#ifndef NFSD_CMD_VERSION_GET
#define NFSD_CMD_VERSION_GET		5
#endif
#ifndef NFSD_CMD_LISTENER_SET
#define NFSD_CMD_LISTENER_SET		6
#endif
#ifndef NFSD_CMD_LISTENER_GET
#define NFSD_CMD_LISTENER_GET		7
#endif
#ifndef NFSD_CMD_POOL_MODE_SET
#define NFSD_CMD_POOL_MODE_SET		8
#endif
#ifndef NFSD_CMD_POOL_MODE_GET
#define NFSD_CMD_POOL_MODE_GET		9
#endif
#ifndef NFSD_CMD_CACHE_NOTIFY
#define NFSD_CMD_CACHE_NOTIFY		10
#endif
#ifndef NFSD_CMD_SVC_EXPORT_GET_REQS
#define NFSD_CMD_SVC_EXPORT_GET_REQS	11
#endif
#ifndef NFSD_CMD_SVC_EXPORT_SET_REQS
#define NFSD_CMD_SVC_EXPORT_SET_REQS	12
#endif
#ifndef NFSD_CMD_EXPKEY_GET_REQS
#define NFSD_CMD_EXPKEY_GET_REQS	13
#endif
#ifndef NFSD_CMD_EXPKEY_SET_REQS
#define NFSD_CMD_EXPKEY_SET_REQS	14
#endif
#ifndef NFSD_CMD_CACHE_FLUSH
#define NFSD_CMD_CACHE_FLUSH		15
#endif
#ifndef NFSD_CMD_UNLOCK_IP
#define NFSD_CMD_UNLOCK_IP		16
#endif
#ifndef NFSD_CMD_UNLOCK_FILESYSTEM
#define NFSD_CMD_UNLOCK_FILESYSTEM	17
#endif
#ifndef NFSD_CMD_UNLOCK_EXPORT
#define NFSD_CMD_UNLOCK_EXPORT		18
#endif
#ifndef NFSD_CMD_SERVER_STATS_GET
#define NFSD_CMD_SERVER_STATS_GET	19
#endif

#ifndef NFSD_A_SERVER_THREADS
#define NFSD_A_SERVER_THREADS		1
#endif
#ifndef NFSD_A_SERVER_GRACETIME
#define NFSD_A_SERVER_GRACETIME		2
#endif
#ifndef NFSD_A_SERVER_LEASETIME
#define NFSD_A_SERVER_LEASETIME		3
#endif
#ifndef NFSD_A_SERVER_SCOPE
#define NFSD_A_SERVER_SCOPE		4
#endif

#ifndef NFSD_A_RPC_STATUS_PROC
#define NFSD_A_RPC_STATUS_PROC		5
#endif
#ifndef NFSD_A_RPC_STATUS_SERVICE_TIME
#define NFSD_A_RPC_STATUS_SERVICE_TIME	6
#endif
#ifndef NFSD_A_RPC_STATUS_PAD
#define NFSD_A_RPC_STATUS_PAD		7
#endif
#ifndef NFSD_A_RPC_STATUS_SADDR4
#define NFSD_A_RPC_STATUS_SADDR4	8
#endif
#ifndef NFSD_A_RPC_STATUS_DADDR4
#define NFSD_A_RPC_STATUS_DADDR4	9
#endif
#ifndef NFSD_A_RPC_STATUS_SADDR6
#define NFSD_A_RPC_STATUS_SADDR6	10
#endif
#ifndef NFSD_A_RPC_STATUS_DADDR6
#define NFSD_A_RPC_STATUS_DADDR6	11
#endif
#ifndef NFSD_A_RPC_STATUS_SPORT
#define NFSD_A_RPC_STATUS_SPORT		12
#endif
#ifndef NFSD_A_RPC_STATUS_DPORT
#define NFSD_A_RPC_STATUS_DPORT		13
#endif
#ifndef NFSD_A_RPC_STATUS_COMPOUND_OPS
#define NFSD_A_RPC_STATUS_COMPOUND_OPS	14
#endif
