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

#ifndef NFSD_A_SERVER_MIN_THREADS
#define NFSD_A_SERVER_MIN_THREADS		5
#endif
#ifndef NFSD_A_SERVER_FH_KEY
#define NFSD_A_SERVER_FH_KEY			6
#endif

#ifndef NFSD_A_VERSION_MAJOR
#define NFSD_A_VERSION_MAJOR			1
#endif
#ifndef NFSD_A_VERSION_MINOR
#define NFSD_A_VERSION_MINOR			2
#endif
#ifndef NFSD_A_VERSION_ENABLED
#define NFSD_A_VERSION_ENABLED			3
#endif
#ifndef NFSD_A_SERVER_PROTO_VERSION
#define NFSD_A_SERVER_PROTO_VERSION		1
#endif

#ifndef NFSD_A_SOCK_ADDR
#define NFSD_A_SOCK_ADDR			1
#endif
#ifndef NFSD_A_SOCK_TRANSPORT_NAME
#define NFSD_A_SOCK_TRANSPORT_NAME		2
#endif
#ifndef NFSD_A_SERVER_SOCK_ADDR
#define NFSD_A_SERVER_SOCK_ADDR			1
#endif
#ifndef NFSD_A_SERVER_SOCK_USERSPACE_RPCBIND
#define NFSD_A_SERVER_SOCK_USERSPACE_RPCBIND	2
#endif
#ifndef NFSD_A_POOL_MODE_MODE
#define NFSD_A_POOL_MODE_MODE			1
#endif

#ifndef NFSD_A_FSLOCATION_HOST
#define NFSD_A_FSLOCATION_HOST			1
#endif
#ifndef NFSD_A_FSLOCATION_PATH
#define NFSD_A_FSLOCATION_PATH			2
#endif
#ifndef NFSD_A_FSLOCATIONS_LOCATION
#define NFSD_A_FSLOCATIONS_LOCATION		1
#endif
#ifndef NFSD_A_AUTH_FLAVOR_PSEUDOFLAVOR
#define NFSD_A_AUTH_FLAVOR_PSEUDOFLAVOR		1
#endif
#ifndef NFSD_A_AUTH_FLAVOR_FLAGS
#define NFSD_A_AUTH_FLAVOR_FLAGS		2
#endif

#ifndef NFSD_A_SVC_EXPORT_SEQNO
#define NFSD_A_SVC_EXPORT_SEQNO			1
#endif
#ifndef NFSD_A_SVC_EXPORT_CLIENT
#define NFSD_A_SVC_EXPORT_CLIENT		2
#endif
#ifndef NFSD_A_SVC_EXPORT_PATH
#define NFSD_A_SVC_EXPORT_PATH			3
#endif
#ifndef NFSD_A_SVC_EXPORT_NEGATIVE
#define NFSD_A_SVC_EXPORT_NEGATIVE		4
#endif
#ifndef NFSD_A_SVC_EXPORT_EXPIRY
#define NFSD_A_SVC_EXPORT_EXPIRY		5
#endif
#ifndef NFSD_A_SVC_EXPORT_ANON_UID
#define NFSD_A_SVC_EXPORT_ANON_UID		6
#endif
#ifndef NFSD_A_SVC_EXPORT_ANON_GID
#define NFSD_A_SVC_EXPORT_ANON_GID		7
#endif
#ifndef NFSD_A_SVC_EXPORT_FSLOCATIONS
#define NFSD_A_SVC_EXPORT_FSLOCATIONS		8
#endif
#ifndef NFSD_A_SVC_EXPORT_UUID
#define NFSD_A_SVC_EXPORT_UUID			9
#endif
#ifndef NFSD_A_SVC_EXPORT_SECINFO
#define NFSD_A_SVC_EXPORT_SECINFO		10
#endif
#ifndef NFSD_A_SVC_EXPORT_XPRTSEC
#define NFSD_A_SVC_EXPORT_XPRTSEC		11
#endif
#ifndef NFSD_A_SVC_EXPORT_FLAGS
#define NFSD_A_SVC_EXPORT_FLAGS			12
#endif
#ifndef NFSD_A_SVC_EXPORT_FSID
#define NFSD_A_SVC_EXPORT_FSID			13
#endif
#ifndef NFSD_A_SVC_EXPORT_REQS_REQUESTS
#define NFSD_A_SVC_EXPORT_REQS_REQUESTS		1
#endif

#ifndef NFSD_A_EXPKEY_SEQNO
#define NFSD_A_EXPKEY_SEQNO			1
#endif
#ifndef NFSD_A_EXPKEY_CLIENT
#define NFSD_A_EXPKEY_CLIENT			2
#endif
#ifndef NFSD_A_EXPKEY_FSIDTYPE
#define NFSD_A_EXPKEY_FSIDTYPE			3
#endif
#ifndef NFSD_A_EXPKEY_FSID
#define NFSD_A_EXPKEY_FSID			4
#endif
#ifndef NFSD_A_EXPKEY_NEGATIVE
#define NFSD_A_EXPKEY_NEGATIVE			5
#endif
#ifndef NFSD_A_EXPKEY_EXPIRY
#define NFSD_A_EXPKEY_EXPIRY			6
#endif
#ifndef NFSD_A_EXPKEY_PATH
#define NFSD_A_EXPKEY_PATH			7
#endif
#ifndef NFSD_A_EXPKEY_REQS_REQUESTS
#define NFSD_A_EXPKEY_REQS_REQUESTS		1
#endif

#ifndef NFSD_A_CACHE_FLUSH_MASK
#define NFSD_A_CACHE_FLUSH_MASK			1
#endif
#ifndef NFSD_A_UNLOCK_IP_ADDRESS
#define NFSD_A_UNLOCK_IP_ADDRESS		1
#endif
#ifndef NFSD_A_UNLOCK_FILESYSTEM_PATH
#define NFSD_A_UNLOCK_FILESYSTEM_PATH		1
#endif
#ifndef NFSD_A_UNLOCK_EXPORT_PATH
#define NFSD_A_UNLOCK_EXPORT_PATH		1
#endif
