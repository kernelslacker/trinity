#pragma once

/*
 * Wrapper around <linux/ip_vs.h> that ships the #ifndef-guarded
 * fallbacks for IPVS_CMD_* / IPVS_CMD_ATTR_* ids added after the
 * installed uapi header.  The .c side includes this from inside
 * its `#if __has_include(<linux/ip_vs.h>)` gate, so the header
 * itself can include <linux/ip_vs.h> unconditionally.
 */
#include <linux/ip_vs.h>

#ifndef IPVS_CMD_GET_SERVICE
#define IPVS_CMD_GET_SERVICE		4
#endif
#ifndef IPVS_CMD_GET_DEST
#define IPVS_CMD_GET_DEST		8
#endif
#ifndef IPVS_CMD_GET_DAEMON
#define IPVS_CMD_GET_DAEMON		11
#endif
#ifndef IPVS_CMD_GET_CONFIG
#define IPVS_CMD_GET_CONFIG		13
#endif
#ifndef IPVS_CMD_GET_INFO
#define IPVS_CMD_GET_INFO		15
#endif

#ifndef IPVS_CMD_ATTR_SERVICE
#define IPVS_CMD_ATTR_SERVICE		1
#endif
#ifndef IPVS_CMD_ATTR_DEST
#define IPVS_CMD_ATTR_DEST		2
#endif
#ifndef IPVS_CMD_ATTR_DAEMON
#define IPVS_CMD_ATTR_DAEMON		3
#endif
#ifndef IPVS_CMD_ATTR_TIMEOUT_TCP
#define IPVS_CMD_ATTR_TIMEOUT_TCP	4
#endif
#ifndef IPVS_CMD_ATTR_TIMEOUT_TCP_FIN
#define IPVS_CMD_ATTR_TIMEOUT_TCP_FIN	5
#endif
#ifndef IPVS_CMD_ATTR_TIMEOUT_UDP
#define IPVS_CMD_ATTR_TIMEOUT_UDP	6
#endif
