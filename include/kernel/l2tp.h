#pragma once

/*
 * Wrapper around <linux/l2tp.h> that ships #ifndef-guarded fallbacks
 * for the L2TP UAPI values touched by childops/net/l2tp-ifname-race.c.
 * The real header is pulled in behind __has_include so stripped
 * sysroots that don't ship <linux/l2tp.h> still compile; per-symbol
 * #ifndef fallbacks then supply any missing values.  The numbering
 * below matches include/uapi/linux/l2tp.h and is stable UAPI.
 */
#if __has_include(<linux/l2tp.h>)
#include <linux/l2tp.h>
#endif

#ifndef L2TP_GENL_NAME
#define L2TP_GENL_NAME			"l2tp"
#endif

#ifndef L2TP_CMD_TUNNEL_CREATE
#define L2TP_CMD_TUNNEL_CREATE		1
#define L2TP_CMD_TUNNEL_DELETE		2
#define L2TP_CMD_TUNNEL_MODIFY		3
#define L2TP_CMD_TUNNEL_GET		4
#define L2TP_CMD_SESSION_CREATE		5
#define L2TP_CMD_SESSION_DELETE		6
#define L2TP_CMD_SESSION_MODIFY		7
#define L2TP_CMD_SESSION_GET		8
#endif

#ifndef L2TP_ATTR_PW_TYPE
#define L2TP_ATTR_PW_TYPE		1
#define L2TP_ATTR_ENCAP_TYPE		2
#define L2TP_ATTR_PROTO_VERSION		7
#define L2TP_ATTR_IFNAME		8
#define L2TP_ATTR_CONN_ID		9
#define L2TP_ATTR_PEER_CONN_ID		10
#define L2TP_ATTR_SESSION_ID		11
#define L2TP_ATTR_PEER_SESSION_ID	12
#define L2TP_ATTR_FD			23
#define L2TP_ATTR_IP_SADDR		24
#define L2TP_ATTR_IP_DADDR		25
#define L2TP_ATTR_UDP_SPORT		26
#define L2TP_ATTR_UDP_DPORT		27
#endif

#ifndef L2TP_PWTYPE_ETH
#define L2TP_PWTYPE_ETH			0x0005
#endif

#ifndef L2TP_ENCAPTYPE_UDP
#define L2TP_ENCAPTYPE_UDP		0
#define L2TP_ENCAPTYPE_IP		1
#endif
