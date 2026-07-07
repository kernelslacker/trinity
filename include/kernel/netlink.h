#pragma once

/*
 * Wrapper around <linux/netlink.h> that ships #ifndef-guarded
 * fallbacks for the netlink UAPI values touched by
 * childops/net/netlink/netlink-monitor-race.c.  The real header is
 * pulled in behind __has_include so stripped sysroots that don't ship
 * <linux/netlink.h> still compile; per-symbol #ifndef fallbacks then
 * supply any missing values.  All three are plain #define in the
 * upstream uapi header, so an inline #ifndef is sufficient.  Values
 * mirror the upstream uapi #define literals exactly.
 */
#if __has_include(<linux/netlink.h>)
#include <linux/netlink.h>
#endif
#if __has_include(<linux/rtnetlink.h>)
#include <linux/rtnetlink.h>
#endif

#ifndef NETLINK_BROADCAST_ERROR
#define NETLINK_BROADCAST_ERROR	4
#endif
#ifndef NETLINK_ADD_MEMBERSHIP
#define NETLINK_ADD_MEMBERSHIP	1
#endif
#ifndef NETLINK_DROP_MEMBERSHIP
#define NETLINK_DROP_MEMBERSHIP	2
#endif

#ifndef NETLINK_CRYPTO
#define NETLINK_CRYPTO 21
#endif
#ifndef NETLINK_SMC
#define NETLINK_SMC 22
#endif
#ifndef NETLINK_RX_RING
#define NETLINK_RX_RING 6
#define NETLINK_TX_RING 7
#endif
#ifndef NETLINK_LISTEN_ALL_NSID
#define NETLINK_LISTEN_ALL_NSID 8
#endif
#ifndef NETLINK_LIST_MEMBERSHIPS
#define NETLINK_LIST_MEMBERSHIPS 9
#endif
#ifndef NETLINK_CAP_ACK
#define NETLINK_CAP_ACK 10
#endif
#ifndef NETLINK_EXT_ACK
#define NETLINK_EXT_ACK 11
#endif
#ifndef NETLINK_GET_STRICT_CHK
#define NETLINK_GET_STRICT_CHK 12
#endif
#ifndef NETLINK_SOCK_DIAG
#define NETLINK_SOCK_DIAG 4
#endif
#ifndef NETLINK_XFRM
#define NETLINK_XFRM 6
#endif
#ifndef RTNLGRP_DCB
#define RTNLGRP_DCB 23
#endif
#ifndef RTNLGRP_IPV4_NETCONF
#define RTNLGRP_IPV4_NETCONF 24
#endif
#ifndef RTNLGRP_IPV6_NETCONF
#define RTNLGRP_IPV6_NETCONF 25
#endif
#ifndef RTNLGRP_MDB
#define RTNLGRP_MDB 26
#endif
#ifndef RTNLGRP_MPLS_ROUTE
#define RTNLGRP_MPLS_ROUTE 27
#endif
#ifndef RTNLGRP_NSID
#define RTNLGRP_NSID 28
#endif
#ifndef RTNLGRP_MPLS_NETCONF
#define RTNLGRP_MPLS_NETCONF 29
#endif

