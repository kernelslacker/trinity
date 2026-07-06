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

#ifndef NETLINK_BROADCAST_ERROR
#define NETLINK_BROADCAST_ERROR	4
#endif
#ifndef NETLINK_ADD_MEMBERSHIP
#define NETLINK_ADD_MEMBERSHIP	1
#endif
#ifndef NETLINK_DROP_MEMBERSHIP
#define NETLINK_DROP_MEMBERSHIP	2
#endif
