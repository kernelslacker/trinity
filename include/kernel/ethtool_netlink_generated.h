#pragma once
#include <linux/ethtool_netlink_generated.h>
#ifndef ETHTOOL_MSG_TSCONFIG_GET
#define ETHTOOL_MSG_TSCONFIG_GET 46
#endif
#ifndef ETHTOOL_MSG_MSE_GET
#define ETHTOOL_MSG_MSE_GET 51
#endif

/*
 * The hardware timestamp provider nest of TSINFO_GET and its two ids came
 * after the header was first generated.  They are enum members, so configure
 * probes them and emits HAVE_<SYMBOL>.
 */
#ifndef HAVE_ETHTOOL_A_TSINFO_HWTSTAMP_PROVIDER
#define ETHTOOL_A_TSINFO_HWTSTAMP_PROVIDER 7
#endif
#ifndef HAVE_ETHTOOL_A_TS_HWTSTAMP_PROVIDER_INDEX
#define ETHTOOL_A_TS_HWTSTAMP_PROVIDER_INDEX 1
#endif
#ifndef HAVE_ETHTOOL_A_TS_HWTSTAMP_PROVIDER_QUALIFIER
#define ETHTOOL_A_TS_HWTSTAMP_PROVIDER_QUALIFIER 2
#endif

/* PORT_GET, which lists the PHY ports of a netdev, and the attributes of its
 * request, added in 7.4.  Probed by configure like the ones above. */
#ifndef HAVE_ETHTOOL_MSG_PORT_GET
#define ETHTOOL_MSG_PORT_GET 52
#endif
#ifndef HAVE_ETHTOOL_A_PORT_HEADER
#define ETHTOOL_A_PORT_HEADER 1
#endif
#ifndef HAVE_ETHTOOL_A_PORT_ID
#define ETHTOOL_A_PORT_ID 2
#endif

/* COALESCE_SET's receive-CQE counters, which follow the profile nests in
 * the coalesce attribute enum.  Probed by configure like the ones above. */
#ifndef HAVE_ETHTOOL_A_COALESCE_RX_CQE_FRAMES
#define ETHTOOL_A_COALESCE_RX_CQE_FRAMES 31
#endif
#ifndef HAVE_ETHTOOL_A_COALESCE_RX_CQE_NSECS
#define ETHTOOL_A_COALESCE_RX_CQE_NSECS 32
#endif
