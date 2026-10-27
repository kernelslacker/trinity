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
