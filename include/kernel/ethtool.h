#pragma once

/*
 * ETH_SS_* string set ids are enum members, so configure compile-tests
 * ETH_SS_PHY_INTERFACES, the newest, and emits HAVE_<SYMBOL>; the fallback
 * below exists only where <linux/ethtool.h> lacks it, so it never shadows the
 * real one.  <linux/ethtool.h> is still included first so a probe that
 * misfires cannot put a macro ahead of the enum body, whatever the
 * consumer's include order.
 */
#include <linux/ethtool.h>

#ifndef HAVE_ETH_SS_PHY_INTERFACES
#define ETH_SS_PHY_INTERFACES		23
#endif
