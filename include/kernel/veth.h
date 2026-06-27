#pragma once
#include <linux/veth.h>

/* linux/veth.h — VETH_INFO_PEER carries an ifinfomsg + IFLA_IFNAME for the
 * peer end of the veth pair inside IFLA_INFO_DATA.  Older kernel-headers
 * packages predate <linux/veth.h>; the enum value (1) is fixed since the
 * 2.6.24 veth merge.
 *
 * VETH_INFO_PEER is an enum member, not a preprocessor macro, so the
 * #ifndef guard always fires.  This header pulls <linux/veth.h> first
 * so the canonical enum body is parsed before the fallback macro
 * becomes live, regardless of the consumer's include order. */
#ifndef VETH_INFO_PEER
#define VETH_INFO_PEER		1
#endif
