#pragma once
#include <linux/gtp.h>

/* linux/gtp.h
 *
 * The upstream <linux/gtp.h> UAPI ships only the GTP_CMD_* command
 * enum, the gtp_version enum, and the GTPA_* attribute enum (plus
 * the GTP_GENL_MCGRP_NAME multicast-group string).  The genl family
 * name and version are not exported as UAPI constants — the kernel
 * registers the family with .name = "gtp" and .version = 0
 * literally, so the walker carries its own GTP_GENL_NAME /
 * GTP_GENL_VERSION constants that match the kernel-side literals
 * byte-for-byte.  Each is gated by per-symbol #ifndef so a future
 * UAPI revision that promotes either to a constant wins.
 *
 * GTPA_FAMILY (id 13) was appended in 5.10 to disambiguate the
 * IPv4 vs IPv6 PDP arm when both PEER_ADDRESS and PEER_ADDR6 are
 * absent; older host headers stop at GTPA_MS_ADDR6 = 12 and pick
 * up the numeric fallback below.  GTPA_PEER_ADDR6 / GTPA_MS_ADDR6
 * (ids 11 / 12) were appended in 5.7 for IPv6 PDP support and
 * carry their own per-symbol fallbacks for the same reason.
 * GTPA_PAD (id 10) was appended in 4.18 as the alignment partner
 * for nla_put_u64_64bit(GTPA_TID); the walker doesn't reference
 * it, but it's defined here for completeness so future walker
 * extensions don't trip on a missing constant.
 *
 * GTPA_* are enum members, not preprocessor macros, so the #ifndef
 * guards always fire.  This header pulls <linux/gtp.h> first so the
 * canonical enum body is parsed before the fallback macros become
 * live, regardless of the consumer's include order.
 */
#ifndef GTP_GENL_NAME
#define GTP_GENL_NAME			"gtp"
#endif
#ifndef GTP_GENL_VERSION
#define GTP_GENL_VERSION		0
#endif
#ifndef GTPA_PAD
#define GTPA_PAD			10
#endif
#ifndef GTPA_PEER_ADDR6
#define GTPA_PEER_ADDR6			11
#endif
#ifndef GTPA_MS_ADDR6
#define GTPA_MS_ADDR6			12
#endif
#ifndef GTPA_FAMILY
#define GTPA_FAMILY			13
#endif
