#pragma once

/*
 * Wrapper around <linux/nl80211.h> that ships #ifndef-guarded fallbacks
 * for the NL80211_CMD_* / NL80211_ATTR_* / NL80211_IFTYPE_* /
 * NL80211_PMSR_* / NL80211_PREAMBLE_* ids the installed uapi header
 * may be too old to know.  Including <linux/nl80211.h> here lets a .c
 * pull "kernel/nl80211.h" once and get the real uapi enums plus the
 * fallback shims for ids the installed header is missing.
 *
 * The <linux/nl80211.h> include is itself `__has_include`-guarded so a
 * stripped sysroot that lacks the header still compiles -- the fallback
 * shims below carry the file on their own in that case.
 *
 * Purely handler-local trinity policy knobs (outer-loop budget, inner
 * burst sizes, recv-timeout, retry cap, created-iface ring) stay with
 * their handler in the .c.
 */
#if __has_include(<linux/nl80211.h>)
#include <linux/nl80211.h>
#endif

/*
 * NL80211 UAPI fallbacks.  Values mirror include/uapi/linux/nl80211.h
 * (mainline since 2.6.x; per-command integers are stable -- documented
 * UAPI).  Supplied for stripped sysroots that omit <linux/nl80211.h>.
 * If a value drifts the kernel returns -EOPNOTSUPP / -EINVAL on the
 * relevant request and the cap-gate latches.
 */
#ifndef NL80211_GENL_NAME
#define NL80211_GENL_NAME		"nl80211"
#endif

#ifndef NL80211_CMD_GET_WIPHY
#define NL80211_CMD_GET_WIPHY		1
#endif
#ifndef NL80211_CMD_NEW_INTERFACE
#define NL80211_CMD_NEW_INTERFACE	7
#endif
#ifndef NL80211_CMD_DEL_INTERFACE
#define NL80211_CMD_DEL_INTERFACE	8
#endif
#ifndef NL80211_CMD_TRIGGER_SCAN
#define NL80211_CMD_TRIGGER_SCAN	33
#endif
#ifndef NL80211_CMD_NEW_SCAN_RESULTS
#define NL80211_CMD_NEW_SCAN_RESULTS	34
#endif
#ifndef NL80211_CMD_CONNECT
#define NL80211_CMD_CONNECT		46
#endif
#ifndef NL80211_CMD_DISCONNECT
#define NL80211_CMD_DISCONNECT		48
#endif
#ifndef NL80211_CMD_REQ_SET_REG
#define NL80211_CMD_REQ_SET_REG		26
#endif

#ifndef NL80211_ATTR_WIPHY
#define NL80211_ATTR_WIPHY		1
#endif
#ifndef NL80211_ATTR_IFINDEX
#define NL80211_ATTR_IFINDEX		3
#endif
#ifndef NL80211_ATTR_IFNAME
#define NL80211_ATTR_IFNAME		4
#endif
#ifndef NL80211_ATTR_IFTYPE
#define NL80211_ATTR_IFTYPE		5
#endif
#ifndef NL80211_ATTR_MAC
#define NL80211_ATTR_MAC		6
#endif
#ifndef NL80211_ATTR_REG_ALPHA2
#define NL80211_ATTR_REG_ALPHA2		33
#endif
#ifndef NL80211_ATTR_SCAN_SSIDS
#define NL80211_ATTR_SCAN_SSIDS		45
#endif
#ifndef NL80211_ATTR_SSID
#define NL80211_ATTR_SSID		52
#endif

#ifndef NL80211_IFTYPE_STATION
#define NL80211_IFTYPE_STATION		2
#endif

/*
 * NL80211 peer-measurement (PMSR) UAPI fallbacks.  Used to drive the
 * net/wireless/pmsr.c FTM request parser.  The FTMS_PER_BURST attribute
 * is the target field: upstream policy is NLA_U8 but the historical
 * getter used nla_get_u32(), so the parser silently consumed three
 * bytes past the policy-validated payload (broken on big-endian, see
 * commit 0f3c0a197309 -- "wifi: nl80211: fix
 * NL80211_PMSR_FTM_REQ_ATTR_FTMS_PER_BURST usage").  Sending the attr
 * at both u8 and u32 widths exercises both the post-fix strict policy
 * (u32 form -> -EINVAL) and the pre-fix mis-sized read (u8 form
 * passes; u32 form pre-fix passes a getter that the policy then
 * tightens).
 */
#ifndef NL80211_CMD_PEER_MEASUREMENT_START
#define NL80211_CMD_PEER_MEASUREMENT_START	131
#endif
#ifndef NL80211_ATTR_PEER_MEASUREMENTS
#define NL80211_ATTR_PEER_MEASUREMENTS		273
#endif
#ifndef NL80211_PMSR_ATTR_PEERS
#define NL80211_PMSR_ATTR_PEERS			5
#endif
#ifndef NL80211_PMSR_TYPE_FTM
#define NL80211_PMSR_TYPE_FTM			1
#endif
#ifndef NL80211_PMSR_PEER_ATTR_ADDR
#define NL80211_PMSR_PEER_ATTR_ADDR		1
#endif
#ifndef NL80211_PMSR_PEER_ATTR_REQ
#define NL80211_PMSR_PEER_ATTR_REQ		3
#endif
#ifndef NL80211_PMSR_REQ_ATTR_DATA
#define NL80211_PMSR_REQ_ATTR_DATA		1
#endif
#ifndef NL80211_PMSR_FTM_REQ_ATTR_PREAMBLE
#define NL80211_PMSR_FTM_REQ_ATTR_PREAMBLE	2
#endif
#ifndef NL80211_PMSR_FTM_REQ_ATTR_NUM_BURSTS_EXP
#define NL80211_PMSR_FTM_REQ_ATTR_NUM_BURSTS_EXP	3
#endif
#ifndef NL80211_PMSR_FTM_REQ_ATTR_BURST_PERIOD
#define NL80211_PMSR_FTM_REQ_ATTR_BURST_PERIOD	4
#endif
#ifndef NL80211_PMSR_FTM_REQ_ATTR_BURST_DURATION
#define NL80211_PMSR_FTM_REQ_ATTR_BURST_DURATION	5
#endif
#ifndef NL80211_PMSR_FTM_REQ_ATTR_FTMS_PER_BURST
#define NL80211_PMSR_FTM_REQ_ATTR_FTMS_PER_BURST	6
#endif
#ifndef NL80211_PREAMBLE_DMG
#define NL80211_PREAMBLE_DMG			3
#endif

/*
 * NL80211 admin-gate probe UAPI fallbacks.  Used to confirm the
 * GENL_ADMIN_PERM flag is set on the genl_ops table entry for each
 * cmd id below.  Upstream commit 381cd547bc6e ("wifi: nl80211: gate
 * SET_PMK/DEL_PMK/SET_WIPHY_NETNS behind admin perm check") audited
 * the table and re-flagged the entries that had been missing the
 * flag; a regression that drops the flag again is silent unless
 * something probes from an unprivileged context.
 */
#ifndef NL80211_CMD_SET_WIPHY_NETNS
#define NL80211_CMD_SET_WIPHY_NETNS		78
#endif
#ifndef NL80211_CMD_SET_PMK
#define NL80211_CMD_SET_PMK			122
#endif
#ifndef NL80211_CMD_DEL_PMK
#define NL80211_CMD_DEL_PMK			123
#endif
#ifndef NL80211_ATTR_NETNS_FD
#define NL80211_ATTR_NETNS_FD			219
#endif
#ifndef NL80211_ATTR_PMK
#define NL80211_ATTR_PMK			254
#endif
