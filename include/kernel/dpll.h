#pragma once
#include <linux/dpll.h>

/* linux/dpll.h
 *
 * The dpll UAPI header shipped in 6.7, but its top-level DPLL_A_*
 * attribute enum has been appended to several times since.  The genl
 * grammar in net/netlink-genl-fam-dpll.c is gated on
 * __has_include(<linux/dpll.h>), so a host that ships an *older*
 * revision of the header (e.g. a distro tracking a pre-6.16 kernel)
 * passes that gate and then fails to compile on the newer enum members
 * the spec table references.  The three post-6.7 appends the walker
 * uses are carried here as numeric fallbacks matching the upstream enum:
 *
 *   DPLL_A_LOCK_STATUS_ERROR    (10) present by 6.11
 *   DPLL_A_CLOCK_QUALITY_LEVEL  (11) appended in 6.13
 *   DPLL_A_PHASE_OFFSET_MONITOR (12) appended in 6.16
 *
 * DPLL_A_* are enum members, not preprocessor macros, so the #ifndef
 * guards always fire.  This header pulls <linux/dpll.h> first so the
 * canonical enum body is parsed before the fallback macros become
 * live, regardless of the consumer's include order.
 */
#ifndef DPLL_A_LOCK_STATUS_ERROR
#define DPLL_A_LOCK_STATUS_ERROR	10
#endif
#ifndef DPLL_A_CLOCK_QUALITY_LEVEL
#define DPLL_A_CLOCK_QUALITY_LEVEL	11
#endif
#ifndef DPLL_A_PHASE_OFFSET_MONITOR
#define DPLL_A_PHASE_OFFSET_MONITOR	12
#endif
