#pragma once
#include <linux/dpll.h>

/* linux/dpll.h
 *
 * The dpll UAPI header shipped in 6.7, but its DPLL_A_* and DPLL_A_PIN_*
 * attribute enums have been appended to several times since.  The genl
 * grammar in net/netlink/genl/dpll.c is gated on
 * __has_include(<linux/dpll.h>), so a host that ships an *older*
 * revision of the header (e.g. a distro tracking a pre-7.2 kernel)
 * passes that gate and then fails to compile on the newer enum members
 * the spec tables reference.  The post-6.7 appends the grammar uses are
 * carried here as numeric fallbacks matching the upstream enums:
 *
 *   DPLL_A_LOCK_STATUS_ERROR    (10) present by 6.11
 *   DPLL_A_CLOCK_QUALITY_LEVEL  (11) appended in 6.13
 *   DPLL_A_PHASE_OFFSET_MONITOR (12) appended in 6.16
 *   DPLL_A_PHASE_OFFSET_AVG_FACTOR (13) appended in 6.18
 *   DPLL_A_FREQUENCY_MONITOR    (14) appended in 7.1
 *   DPLL_A_PIN_REFERENCE_SYNC   (28) appended in 6.17
 *   DPLL_A_PIN_FRACTIONAL_FREQUENCY_OFFSET_PPT (30) appended in 7.0
 *   DPLL_A_PIN_OPERSTATE        (32) appended in 7.2
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
#ifndef DPLL_A_PHASE_OFFSET_AVG_FACTOR
#define DPLL_A_PHASE_OFFSET_AVG_FACTOR	13
#endif
#ifndef DPLL_A_FREQUENCY_MONITOR
#define DPLL_A_FREQUENCY_MONITOR	14
#endif
#ifndef DPLL_A_PIN_REFERENCE_SYNC
#define DPLL_A_PIN_REFERENCE_SYNC	28
#endif
#ifndef DPLL_A_PIN_FRACTIONAL_FREQUENCY_OFFSET_PPT
#define DPLL_A_PIN_FRACTIONAL_FREQUENCY_OFFSET_PPT	30
#endif
#ifndef DPLL_A_PIN_OPERSTATE
#define DPLL_A_PIN_OPERSTATE		32
#endif
