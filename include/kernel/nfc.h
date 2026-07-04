#pragma once
#include <linux/nfc.h>

/* linux/nfc.h
 *
 * The nfc genl grammar in net/netlink/genl/nfc.c is gated on
 * __has_include(<linux/nfc.h>), so a host that ships an *older*
 * revision of the header passes that gate and then fails to compile on
 * the newest NFC_ATTR_* members the spec table references.  The
 * ISO 14443-A "Answer To Select" surface was appended in 6.13
 * (absent in 6.11, present in 6.13):
 *
 *   NFC_ATTR_TARGET_ATS (32) enum member
 *   NFC_ATS_MAXSIZE     (20) #define, the binary attr's size cap
 *
 * A distro tracking a pre-6.13 kernel (e.g. a 6.12 stable series)
 * builds with a header missing both, so the translation unit hit
 * 'NFC_ATTR_TARGET_ATS undeclared'.
 *
 * NFC_ATTR_* are enum members, not preprocessor macros, so the
 * NFC_ATTR_TARGET_ATS #ifndef always fires.  This header pulls
 * <linux/nfc.h> first so the canonical enum body is parsed before the
 * fallback macro becomes live, regardless of the consumer's include
 * order.  NFC_ATS_MAXSIZE is a real #define, so its guard detects a
 * header that already carries it.
 */
#ifndef NFC_ATTR_TARGET_ATS
#define NFC_ATTR_TARGET_ATS	32
#endif
#ifndef NFC_ATS_MAXSIZE
#define NFC_ATS_MAXSIZE		20
#endif
