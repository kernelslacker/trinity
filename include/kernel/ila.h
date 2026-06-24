#pragma once

/*
 * Wrapper around <linux/ila.h> that ships the #ifndef-guarded fallbacks
 * for ILA_ATTR_* / ILA_CMD_* ids added after the installed uapi header.
 * The .c side includes this from inside its
 * `#if __has_include(<linux/ila.h>)` gate, so the header itself can
 * include <linux/ila.h> unconditionally.
 */
#include <linux/ila.h>

/*
 * Per-symbol shims for ILA_ATTR_* / ILA_CMD_* ids.  Build hosts whose
 * <linux/ila.h> predates a given attribute (the post-4.10 CSUM_MODE,
 * the post-4.18 IDENT_TYPE / HOOK_TYPE pair) silently miss it from the
 * validator coverage; the fallback values match the upstream uapi enum
 * ordering so the wire-format ids the kernel parses match the ones the
 * generator emits.
 */
#ifndef ILA_ATTR_LOCATOR
#define ILA_ATTR_LOCATOR		1
#endif
#ifndef ILA_ATTR_IDENTIFIER
#define ILA_ATTR_IDENTIFIER		2
#endif
#ifndef ILA_ATTR_LOCATOR_MATCH
#define ILA_ATTR_LOCATOR_MATCH		3
#endif
#ifndef ILA_ATTR_IFINDEX
#define ILA_ATTR_IFINDEX		4
#endif
#ifndef ILA_ATTR_DIR
#define ILA_ATTR_DIR			5
#endif
#ifndef ILA_ATTR_PAD
#define ILA_ATTR_PAD			6
#endif
#ifndef ILA_ATTR_CSUM_MODE
#define ILA_ATTR_CSUM_MODE		7
#endif
#ifndef ILA_ATTR_IDENT_TYPE
#define ILA_ATTR_IDENT_TYPE		8
#endif
#ifndef ILA_ATTR_HOOK_TYPE
#define ILA_ATTR_HOOK_TYPE		9
#endif

#ifndef ILA_CMD_ADD
#define ILA_CMD_ADD			1
#endif
#ifndef ILA_CMD_DEL
#define ILA_CMD_DEL			2
#endif
#ifndef ILA_CMD_GET
#define ILA_CMD_GET			3
#endif
#ifndef ILA_CMD_FLUSH
#define ILA_CMD_FLUSH			4
#endif
