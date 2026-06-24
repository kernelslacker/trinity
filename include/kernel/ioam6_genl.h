#pragma once

/*
 * Wrapper around <linux/ioam6_genl.h> that ships the #ifndef-guarded
 * fallbacks for IOAM6_ATTR_* / IOAM6_CMD_* ids and the
 * IOAM6_MAX_SCHEMA_DATA_LEN cap added after the installed uapi
 * header.  The .c side includes this from inside its
 * `#if __has_include(<linux/ioam6_genl.h>)` gate, so the header
 * itself can include <linux/ioam6_genl.h> unconditionally.
 */
#include <linux/ioam6_genl.h>

/*
 * Per-symbol shims for IOAM6_ATTR_* / IOAM6_CMD_* ids.  Build hosts
 * whose <linux/ioam6_genl.h> predates a given attribute (the post-5.15
 * NS_DATA_WIDE / SC_* schema additions) silently miss it from the
 * validator coverage; the fallback values match the upstream uapi
 * enum ordering so the wire-format ids the kernel parses match the
 * ones the generator emits.
 */
#ifndef IOAM6_ATTR_NS_ID
#define IOAM6_ATTR_NS_ID		1
#endif
#ifndef IOAM6_ATTR_NS_DATA
#define IOAM6_ATTR_NS_DATA		2
#endif
#ifndef IOAM6_ATTR_NS_DATA_WIDE
#define IOAM6_ATTR_NS_DATA_WIDE		3
#endif
#ifndef IOAM6_ATTR_SC_ID
#define IOAM6_ATTR_SC_ID		4
#endif
#ifndef IOAM6_ATTR_SC_DATA
#define IOAM6_ATTR_SC_DATA		5
#endif
#ifndef IOAM6_ATTR_SC_NONE
#define IOAM6_ATTR_SC_NONE		6
#endif
#ifndef IOAM6_ATTR_PAD
#define IOAM6_ATTR_PAD			7
#endif

#ifndef IOAM6_CMD_ADD_NAMESPACE
#define IOAM6_CMD_ADD_NAMESPACE		1
#endif
#ifndef IOAM6_CMD_DEL_NAMESPACE
#define IOAM6_CMD_DEL_NAMESPACE		2
#endif
#ifndef IOAM6_CMD_DUMP_NAMESPACES
#define IOAM6_CMD_DUMP_NAMESPACES	3
#endif
#ifndef IOAM6_CMD_ADD_SCHEMA
#define IOAM6_CMD_ADD_SCHEMA		4
#endif
#ifndef IOAM6_CMD_DEL_SCHEMA
#define IOAM6_CMD_DEL_SCHEMA		5
#endif
#ifndef IOAM6_CMD_DUMP_SCHEMAS
#define IOAM6_CMD_DUMP_SCHEMAS		6
#endif
#ifndef IOAM6_CMD_NS_SET_SCHEMA
#define IOAM6_CMD_NS_SET_SCHEMA		7
#endif

/*
 * IOAM6_MAX_SCHEMA_DATA_LEN is defined inside the IOAM6_ATTR_* enum in
 * the upstream uapi header (255 * 4 = 1020 bytes — the kernel policy
 * cap on SC_DATA blob length).  Provide a fallback so the SC_DATA spec
 * below has a sane upper bound on hosts whose uapi predates the macro.
 */
#ifndef IOAM6_MAX_SCHEMA_DATA_LEN
#define IOAM6_MAX_SCHEMA_DATA_LEN	(255 * 4)
#endif
