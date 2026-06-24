#pragma once

/*
 * Wrapper around <linux/fou.h> that ships the #ifndef-guarded
 * fallbacks for FOU_ATTR_* / FOU_CMD_* ids added after the
 * installed uapi header (REMCSUM_NOPARTIAL, the peer-side V4/V6
 * / PEER_PORT triple, IFINDEX).  The .c side includes this from
 * inside its `#if __has_include(<linux/fou.h>)` gate, so the
 * header itself can include <linux/fou.h> unconditionally.
 */
#include <linux/fou.h>

/*
 * Per-symbol shims for FOU_ATTR_* / FOU_CMD_* ids.  Build hosts whose
 * <linux/fou.h> predates a given attribute (REMCSUM_NOPARTIAL, the
 * peer-side V4/V6 / PEER_PORT triple, IFINDEX) silently miss it from
 * the validator coverage; the fallback values match the upstream uapi
 * enum ordering so the wire-format ids the kernel parses match the
 * ones the generator emits.
 */
#ifndef FOU_ATTR_PORT
#define FOU_ATTR_PORT			1
#endif
#ifndef FOU_ATTR_AF
#define FOU_ATTR_AF			2
#endif
#ifndef FOU_ATTR_IPPROTO
#define FOU_ATTR_IPPROTO		3
#endif
#ifndef FOU_ATTR_TYPE
#define FOU_ATTR_TYPE			4
#endif
#ifndef FOU_ATTR_REMCSUM_NOPARTIAL
#define FOU_ATTR_REMCSUM_NOPARTIAL	5
#endif
#ifndef FOU_ATTR_LOCAL_V4
#define FOU_ATTR_LOCAL_V4		6
#endif
#ifndef FOU_ATTR_LOCAL_V6
#define FOU_ATTR_LOCAL_V6		7
#endif
#ifndef FOU_ATTR_PEER_V4
#define FOU_ATTR_PEER_V4		8
#endif
#ifndef FOU_ATTR_PEER_V6
#define FOU_ATTR_PEER_V6		9
#endif
#ifndef FOU_ATTR_PEER_PORT
#define FOU_ATTR_PEER_PORT		10
#endif
#ifndef FOU_ATTR_IFINDEX
#define FOU_ATTR_IFINDEX		11
#endif

#ifndef FOU_CMD_ADD
#define FOU_CMD_ADD			1
#endif
#ifndef FOU_CMD_DEL
#define FOU_CMD_DEL			2
#endif
#ifndef FOU_CMD_GET
#define FOU_CMD_GET			3
#endif
