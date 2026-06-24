#pragma once

/*
 * Wrapper around <linux/seg6_genl.h> that ships the #ifndef-guarded
 * fallbacks for SEG6_ATTR_* / SEG6_CMD_* ids added after the installed
 * uapi header.  The .c side includes this from inside its
 * `#if __has_include(<linux/seg6_genl.h>)` gate, so the header itself
 * can include <linux/seg6_genl.h> unconditionally.
 */
#include <linux/seg6_genl.h>

/*
 * Per-symbol shims for SEG6_ATTR_* / SEG6_CMD_* ids.  Build hosts
 * whose <linux/seg6_genl.h> predates a given attribute or command
 * silently miss it from the validator coverage; the fallback values
 * match the upstream uapi enum ordering so the wire-format ids the
 * kernel parses match the ones the generator emits.
 */
#ifndef SEG6_ATTR_DST
#define SEG6_ATTR_DST			1
#endif
#ifndef SEG6_ATTR_DSTLEN
#define SEG6_ATTR_DSTLEN		2
#endif
#ifndef SEG6_ATTR_HMACKEYID
#define SEG6_ATTR_HMACKEYID		3
#endif
#ifndef SEG6_ATTR_SECRET
#define SEG6_ATTR_SECRET		4
#endif
#ifndef SEG6_ATTR_SECRETLEN
#define SEG6_ATTR_SECRETLEN		5
#endif
#ifndef SEG6_ATTR_ALGID
#define SEG6_ATTR_ALGID			6
#endif
#ifndef SEG6_ATTR_HMACINFO
#define SEG6_ATTR_HMACINFO		7
#endif

#ifndef SEG6_CMD_SETHMAC
#define SEG6_CMD_SETHMAC		1
#endif
#ifndef SEG6_CMD_DUMPHMAC
#define SEG6_CMD_DUMPHMAC		2
#endif
#ifndef SEG6_CMD_SET_TUNSRC
#define SEG6_CMD_SET_TUNSRC		3
#endif
#ifndef SEG6_CMD_GET_TUNSRC
#define SEG6_CMD_GET_TUNSRC		4
#endif
