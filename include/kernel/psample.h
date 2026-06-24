#pragma once

/*
 * Wrapper around <linux/psample.h> that ships the #ifndef-guarded
 * fallbacks for PSAMPLE_ATTR_* / PSAMPLE_CMD_* ids added after the
 * installed uapi header.  The .c side includes this from inside its
 * `#if __has_include(<linux/psample.h>)` gate, so the header itself
 * can include <linux/psample.h> unconditionally.
 */
#include <linux/psample.h>

/*
 * Per-symbol shims for PSAMPLE_ATTR_* / PSAMPLE_CMD_* ids.  Build hosts
 * whose <linux/psample.h> predates a given attribute (the post-4.11
 * tunnel / OUT_TC / OUT_TC_OCC, the post-5.13 LATENCY / TIMESTAMP /
 * PROTO triple, the post-6.4 USER_COOKIE, the post-6.7
 * SAMPLE_PROBABILITY flag) silently miss it from the validator
 * coverage; the fallback values match the upstream uapi enum ordering
 * so the wire-format ids the kernel parses match the ones the
 * generator emits.  PSAMPLE_CMD_NEW_GROUP / DEL_GROUP were added in
 * 6.10 and similarly fall back to the upstream enum values.
 */
#ifndef PSAMPLE_ATTR_IIFINDEX
#define PSAMPLE_ATTR_IIFINDEX			0
#endif
#ifndef PSAMPLE_ATTR_OIFINDEX
#define PSAMPLE_ATTR_OIFINDEX			1
#endif
#ifndef PSAMPLE_ATTR_ORIGSIZE
#define PSAMPLE_ATTR_ORIGSIZE			2
#endif
#ifndef PSAMPLE_ATTR_SAMPLE_GROUP
#define PSAMPLE_ATTR_SAMPLE_GROUP		3
#endif
#ifndef PSAMPLE_ATTR_GROUP_SEQ
#define PSAMPLE_ATTR_GROUP_SEQ			4
#endif
#ifndef PSAMPLE_ATTR_SAMPLE_RATE
#define PSAMPLE_ATTR_SAMPLE_RATE		5
#endif
#ifndef PSAMPLE_ATTR_DATA
#define PSAMPLE_ATTR_DATA			6
#endif
#ifndef PSAMPLE_ATTR_GROUP_REFCOUNT
#define PSAMPLE_ATTR_GROUP_REFCOUNT		7
#endif
#ifndef PSAMPLE_ATTR_TUNNEL
#define PSAMPLE_ATTR_TUNNEL			8
#endif
#ifndef PSAMPLE_ATTR_PAD
#define PSAMPLE_ATTR_PAD			9
#endif
#ifndef PSAMPLE_ATTR_OUT_TC
#define PSAMPLE_ATTR_OUT_TC			10
#endif
#ifndef PSAMPLE_ATTR_OUT_TC_OCC
#define PSAMPLE_ATTR_OUT_TC_OCC			11
#endif
#ifndef PSAMPLE_ATTR_LATENCY
#define PSAMPLE_ATTR_LATENCY			12
#endif
#ifndef PSAMPLE_ATTR_TIMESTAMP
#define PSAMPLE_ATTR_TIMESTAMP			13
#endif
#ifndef PSAMPLE_ATTR_PROTO
#define PSAMPLE_ATTR_PROTO			14
#endif
#ifndef PSAMPLE_ATTR_USER_COOKIE
#define PSAMPLE_ATTR_USER_COOKIE		15
#endif
#ifndef PSAMPLE_ATTR_SAMPLE_PROBABILITY
#define PSAMPLE_ATTR_SAMPLE_PROBABILITY		16
#endif

#ifndef PSAMPLE_CMD_SAMPLE
#define PSAMPLE_CMD_SAMPLE			0
#endif
#ifndef PSAMPLE_CMD_GET_GROUP
#define PSAMPLE_CMD_GET_GROUP			1
#endif
#ifndef PSAMPLE_CMD_NEW_GROUP
#define PSAMPLE_CMD_NEW_GROUP			2
#endif
#ifndef PSAMPLE_CMD_DEL_GROUP
#define PSAMPLE_CMD_DEL_GROUP			3
#endif
