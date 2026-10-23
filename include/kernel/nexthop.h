#pragma once

/*
 * NHA_* nexthop attribute types are enum members upstream, not macros,
 * so the #ifndef guards below always fire and the #defines are the
 * definition on every kernel; a wrong number is wrong everywhere.
 * <linux/nexthop.h> is included first so the enum body is parsed
 * before the macros go live, whatever the consumer's include order.
 */
#include <linux/nexthop.h>

#ifndef NHA_DST_PORT
#define NHA_DST_PORT			18
#endif
