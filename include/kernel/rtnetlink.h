#pragma once

/*
 * RTA_* route attribute types are enum members upstream, not macros,
 * so the #ifndef guards below always fire and the #defines are the
 * definition on every kernel; a wrong number is wrong everywhere.
 * <linux/rtnetlink.h> is included first so the enum body is parsed
 * before the macros go live, whatever the consumer's include order.
 */
#include <linux/rtnetlink.h>

#ifndef RTA_DEL_REASON
#define RTA_DEL_REASON			32
#endif
