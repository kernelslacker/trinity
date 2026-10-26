#pragma once

/*
 * NHA_* nexthop attribute types are enum members upstream, not macros, so
 * #ifndef cannot tell whether <linux/nexthop.h> has one.  configure
 * compile-tests each and emits HAVE_<SYMBOL>; the fallback below exists only
 * where the header lacks the member, so it never shadows the real one.
 * <linux/nexthop.h> is still included first so a probe that misfires cannot
 * put a macro ahead of the enum body, whatever the consumer's include order.
 */
#include <linux/nexthop.h>

#ifndef HAVE_NHA_DST_PORT
#define NHA_DST_PORT			18
#endif
