#pragma once

/*
 * CTA_FILTER_* ctnetlink filter attribute types are enum members upstream,
 * not macros, so #ifndef cannot tell whether
 * <linux/netfilter/nfnetlink_conntrack.h> has one.  configure compile-tests
 * each and emits HAVE_<SYMBOL>; the fallback below exists only where the
 * header lacks the member, so it never shadows the real one.  The header is
 * still included first so a probe that misfires cannot put a macro ahead of
 * the enum body, whatever the consumer's include order.
 */
#include <linux/netfilter/nfnetlink_conntrack.h>

#ifndef HAVE_CTA_FILTER_ZONE
#define CTA_FILTER_ZONE			3
#endif
