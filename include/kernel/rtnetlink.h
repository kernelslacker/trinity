#pragma once

/*
 * RTA_* route attribute types are enum members upstream, not macros, so
 * #ifndef cannot tell whether <linux/rtnetlink.h> has one.  configure
 * compile-tests each and emits HAVE_<SYMBOL>; the fallback below exists only
 * where the header lacks the member, so it never shadows the real one.
 * <linux/rtnetlink.h> is still included first so a probe that misfires
 * cannot put a macro ahead of the enum body, whatever the consumer's include
 * order.
 */
#include <linux/rtnetlink.h>

#ifndef HAVE_RTA_FLOWLABEL
#define RTA_FLOWLABEL			31
#endif

#ifndef HAVE_RTA_DEL_REASON
#define RTA_DEL_REASON			32
#endif

/* The RTM_* message types are macros as well as enum members. */
#ifndef RTM_DELLINKPROP
#define RTM_DELLINKPROP			109
#endif
