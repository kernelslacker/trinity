#pragma once

/*
 * IFA_* address attributes are enum members upstream, not macros, so #ifndef
 * cannot tell whether <linux/if_addr.h> has one.  configure compile-tests
 * IFA_TARGET_NETNSID and emits HAVE_<SYMBOL>; the fallback below exists only
 * where the header lacks the member, so it never shadows the real one.
 * <linux/if_addr.h> is still included first so a probe that misfires cannot
 * put a macro ahead of the enum body, whatever the consumer's include order.
 */
#include <linux/if_addr.h>

#ifndef HAVE_IFA_TARGET_NETNSID
#define IFA_TARGET_NETNSID		10
#endif
