#pragma once

/*
 * IFLA_* link attribute types are enum members upstream, not macros, so
 * #ifndef cannot tell whether <linux/if_link.h> has one.  configure
 * compile-tests each and emits HAVE_<SYMBOL>; the fallback below exists only
 * where the header lacks the member, so it never shadows the real one.
 * <linux/if_link.h> is still included first so a probe that misfires cannot
 * put a macro ahead of the enum body, whatever the consumer's include order.
 */
#include <linux/if_link.h>

#ifndef HAVE_IFLA_GRO_MAX_SIZE
#define IFLA_GRO_MAX_SIZE		58
#endif
#ifndef HAVE_IFLA_GSO_IPV4_MAX_SIZE
#define IFLA_GSO_IPV4_MAX_SIZE		63
#endif
#ifndef HAVE_IFLA_GRO_IPV4_MAX_SIZE
#define IFLA_GRO_IPV4_MAX_SIZE		64
#endif
#ifndef HAVE_IFLA_PACING_OFFLOAD
#define IFLA_PACING_OFFLOAD		70
#endif
