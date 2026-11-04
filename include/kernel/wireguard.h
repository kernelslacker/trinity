#pragma once

/*
 * WGALLOWEDIP_A_FLAGS and WGALLOWEDIP_F_REMOVE_ME are enum members
 * upstream, not macros, so #ifndef cannot tell whether
 * <linux/wireguard.h> has them.  configure compile-tests each and
 * emits HAVE_<SYMBOL>; the fallback below exists only where the
 * header lacks the member, so it never shadows the real one.
 * <linux/wireguard.h> is still included first so a probe that
 * misfires cannot put a macro ahead of the enum body, whatever the
 * consumer's include order.
 */
#include <linux/wireguard.h>

#ifndef HAVE_WGALLOWEDIP_A_FLAGS
#define WGALLOWEDIP_A_FLAGS	4
#endif
#ifndef HAVE_WGALLOWEDIP_F_REMOVE_ME
#define WGALLOWEDIP_F_REMOVE_ME	(1U << 0)
#endif
