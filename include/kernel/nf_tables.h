#pragma once

/*
 * NFTA_DEVICE_PREFIX is an enum nft_devices_attributes member upstream,
 * not a macro, so #ifndef cannot tell whether
 * <linux/netfilter/nf_tables.h> has it.  configure compile-tests it and
 * emits HAVE_NFTA_DEVICE_PREFIX; the fallback below exists only where the
 * header lacks the member, so it never shadows the real one.  The header
 * is included first so a probe that misfires cannot put a macro ahead of
 * the enum body, whatever the consumer's include order.
 */
#include <linux/netfilter/nf_tables.h>

#ifndef HAVE_NFTA_DEVICE_PREFIX
#define NFTA_DEVICE_PREFIX		2
#endif
