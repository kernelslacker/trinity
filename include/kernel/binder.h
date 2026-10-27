#pragma once

/*
 * Fallbacks for the <linux/android/binder.h> ioctl requests that came after
 * the first seven.  They are enum members, so configure compile-tests each
 * and emits HAVE_<SYMBOL>; a header without one gets the number written out,
 * since the struct whose size it encodes is missing from that header too.
 */
#include <linux/android/binder.h>

#ifndef HAVE_BINDER_GET_NODE_DEBUG_INFO
#define BINDER_GET_NODE_DEBUG_INFO		0xc018620b
#endif
#ifndef HAVE_BINDER_GET_NODE_INFO_FOR_REF
#define BINDER_GET_NODE_INFO_FOR_REF		0xc018620c
#endif
#ifndef HAVE_BINDER_SET_CONTEXT_MGR_EXT
#define BINDER_SET_CONTEXT_MGR_EXT		0x4018620d
#endif
#ifndef HAVE_BINDER_FREEZE
#define BINDER_FREEZE				0x400c620e
#endif
#ifndef HAVE_BINDER_GET_FROZEN_INFO
#define BINDER_GET_FROZEN_INFO			0xc00c620f
#endif
#ifndef HAVE_BINDER_ENABLE_ONEWAY_SPAM_DETECTION
#define BINDER_ENABLE_ONEWAY_SPAM_DETECTION	0x40046210
#endif
#ifndef HAVE_BINDER_GET_EXTENDED_ERROR
#define BINDER_GET_EXTENDED_ERROR		0xc00c6211
#endif
