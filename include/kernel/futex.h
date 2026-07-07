#pragma once

/*
 * Wrapper around <linux/futex.h> that ships #ifndef-guarded fallbacks for
 * FUTEX_32 (an alias for the FUTEX2 size-U32 encoding) and FUTEX_NO_NODE
 * (the "no NUMA node preference" sentinel used in FUTEX2_MPOL waiters).
 * Defined locally so trinity builds against older kernel headers that
 * predate the futex_waitv UAPI additions.
 */
#include <linux/futex.h>

#ifndef FUTEX_32
#define FUTEX_32		FUTEX2_SIZE_U32
#endif

/* Sentinel for "no NUMA node preference" in FUTEX2_MPOL waiters. */
#ifndef FUTEX_NO_NODE
#define FUTEX_NO_NODE		(-1)
#endif

#ifndef FUTEX2_SIZE_U8
#define FUTEX2_SIZE_U8		0x00
#endif
#ifndef FUTEX2_SIZE_U16
#define FUTEX2_SIZE_U16		0x01
#endif
#ifndef FUTEX2_SIZE_U32
#define FUTEX2_SIZE_U32		0x02
#endif
#ifndef FUTEX2_SIZE_U64
#define FUTEX2_SIZE_U64		0x03
#endif
#ifndef FUTEX2_NUMA
#define FUTEX2_NUMA		0x04
#endif
#ifndef FUTEX2_MPOL
#define FUTEX2_MPOL		0x08
#endif
#ifndef FUTEX2_PRIVATE
#define FUTEX2_PRIVATE		0x80
#endif

