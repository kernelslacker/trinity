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
