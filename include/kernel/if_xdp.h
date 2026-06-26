#pragma once

/*
 * Wrapper around <linux/if_xdp.h> that ships the #ifndef-guarded
 * fallbacks for XDP_UMEM_* / XDP_STATISTICS / XDP_OPTIONS setsockopt
 * ids and the XDP_*_PGOFF / XDP_MMAP_OFFSETS mmap-offset ids added
 * after the installed uapi header.  The .c side is wrapped in
 * `#ifdef USE_XDP` (set by configure when <linux/if_xdp.h> exists),
 * so the header itself can include <linux/if_xdp.h> unconditionally.
 */
#include <linux/if_xdp.h>

#ifndef XDP_UMEM_REG
#define XDP_UMEM_REG		4
#endif
#ifndef XDP_UMEM_FILL_RING
#define XDP_UMEM_FILL_RING	5
#endif
#ifndef XDP_UMEM_COMPLETION_RING
#define XDP_UMEM_COMPLETION_RING 6
#endif
#ifndef XDP_STATISTICS
#define XDP_STATISTICS		7
#endif
#ifndef XDP_OPTIONS
#define XDP_OPTIONS		8
#endif

#ifndef XDP_MMAP_OFFSETS
#define XDP_MMAP_OFFSETS	1
#endif
#ifndef XDP_PGOFF_RX_RING
#define XDP_PGOFF_RX_RING			  0
#endif
#ifndef XDP_PGOFF_TX_RING
#define XDP_PGOFF_TX_RING		 0x80000000
#endif
#ifndef XDP_UMEM_PGOFF_FILL_RING
#define XDP_UMEM_PGOFF_FILL_RING	0x100000000ULL
#endif
#ifndef XDP_UMEM_PGOFF_COMPLETION_RING
#define XDP_UMEM_PGOFF_COMPLETION_RING	0x180000000ULL
#endif
