#pragma once

#include <stdbool.h>
#include <stddef.h>

/*
 * Per-fd ownership table for AF_XDP UMEM mmap()s.
 *
 * Closing an AF_XDP fd releases the kernel-side umem registration but
 * does NOT munmap() the userspace VMA the caller allocated with mmap()
 * and registered via XDP_UMEM_REG.  The mapping persists for the life
 * of the process unless an explicit munmap() is issued.  Without that
 * matching unmap every XDP setup chain leaves behind a UMEM region
 * (16 pages for the grammar walker, 64 pages for the per-socket setup)
 * and a long-lived fuzzing child grows its VMA / RSS without bound.
 *
 * The record / release helpers below keep a small fd-keyed side table
 * of (ptr, len) pairs so the fd's close path can issue the matching
 * munmap() without having to plumb the pointer through every caller.
 * The side table is intentionally not part of the generic object
 * record so the shared obj heap stays free of family-specific fields.
 */

#ifdef USE_XDP

bool xdp_umem_record(int fd, void *ptr, size_t len);
void xdp_umem_release(int fd);

#else

static inline bool xdp_umem_record(int fd, void *ptr, size_t len)
{
	(void) fd;
	(void) ptr;
	(void) len;
	return false;
}

static inline void xdp_umem_release(int fd)
{
	(void) fd;
}

#endif /* USE_XDP */
