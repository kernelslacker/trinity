#ifdef USE_XDP
#include <stddef.h>
#include <sys/mman.h>

#include "xdp-umem-track.h"

/*
 * 256 slots is plenty in practice: the per-process socket pool caps at
 * NR_SOCKET_FDS (50) and the per-family grammar walker only holds one
 * AF_XDP fd in flight at a time.  Trinity is fork-based, so each child
 * inherits its own COW copy of this table and no locking is needed.
 */
#define XDP_UMEM_SLOTS 256

struct xdp_umem_rec {
	int	fd;
	void	*ptr;
	size_t	len;
};

/*
 * Slots are empty when ptr == NULL.  The static zero-init leaves
 * fd == 0, which is a valid fd in principle, so all lookups gate on
 * ptr != NULL first before comparing fd.
 */
static struct xdp_umem_rec xdp_umem_table[XDP_UMEM_SLOTS];

bool xdp_umem_record(int fd, void *ptr, size_t len)
{
	int empty = -1;
	int i;

	if (fd < 0 || ptr == NULL || ptr == MAP_FAILED || len == 0)
		return false;

	for (i = 0; i < XDP_UMEM_SLOTS; i++) {
		if (xdp_umem_table[i].ptr == NULL) {
			if (empty < 0)
				empty = i;
			continue;
		}
		if (xdp_umem_table[i].fd == fd) {
			/*
			 * Stale record from a prior owner of this fd that
			 * never went through release (e.g. a setup path
			 * that failed before recording the new mapping but
			 * after the kernel handed the fd back).  Unmap the
			 * old pointer before overwriting so the prior VMA
			 * is not stranded.
			 */
			(void) munmap(xdp_umem_table[i].ptr,
				      xdp_umem_table[i].len);
			xdp_umem_table[i].ptr = ptr;
			xdp_umem_table[i].len = len;
			return true;
		}
	}

	if (empty < 0)
		return false;

	xdp_umem_table[empty].fd  = fd;
	xdp_umem_table[empty].ptr = ptr;
	xdp_umem_table[empty].len = len;
	return true;
}

void xdp_umem_release(int fd)
{
	int i;

	if (fd < 0)
		return;

	for (i = 0; i < XDP_UMEM_SLOTS; i++) {
		if (xdp_umem_table[i].ptr == NULL)
			continue;
		if (xdp_umem_table[i].fd != fd)
			continue;

		(void) munmap(xdp_umem_table[i].ptr, xdp_umem_table[i].len);
		/*
		 * Zero the slot so a recycled fd that lands on this row
		 * before the next xdp_umem_record() cannot trigger a
		 * double-munmap of an address the kernel has since
		 * handed back to another mmap() caller.
		 */
		xdp_umem_table[i].ptr = NULL;
		xdp_umem_table[i].len = 0;
		xdp_umem_table[i].fd  = -1;
		return;
	}
}

#endif /* USE_XDP */
