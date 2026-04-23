#ifdef USE_XDP
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <string.h>
#include <linux/if_xdp.h>
#include "net.h"
#include "random.h"
#include "utils.h"
#include "compat.h"

#ifndef SOL_XDP
#define SOL_XDP 283
#endif

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

#define XDP_UMEM_SIZE	(4096 * 64)
#define XDP_NUM_FRAMES	64
#define XDP_FRAME_SIZE	4096
#define XDP_RING_SIZE	64

/*
 * Set up the full XDP lifecycle on fd:
 * 1. Allocate UMEM via anonymous mmap
 * 2. Register UMEM via XDP_UMEM_REG setsockopt
 * 3. Set ring sizes for fill, completion, rx, tx
 * 4. Query mmap offsets via XDP_MMAP_OFFSETS getsockopt
 * 5. mmap each ring
 */
static void xdp_socket_setup(int fd)
{
	struct xdp_umem_reg reg;
	struct xdp_mmap_offsets offsets;
	socklen_t optlen;
	int ring_size = XDP_RING_SIZE;
	void *umem_area;
	void *map;

	/* 1. Allocate UMEM area */
	umem_area = mmap(NULL, XDP_UMEM_SIZE, PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (umem_area == MAP_FAILED)
		return;
	track_shared_region((unsigned long)umem_area, XDP_UMEM_SIZE);

	/* 2. Register UMEM */
	memset(&reg, 0, sizeof(reg));
	reg.addr = (unsigned long long) umem_area;
	reg.len = XDP_UMEM_SIZE;
	reg.chunk_size = XDP_FRAME_SIZE;
	reg.headroom = 0;
	reg.flags = 0;
	if (setsockopt(fd, SOL_XDP, XDP_UMEM_REG, &reg, sizeof(reg)) == -1)
		goto out_unmap_umem;

	/* 3. Set ring sizes */
	if (setsockopt(fd, SOL_XDP, XDP_UMEM_FILL_RING, &ring_size, sizeof(ring_size)) == -1)
		goto out_unmap_umem;
	if (setsockopt(fd, SOL_XDP, XDP_UMEM_COMPLETION_RING, &ring_size, sizeof(ring_size)) == -1)
		goto out_unmap_umem;
	if (setsockopt(fd, SOL_XDP, XDP_RX_RING, &ring_size, sizeof(ring_size)) == -1)
		goto out_unmap_umem;
	if (setsockopt(fd, SOL_XDP, XDP_TX_RING, &ring_size, sizeof(ring_size)) == -1)
		goto out_unmap_umem;

	/* 4. Query mmap offsets */
	optlen = sizeof(offsets);
	if (getsockopt(fd, SOL_XDP, XDP_MMAP_OFFSETS, &offsets, &optlen) == -1)
		goto out_unmap_umem;

	/* 5. mmap each ring — these will likely fail without a real
	 * netdev, but we exercise the kernel mmap paths regardless. */
	map = mmap(NULL, offsets.rx.desc + XDP_RING_SIZE * sizeof(__u64),
		   PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
		   fd, XDP_PGOFF_RX_RING);
	if (map != MAP_FAILED)
		munmap(map, offsets.rx.desc + XDP_RING_SIZE * sizeof(__u64));

	map = mmap(NULL, offsets.tx.desc + XDP_RING_SIZE * sizeof(__u64),
		   PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
		   fd, XDP_PGOFF_TX_RING);
	if (map != MAP_FAILED)
		munmap(map, offsets.tx.desc + XDP_RING_SIZE * sizeof(__u64));

	map = mmap(NULL, offsets.fr.desc + XDP_RING_SIZE * sizeof(__u64),
		   PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
		   fd, XDP_UMEM_PGOFF_FILL_RING);
	if (map != MAP_FAILED)
		munmap(map, offsets.fr.desc + XDP_RING_SIZE * sizeof(__u64));

	map = mmap(NULL, offsets.cr.desc + XDP_RING_SIZE * sizeof(__u64),
		   PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
		   fd, XDP_UMEM_PGOFF_COMPLETION_RING);
	if (map != MAP_FAILED)
		munmap(map, offsets.cr.desc + XDP_RING_SIZE * sizeof(__u64));

	/* Leave UMEM mapped — the kernel holds a reference while the
	 * socket is alive.  It gets cleaned up when the fd closes. */
	return;

out_unmap_umem:
	munmap(umem_area, XDP_UMEM_SIZE);
}

static void xdp_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_xdp *xdp;

	xdp = zmalloc(sizeof(struct sockaddr_xdp));

	xdp->sxdp_family = PF_XDP;

	/* Flags: various combinations of copy/zerocopy/shared/sg */
	switch (rand() % 6) {
	case 0: xdp->sxdp_flags = 0; break;
	case 1: xdp->sxdp_flags = XDP_COPY; break;
	case 2: xdp->sxdp_flags = XDP_ZEROCOPY; break;
	case 3: xdp->sxdp_flags = XDP_SHARED_UMEM; break;
	case 4: xdp->sxdp_flags = XDP_USE_NEED_WAKEUP; break;
	case 5: xdp->sxdp_flags = rand() & 0x1f; break;
	}

	xdp->sxdp_ifindex = rand() % 512;
	xdp->sxdp_queue_id = rand() % 256;
	xdp->sxdp_shared_umem_fd = rand() % 1024;

	*addr = (struct sockaddr *) xdp;
	*addrlen = sizeof(struct sockaddr_xdp);
}

static const unsigned int xdp_opts[] = {
	XDP_RX_RING, XDP_TX_RING,
	XDP_UMEM_REG, XDP_UMEM_FILL_RING, XDP_UMEM_COMPLETION_RING,
};

static void xdp_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	so->level = SOL_XDP;
	so->optname = RAND_ARRAY(xdp_opts);

	switch (so->optname) {
	case XDP_RX_RING:
	case XDP_TX_RING:
	case XDP_UMEM_FILL_RING:
	case XDP_UMEM_COMPLETION_RING: {
		/* Ring size — must be power of 2 */
		int *optval32 = (int *) so->optval;

		switch (rand() % 5) {
		case 0: *optval32 = 0; break;
		case 1: *optval32 = 64; break;
		case 2: *optval32 = 2048; break;
		case 3: *optval32 = 4096; break;
		case 4: *optval32 = 1 << (rand() % 16); break;
		}
		so->optlen = sizeof(int);
		break;
	}

	case XDP_UMEM_REG: {
		struct xdp_umem_reg *reg = (struct xdp_umem_reg *) so->optval;

		memset(reg, 0, sizeof(struct xdp_umem_reg));
		reg->addr = 0;	/* Will be an invalid addr, exercises error paths */
		switch (rand() % 3) {
		case 0: reg->len = 4096; break;
		case 1: reg->len = 4096 * 64; break;
		case 2: reg->len = rand(); break;
		}
		switch (rand() % 3) {
		case 0: reg->chunk_size = 2048; break;
		case 1: reg->chunk_size = 4096; break;
		case 2: reg->chunk_size = rand() % 8192 + 1; break;
		}
		reg->headroom = rand() % 256;
		reg->flags = rand() & 0x7;
		so->optlen = sizeof(struct xdp_umem_reg);
		break;
	}

	default:
		break;
	}
}

static struct socket_triplet xdp_triplet[] = {
	{ .family = PF_XDP, .protocol = 0, .type = SOCK_RAW },
};

const struct netproto proto_xdp = {
	.name = "xdp",
	.socket_setup = xdp_socket_setup,
	.gen_sockaddr = xdp_gen_sockaddr,
	.setsockopt = xdp_setsockopt,
	.valid_triplets = xdp_triplet,
	.nr_triplets = ARRAY_SIZE(xdp_triplet),
};
#endif /* USE_XDP */
