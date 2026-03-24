#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>
#include <linux/if_xdp.h>
#include "net.h"
#include "random.h"
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

	xdp->sxdp_ifindex = rand() % 4;	/* 0=invalid, 1=lo, 2-3=maybe eth */
	xdp->sxdp_queue_id = rand() % 8;
	xdp->sxdp_shared_umem_fd = rand() % 16;

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
	.gen_sockaddr = xdp_gen_sockaddr,
	.setsockopt = xdp_setsockopt,
	.valid_triplets = xdp_triplet,
	.nr_triplets = ARRAY_SIZE(xdp_triplet),
};
