#ifdef USE_XDP
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <string.h>
#include <unistd.h>
#include "kernel/if_xdp.h"
#include "net.h"
#include "random.h"
#include "socket-family-grammar.h"
#include "utils.h"
#include "compat.h"
#include "rnd.h"
#include "xdp-umem-track.h"

#include "kernel/socket.h"
#define XDP_UMEM_SIZE	(4096 * 64)
#define XDP_NUM_FRAMES	64
#define XDP_FRAME_SIZE	4096
#define XDP_RING_SIZE	64

/*
 * Compute mmap length for an XDP ring as desc_off + entries * entry_sz.
 * Returns false on wrap from the kernel-supplied desc_off or the
 * multiplication so a short/corrupt XDP_MMAP_OFFSETS reply can't drive
 * a bogus mmap (and matching bogus munmap) length.
 */
static bool xdp_ring_mmap_size(__u64 desc_off, size_t entries,
			       size_t entry_sz, size_t *out)
{
	size_t prod;

	if (__builtin_mul_overflow(entries, entry_sz, &prod))
		return false;
	if (__builtin_add_overflow((size_t)desc_off, prod, out))
		return false;
	return true;
}

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
	size_t map_sz;
	int ring_size = XDP_RING_SIZE;
	void *umem_area;
	void *map;

	/* 1. Allocate UMEM area */
	umem_area = mmap(NULL, XDP_UMEM_SIZE, PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (umem_area == MAP_FAILED)
		return;

	/*
	 * Record ownership of the UMEM mapping against the fd up front,
	 * before any setsockopt that may fail and short-circuit setup.
	 * The matching unmap is issued from the fd close path; the
	 * out_unmap_umem error label still tears the mapping down
	 * directly for now.
	 */
	(void) xdp_umem_record(fd, umem_area, XDP_UMEM_SIZE);

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

	/* 4. Query mmap offsets.  Zero first so a short getsockopt leaves
	 * known state, then require the full struct came back before we
	 * trust any of its fields. */
	memset(&offsets, 0, sizeof(offsets));
	optlen = sizeof(offsets);
	if (getsockopt(fd, SOL_XDP, XDP_MMAP_OFFSETS, &offsets, &optlen) == -1)
		goto out_unmap_umem;
	if (optlen < sizeof(offsets))
		goto out_unmap_umem;

	/* 5. mmap each ring — these will likely fail without a real
	 * netdev, but we exercise the kernel mmap paths regardless. */
	if (xdp_ring_mmap_size(offsets.rx.desc, XDP_RING_SIZE,
			       sizeof(__u64), &map_sz)) {
		map = mmap(NULL, map_sz, PROT_READ | PROT_WRITE,
			   MAP_SHARED | MAP_POPULATE, fd, XDP_PGOFF_RX_RING);
		if (map != MAP_FAILED)
			munmap(map, map_sz);
	}

	if (xdp_ring_mmap_size(offsets.tx.desc, XDP_RING_SIZE,
			       sizeof(__u64), &map_sz)) {
		map = mmap(NULL, map_sz, PROT_READ | PROT_WRITE,
			   MAP_SHARED | MAP_POPULATE, fd, XDP_PGOFF_TX_RING);
		if (map != MAP_FAILED)
			munmap(map, map_sz);
	}

	if (xdp_ring_mmap_size(offsets.fr.desc, XDP_RING_SIZE,
			       sizeof(__u64), &map_sz)) {
		map = mmap(NULL, map_sz, PROT_READ | PROT_WRITE,
			   MAP_SHARED | MAP_POPULATE, fd,
			   XDP_UMEM_PGOFF_FILL_RING);
		if (map != MAP_FAILED)
			munmap(map, map_sz);
	}

	if (xdp_ring_mmap_size(offsets.cr.desc, XDP_RING_SIZE,
			       sizeof(__u64), &map_sz)) {
		map = mmap(NULL, map_sz, PROT_READ | PROT_WRITE,
			   MAP_SHARED | MAP_POPULATE, fd,
			   XDP_UMEM_PGOFF_COMPLETION_RING);
		if (map != MAP_FAILED)
			munmap(map, map_sz);
	}

	/*
	 * Leave UMEM mapped here — ownership has been handed to the
	 * fd-keyed table by the xdp_umem_record() call above, so the
	 * matching munmap() is issued from the socket destructor when
	 * the fd is closed.  Closing the fd alone only releases the
	 * kernel-side umem registration; the userspace VMA persists
	 * until an explicit munmap().
	 */
	return;

out_unmap_umem:
	/*
	 * Partial setup failure: the UMEM was mmap'd and recorded
	 * before the failing setsockopt, so route the cleanup through
	 * xdp_umem_release() rather than a bare munmap().  That tears
	 * down the VMA AND clears the table slot in one step so the
	 * later socket destructor cannot revisit a stale (fd, ptr) row
	 * whose address may by then have been reused by another mmap().
	 */
	xdp_umem_release(fd);
}

static void xdp_gen_sockaddr(__unused__ struct socket_triplet *triplet, struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_xdp *xdp;

	xdp = zmalloc_tracked(sizeof(struct sockaddr_xdp));

	xdp->sxdp_family = PF_XDP;

	/* Flags: various combinations of copy/zerocopy/shared/sg */
	switch (rnd_modulo_u32(6)) {
	case 0: xdp->sxdp_flags = 0; break;
	case 1: xdp->sxdp_flags = XDP_COPY; break;
	case 2: xdp->sxdp_flags = XDP_ZEROCOPY; break;
	case 3: xdp->sxdp_flags = XDP_SHARED_UMEM; break;
	case 4: xdp->sxdp_flags = XDP_USE_NEED_WAKEUP; break;
	case 5: xdp->sxdp_flags = rnd_u32() & 0x1f; break;
	}

	xdp->sxdp_ifindex = rnd_modulo_u32(512);
	xdp->sxdp_queue_id = rnd_modulo_u32(256);
	xdp->sxdp_shared_umem_fd = rnd_modulo_u32(1024);

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

		switch (rnd_modulo_u32(5)) {
		case 0: *optval32 = 0; break;
		case 1: *optval32 = 64; break;
		case 2: *optval32 = 2048; break;
		case 3: *optval32 = 4096; break;
		case 4: *optval32 = 1 << (rnd_modulo_u32(16)); break;
		}
		so->optlen = sizeof(int);
		break;
	}

	case XDP_UMEM_REG: {
		struct xdp_umem_reg *reg = (struct xdp_umem_reg *) so->optval;

		memset(reg, 0, sizeof(struct xdp_umem_reg));
		reg->addr = 0;	/* Will be an invalid addr, exercises error paths */
		switch (rnd_modulo_u32(3)) {
		case 0: reg->len = 4096; break;
		case 1: reg->len = 4096 * 64; break;
		case 2: reg->len = rnd_u32(); break;
		}
		switch (rnd_modulo_u32(3)) {
		case 0: reg->chunk_size = 2048; break;
		case 1: reg->chunk_size = 4096; break;
		case 2: reg->chunk_size = rnd_modulo_u32(8192) + 1; break;
		}
		reg->headroom = rnd_modulo_u32(256);
		reg->flags = rnd_u32() & 0x7;
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

/*
 * grammar_xdp — coherent walk for AF_XDP driven by the per-family
 * grammar dispatcher (net/socket-family-grammar.c).
 *
 * walk_setsockopts walks the canonical UMEM/ring setup
 * (XDP_UMEM_REG → fill ring → completion ring → RX_RING → TX_RING)
 * but deliberately churns the order — half the time RX_RING lands
 * BEFORE XDP_UMEM_REG so the kernel's xsk_setsockopt ordering check
 * runs against an unregistered umem.  The other half walks the
 * canonical order so the success path also gets coverage on the
 * same fd that just registered the umem.
 *
 * The umem is mmap'd at 64 * 4096 == 16 pages, the smallest size
 * the kernel will accept with chunk_size 4096 and frame headroom 0.
 * Ownership is recorded against fd via xdp_umem_record() so the
 * grammar dispatcher's close path can issue the matching munmap();
 * the AF_XDP fd close on its own only releases the kernel-side umem
 * registration, the userspace VMA persists until munmap().
 * bind_or_connect uses sxdp_ifindex of "lo" with
 * a random sxdp_flags; bind() is expected to fail on lo with most
 * flag combinations and EOPNOTSUPP / EINVAL is swallowed by the
 * framework's err_burst counter rather than latching the family.
 *
 * data_leg stays NULL — XDP doesn't drive sendmsg through this
 * path; packets flow through the rings instead.  needs_listen_accept
 * is also false.  can_run probes socket(AF_XDP, SOCK_RAW, 0) and
 * latches off on ENOSYS / EPROTONOSUPPORT for kernels without
 * CONFIG_XDP_SOCKETS.
 */

#define XDP_GRAMMAR_UMEM_PAGES		16
#define XDP_GRAMMAR_UMEM_BYTES		(XDP_GRAMMAR_UMEM_PAGES * 4096)
#define XDP_GRAMMAR_RING_SIZE		64

static bool xdp_grammar_can_run(void)
{
	int fd;

	fd = socket(AF_XDP, SOCK_RAW, 0);
	if (fd < 0)
		return false;
	close(fd);
	return true;
}

static void xdp_grammar_pick_triplet(struct socket_triplet *out)
{
	out->family = AF_XDP;
	out->type = SOCK_RAW;
	out->protocol = 0;
}

static void xdp_grammar_configure_pre_bind(int fd, struct socket_triplet *t)
{
	int flags;

	(void) t;
	flags = fcntl(fd, F_GETFL, 0);
	if (flags >= 0)
		(void) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int xdp_grammar_bind(int fd, struct socket_triplet *t)
{
	struct sockaddr_xdp xdp;
	unsigned int ifindex;

	(void) t;

	memset(&xdp, 0, sizeof(xdp));
	xdp.sxdp_family = AF_XDP;
	ifindex = if_nametoindex("lo");
	xdp.sxdp_ifindex = ifindex;
	xdp.sxdp_queue_id = 0;
	switch (rnd_modulo_u32(4)) {
	case 0:	xdp.sxdp_flags = 0; break;
	case 1: xdp.sxdp_flags = XDP_USE_NEED_WAKEUP; break;
	case 2: xdp.sxdp_flags = XDP_COPY; break;
	case 3: xdp.sxdp_flags = XDP_ZEROCOPY; break;
	}

	/* bind() likely fails on lo with most flag combinations.
	 * Swallow EOPNOTSUPP / EINVAL gracefully — the kernel paths
	 * we wanted to walk already ran via walk_setsockopts. */
	if (bind(fd, (struct sockaddr *) &xdp, sizeof(xdp)) < 0) {
		if (errno == EOPNOTSUPP || errno == EINVAL ||
		    errno == ENODEV)
			return 0;
		return -1;
	}
	return 0;
}

static bool xdp_grammar_needs_listen_accept(struct socket_triplet *t)
{
	(void) t;
	return false;
}

static void *xdp_grammar_alloc_umem(void)
{
	void *area;

	area = mmap(NULL, XDP_GRAMMAR_UMEM_BYTES, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (area == MAP_FAILED)
		return NULL;
	return area;
}

static void xdp_grammar_set_ring(int fd, int optname)
{
	int sz = XDP_GRAMMAR_RING_SIZE;

	(void) setsockopt(fd, SOL_XDP, optname, &sz, sizeof(sz));
}

static void xdp_grammar_register_umem(int fd, void *area)
{
	struct xdp_umem_reg reg;

	memset(&reg, 0, sizeof(reg));
	reg.addr = (unsigned long long) area;
	reg.len = XDP_GRAMMAR_UMEM_BYTES;
	reg.chunk_size = 4096;
	reg.headroom = 0;
	reg.flags = 0;
	(void) setsockopt(fd, SOL_XDP, XDP_UMEM_REG, &reg, sizeof(reg));
}

static void xdp_grammar_walk_setsockopts(int fd, struct socket_triplet *t,
					 unsigned int n)
{
	void *area;
	bool churn_order = RAND_BOOL();
	unsigned int step = 0;

	(void) t;

	area = xdp_grammar_alloc_umem();
	if (area == NULL)
		return;

	/*
	 * Record ownership against the AF_XDP fd so the dispatcher's
	 * close path can issue the matching munmap().  Without this the
	 * VMA persists for the life of the long-lived fuzz child and
	 * every grammar invocation adds another 16-page region.
	 */
	(void) xdp_umem_record(fd, area, XDP_GRAMMAR_UMEM_BYTES);

	if (churn_order) {
		/* Out-of-order: install RX ring before UMEM_REG so the
		 * kernel's ordering check rejects the call.  Then install
		 * UMEM_REG and the rest of the canonical walk to also
		 * exercise the success path in the same chain. */
		if (step++ < n)
			xdp_grammar_set_ring(fd, XDP_RX_RING);
		if (step++ < n)
			xdp_grammar_register_umem(fd, area);
		if (step++ < n)
			xdp_grammar_set_ring(fd, XDP_UMEM_FILL_RING);
		if (step++ < n)
			xdp_grammar_set_ring(fd, XDP_UMEM_COMPLETION_RING);
		if (step++ < n)
			xdp_grammar_set_ring(fd, XDP_TX_RING);
	} else {
		if (step++ < n)
			xdp_grammar_register_umem(fd, area);
		if (step++ < n)
			xdp_grammar_set_ring(fd, XDP_UMEM_FILL_RING);
		if (step++ < n)
			xdp_grammar_set_ring(fd, XDP_UMEM_COMPLETION_RING);
		if (step++ < n)
			xdp_grammar_set_ring(fd, XDP_RX_RING);
		if (step++ < n)
			xdp_grammar_set_ring(fd, XDP_TX_RING);
	}

	/*
	 * Leave the umem mapped here — ownership was recorded against
	 * fd via xdp_umem_record() above, so the dispatcher's close
	 * path will issue the matching munmap() when this grammar pass
	 * returns.
	 */
}

const struct socket_family_grammar grammar_xdp = {
	.family			= AF_XDP,
	.name			= "xdp",
	.can_run		= xdp_grammar_can_run,
	.pick_triplet		= xdp_grammar_pick_triplet,
	.configure_pre_bind	= xdp_grammar_configure_pre_bind,
	.bind_or_connect	= xdp_grammar_bind,
	.walk_setsockopts	= xdp_grammar_walk_setsockopts,
	.needs_listen_accept	= xdp_grammar_needs_listen_accept,
};
#endif /* USE_XDP */
