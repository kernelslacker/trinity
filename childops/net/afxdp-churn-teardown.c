/*
 * afxdp-churn-teardown: init / teardown for the per-iter xsk_state.
 *
 * Kept in its own TU because the teardown reverses everything the
 * setup / attach / io TUs did — closing fds, munmap'ing rings + UMEM,
 * running the netlink-attach reverse via xdp_netlink_set_fd(prog_fd=-1)
 * — and iter_one runs it unconditionally on every early-out path.
 * Splitting it out keeps that lifecycle in one obvious place.
 *
 *   xsk_init      — zero the struct, -1 the fd fields, MAP_FAILED
 *                   the mmap slots so a partial-setup teardown never
 *                   touches an uninitialised fd or address.
 *   xsk_teardown  — mirror image: BPF link fd first (auto-detach on
 *                   close), then netlink-attached prog if any, then
 *                   the four ring mmaps and the UMEM, then the raw
 *                   fds (xsk / prog / map / tun).
 */

#if __has_include(<linux/if_xdp.h>) && __has_include(<linux/bpf.h>)

#include "afxdp-churn-internal.h"

void xsk_init(struct xsk_state *st)
{
	memset(st, 0, sizeof(*st));
	st->xsk_fd      = -1;
	st->map_fd      = -1;
	st->prog_fd     = -1;
	st->xdp_link_fd = -1;
	st->rtnl.fd     = -1;
	st->tun_fd      = -1;
	st->umem    = MAP_FAILED;
	st->rx_ring = MAP_FAILED;
	st->tx_ring = MAP_FAILED;
	st->fr_ring = MAP_FAILED;
	st->cr_ring = MAP_FAILED;
}

void xsk_teardown(struct xsk_state *st)
{
	/* Detach order: BPF link first (auto-detaches on close), then any
	 * netlink-attached prog (explicit RTM_NEWLINK with prog_fd=-1 in
	 * SKB mode), then close prog/map fds. */
	if (st->xdp_link_fd >= 0)
		close(st->xdp_link_fd);
	if (st->nl_attached_ifindex && st->rtnl.fd >= 0)
		(void)xdp_netlink_set_fd(&st->rtnl,
					 st->nl_attached_ifindex, -1);
	if (st->rtnl.fd >= 0)
		nl_close(&st->rtnl);
	if (st->fr_ring != MAP_FAILED && st->fr_ring_sz)
		(void)munmap(st->fr_ring, st->fr_ring_sz);
	if (st->cr_ring != MAP_FAILED && st->cr_ring_sz)
		(void)munmap(st->cr_ring, st->cr_ring_sz);
	if (st->rx_ring != MAP_FAILED && st->rx_ring_sz)
		(void)munmap(st->rx_ring, st->rx_ring_sz);
	if (st->tx_ring != MAP_FAILED && st->tx_ring_sz)
		(void)munmap(st->tx_ring, st->tx_ring_sz);
	if (st->umem != MAP_FAILED)
		(void)munmap(st->umem, AFXDP_UMEM_BYTES);
	if (st->xsk_fd  >= 0) close(st->xsk_fd);
	if (st->prog_fd >= 0) close(st->prog_fd);
	if (st->map_fd  >= 0) close(st->map_fd);
	if (st->tun_fd  >= 0) close(st->tun_fd);
}

#endif /* __has_include(<linux/if_xdp.h>) && __has_include(<linux/bpf.h>) */
