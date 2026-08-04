/*
 * psp-key-rotate-traffic - inner traffic + race loop carved out of
 * childops/net/psp-key-rotate.c.  Owns the mid-flow send/recv burst
 * against the assoc-bound TCP socket, the KEY_ROTATE + TX_ASSOC "spi
 * switch" race window that reruns on every inner iter, and the
 * randomised teardown that varies fd close order across iterations:
 *
 *   inner_traffic_burst              - non-blocking send + recv burst
 *                                      accounted into stats.send_ok;
 *   psp_key_rotate_iter_traffic      - the outer BUDGETED+JITTER loop
 *                                      that pairs each burst with a
 *                                      rotate + re-bind, wall-bounded
 *                                      by PKR_WALL_CAP_NS, ending in a
 *                                      single shutdown(SHUT_RDWR);
 *   psp_key_rotate_iter_teardown     - randomised close ordering of
 *                                      sockfd / psp_ctx / rtnl to vary
 *                                      teardown sequencing across
 *                                      iterations.
 *
 * The whole loop consumes the shared PSP genl context and dev_id
 * arrival-bound by the lifecycle setup; it never touches file-static
 * state and never opens or closes the underlying socket itself.  It
 * calls psp_key_rotate_cmd / psp_tx_assoc_cmd from the -cmd TU across
 * the TU boundary.
 */

#if __has_include(<linux/genetlink.h>) && \
	__has_include(<linux/if_link.h>) && \
	__has_include(<linux/rtnetlink.h>)

#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "childops-genl.h"
#include "childops-util.h"
#include "jitter.h"
#include "shm.h"

#include "psp-key-rotate-internal.h"

static void inner_traffic_burst(int sockfd)
{
	static const unsigned char payload[16] = { 0 };
	unsigned char rx[64];
	ssize_t r;

	r = send(sockfd, payload, sizeof(payload), MSG_DONTWAIT | MSG_NOSIGNAL);
	if (r > 0)
		__atomic_add_fetch(&shm->stats.psp_key_rotate.send_ok,
				   1, __ATOMIC_RELAXED);

	(void)recv(sockfd, rx, sizeof(rx), MSG_DONTWAIT);
}

/* Drive the inner traffic loop on the bound socket: BUDGETED+JITTER
 * iterations, each one send/recv burst -> PSP_CMD_KEY_ROTATE (race
 * target) -> PSP_CMD_TX_ASSOC re-bind -> second send/recv burst.  The
 * outer 200 ms wall-clock cap (PKR_WALL_CAP_NS) bounds the loop.  On
 * exit a single shutdown(SHUT_RDWR) flushes the socket. */
void psp_key_rotate_iter_traffic(int sockfd,
				 struct genl_ctx *psp_ctx,
				 uint32_t dev_id,
				 const struct timespec *t_outer,
				 unsigned long *dc)
{
	unsigned int inner, j;
	int rc;

	inner = JITTER_RANGE(PKR_OUTER_BASE);
	if (inner < PKR_OUTER_FLOOR)
		inner = PKR_OUTER_FLOOR;
	if (inner > PKR_OUTER_CAP)
		inner = PKR_OUTER_CAP;

	for (j = 0; j < inner; j++) {
		if ((unsigned long long)ns_since(t_outer) >= PKR_WALL_CAP_NS)
			break;

		inner_traffic_burst(sockfd);
		*dc += 2;		/* send() + recv() */

		/* RACE TARGET: rotate keys mid-flow. */
		rc = psp_key_rotate_cmd(psp_ctx, dev_id);
		*dc += 2;		/* genl_send_recv: sendmsg() + recv() */
		if (rc == 0)
			__atomic_add_fetch(&shm->stats.psp_key_rotate.rotate_ok,
					   1, __ATOMIC_RELAXED);

		/* Re-bind the assoc to the rotated generation mid-flow --
		 * "spi switch" per spec naming. */
		rc = psp_tx_assoc_cmd(psp_ctx, dev_id, sockfd);
		*dc += 2;		/* genl_send_recv: sendmsg() + recv() */
		if (rc == 0)
			__atomic_add_fetch(&shm->stats.psp_key_rotate.spi_switch_ok,
					   1, __ATOMIC_RELAXED);

		inner_traffic_burst(sockfd);
		*dc += 2;		/* send() + recv() */
	}

	(void)shutdown(sockfd, SHUT_RDWR);
	*dc += 1;			/* shutdown() */
	__atomic_add_fetch(&shm->stats.psp_key_rotate.shutdown_ok,
			   1, __ATOMIC_RELAXED);
}

/* Randomised teardown order: rotate which fd dies first so the
 * rtnl/genl/SOCK_STREAM teardown ordering varies across iterations.
 * nl_close() / genl_close() leave fd at -1, but iter_one's out:
 * cleanup runs only on the early-bail paths -- by the time this
 * helper is called the standard path is done and there is no
 * subsequent observer of sockfd, so the cases need not reset it. */
void psp_key_rotate_iter_teardown(unsigned int iter_idx, int sockfd,
				  struct genl_ctx *psp_ctx,
				  struct nl_ctx *rtnl,
				  unsigned long *dc)
{
	switch (iter_idx & 3U) {
	case 0:
		if (sockfd >= 0) close(sockfd);
		if (psp_ctx->nl.fd >= 0) genl_close(psp_ctx);
		if (rtnl->fd >= 0) nl_close(rtnl);
		break;
	case 1:
		if (psp_ctx->nl.fd >= 0) genl_close(psp_ctx);
		if (sockfd >= 0) close(sockfd);
		if (rtnl->fd >= 0) nl_close(rtnl);
		break;
	case 2:
		if (rtnl->fd >= 0) nl_close(rtnl);
		if (sockfd >= 0) close(sockfd);
		if (psp_ctx->nl.fd >= 0) genl_close(psp_ctx);
		break;
	default:
		if (sockfd >= 0) close(sockfd);
		if (rtnl->fd >= 0) nl_close(rtnl);
		if (psp_ctx->nl.fd >= 0) genl_close(psp_ctx);
		break;
	}
	/* close(sockfd) + genl_close (nl_close -> close) + nl_close (close). */
	*dc += 3;
}

#endif /* __has_include gate matches psp-key-rotate.c */
