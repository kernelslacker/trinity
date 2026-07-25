/*
 * bridge_fdb_stp - receive-path traffic burst.
 *
 * Opens the AF_PACKET raw socket on the first surviving port, sprays
 * a bounded burst of broadcast frames with random locally-administered
 * unicast src MACs to drive br_fdb_update via the receive path, then
 * races an RTM_DELNEIGH against the rx-driven learning that may be
 * re-installing the last src.  The bridge-flooded broadcast
 * destination guarantees the bridge ingress hook sees every frame
 * regardless of fdb state; the random src is what triggers the
 * learn-on-rx path the op exists to exercise.  Wall-cap
 * STORM_BUDGET_NS holds the inner send loop well inside the
 * SIGALRM(1s) child cap.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>

#include <linux/if_ether.h>
#include <linux/if_packet.h>

#include "child.h"
#include "childops-netlink.h"
#include "jitter.h"
#include "shm.h"
#include "trinity.h"

#include "kernel/socket.h"

#include "bridge-fdb-stp-internal.h"

/*
 * Phase 4: open the AF_PACKET raw socket on the first surviving port,
 * spray a bounded burst of broadcast frames with random
 * locally-administered unicast src MACs to drive br_fdb_update via the
 * receive path, then race an RTM_DELNEIGH against the rx-driven
 * learning that may be re-installing the last src.  The bridge-flooded
 * broadcast destination guarantees the bridge ingress hook sees every
 * frame regardless of fdb state; the random src is what triggers the
 * learn-on-rx path the op exists to exercise.  Wall-cap STORM_BUDGET_NS
 * holds the inner send loop well inside the SIGALRM(1s) child cap; the
 * raw socket open / bind failures degrade gracefully — there's no
 * targeted race left to run if the raw fd is missing, so we just skip.
 */
void bridge_fdb_stp_iter_traffic_burst(struct bridge_fdb_stp_iter_ctx *ctx)
{
	unsigned char last_src_mac[6] = { 0 };
	bool have_last_mac = false;
	struct timespec t0;
	unsigned int iters, i, j;
	int tx_port_idx = 0;

	for (j = 0; j < 4; j++) {
		if (ctx->port_idx[j] > 0) {
			tx_port_idx = ctx->port_idx[j];
			break;
		}
	}
	if (tx_port_idx <= 0)
		return;

	ctx->raw = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC,
			  htons(ETH_P_ALL));
	if (ctx->raw >= 0) {
		struct sockaddr_ll sll;

		memset(&sll, 0, sizeof(sll));
		sll.sll_family   = AF_PACKET;
		sll.sll_protocol = htons(ETH_P_ALL);
		sll.sll_ifindex  = tx_port_idx;
		(void)bind(ctx->raw, (struct sockaddr *)&sll, sizeof(sll));
	}

	if (ctx->raw >= 0) {
		(void)clock_gettime(CLOCK_MONOTONIC, &t0);
		iters = BUDGETED(CHILD_OP_BRIDGE_FDB_STP,
				 JITTER_RANGE(BRIDGE_PACKET_BASE));
		if (iters < BRIDGE_PACKET_FLOOR)
			iters = BRIDGE_PACKET_FLOOR;
		if (iters > BRIDGE_PACKET_CAP)
			iters = BRIDGE_PACKET_CAP;

		for (i = 0; i < iters; i++) {
			struct sockaddr_ll sll;
			unsigned char frame[64];
			unsigned char dst_mac[6];
			unsigned char src_mac[6];
			ssize_t n;

			if (ns_since(&t0) >= STORM_BUDGET_NS)
				break;

			/* Random locally-administered unicast src;
			 * deterministic broadcast dst so the bridge floods
			 * the frame and the src triggers br_fdb_update on
			 * ingress. */
			random_unicast_lla(src_mac);
			memset(dst_mac, 0xff, sizeof(dst_mac));

			memset(frame, 0, sizeof(frame));
			memcpy(frame + 0, dst_mac, 6);
			memcpy(frame + 6, src_mac, 6);
			frame[12] = 0x08;	/* ETH_P_IP */
			frame[13] = 0x00;
			/* payload is zeros — the bridge doesn't parse
			 * upper layers for the learning-on-rx path. */

			memset(&sll, 0, sizeof(sll));
			sll.sll_family   = AF_PACKET;
			sll.sll_protocol = htons(ETH_P_ALL);
			sll.sll_ifindex  = tx_port_idx;
			sll.sll_halen    = 6;
			memcpy(sll.sll_addr, dst_mac, 6);

			n = sendto(ctx->raw, frame, sizeof(frame),
				   MSG_DONTWAIT,
				   (struct sockaddr *)&sll, sizeof(sll));
			if (n > 0) {
				__atomic_add_fetch(&shm->stats.bridge_fdb_stp.raw_send_ok,
						   1, __ATOMIC_RELAXED);
				memcpy(last_src_mac, src_mac,
				       sizeof(last_src_mac));
				have_last_mac = true;
			}
		}
	}

	/* fdb DELNEIGH on the most-recently-sent src mac races the
	 * rx-driven learning that may be re-installing it.  Use the
	 * same port we sent on. */
	if (have_last_mac) {
		if (build_fdb_del(&ctx->ctx, tx_port_idx, last_src_mac) == 0)
			__atomic_add_fetch(&shm->stats.bridge_fdb_stp.fdb_del_ok,
					   1, __ATOMIC_RELAXED);
	}
}
