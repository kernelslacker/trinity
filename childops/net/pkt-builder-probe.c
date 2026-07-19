/*
 * pkt_builder_probe - childop-local prover for the layered packet
 * builder (include/pkt-builder.h + childops/net/pkt-builder.c).
 *
 * Purpose: exercise the composable stack-of-layers API from a real
 * childop before the consolidation batch that ports the existing
 * partial builders (eth-emitter, flowtable-encap-vlan,
 * bridge-vlan-churn, ipfrag-source-churn, recipe-net) onto it.  This
 * op is deliberately lightweight — it opens sockets once, stacks a
 * handful of small recipes per invocation, mutates + repairs + delivers
 * each, and self-latches off if AF_PACKET / RAW isn't available.
 *
 * The op picks from a fixed table of layer STACKS (recipes), not
 * random layer permutations, so the "the API assembles the shape we
 * asked for" invariant is trivially observable in per-stack stats.
 * Random permutation over the layer set is a later step; the point of
 * a prover is to fail loudly on wiring bugs, not to fuzz on top of
 * the API on its first day out.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "child.h"
#include "childops-util.h"
#include "pkt-builder.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"

#define PKTB_PROBE_PER_INVOCATION	6	/* frames per invocation */
#define PKTB_PROBE_WALL_CAP_NS		(50ULL * 1000ULL * 1000ULL)
#define PKTB_PROBE_NR_RECIPES		6

/*
 * Recipes: named layer stacks the prover assembles.  Each row lists
 * layers OUTERMOST-first.  The delivery path is implied by the outer
 * layer's manifest, so the same recipe fans out to whichever socket
 * class the manifest hard-wired.
 *
 *   ETH_IP4_UDP_VXLAN_ETH_IP4  — classic VXLAN encap, AF_PACKET.
 *   ETH_IP4_GRE_TEB_ETH_IP4    — gretap.
 *   IP4_GRE_TEB_ETH_IP4        — bare IPv4 outer, RAW_IPV4.
 *   ETH_VLAN_QINQ_IP4          — 802.1ad Q-in-Q over v4, AF_PACKET.
 *   ETH_IP6_UDP_GENEVE_ETH_IP6 — Geneve encap on v6, AF_PACKET.
 *   ETH_MPLS_IP4               — MPLS shim to IPv4, AF_PACKET.
 *
 * Each row is capped at PKTB_MAX_LAYERS.  A future extension can add
 * ESP / RPL_SRH recipes; two-stack Geneve/VXLAN + inner (eth, ip4) is
 * enough to prove the outer/inner discriminator patching.
 */
struct pktb_probe_recipe {
	const char *name;
	uint8_t     n;
	enum pktb_layer_kind layers[PKTB_MAX_LAYERS];
};

static const struct pktb_probe_recipe probe_recipes[PKTB_PROBE_NR_RECIPES] = {
	{
		.name = "vxlan_eth_ip4", .n = 6, .layers = {
			PKTB_LAYER_ETH, PKTB_LAYER_IP4, PKTB_LAYER_UDP_ENCAP,
			PKTB_LAYER_VXLAN, PKTB_LAYER_ETH, PKTB_LAYER_IP4,
		}
	},
	{
		.name = "gretap_eth_ip4", .n = 5, .layers = {
			PKTB_LAYER_ETH, PKTB_LAYER_IP4, PKTB_LAYER_GRE_TEB,
			PKTB_LAYER_ETH, PKTB_LAYER_IP4,
		}
	},
	{
		.name = "raw_ip4_gretap_ip4", .n = 4, .layers = {
			PKTB_LAYER_IP4, PKTB_LAYER_GRE_TEB,
			PKTB_LAYER_ETH, PKTB_LAYER_IP4,
		}
	},
	{
		.name = "qinq_ip4", .n = 3, .layers = {
			PKTB_LAYER_ETH, PKTB_LAYER_VLAN_DOUBLE, PKTB_LAYER_IP4,
		}
	},
	{
		.name = "geneve_v6_eth_ip6", .n = 6, .layers = {
			PKTB_LAYER_ETH, PKTB_LAYER_IP6, PKTB_LAYER_UDP_ENCAP,
			PKTB_LAYER_GENEVE, PKTB_LAYER_ETH, PKTB_LAYER_IP6,
		}
	},
	{
		.name = "mpls_ip4", .n = 3, .layers = {
			PKTB_LAYER_ETH, PKTB_LAYER_MPLS, PKTB_LAYER_IP4,
		}
	},
};

/* One-shot per-child latches. */
static bool pktb_probe_self_check_ran;
static bool pktb_probe_self_check_ok;
static bool pktb_probe_disabled;
static bool pktb_probe_warned_disabled;

/*
 * Assemble one recipe into the frame, mutate + repair, and deliver.
 * Returns 0 on any send success, -1 on send failure, -2 on build
 * failure (recipe rejected by the builder), -3 on permanent
 * delivery-disabled latch.
 */
static int probe_one_recipe(struct pktb_ctx *ctx,
			    const struct pktb_probe_recipe *r)
{
	struct pktb_frame frame;
	uint8_t li;
	bool truncate_this;
	int rc;

	pktb_frame_init(&frame);
	for (li = 0; li < r->n; li++) {
		if (!pktb_push(&frame, r->layers[li])) {
			__atomic_add_fetch(&shm->stats.pkt_builder.build_failed,
					   1, __ATOMIC_RELAXED);
			return -2;
		}
	}
	__atomic_add_fetch(&shm->stats.pkt_builder.built_ok, 1, __ATOMIC_RELAXED);

	truncate_this = ONE_IN(4);
	pktb_mutate_and_repair(&frame, truncate_this);
	if (truncate_this)
		__atomic_add_fetch(&shm->stats.pkt_builder.truncated,
				   1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.pkt_builder.mutated, 1, __ATOMIC_RELAXED);

	rc = pktb_deliver(ctx, &frame);
	if (rc > 0) {
		__atomic_add_fetch(&shm->stats.pkt_builder.delivered_ok,
				   1, __ATOMIC_RELAXED);
		return 0;
	}
	if (rc == -3) {
		__atomic_add_fetch(&shm->stats.pkt_builder.delivery_disabled,
				   1, __ATOMIC_RELAXED);
		return -3;
	}
	__atomic_add_fetch(&shm->stats.pkt_builder.delivery_failed,
			   1, __ATOMIC_RELAXED);
	return -1;
}

bool pkt_builder_probe(struct childdata *child)
{
	struct pktb_ctx ctx;
	struct timespec t0;
	unsigned int i;
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	__atomic_add_fetch(&shm->stats.pkt_builder.runs, 1, __ATOMIC_RELAXED);

	if (!pktb_probe_self_check_ran) {
		pktb_probe_self_check_ok = pktb_self_check();
		pktb_probe_self_check_ran = true;
	}
	if (!pktb_probe_self_check_ok) {
		__atomic_add_fetch(&shm->stats.pkt_builder.setup_failed,
				   1, __ATOMIC_RELAXED);
		if (valid_op)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_INIT_FAILED,
					 __ATOMIC_RELAXED);
		return true;
	}

	if (pktb_probe_disabled) {
		__atomic_add_fetch(&shm->stats.pkt_builder.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	pktb_ctx_init(&ctx);
	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	}
	if (clock_gettime(CLOCK_MONOTONIC, &t0) < 0) {
		t0.tv_sec  = 0;
		t0.tv_nsec = 0;
	}

	for (i = 0; i < PKTB_PROBE_PER_INVOCATION; i++) {
		unsigned int pick = rnd_modulo_u32(PKTB_PROBE_NR_RECIPES);
		int rc;

		if (budget_elapsed_ns(&t0, (long)PKTB_PROBE_WALL_CAP_NS))
			break;

		rc = probe_one_recipe(&ctx, &probe_recipes[pick]);
		if (rc == 0)
			__atomic_add_fetch(&shm->stats.pkt_builder.per_recipe[pick],
					   1, __ATOMIC_RELAXED);
		if (rc == -3) {
			pktb_probe_disabled = true;
			if (!pktb_probe_warned_disabled) {
				pktb_probe_warned_disabled = true;
				/* check-static: child-output-ok */
				outputerr("pkt_builder_probe: raw socket setup refused (errno=%d), latching off\n",
					  errno);
			}
			if (valid_op)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_NS_UNSUPPORTED,
						 __ATOMIC_RELAXED);
			break;
		}
	}

	pktb_ctx_close(&ctx);
	return true;
}
