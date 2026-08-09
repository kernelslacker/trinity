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
#include <fcntl.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "child.h"
#include "childop-outcome.h"
#include "childops-netlink.h"
#include "childops-util.h"
#include "pkt-builder.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"
#include "userns-bootstrap.h"
#include "utils.h"

#define PKTB_PROBE_PER_INVOCATION	6	/* frames per invocation */
#define PKTB_PROBE_WALL_CAP_NS		(50ULL * 1000ULL * 1000ULL)
#define PKTB_PROBE_NR_RECIPES		10
_Static_assert(PKTB_PROBE_NR_RECIPES <=
	       ARRAY_SIZE(((struct pkt_builder_stats *)0)->per_recipe),
	       "per_recipe[] too small for PKTB_PROBE_NR_RECIPES");

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
 *   ETH_IP6_SEG6_SRH_UDP       — IPv6 with a segment-routing (SRH type 4)
 *                                extension header carrying a UDP payload;
 *                                exercises the ipv6 routing-header parser
 *                                path and the SRH length-field repair.
 *   IP4_ESP                    — bare IPv4 outer with an IPsec ESP
 *                                header, RAW_IPV4; exercises the xfrm4
 *                                ESP receive path with no encryption.
 *   VLAN_IP4                   — single 802.1Q VLAN tag to IPv4,
 *                                AF_PACKET; exercises PKTB_LAYER_VLAN_SINGLE
 *                                (previously unreferenced by any recipe).
 *
 * Each row is capped at PKTB_MAX_LAYERS.
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
	{
		.name = "rpl_srh_udp", .n = 4, .layers = {
			PKTB_LAYER_ETH, PKTB_LAYER_IP6,
			PKTB_LAYER_RPL_SRH, PKTB_LAYER_UDP_ENCAP,
		}
	},
	{
		.name = "seg6_srh_udp", .n = 4, .layers = {
			PKTB_LAYER_ETH, PKTB_LAYER_IP6,
			PKTB_LAYER_SEG6_SRH, PKTB_LAYER_UDP_ENCAP,
		}
	},
	{
		.name = "esp_ip4", .n = 2, .layers = {
			PKTB_LAYER_IP4, PKTB_LAYER_ESP,
		}
	},
	{
		.name = "vlan_ip4", .n = 3, .layers = {
			PKTB_LAYER_ETH, PKTB_LAYER_VLAN_SINGLE, PKTB_LAYER_IP4,
		}
	},
};

/* One-shot per-child latches. */
static bool pktb_probe_self_check_ran;
static bool pktb_probe_self_check_ok;
static bool pktb_probe_disabled;
static bool pktb_probe_warned_disabled;
/*
 * Set when userns_run_in_ns(CLONE_NEWNET) is refused by a hardened
 * policy (user.max_user_namespaces=0 or
 * kernel.unprivileged_userns_clone=0).  Without a private netns we
 * cannot safely write the per-net SRH sysctls, so the two SRH
 * recipes are skipped for the lifetime of this child.
 */
static bool pktb_probe_srh_ns_unsupported;

/*
 * Returns true when the recipe at index `pick` contains an SRH layer
 * (RPL type 3 or SEG6 type 4) that requires per-netns sysctl setup
 * before the kernel's extension-header receive path will process it.
 */
static bool recipe_needs_srh_ns(unsigned int pick)
{
	const struct pktb_probe_recipe *r = &probe_recipes[pick];
	uint8_t li;

	for (li = 0; li < r->n; li++) {
		if (r->layers[li] == PKTB_LAYER_RPL_SRH ||
		    r->layers[li] == PKTB_LAYER_SEG6_SRH)
			return true;
	}
	return false;
}

/*
 * Write "1" to /proc/sys/net/ipv6/conf/{all,lo}/<knob> inside the
 * current (private) netns.  Per-net sysctl; the host tree is
 * untouched.  Best-effort: a missing file (ENOENT) means the kernel
 * predates the knob and the deliver attempt below will simply be
 * dropped; open/write failures are silently ignored.
 */
static void pktb_probe_write_ipv6_sysctl(const char *knob,
					 unsigned long *direct_calls_p)
{
	char path[128];
	static const char * const ifaces[] = { "all", "lo" };
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(ifaces); i++) {
		int fd;
		ssize_t n;

		snprintf(path, sizeof(path),
			 "/proc/sys/net/ipv6/conf/%s/%s", ifaces[i], knob);
		fd = open(path, O_WRONLY | O_CLOEXEC);
		(*direct_calls_p)++;
		if (fd < 0)
			continue;
		n = write(fd, "1", 1);
		(*direct_calls_p)++;
		(void)n;
		close(fd);
	}
}

/* Forward declaration: defined after the helpers below. */
static int probe_one_recipe(struct pktb_ctx *ctx,
			    const struct pktb_probe_recipe *r);

struct pktb_probe_srh_arg {
	const struct pktb_probe_recipe *r;
	enum child_op_type		op;
};

/*
 * Callback for userns_run_in_ns(): runs inside a transient grandchild
 * that owns a private CLONE_NEWNET netns.
 *
 * 1. Enables net.ipv6.conf.{all,lo}.rpl_seg_enabled = 1 for RPL SRH
 *    recipes, or net.ipv6.conf.{all,lo}.seg6_enabled = 1 for SEG6 SRH
 *    recipes.  These are per-net sysctls; writes are confined to the
 *    grandchild's private netns and do not affect the host network tree.
 * 2. Opens a fresh delivery context in the same netns (the AF_PACKET
 *    socket created by pktb_deliver lives in the grandchild's netns so
 *    the kernel receives the frame in a namespace where the sysctl is
 *    already set to 1).
 * 3. The grandchild exits when this returns, tearing down the netns;
 *    the socket, sysctl change, and any routing state vanish with it.
 */
static int pktb_probe_srh_in_ns(void *arg)
{
	const struct pktb_probe_srh_arg *a =
		(const struct pktb_probe_srh_arg *)arg;
	const struct pktb_probe_recipe  *r = a->r;
	struct nl_ctx nl = NL_CTX_INIT;
	struct nl_open_opts nlopts = {
		.proto        = NETLINK_ROUTE,
		.recv_timeo_s = 1,
		.caller_op    = CHILD_OP_PKT_BUILDER_PROBE,
	};
	bool nl_opened = false;
	struct pktb_ctx ctx;
	unsigned long dc = 0;
	uint8_t li;

	/*
	 * Bring lo up in the private netns so AF_PACKET sendto() on lo
	 * does not fail with -ENETDOWN at af_packet.c:1984.
	 */
	if (nl_open(&nl, &nlopts) == 0) {
		nl_opened = true;
		rtnl_bring_lo_up(&nl);
	} else {
		__atomic_add_fetch(&shm->stats.pkt_builder.srh_nl_open_failed,
				   1, __ATOMIC_RELAXED);
	}

	for (li = 0; li < r->n; li++) {
		if (r->layers[li] == PKTB_LAYER_RPL_SRH)
			pktb_probe_write_ipv6_sysctl("rpl_seg_enabled", &dc);
		else if (r->layers[li] == PKTB_LAYER_SEG6_SRH)
			pktb_probe_write_ipv6_sysctl("seg6_enabled", &dc);
	}

	pktb_ctx_init(&ctx);
	if (probe_one_recipe(&ctx, r) != 0)
		__atomic_add_fetch(&shm->stats.pkt_builder.srh_probe_inert,
				   1, __ATOMIC_RELAXED);

	/* Tally the close(2)s pktb_ctx_close is about to issue. */
	if (ctx.af_packet_fd >= 0)    dc++;
	if (ctx.raw_ipv4_fd >= 0)     dc++;
	if (ctx.raw_ipv6_fd >= 0)     dc++;
	if (ctx.loopback_udp_fd >= 0) dc++;
	pktb_ctx_close(&ctx);

	/* Tally the netlink socket syscalls (open + rtnl RTM_NEWLINK
	 * round-trip) and the close(2) nl_close() is about to issue. */
	if (nl_opened) {
		dc += nl.direct_syscalls + 1; /* +1 for close(2) in nl_close */
		nl_close(&nl);
	}

	if ((int)a->op >= 0 && a->op < NR_CHILD_OP_TYPES)
		childop_direct_syscalls_add(a->op, dc);
	return 0;
}

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
	unsigned long direct_calls = 0;
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

		/*
		 * SRH recipes (RPL type 3 / SEG6 type 4) require per-net
		 * sysctl setup before the kernel's extension-header receive
		 * path will process them.  Run them inside a private netns
		 * (CLONE_NEWNET) via userns_run_in_ns() so the sysctl
		 * writes are confined to the grandchild's netns and never
		 * touch the host network tree.
		 */
		if (recipe_needs_srh_ns(pick)) {
			if (!pktb_probe_srh_ns_unsupported) {
				struct pktb_probe_srh_arg srh_arg = {
					.r    = &probe_recipes[pick],
					.op   = op,
				};
				int nsrc = userns_run_in_ns(CLONE_NEWNET,
							    pktb_probe_srh_in_ns,
							    &srh_arg);

				if (nsrc == -EPERM)
					pktb_probe_srh_ns_unsupported = true;
				/* Count the fork+in-ns path as one direct
				 * syscall; the grandchild accounts the rest
				 * via childop_direct_syscalls_add(). */
				direct_calls++;
			}
			continue;
		}

		rc = probe_one_recipe(&ctx, &probe_recipes[pick]);
		/* rc == -2 means pktb_push rejected the recipe before any
		 * kernel entry; every other outcome ran pktb_deliver, which
		 * issues at least one syscall (a sendto attempt, or a
		 * failing socket() that latched off delivery). */
		if (rc != -2)
			direct_calls++;
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

	/* Account for the close(2)s pktb_ctx_close is about to issue —
	 * one per open delivery fd — so the reporter reflects every
	 * kernel entry this invocation caused. */
	if (ctx.af_packet_fd >= 0)
		direct_calls++;
	if (ctx.raw_ipv4_fd >= 0)
		direct_calls++;
	if (ctx.raw_ipv6_fd >= 0)
		direct_calls++;
	if (ctx.loopback_udp_fd >= 0)
		direct_calls++;

	pktb_ctx_close(&ctx);

	if (valid_op)
		childop_direct_syscalls_add(op, direct_calls);
	return true;
}
