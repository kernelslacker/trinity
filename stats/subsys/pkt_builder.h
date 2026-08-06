#ifndef _TRINITY_STATS_SUBSYS_PKT_BUILDER_H
#define _TRINITY_STATS_SUBSYS_PKT_BUILDER_H

/* pkt_builder_probe childop counters: prover for the composable
 * layered structured-packet builder (include/pkt-builder.h + childops/
 * net/pkt-builder.c).  per_recipe[] indexes deliveries per layer
 * stack (NR_RECIPES in childops/net/pkt-builder-probe.c) so the
 * operator can confirm coverage stays spread across all recipes.
 * build/mutate/deliver counters split the pipeline so a regression
 * in one stage is visible without cross-referencing another op. */
struct pkt_builder_stats {
	unsigned long runs;			/* total pkt_builder_probe invocations */
	unsigned long setup_failed;		/* self-check failed or delivery latched off */
	unsigned long built_ok;			/* pktb_push chain fully assembled */
	unsigned long build_failed;		/* pktb_push refused a layer (overflow / bad kind) */
	unsigned long mutated;			/* pktb_mutate_and_repair completed */
	unsigned long truncated;		/* mutate pass hit a manifest truncation point */
	unsigned long delivered_ok;		/* pktb_deliver returned >0 */
	unsigned long delivery_failed;		/* pktb_deliver returned -1 / -2 (send error / bad frame) */
	unsigned long delivery_disabled;	/* CAP_NET_RAW absent — permanent per-child latch */
	unsigned long per_recipe[10];		/* per-recipe successful deliveries */

	/* SRH netns-path inertness counters.  The SRH callback
	 * (pktb_probe_srh_in_ns) runs inside a CLONE_NEWNET grandchild;
	 * its probe_one_recipe() return was previously discarded with
	 * (void), hiding delivery failures in the namespace-nested path.
	 * srh_probe_inert counts invocations where probe_one_recipe()
	 * returned non-zero (send failure, build failure, or the
	 * delivery-disabled latch).  srh_nl_open_failed counts the
	 * nl_open() error path; when nl_open() fails lo stays down and
	 * any subsequent sendto() will fail with -ENETDOWN. */
	unsigned long srh_probe_inert;		/* probe_one_recipe() != 0 in SRH netns path */
	unsigned long srh_nl_open_failed;	/* nl_open() failed in SRH netns callback */
};

#endif /* _TRINITY_STATS_SUBSYS_PKT_BUILDER_H */
