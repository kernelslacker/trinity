#ifndef _TRINITY_STATS_SUBSYS_TOPO_PAIR_H
#define _TRINITY_STATS_SUBSYS_TOPO_PAIR_H

#include <stdint.h>

/*
 * SHADOW-ONLY topology-pair sample ring sizing.  Size must be a power
 * of two; the producer masks the fetch-added head with
 * TOPO_PAIR_RING_MASK to derive the destination slot.
 */
#define TOPO_PAIR_RING_SIZE	256u
#define TOPO_PAIR_RING_MASK	(TOPO_PAIR_RING_SIZE - 1u)

/*
 * SHADOW-ONLY topology-pair sample ring + companion counters.
 *
 * Bespoke (non-category) RAW group.  The ring captures packed
 * {setup_op, reason, syscall_nr, age_in_syscalls} tuples emitted by
 * frontier_record_new_edge() and the ungated kcov transition path so
 * dump_stats_topo_pair_shadow() can render per-setup_op summaries at
 * shutdown.  See stats.h for the ring-slot bit-packing layout and
 * TOPO_PAIR_RING_SIZE / TOPO_PAIR_RING_MASK, both defined in stats.h.
 * The surrounding struct stats_s composes an instance of struct
 * topo_pair_stats as its "topo_pair" member.
 */
struct topo_pair_stats {
	/* SHADOW-ONLY topology-pair sample ring.
	 * When a syscall flips a new PC bucket bit or a new transition slot,
	 * frontier_record_new_edge() (PC lane, strategy-frontier.c) or the
	 * ungated kcov_collect() transition block in kcov.c (transition lane,
	 * co-located with the per_syscall_transition_edges_real bump)
	 * looks at the firing child's latched last_setup_op + last_setup_op_nr
	 * (stamped in child_process() at the top of every alt-op dispatch)
	 * and packs a {setup_op, reason, syscall_nr, age_in_syscalls} tuple
	 * into the slot at (ring_head & TOPO_PAIR_RING_MASK).  The
	 * head is bumped with atomic_fetch_add so concurrent children claim
	 * disjoint slots; the slot itself is written with a single 64-bit
	 * RELAXED store so a reader observes either the prior entry or the
	 * fresh entry but never a torn mix of the two.  Overwrite-oldest
	 * once the ring wraps -- the aggregator does not depend on which
	 * specific events survived, only on the distribution across setup
	 * ops, and the cumulative records counter records how many
	 * total events landed so an operator can tell whether the visible
	 * sample fills the ring (records >= TOPO_PAIR_RING_SIZE) or not.
	 *
	 * Packed entry layout (bit positions, LSB first):
	 *   [ 0.. 7]  setup_op       (uint8_t cast of enum child_op_type;
	 *                              NR_CHILD_OP_TYPES sentinel never
	 *                              recorded -- those events bump
	 *                              no_setup_observed instead)
	 *   [ 8.. 9]  reason         (1=PC-edge new bucket bit,
	 *                              2=new transition; 0 reserved for
	 *                              the uninitialised slot state)
	 *   [10..25]  syscall_nr     (16 bits; MAX_NR_SYSCALL=1024 fits)
	 *   [26..45]  age_in_syscalls (20 bits, saturated at (1<<20)-1)
	 *   [46]      valid          (1 = written entry; 0 in unwritten
	 *                              slots so the aggregator can skip
	 *                              the uninitialised tail before the
	 *                              ring has wrapped)
	 *   [47..63]  reserved (must be zero on write)
	 *
	 * SHADOW: no scheduler / picker / scoring code reads either the
	 * ring or any of the companion scalars; the only reader is
	 * stats/childop/local.c's dump_stats_topo_pair_shadow() at shutdown.
	 * It aggregates the surviving ring entries into per-setup_op (count,
	 * mean-age, reason
	 * split) summaries.  This render enables the 103·B go/no-go on a
	 * LIVE topology-pair experiment that would actually save seeds /
	 * replay pairs -- it is not a cosmetic surface. */
	uint64_t ring[TOPO_PAIR_RING_SIZE];
	unsigned int ring_head;
	unsigned long records;
	unsigned long no_setup_observed;
};

#endif	/* _TRINITY_STATS_SUBSYS_TOPO_PAIR_H */
