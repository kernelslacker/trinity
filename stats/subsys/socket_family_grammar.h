#ifndef _TRINITY_STATS_SUBSYS_SOCKET_FAMILY_GRAMMAR_H
#define _TRINITY_STATS_SUBSYS_SOCKET_FAMILY_GRAMMAR_H

struct socket_family_grammar_stats {
	/* socket-family-grammar dispatcher counters
	 * (net/socket-family-grammar.c).  Bumped per call into
	 * run_grammar_chain() — runs counts every entry, completed counts
	 * the walks that reached the data leg cleanly.  Per-family
	 * completion counters are intentionally absent: the existing
	 * chrono log + per-syscall stats already attribute coverage.
	 *
	 * distinct_seq is the population of the shm sfg_seq_hashes ring:
	 * the number of DISTINCT executed step-ID sequences observed
	 * fleet-wide since startup.  Rises as the per-family phase-order
	 * table exposes new legal permutations; saturates once the ring
	 * fills at SFG_SEQ_HASH_CAP.  A value > 1 proves the ordering
	 * table is live and the executor is actually varying the walk. */
	unsigned long runs;
	unsigned long completed;
	unsigned long distinct_seq;
	unsigned long reward;		/* new-edge reward credited to grammar arms */
	unsigned long feedback_picks;	/* order picks steered by reward vs uniform */
};

#endif /* _TRINITY_STATS_SUBSYS_SOCKET_FAMILY_GRAMMAR_H */
