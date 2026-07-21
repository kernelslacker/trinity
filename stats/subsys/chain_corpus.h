#ifndef _TRINITY_STATS_SUBSYS_CHAIN_CORPUS_H
#define _TRINITY_STATS_SUBSYS_CHAIN_CORPUS_H

/*
 * Chain-corpus duplicate-shape rate (sequence.c).  Bumped from
 * chain_corpus_save() under the ring lock: dup means the incoming
 * chain's (nr, do32bit) tuple shape matched at least one of the
 * CHAIN_CORPUS_DUP_LOOKBACK most-recent saved slots; unique means
 * no match.  Rate save_dup_shape / (save_dup_shape + save_unique_
 * shape) is the realised duplicate-shape rate a per-shape chain
 * quota is gated on.  The surrounding struct stats_s composes an
 * instance of struct chain_corpus_stats as its "chain_corpus"
 * member.
 */
struct chain_corpus_stats {
	unsigned long save_dup_shape;
	unsigned long save_unique_shape;
};

#endif	/* _TRINITY_STATS_SUBSYS_CHAIN_CORPUS_H */
