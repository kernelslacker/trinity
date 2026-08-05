#ifndef _TRINITY_STATS_SUBSYS_INPLACE_CRYPTO_H
#define _TRINITY_STATS_SUBSYS_INPLACE_CRYPTO_H

struct inplace_crypto_stats {
	/* inplace_crypto_oracle childop counters.  Bumped when the
	 * oracle observes a splice -> in-place crypto path mutating the
	 * source file's contents -- a real kernel bug class (input-handler
	 * skip_cow on a nonlinear-but-not-cloned skb whose frags are
	 * page-cache pages).  The op's outputerr() line is silenced by the
	 * /dev/null dup2 in init_child() unless the operator is running
	 * with a logfile / strace attached, so this counter is the durable
	 * headless signal that a mutation was detected. */
	unsigned long mutated;

	/* splice_into_socket() inertness gate.  Tracks whether the
	 * pipe->socket splice half ever returns >0 bytes across all
	 * targets.  Lives in shm->stats so the counters survive across
	 * child respawns -- process-local statics reset to zero on every
	 * fork, preventing the 1000-attempt threshold from ever firing in
	 * recycled children. */
	unsigned long splice_attempts;	/* total pipe->socket splice attempts */
	unsigned long splice_ok;		/* attempts where splice returned >0  */
	unsigned long splice_warned;	/* 1 once the inertness warning fires  */
};

#endif /* _TRINITY_STATS_SUBSYS_INPLACE_CRYPTO_H */
