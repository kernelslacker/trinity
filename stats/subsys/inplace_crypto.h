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
};

#endif /* _TRINITY_STATS_SUBSYS_INPLACE_CRYPTO_H */
