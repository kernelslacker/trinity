#ifndef _TRINITY_STATS_SUBSYS_AF_UNIX_PEEK_RACE_H
#define _TRINITY_STATS_SUBSYS_AF_UNIX_PEEK_RACE_H

struct af_unix_peek_race_stats {
	/* af_unix_peek_race childop counters */
	unsigned long runs;			/* total af_unix_peek_race invocations */
	unsigned long setup_failed;		/* AF_UNIX SOCK_STREAM socketpair / probe latch fired */
	unsigned long pair_open_ok;		/* fresh SOCK_STREAM socketpair + prefill landed */
	unsigned long peek_off_armed;		/* setsockopt SO_PEEK_OFF accepted on the reader half */
	unsigned long peek_off_rejected;	/* setsockopt SO_PEEK_OFF rejected (old kernel; coverage still proceeds) */
	unsigned long send_ok;		/* parent send() landed bytes on the writer half */
	unsigned long shutdown_ok;		/* parent shutdown(SHUT_WR) flipped peer state */
	unsigned long pair_rebuilds;		/* post-EPIPE socketpair() rebuilds (bounded per burst) */
	unsigned long sibling_spawn_ok;	/* clone(CLONE_FILES|SIGCHLD) sibling race-producer spawned */
	unsigned long sibling_spawn_failed;	/* clone()/clone3() failed; fell back to single-task race burst */
	unsigned long sibling_reaped_ok;	/* sibling exited normally and was reaped by parent */
	unsigned long sibling_crashed;	/* sibling killed by signal (SEGV/BUS/KILL) -- forensic hint */
};

#endif /* _TRINITY_STATS_SUBSYS_AF_UNIX_PEEK_RACE_H */
