#ifndef _TRINITY_STATS_SUBSYS_ACCEPT_UNBLOCKER_H
#define _TRINITY_STATS_SUBSYS_ACCEPT_UNBLOCKER_H

/*
 * accept-unblocker counters.  Fires a loopback connect() at a pooled
 * listening socket so a concurrent accept() sees a non-empty backlog
 * and never parks in inet_csk_accept's wait loop.  See
 * net/unblocker.c for the loopback-only safety check.
 *
 * Bespoke (non-category) RAW group.  All bumps RELAXED on shm->stats.
 * The surrounding struct stats_s composes an instance of struct
 * accept_unblocker_stats as its "accept_unblocker" member.
 */
struct accept_unblocker_stats {
	unsigned long connects_fired;		/* fire-and-forget connect() issued at a listener (SYN sent or EINPROGRESS) */
	unsigned long loopback_only_skipped;	/* listener bound to non-loopback addr; refused to connect */
	unsigned long probe_failed;		/* getsockopt(SO_ACCEPTCONN) / getsockname / socket() / connect() returned an unexpected error */
};

#endif	/* _TRINITY_STATS_SUBSYS_ACCEPT_UNBLOCKER_H */
