#ifndef _TRINITY_STATS_SUBSYS_SOCK_DIAG_WALKER_H
#define _TRINITY_STATS_SUBSYS_SOCK_DIAG_WALKER_H

/*
 * sock_diag_walker childop counters.  The walker in
 * childops/net/sock-diag-walker.c opens a NETLINK_SOCK_DIAG socket
 * and dispatches one of the five per-family request variants
 * (inet, unix, netlink, packet, vsock) per invocation; each variant
 * bumps its own counter, runs is bumped once per invocation, and
 * setup_failed accounts the pre-dispatch socket() open failure.
 * All bumps RELAXED on shm->stats; diagnostic-only.
 *
 * The surrounding struct stats_s composes an instance of struct
 * sock_diag_walker_stats as its "sock_diag_walker" member.
 */
struct sock_diag_walker_stats {
	unsigned long runs;		/* total invocations */
	unsigned long setup_failed;	/* socket(NETLINK_SOCK_DIAG) failed */
	unsigned long inet;		/* inet_diag_req_v2 variant dispatched */
	unsigned long unix_;		/* unix_diag_req variant dispatched */
	unsigned long netlink;		/* netlink_diag_req variant dispatched */
	unsigned long packet;		/* packet_diag_req variant dispatched */
	unsigned long vsock;		/* vsock_diag_req variant dispatched */
};

#endif	/* _TRINITY_STATS_SUBSYS_SOCK_DIAG_WALKER_H */
