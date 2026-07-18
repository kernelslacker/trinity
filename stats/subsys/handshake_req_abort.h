#ifndef _TRINITY_STATS_SUBSYS_HANDSHAKE_REQ_ABORT_H
#define _TRINITY_STATS_SUBSYS_HANDSHAKE_REQ_ABORT_H

struct handshake_req_abort_stats {
	/* handshake_req_abort childop counters */
	unsigned long runs;			/* total handshake_req_abort invocations */
	unsigned long setup_failed;		/* genl resolve / socket setup failed (incl. !CONFIG_NET_HANDSHAKE) */
	unsigned long accept_ok;		/* HANDSHAKE_CMD_ACCEPT issued (lookup-by-class path ran) */
	unsigned long done_ok;		/* HANDSHAKE_CMD_DONE status=0 issued (lookup-by-sockfd ran) */
	unsigned long abort_ok;		/* HANDSHAKE_CMD_DONE status!=0 issued (abort-shape race) */
	unsigned long orphan_close;		/* close() while requests outstanding (sk_destruct path) */
};

#endif /* _TRINITY_STATS_SUBSYS_HANDSHAKE_REQ_ABORT_H */
