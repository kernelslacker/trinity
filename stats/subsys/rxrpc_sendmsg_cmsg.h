#ifndef _TRINITY_STATS_SUBSYS_RXRPC_SENDMSG_CMSG_H
#define _TRINITY_STATS_SUBSYS_RXRPC_SENDMSG_CMSG_H

/*
 * rxrpc_sendmsg_cmsg_churn childop counters.  The churn fuzzes the
 * AF_RXRPC sendmsg() control-message parser; each invocation opens
 * an AF_RXRPC socket, builds one of the RXRPC_ cmsg slots
 * (USER_CALL_ID..CHARGE_ACCEPT), and issues sendmsg() to the loopback
 * peer.  Counters are diagnostic-only; each bump RELAXED on shm->stats.
 *
 * The sent[] histogram sizing (8) matches the RXRPC_ cmsg slot count
 * exposed to userspace; keep the sizing here in step with any kernel
 * uapi extension.
 *
 * The surrounding struct stats_s composes an instance of struct
 * rxrpc_sendmsg_cmsg_stats as its "rxrpc_sendmsg_cmsg" member.
 */
struct rxrpc_sendmsg_cmsg_stats {
	unsigned long runs;		/* total rxrpc_sendmsg_cmsg_churn invocations */
	unsigned long socket_failed;	/* socket()/bind() rejected (incl EPROTONOSUPPORT-latch trip) */
	unsigned long sent[8];		/* per-cmsg-slot histogram (USER_CALL_ID..CHARGE_ACCEPT) */
	unsigned long sendmsg_ok;	/* sendmsg() returned >=0 */
	unsigned long sendmsg_fail;	/* sendmsg() returned -1 (kernel rejected the cmsg shape) */
};

#endif	/* _TRINITY_STATS_SUBSYS_RXRPC_SENDMSG_CMSG_H */
