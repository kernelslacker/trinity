#ifndef _TRINITY_STATS_SUBSYS_VSOCK_TRANSPORT_CHURN_H
#define _TRINITY_STATS_SUBSYS_VSOCK_TRANSPORT_CHURN_H

struct vsock_transport_churn_stats {
	/* vsock_transport_churn childop counters */
	unsigned long runs;			/* total vsock_transport_churn invocations */
	unsigned long setup_failed;		/* socket / bind / listen / connect / unsupported latch fired */
	unsigned long bind_ok;			/* bind(VMADDR_CID_LOCAL) + listen accepted */
	unsigned long connect_ok;		/* loopback connect to listener accepted */
	unsigned long send_ok;			/* send(MSG_DONTWAIT) returned >=0 on the loopback transport */
	unsigned long buffer_size_ok;	/* setsockopt(SO_VM_SOCKETS_BUFFER_SIZE) accepted mid-flow */
	unsigned long timeout_ok;		/* setsockopt(SO_VM_SOCKETS_CONNECT_TIMEOUT_NEW) accepted mid-flow */
	unsigned long get_cid_ok;		/* ioctl(IOCTL_VM_SOCKETS_GET_LOCAL_CID) returned the local cid */
	unsigned long seq_eom_runs;			/* SEQ_EOM 0-length burst sub-mode invocations */
	unsigned long seq_eom_sends_ok;			/* sendmsg(MSG_EOR, iov_len=0) returned >= 0 */
	unsigned long seq_eom_sends_failed;		/* sendmsg(MSG_EOR, iov_len=0) returned < 0 */
	unsigned long seq_eom_skipped;			/* sub-mode gated out: no socket / unsupported / wall-cap */
};

#endif /* _TRINITY_STATS_SUBSYS_VSOCK_TRANSPORT_CHURN_H */
