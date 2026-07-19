#ifndef _TRINITY_STATS_SUBSYS_IOURING_NET_MULTISHOT_H
#define _TRINITY_STATS_SUBSYS_IOURING_NET_MULTISHOT_H

struct iouring_net_multishot_stats {
	/* iouring_net_multishot childop counters */
	unsigned long runs;		/* total iouring_net_multishot invocations */
	unsigned long setup_failed;	/* ring/socket/buffer-pool setup failed */
	unsigned long pbuf_ring_ok;	/* IORING_REGISTER_PBUF_RING accepted */
	unsigned long pbuf_legacy_ok;	/* fell back to PROVIDE_BUFFERS */
	unsigned long armed;		/* multishot RECV submitted+entered */
	unsigned long packets_sent;	/* peer UDP packets sendto()'d */
	unsigned long completions;	/* CQEs drained for the multishot */
	unsigned long cancel_submitted; /* ASYNC_CANCEL submitted+entered */
	unsigned long napi_register_ok;		/* IORING_REGISTER_NAPI accepted */
	unsigned long napi_register_fail;	/* IORING_REGISTER_NAPI rejected */
	unsigned long napi_unregister_ok;	/* IORING_UNREGISTER_NAPI accepted */
	unsigned long napi_unregister_fail;	/* IORING_UNREGISTER_NAPI rejected */
};

#endif /* _TRINITY_STATS_SUBSYS_IOURING_NET_MULTISHOT_H */
