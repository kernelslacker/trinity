#ifndef _TRINITY_STATS_SUBSYS_SCTP_CHUNK_RX_H
#define _TRINITY_STATS_SUBSYS_SCTP_CHUNK_RX_H

struct sctp_chunk_rx_stats {
	/* sctp_chunk_rx childop counters */
	unsigned long runs;			/* total sctp_chunk_rx invocations */
	unsigned long setup_failed;		/* userns_run_in_ns / listener / raw setup failed (incl. !CONFIG_IP_SCTP) */
	unsigned long listener_ok;		/* SCTP listener created + bound + listen() accepted */
	unsigned long packet_sent_ok;		/* sendto on IPPROTO_RAW returned >0 */
};

#endif /* _TRINITY_STATS_SUBSYS_SCTP_CHUNK_RX_H */
