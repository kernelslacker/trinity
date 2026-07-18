#ifndef _TRINITY_STATS_SUBSYS_SPLICE_PROTOCOLS_H
#define _TRINITY_STATS_SUBSYS_SPLICE_PROTOCOLS_H

struct splice_protocols_stats {
	/* splice_protocols childop counters.  Coverage of splice() into
	 * sockets whose protocol state has been steered into one of
	 * several non-default modes (UDP_ENCAP, TCP_REPAIR, AF_PACKET
	 * RX-ring, AF_ALG skcipher, AF_RXRPC bound). */
	unsigned long runs;			/* total splice_protocols invocations */
	unsigned long setup_failed;		/* per-iter setup latched (every supported setup exhausted) */
	unsigned long chain_ok;		/* both splice() halves returned >0 */
	unsigned long in_bytes;		/* bytes splice'd file_fd -> pipe[1] */
	unsigned long out_bytes;		/* bytes splice'd pipe[0] -> socket_fd */
	unsigned long udp_encap_attempted;	/* UDP_ENCAP setup arm picked (ESPINUDP / L2TPINUDP) */
	unsigned long tcp_repair_attempted;	/* TCP_REPAIR setup arm picked */
	unsigned long packet_ring_attempted;	/* AF_PACKET TPACKET RX-ring setup arm picked */
	unsigned long alg_attempted;		/* AF_ALG skcipher setup arm picked */
	unsigned long rxrpc_attempted;		/* AF_RXRPC bound-socket setup arm picked */
	unsigned long msg_splice_pages_attempted;	/* splice()/sendmsg() calls where the kernel is expected to plant pages via MSG_SPLICE_PAGES */
	unsigned long msg_splice_pages_path_taken_inferred;	/* of those, how many returned len matching input with no errno (zero-copy plant inferred). Operator: ratio < 90% means many calls fell back to copy and aren't reproducing the intended bug shape. */
};

#endif /* _TRINITY_STATS_SUBSYS_SPLICE_PROTOCOLS_H */
