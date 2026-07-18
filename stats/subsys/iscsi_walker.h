#ifndef _TRINITY_STATS_SUBSYS_ISCSI_WALKER_H
#define _TRINITY_STATS_SUBSYS_ISCSI_WALKER_H

struct iscsi_walker_stats {
	/* iscsi_login_walker childop counters.  Companion to
	 * iscsi_target_probe: instead of single one-shot PDUs, this walker
	 * drives the LIO Login state machine through its real-protocol
	 * transitions to land coverage past the BHS / parser-level
	 * rejection gates.  Latches off (no_target) on first ECONNREFUSED
	 * exactly like iscsi_target_probe. */
	unsigned long runs;			/* total iscsi_login_walker invocations */
	unsigned long setup_failed;		/* socket() / non-ECONNREFUSED connect failure */
	unsigned long no_target;			/* ECONNREFUSED on connect — latched per-child */
	unsigned long connected;			/* TCP connect to 3260 returned 0 / completed */
	unsigned long state_security_sent;		/* PDU1 (T=1 CSG=0 NSG=1) send returned >0 */
	unsigned long state_op_neg_sent;		/* PDU2 (T=1 CSG=1 NSG=3) send returned >0 */
	unsigned long login_response_ok;		/* full 48-byte Login Response BHS with opcode 0x23 received */
	unsigned long login_rejected;		/* Login Response Status-Class != 0 */
	unsigned long ffp_reached;			/* Login walk completed with T=1 and NSG=FFP -- the KPI */
	unsigned long ffp_iters;			/* iterations that entered the FFP-fuzz phase */
	unsigned long ffp_pdus;			/* FFP fuzz PDUs send() returned >0 */
	unsigned long chaos_runs;			/* invocations that took the chaos path (1-in-N) */
	unsigned long chaos_pdus;			/* random-BHS PDUs send() returned >0 in chaos mode */
	unsigned long bytes_out;			/* total bytes successfully send()'d */
	unsigned long bytes_in;			/* total bytes successfully recv()'d */
};

#endif /* _TRINITY_STATS_SUBSYS_ISCSI_WALKER_H */
