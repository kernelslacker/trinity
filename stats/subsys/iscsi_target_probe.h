#ifndef _TRINITY_STATS_SUBSYS_ISCSI_TARGET_PROBE_H
#define _TRINITY_STATS_SUBSYS_ISCSI_TARGET_PROBE_H

struct iscsi_target_probe_stats {
	/* iscsi_target_probe childop counters.  Tracks reach into the
	 * in-kernel LIO target login + post-login SCSI Command path via a
	 * real TCP connection to 127.0.0.1:3260.  Latches off
	 * (no_target) when the very first connect() returns
	 * ECONNREFUSED, so an operator can spot "target absent" runs
	 * cheaply by reading no_target vs connected. */
	unsigned long runs;			/* total iscsi_target_probe invocations */
	unsigned long setup_failed;		/* socket() / non-ECONNREFUSED connect failure */
	unsigned long no_target;		/* ECONNREFUSED on connect — latched per-child */
	unsigned long connected;		/* TCP connect to 3260 returned 0 / completed */
	unsigned long login_sent;		/* Login PDU send() returned >0 */
	unsigned long login_replies;		/* drain() executed after a login send */
	unsigned long scsi_cmd_sent;		/* post-login SCSI Command PDU sent (arm c) */
	unsigned long bytes_out;		/* total bytes successfully send()'d */
	unsigned long bytes_in;		/* total bytes successfully recv()'d */
	unsigned long length_decoupled;	/* arm (d): BHS DataSegmentLength != actual payload */
};

#endif /* _TRINITY_STATS_SUBSYS_ISCSI_TARGET_PROBE_H */
