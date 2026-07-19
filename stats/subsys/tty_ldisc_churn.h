#ifndef _TRINITY_STATS_SUBSYS_TTY_LDISC_CHURN_H
#define _TRINITY_STATS_SUBSYS_TTY_LDISC_CHURN_H

struct tty_ldisc_churn_stats {
	/* tty_ldisc_churn childop counters.  Targets the n_tty_receive_buf_standard
	 * KMSAN, n_tty_lookahead_flow_ctrl uninit, do_con_write slab-OOB cluster
	 * (May serial Monthly) plus the kbd_event UAFs (April input Monthly) by
	 * cycling pty pairs through TIOCSETD across 0..24, fuzzing per-iter
	 * write/read at the master end.  The per-disc histogram lets the operator
	 * see which N_* values are landing the most ldisc_set_ok hits, so a future
	 * dispatch can bias toward a struggling line discipline. */
	unsigned long runs;		/* total tty_ldisc_churn invocations */
	unsigned long setup_failed;	/* posix_openpt / grantpt / unlockpt / ptsname_r / open(pts) failed */
	unsigned long ldisc_set_ok;	/* TIOCSETD accepted */
	unsigned long ldisc_set_failed;	/* TIOCSETD rejected (autoload miss, gated, etc.) */
	unsigned long write_ok;		/* write() at the pts end returned > 0 */
	unsigned long read_ok;		/* read() at the master end returned > 0 */
	unsigned long ldisc_set_ok_per_disc[25];	/* per-N_* hit histogram (slot 21 / N_GSM stays zero) */
};

#endif /* _TRINITY_STATS_SUBSYS_TTY_LDISC_CHURN_H */
