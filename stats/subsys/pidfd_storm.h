#ifndef _TRINITY_STATS_SUBSYS_PIDFD_STORM_H
#define _TRINITY_STATS_SUBSYS_PIDFD_STORM_H

struct pidfd_storm_stats {
	/* pidfd_storm childop counters */
	unsigned long runs;		/* total pidfd_storm invocations */
	unsigned long signals;	/* successful pidfd_send_signal calls */
	unsigned long getfds;	/* successful pidfd_getfd calls */
	unsigned long failed;	/* pidfd_open/send_signal/getfd returned -1 */
	unsigned long iters;	/* cumulative inner-loop pidfd syscalls */
	unsigned long reap_slow;	/* teardown poll(pidfd) exceeded PER_PIDFD_REAP_TIMEOUT_MS -- SIGKILL not observed within the budget */
	unsigned long reap_zombies;	/* teardown reap escaped (WNOHANG waitpid did not collect) after the poll timeout; a zombie was left behind for the parent's SIGCHLD path to catch */
};

#endif /* _TRINITY_STATS_SUBSYS_PIDFD_STORM_H */
