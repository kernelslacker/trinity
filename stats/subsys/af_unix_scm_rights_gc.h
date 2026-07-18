#ifndef _TRINITY_STATS_SUBSYS_AF_UNIX_SCM_RIGHTS_GC_H
#define _TRINITY_STATS_SUBSYS_AF_UNIX_SCM_RIGHTS_GC_H

struct af_unix_scm_rights_gc_stats {
	/* af_unix_scm_rights_gc_churn childop counters */
	unsigned long runs;		/* total af_unix_scm_rights_gc_churn invocations */
	unsigned long setup_failed;	/* AF_UNIX socketpair() failed (probe latch) */
	unsigned long cycle_built_ok;	/* full 3-pair SCM_RIGHTS cycle constructed end-to-end */
	unsigned long close_ok;		/* userspace dropped its refs to cycle members (gc fodder) */
	unsigned long trigger_ok;		/* gc-trigger sendmsg / drain landed (unix_inflight or workqueue) */
	unsigned long recv_ok;		/* recvmsg drained queued SCM_RIGHTS msg (race vs unix_gc walk) */
	unsigned long peek_ok;		/* recvmsg(MSG_PEEK) walked unix_peek_fpl on queued SCM_RIGHTS */
	unsigned long iouring_variant_ok;	/* io_uring fd inserted into the unix-scm reference graph */
	unsigned long sibling_spawn_ok;	/* clone(CLONE_FILES|SIGCHLD) sibling race-producer spawned */
	unsigned long sibling_spawn_failed;/* clone()/clone3() failed; fell back to single-task race burst */
	unsigned long sibling_reaped_ok;	/* sibling exited normally and was reaped by parent */
	unsigned long sibling_crashed;	/* sibling killed by signal (SEGV/BUS/KILL) -- forensic hint */
};

#endif /* _TRINITY_STATS_SUBSYS_AF_UNIX_SCM_RIGHTS_GC_H */
