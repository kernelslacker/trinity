#ifndef _TRINITY_STATS_SUBSYS_SYSV_SHM_ORPHAN_RACE_H
#define _TRINITY_STATS_SUBSYS_SYSV_SHM_ORPHAN_RACE_H

struct sysv_shm_orphan_race_stats {
	/* sysv_shm_orphan_race childop counters */
	unsigned long runs;		/* total sysv_shm_orphan_race invocations */
	unsigned long setup_failed;	/* probe latch fired or per-iter shared-state alloc failed */
	unsigned long shmget_ok;		/* originator shmget(IPC_PRIVATE) created a fresh segment */
	unsigned long shmget_failed;	/* originator shmget() failed or never published shmid */
	unsigned long attach_ok;		/* parent / solo-burst shmat() returned a valid address */
	unsigned long attach_failed;	/* parent / solo-burst shmat() returned -1 (typically EIDRM after destroy) */
	unsigned long rmid_ok;		/* shmctl(IPC_RMID) returned 0 (originator already-RMID'd path NOT counted here) */
	unsigned long rmid_failed;	/* shmctl(IPC_RMID) returned -1 (typically EIDRM; segment already destroyed -- expected coverage) */
	unsigned long sibling_spawn_ok;	/* clone3(SIGCHLD) originator/attacher sibling spawned */
	unsigned long sibling_spawn_failed;/* clone3() failed; fell back to single-task race burst */
	unsigned long sibling_reaped_ok;	/* sibling exited normally and was reaped by parent */
	unsigned long sibling_crashed;	/* sibling killed by signal (SEGV/BUS/KILL) -- forensic hint */
};

#endif /* _TRINITY_STATS_SUBSYS_SYSV_SHM_ORPHAN_RACE_H */
