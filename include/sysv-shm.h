#pragma once

struct childdata;

void create_sysv_shms(void);

/* RMID every fuzzed SysV shm segment this child created but never cleaned up
 * (a SIGKILL/OOM death skips the OBJ_LOCAL RMID destructor).  Called from
 * reap_child() parent-side, after the child is confirmed dead. */
void reap_child_sysv_shm(struct childdata *child);

struct sysv_shm {
	void *ptr;
	int id;
	size_t size;
	int flags;
};
