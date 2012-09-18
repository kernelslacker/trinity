#include "trinity.h"
#include "shm.h"

int find_pid_slot(pid_t mypid)
{
	unsigned int i;

	for (i = 0; i < shm->max_children; i++) {
		if (shm->pids[i] == mypid)
			return i;
	}
	return PIDSLOT_NOT_FOUND;
}

bool pidmap_empty(void)
{
	unsigned int i;

	for (i = 0; i < shm->max_children; i++) {
		if (shm->pids[i] != EMPTY_PIDSLOT)
			return FALSE;
	}
	return TRUE;
}

void dump_pid_slots(void)
{
	unsigned int i;

	printf("## pids:\n");

	for (i = 0; i < shm->max_children; i++)
		printf("## slot%d: %d\n", i, shm->pids[i]);
}

int pid_is_valid(pid_t pid)
{
	if ((pid > 65535) || (pid < 1)) {
		output("Sanity check failed! Found pid %d!\n", pid);
		return FALSE;
	}

	return TRUE;
}
