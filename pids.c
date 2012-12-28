#include <stdlib.h>
#include "trinity.h"
#include "shm.h"

int find_pid_slot(pid_t mypid)
{
	unsigned int i;

	for_each_pidslot(i) {
		if (shm->pids[i] == mypid)
			return i;
	}
	return PIDSLOT_NOT_FOUND;
}

bool pidmap_empty(void)
{
	unsigned int i;

	for_each_pidslot(i) {
		if (shm->pids[i] != EMPTY_PIDSLOT)
			return FALSE;
	}
	return TRUE;
}

void dump_pid_slots(void)
{
	unsigned int i;

	printf("## pids:\n");

	for_each_pidslot(i)
		printf("## slot%d: %d\n", i, shm->pids[i]);
}

int pid_is_valid(pid_t pid)
{
	if ((pid > 65535) || (pid < 1)) {
		output(0, "Sanity check failed! Found pid %d!\n", pid);
		return FALSE;
	}

	return TRUE;
}

unsigned int get_pid(void)
{
	unsigned int i;
	pid_t pid = 0;

	/* If we get called from the parent, and there are no
	 * children around yet, we need to not look at the pidmap. */
	if (shm->running_childs == 0)
		return 0;

	switch (rand() % 3) {
	case 0:
retry:		i = rand() % shm->max_children;
		pid = shm->pids[i];
		if (pid == EMPTY_PIDSLOT)
			goto retry;
		break;

	case 1:	pid = 0;
		break;

	case 2:	if (dangerous == TRUE)	// We don't want root trying to kill init.
			pid = 1;
		break;

	default:
		break;
	}

	return pid;
}
