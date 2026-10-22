/*
 * Self-checks for fork_children() and replace_child() (main/spawn.c):
 * the startup barrier the fresh children wait at, and the fill that
 * opens it.  The fork is faked per slot (fake_parent.c), so nothing is
 * forked; the slots hold made-up pids.
 */

#include <sys/types.h>

#include "debug.h"		/* BUG */
#include "main-internal.h"
#include "pids.h"
#include "shm.h"

#include "fake_parent.h"

#define BARRIER_OPEN	(__atomic_load_n(&shm->ready, __ATOMIC_ACQUIRE))

/* Nothing fails and nothing throttles: one call forks every slot, and
 * the barrier opens on leaving the loop, once the last one has. */
static void barrier_opens_once_every_slot_fills(void)
{
	unsigned int i;

	fake_parent_reset();

	fork_children();

	for_each_child(i) {
		if (pids[i] != FAKE_FORK_PID(i) || fake_slot_log[i].forks != 1)
			BUG("spawn: a fill did not fork every slot exactly once");
	}
	if (shm->running_childs != FAKE_NR_CHILDREN)
		BUG("spawn: a full fill left the running count short");
	if (!BARRIER_OPEN)
		BUG("spawn: the startup barrier stayed shut with every slot filled");
}

void spawn_self_check(void);
void spawn_self_check(void)
{
	barrier_opens_once_every_slot_fills();

	/* Leave no pids or counts for later suites. */
	fake_parent_reset();
}
