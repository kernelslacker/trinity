/*
 * Parent environment for the PARENT_SRCS tests: storage for the parent
 * globals main/loop.c and main/reap-zombie.c read, and stand-ins for
 * the parent calls their reachable code makes.  Calls that act on one
 * slot land in fake_slot_log[]; the rest do nothing.
 */

#include <stdbool.h>
#include <string.h>
#include <time.h>

#include "child.h"
#include "debug.h"		/* classify_child_buglog, beacon_loss_* */
#include "fd-event.h"
#include "main-internal.h"
#include "main/reap-internal.h"
#include "pids.h"
#include "random.h"
#include "shm.h"
#include "stats_ring.h"
#include "sysv-msg.h"
#include "sysv-sem.h"
#include "sysv-shm.h"
#include "tables.h"
#include "trinity.h"

#include "fake_parent.h"

/* Owned by trinity-warmstart.c, dispatch/pids.c, utils/shm.c,
 * main/reap.c and stats/stats-ring.c in production. */
unsigned int max_children;
pid_t *pids;
struct childdata **children;
int *pidstatfiles;
time_t *spawn_times;
struct stats_published *shm_published;

struct fake_slot_log fake_slot_log[FAKE_NR_CHILDREN];

static pid_t pid_slots[FAKE_NR_CHILDREN];
static int pidstat_slots[FAKE_NR_CHILDREN];
static time_t spawn_time_slots[FAKE_NR_CHILDREN];
static pid_t zombie_pid_slots[FAKE_NR_CHILDREN];
static time_t zombie_since_slots[FAKE_NR_CHILDREN];
static bool quarantine_slots[FAKE_NR_CHILDREN];
static struct childdata childdata[FAKE_NR_CHILDREN];
static struct childdata *child_ptrs[FAKE_NR_CHILDREN];
static struct fd_event_ring rings[FAKE_NR_CHILDREN];

void fake_parent_reset(void)
{
	unsigned int i;

	max_children = FAKE_NR_CHILDREN;
	pids = pid_slots;
	children = child_ptrs;
	pidstatfiles = pidstat_slots;
	spawn_times = spawn_time_slots;
	zombie_pids = zombie_pid_slots;
	zombie_since = zombie_since_slots;
	zombie_quarantined = quarantine_slots;

	for_each_child(i) {
		children[i] = &childdata[i];
		children[i]->num = i;
		children[i]->fd_event_ring = &rings[i];
		pids[i] = EMPTY_PIDSLOT;
		pidstatfiles[i] = -1;
		zombie_pids[i] = EMPTY_PIDSLOT;
		zombie_since[i] = 0;
		zombie_quarantined[i] = false;
	}
	live_child_slots = max_children;
	memset(&shm->stats.zombie_reaper, 0, sizeof(shm->stats.zombie_reaper));
	__atomic_store_n(&shm->exit_reason, STILL_RUNNING, __ATOMIC_RELAXED);
	__atomic_store_n(&shm->spawn_no_more, false, __ATOMIC_RELAXED);

	memset(fake_slot_log, 0, sizeof(fake_slot_log));
}

void clean_childdata(struct childdata *child)
{
	fake_slot_log[child->num].cleaned++;
}

void fd_event_ring_init(struct fd_event_ring *ring)
{
	fake_slot_log[ring - rings].ring_reset++;
}

void classify_child_buglog(struct childdata *child, pid_t pid)
{
	fake_slot_log[child->num].classified_pid = pid;
}

void reap_child_sysv_shm(struct childdata *child)
{
	fake_slot_log[child->num].sysv_drained++;
}

void reap_child_sysv_msg(struct childdata *child)
{
	fake_slot_log[child->num].sysv_drained++;
}

void reap_child_sysv_sem(struct childdata *child)
{
	fake_slot_log[child->num].sysv_drained++;
}

void replace_child(int childno)
{
	fake_slot_log[childno].replaced++;
}

void reap_child(struct childdata *child, int childno, bool child_dead)
{
	(void)child; (void)childno; (void)child_dead;
}

struct syscallentry *get_syscall_entry(unsigned int calln, bool do32)
{
	(void)calln; (void)do32;
	return NULL;
}

void dump_pid_stack(int pid)
{
	(void)pid;
}

void dump_pid_syscall(int pid)
{
	(void)pid;
}

void beacon_loss_count_skipped_timed_out(void)
{
}

void reseed(void)
{
}

void output(int level, const char *fmt, ...)
{
	(void)level; (void)fmt;
}
