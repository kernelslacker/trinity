/*
 * Parent environment for the PARENT_SRCS tests: storage for the parent
 * globals main/loop.c, main/reap.c and main/reap-zombie.c read, and
 * stand-ins for the parent calls their reachable code makes.  Calls
 * that act on one slot land in fake_slot_log[], kill_pid() and output()
 * keep what they were given, and the rest do nothing.
 */

#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <time.h>
#include <unistd.h>

#include "child.h"
#include "debug.h"		/* BUG, classify_child_buglog, beacon_loss_* */
#include "fd-event.h"
#include "kmsg-monitor.h"
#include "main-internal.h"
#include "main/reap-internal.h"
#include "pids.h"
#include "pre_crash_ring.h"
#include "random.h"
#include "shm.h"
#include "stats_ring.h"
#include "sysv-msg.h"
#include "sysv-sem.h"
#include "sysv-shm.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"		/* kill_pid */

#include "fake_parent.h"

/* Owned by trinity-warmstart.c, dispatch/pids.c, utils/shm.c and
 * stats/stats-ring.c in production. */
unsigned int max_children;
pid_t *pids;
struct childdata **children;
struct stats_published *shm_published;

struct fake_slot_log fake_slot_log[FAKE_NR_CHILDREN];
pid_t fake_killed_pid;
char fake_output_log[1024];

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
	fake_killed_pid = 0;
	fake_output_log[0] = '\0';
}

pid_t fake_hold_task(int stopsig)
{
	pid_t parent = getpid();
	pid_t pid = fork();

	if (pid < 0)
		BUG("fake parent: fork failed");
	if (pid == 0) {
		prctl(PR_SET_PDEATHSIG, SIGKILL);
		if (getppid() == parent) {
			if (stopsig != 0)
				raise(stopsig);
			for (;;)
				pause();
		}
		_exit(0);
	}
	return pid;
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

int find_childno(pid_t pid)
{
	unsigned int i;

	for_each_child(i) {
		if (pids[i] == pid)
			return i;
	}
	return CHILD_NOT_FOUND;
}

void kill_pid(pid_t pid)
{
	fake_killed_pid = pid;
}

void canary_queue_on_crash(int childno, int signo)
{
	(void)childno; (void)signo;
}

void record_reap(int childno, int childstatus)
{
	(void)childno; (void)childstatus;
}

void dump_child_fault_beacon(struct childdata *child)
{
	(void)child;
}

void pre_crash_ring_reset(struct pre_crash_ring *ring)
{
	(void)ring;
}

void inode_spewer_reap(pid_t pid)
{
	(void)pid;
}

void kmsg_monitor_note_reaped(pid_t pid, int status)
{
	(void)pid; (void)status;
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

void debugf(const char *fmt, ...)
{
	(void)fmt;
}

void output(int level, const char *fmt, ...)
{
	size_t used = strlen(fake_output_log);
	va_list args;

	(void)level;
	va_start(args, fmt);
	vsnprintf(fake_output_log + used, sizeof(fake_output_log) - used,
		  fmt, args);
	va_end(args);
}
