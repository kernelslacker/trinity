/*
 * Parent environment for the PARENT_SRCS tests: storage for the parent
 * globals main/loop.c, main/reap.c, main/reap-zombie.c and
 * tables/table-meta.c read, and stand-ins for the parent calls their
 * reachable code makes.  Calls that act on one slot land in
 * fake_slot_log[], kill_pid() and output() keep what they were given,
 * and the rest do nothing.
 */

#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <time.h>
#include <unistd.h>

#include "child.h"
#include "debug.h"		/* BUG, classify_child_buglog, beacon_loss_* */
#include "fd-event.h"
#include "health/signals-internal.h"
#include "kmsg-monitor.h"
#include "locks.h"
#include "main-internal.h"
#include "main/reap-internal.h"
#include "pids.h"
#include "post-mortem.h"
#include "pre_crash_ring.h"
#include "random.h"
#include "shm.h"
#include "stats_ring.h"
#include "sysv-msg.h"
#include "sysv-sem.h"
#include "sysv-shm.h"
#include "tables.h"
#include "taint.h"
#include "trinity.h"
#include "utils.h"		/* kill_pid */

#include "fake_parent.h"

/* Owned by trinity-warmstart.c, dispatch/pids.c, utils/shm.c and
 * stats/stats-ring.c in production. */
unsigned int max_children;
pid_t *pids;
struct childdata **children;
struct fd_event_ring **expected_fd_event_rings;
struct stats_ring **expected_stats_rings;
struct stats_published *shm_published;

/* Owned by main/spawn.c in production. */
uint64_t spawn_stall_deadline;

/* Owned by tables/tables.c, tables-uniarch.c and tables-biarch.c in
 * production.  Empty, so get_syscall_entry() finds no entry. */
bool biarch;
const struct syscalltable *syscalls;
const struct syscalltable *syscalls_32bit;
const struct syscalltable *syscalls_64bit;
unsigned int max_nr_syscalls;
unsigned int max_nr_32bit_syscalls;
unsigned int max_nr_64bit_syscalls;

struct fake_slot_log fake_slot_log[FAKE_NR_CHILDREN];
pid_t fake_killed_pid;
unsigned int fake_sleeps;
void (*fake_sleep_hook)(void);
char fake_output_log[1024];
unsigned int fake_stray_ring_init;

static bool fake_clock_running;
static uint64_t fake_clock_now_ns;
static uint64_t fake_clock_started_ns;
static pid_t pid_slots[FAKE_NR_CHILDREN];
static int pidstat_slots[FAKE_NR_CHILDREN];
static time_t spawn_time_slots[FAKE_NR_CHILDREN];
static pid_t zombie_pid_slots[FAKE_NR_CHILDREN];
static time_t zombie_since_slots[FAKE_NR_CHILDREN];
static bool quarantine_slots[FAKE_NR_CHILDREN];
static struct childdata childdata[FAKE_NR_CHILDREN];
static struct childdata *child_ptrs[FAKE_NR_CHILDREN];
static struct fd_event_ring rings[FAKE_NR_CHILDREN];
static struct stats_ring stats_rings[FAKE_NR_CHILDREN];
static struct fd_event_ring *canary_fd_slots[FAKE_NR_CHILDREN];
static struct stats_ring *canary_stats_slots[FAKE_NR_CHILDREN];

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
	expected_fd_event_rings = canary_fd_slots;
	expected_stats_rings = canary_stats_slots;

	for_each_child(i) {
		children[i] = &childdata[i];
		children[i]->num = i;
		children[i]->fd_event_ring = &rings[i];
		children[i]->stats_ring = &stats_rings[i];
		expected_fd_event_rings[i] = &rings[i];
		expected_stats_rings[i] = &stats_rings[i];
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
	fake_stray_ring_init = 0;
	fake_clock_running = false;
	fake_sleeps = 0;
	fake_sleep_hook = NULL;
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
			if (stopsig != 0) {
				sigset_t set;

				/* A process group of its own in the test's
				 * session is not orphaned, so the kernel
				 * honours a job-control stop as well.  The
				 * harness may block or ignore the signal. */
				setpgid(0, 0);
				sigemptyset(&set);
				sigaddset(&set, stopsig);
				sigprocmask(SIG_UNBLOCK, &set, NULL);
				signal(stopsig, SIG_DFL);
				raise(stopsig);
			}
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
	if ((uintptr_t)ring < (uintptr_t)rings ||
	    (uintptr_t)ring >= (uintptr_t)&rings[FAKE_NR_CHILDREN]) {
		fake_stray_ring_init++;
		return;
	}
	fake_slot_log[ring - rings].ring_reset++;
}

void stats_ring_init(struct stats_ring *ring)
{
	if ((uintptr_t)ring < (uintptr_t)stats_rings ||
	    (uintptr_t)ring >= (uintptr_t)&stats_rings[FAKE_NR_CHILDREN]) {
		fake_stray_ring_init++;
		return;
	}
	fake_slot_log[ring - stats_rings].stats_ring_reset++;
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

int pid_is_valid(pid_t pid)
{
	return pid > 0;
}

bool pidmap_empty(void)
{
	unsigned int i;

	for_each_child(i) {
		if (pids[i] != EMPTY_PIDSLOT)
			return false;
	}
	return true;
}

/* Alive as far as kill(pid, 0) goes.  A zombie reads alive here, which
 * none of the tasks the tests hold is. */
bool pid_alive(pid_t pid)
{
	return kill(pid, 0) == 0;
}

/* No child holds a lock in a test. */
bool check_all_locks(void)
{
	return false;
}

void force_bust_lock(lock_t *lk)
{
	(void)lk;
}

bool is_tainted(void)
{
	return false;
}

void tainted_postmortem(void)
{
}

void __wrap_kill_pid(pid_t pid);
void __wrap_kill_pid(pid_t pid)
{
	fake_killed_pid = pid;
}

void canary_queue_on_crash(int childno, int signo)
{
	fake_slot_log[childno].canary_crashes++;
	fake_slot_log[childno].canary_signo = signo;
}

void record_reap(int childno, int childstatus)
{
	fake_slot_log[childno].reaps++;
	fake_slot_log[childno].reap_status = childstatus;
}

void dump_child_fault_beacon(struct childdata *child)
{
	(void)child;
}

/* What the fault handlers in health/ reach.  There is no childdata, no
 * tracked region and no bug log in a test, so a crash report is the
 * text on stderr and nothing more. */
unsigned long trinity_load_base;

const char *alt_op_name(enum child_op_type op)
{
	(void)op;
	return NULL;
}

bool range_in_tracked_shared(unsigned long addr, unsigned long len)
{
	(void)addr; (void)len;
	return false;
}

void open_buglog_and_drain_stderr(int sig)
{
	(void)sig;
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

int __real_clock_gettime(clockid_t clk, struct timespec *ts);
int __wrap_clock_gettime(clockid_t clk, struct timespec *ts);
unsigned int __real_sleep(unsigned int seconds);
unsigned int __wrap_sleep(unsigned int seconds);
int __real_usleep(useconds_t usec);
int __wrap_usleep(useconds_t usec);

void fake_clock_start(void)
{
	/* Well clear of 0, which the code under test uses for "unset". */
	fake_clock_now_ns = 1000 * 1000000000ULL;
	fake_clock_started_ns = fake_clock_now_ns;
	fake_sleeps = 0;
	fake_clock_running = true;
}

uint64_t fake_clock_elapsed_ns(void)
{
	return fake_clock_now_ns - fake_clock_started_ns;
}

int __wrap_clock_gettime(clockid_t clk, struct timespec *ts)
{
	if (!fake_clock_running || clk != CLOCK_MONOTONIC)
		return __real_clock_gettime(clk, ts);

	ts->tv_sec = fake_clock_now_ns / 1000000000ULL;
	ts->tv_nsec = fake_clock_now_ns % 1000000000ULL;
	return 0;
}

static void fake_sleep_ns(uint64_t ns)
{
	fake_clock_now_ns += ns;
	fake_sleeps++;
	if (fake_clock_elapsed_ns() > FAKE_CLOCK_LIMIT_S * 1000000000ULL)
		BUG("fake clock: slept past the limit, the code under test is spinning");
	if (fake_sleep_hook != NULL)
		fake_sleep_hook();
}

unsigned int __wrap_sleep(unsigned int seconds)
{
	if (!fake_clock_running)
		return __real_sleep(seconds);

	fake_sleep_ns(seconds * 1000000000ULL);
	return 0;
}

int __wrap_usleep(useconds_t usec)
{
	if (!fake_clock_running)
		return __real_usleep(usec);

	fake_sleep_ns(usec * 1000ULL);
	return 0;
}
