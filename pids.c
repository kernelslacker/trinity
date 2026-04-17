#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>
#include "params.h"	// dangerous
#include "pids.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"

#include <debug.h>

pid_t *pids;

/* Per-child cache: set once in init_child(), avoids O(n) scans. */
static int cached_childno = CHILD_NOT_FOUND;
static pid_t cached_pid = EMPTY_PIDSLOT;
static struct childdata *cached_child = NULL;

void set_child_cache(int childno, pid_t pid, struct childdata *child)
{
	cached_childno = childno;
	cached_pid = pid;
	cached_child = child;
}

bool pid_alive(pid_t pid)
{
	if (pid < -1) {
		syslogf("kill_pid tried to kill %d!\n", pid);
		show_backtrace();
		return true;
	}
	if (pid == -1) {
		syslogf("kill_pid tried to kill -1!\n");
		show_backtrace();
		return true;
	}
	if (pid == 0) {
		syslogf("tried to kill_pid 0!\n");
		show_backtrace();
		return true;
	}

	if (kill(pid, 0) == 0)
		return true;
	return false;
}

struct childdata * this_child(void)
{
	if (cached_childno != CHILD_NOT_FOUND && cached_pid == getpid())
		return cached_child;

	/* Fallback for main process or before cache is set */
	pid_t mypid = getpid();
	unsigned int i;

	for_each_child(i) {
		if (__atomic_load_n(&pids[i], __ATOMIC_RELAXED) == mypid)
			return children[i];
	}
	return NULL;
}

int find_childno(pid_t mypid)
{
	if (cached_childno != CHILD_NOT_FOUND && cached_pid == mypid)
		return cached_childno;

	unsigned int i;

	for_each_child(i) {
		if (__atomic_load_n(&pids[i], __ATOMIC_RELAXED) == mypid)
			return i;
	}
	return CHILD_NOT_FOUND;
}

bool pidmap_empty(void)
{
	unsigned int i;

	for_each_child(i) {
		if (__atomic_load_n(&pids[i], __ATOMIC_RELAXED) != EMPTY_PIDSLOT)
			return false;
	}
	return true;
}

void dump_childnos(void)
{
	unsigned int i, j = 0;
	char string[512], *sptr = string;
	char *end = string + sizeof(string);
	int n;

	n = snprintf(sptr, end - sptr, "## pids: (%u active)\n",
		     __atomic_load_n(&shm->running_childs, __ATOMIC_RELAXED));
	if (n > 0 && n < end - sptr)
		sptr += n;

	for (i = 0; i < max_children; i += 8) {
		n = snprintf(sptr, end - sptr, "%u-%u: ", i, i + 7);
		if (n > 0 && n < end - sptr)
			sptr += n;
		for (j = 0; j < 8; j++) {
			if (i + j >= max_children)
				break;

			if (__atomic_load_n(&pids[i + j], __ATOMIC_RELAXED) == EMPTY_PIDSLOT) {
				n = snprintf(sptr, end - sptr, "[empty] ");
			} else {
				pid_t pid = __atomic_load_n(&pids[i + j], __ATOMIC_RELAXED);

				n = snprintf(sptr, end - sptr, "%u ", pid);
			}
			if (n > 0 && n < end - sptr)
				sptr += n;
		}
		n = snprintf(sptr, end - sptr, "\n");
		if (n > 0 && n < end - sptr)
			sptr += n;
		*sptr = '\0';
		outputerr("%s", string);
		sptr = string;
	}
}

static pid_t pidmax;

static int read_pid_max(void)
{
	unsigned long result;
	char *end, buf[32];
	FILE *fp;
	int rc;

	fp = fopen("/proc/sys/kernel/pid_max", "r");
	if (!fp) {
		perror("fopen");
		return -1;
	}

	rc = -1;
	if (!fgets(buf, sizeof(buf), fp))
		goto out;

	errno = 0;
	result = strtoul(buf, &end, 10);
	if (end == buf)
		goto out;
	if (errno == ERANGE)
		goto out;

	pidmax = result;
	rc = 0;
out:
	fclose(fp);
	return rc;
}

void pids_init(void)
{
	unsigned int i;

	if (read_pid_max()) {
#ifdef __x86_64__
		pidmax = 4194304;
#else
		pidmax = 32768;
#endif
		outputerr("Couldn't read pid_max from proc\n");
	}

	output(0, "Using pid_max = %d\n", pidmax);

	pids = alloc_shared(max_children * sizeof(pid_t));
	for_each_child(i)
		__atomic_store_n(&pids[i], EMPTY_PIDSLOT, __ATOMIC_RELAXED);
}

int pid_is_valid(pid_t pid)
{
	if ((pid > pidmax) || (pid < 1))
		return false;

	return true;
}

unsigned int get_pid(void)
{
	unsigned int i;
	pid_t pid = 0;
	unsigned int dice;

	/* If we get called from the parent, and there are no
	 * children around yet, we need to not look at the pidmap. */
	if (__atomic_load_n(&shm->running_childs, __ATOMIC_RELAXED) == 0)
		return 0;

	/*
	 * Bias heavily toward real live child PIDs so that process-targeting
	 * syscalls (kill, ptrace, waitpid, etc.) actually reach running
	 * processes rather than failing with ESRCH.
	 *
	 *  70%: a real child from pids[]
	 *  15%: our own PID (valid, exercises self-targeting)
	 *  10%: 0 (process group semantics)
	 *   5%: 1 (init; only when dangerous flag set)
	 */
	dice = rand() % 100;

	if (dice < 70) {
		unsigned int retries = 0;
retry:		i = rand() % max_children;
		pid = __atomic_load_n(&pids[i], __ATOMIC_RELAXED);
		if (pid == EMPTY_PIDSLOT || pid == getppid()) {
			if (++retries >= 100)
				return getpid();
			goto retry;
		}
		return pid;
	}

	if (dice < 85)
		return getpid();

	if (dice < 95)
		return 0;

	/* dice 95-99: return 1 only when dangerous is set */
	if (dangerous)
		return 1;

	return getpid();
}
