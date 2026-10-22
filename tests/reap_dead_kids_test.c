/*
 * Self-check for the second pass of reap_dead_kids() (main/reap.c): a
 * slot with a pidstat fd is judged by that fd alone, and one without is
 * probed with kill(pid, 0), where only ESRCH reaps it.  The probe is
 * failed with any errno, and the probes counted, through the kill()
 * wrapper in fake_parent.c, which is transparent unless armed.
 */

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "debug.h"		/* BUG */
#include "main-internal.h"
#include "params.h"		/* verbosity */
#include "pids.h"
#include "shm.h"
#include "utils-macros.h"	/* ARRAY_SIZE */
#include "utils.h"		/* waitpid_eintr */

#include "fake_parent.h"

/* Owned by main/params/state.c in production. */
unsigned char verbosity = 1;

static void start_scenario(void)
{
	fake_parent_reset();
	shm->running_childs = 0;
	verbosity = 1;
}

/* A task that stays alive, in @slot, as a running child. */
static pid_t occupy_slot(unsigned int slot)
{
	pid_t pid = fake_hold_task(0);

	pids[slot] = pid;
	shm->running_childs = 1;
	return pid;
}

static void end_task(pid_t pid)
{
	if (kill(pid, SIGKILL) != 0 || waitpid_eintr(pid, NULL, 0) != pid)
		BUG("reap dead kids: cannot end the held task");
}

/* A slot whose task another path already waited for: its pidstat fd was
 * opened while the task existed, so it now answers that the task is
 * gone.  The second pass must reap the slot from the fd alone. */
static void pidstat_fd_reaps_a_gone_task(unsigned int slot)
{
	pid_t pid;

	start_scenario();
	pid = fork();
	if (pid < 0)
		BUG("reap dead kids: fork failed");
	if (pid == 0)
		_exit(0);

	pidstatfiles[slot] = open_child_pidstat(pid);
	if (pidstatfiles[slot] < 0)
		BUG("reap dead kids: cannot open the task's stat file");
	if (waitpid_eintr(pid, NULL, 0) != pid)
		BUG("reap dead kids: cannot wait for the exited task");
	pids[slot] = pid;
	shm->running_childs = 1;

	reap_dead_kids();

	if (pids[slot] != EMPTY_PIDSLOT || pidstatfiles[slot] != -1 ||
	    shm->running_childs != 0)
		BUG("reap dead kids: a gone task's slot was not reaped");
	if (strstr(fake_output_log, "disappeared") == NULL)
		BUG("reap dead kids: a gone task was reaped without a word");
	if (fake_kill_probes != 0)
		BUG("reap dead kids: a slot with a pidstat fd was probed");
}

/* A live task's pidstat fd is the whole answer, however verbose the
 * run: a kill() probe on top of it is a syscall per slot per pass. */
static void pidstat_fd_leaves_a_live_task(unsigned int slot)
{
	pid_t pid;

	start_scenario();
	verbosity = 2;
	pid = occupy_slot(slot);
	pidstatfiles[slot] = open_child_pidstat(pid);
	if (pidstatfiles[slot] < 0)
		BUG("reap dead kids: cannot open the task's stat file");

	reap_dead_kids();

	if (pids[slot] != pid || shm->running_childs != 1)
		BUG("reap dead kids: a live task's slot was reaped");
	if (fake_kill_probes != 0)
		BUG("reap dead kids: a slot with a pidstat fd was probed");

	close(pidstatfiles[slot]);
	pidstatfiles[slot] = -1;
	end_task(pid);
}

struct probe_case {
	int err;
	bool reaped;
};

/* A slot with no pidstat fd falls back to kill(pid, 0).  The task
 * stays alive under every errno, so the answer must come from the errno
 * alone: only ESRCH says the pid is gone.  EPERM is what the kernel's
 * uid and CAP_KILL check gives, a security module's CAP_KILL hook
 * included, and EACCES what the security_task_kill hooks give; neither
 * may reap a live slot, and neither is a privilege drop. */
static const struct probe_case probe_cases[] = {
	{ ESRCH, true },
	{ EPERM, false },
	{ EACCES, false },
};

static void kill_probe_decides_without_a_pidstat_fd(unsigned int slot,
						    const struct probe_case *c)
{
	pid_t pid;

	start_scenario();
	pid = occupy_slot(slot);
	fake_kill_probe_pid = pid;
	fake_kill_probe_errno = c->err;

	reap_dead_kids();

	if (fake_kill_probes == 0)
		BUG("reap dead kids: a slot with no pidstat fd was not probed");
	if (c->reaped) {
		if (pids[slot] != EMPTY_PIDSLOT || shm->running_childs != 0)
			BUG("reap dead kids: ESRCH did not reap the slot");
		if (strstr(fake_output_log, "disappeared") == NULL)
			BUG("reap dead kids: ESRCH reaped without a word");
	} else {
		if (pids[slot] != pid || shm->running_childs != 1)
			BUG("reap dead kids: a failed probe reaped a live slot");
		if (strstr(fake_output_log, strerror(c->err)) == NULL)
			BUG("reap dead kids: a failed probe was not reported");
		if (strstr(fake_output_log, "dropped privileges") != NULL)
			BUG("reap dead kids: a failed probe was put down to a privilege drop");
	}

	end_task(pid);
}

void reap_dead_kids_self_check(void);
void reap_dead_kids_self_check(void)
{
	unsigned int i;

	pidstat_fd_reaps_a_gone_task(2);
	pidstat_fd_leaves_a_live_task(3);
	for (i = 0; i < ARRAY_SIZE(probe_cases); i++)
		kill_probe_decides_without_a_pidstat_fd(5, &probe_cases[i]);

	/* Leave no armed probe for later suites. */
	start_scenario();
}
