#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "pidstat-probe.h"

/*
 * Task-identity liveness probe.
 *
 * A `kill(pid, 0)` probe answers a question about a pid *number*, not
 * about a task.  Once the kernel has recycled that number onto an
 * unrelated process the probe succeeds, so a dead child reads as
 * alive: its slot is never reaped, and the pid keeps being handed to
 * the process-targeting syscalls (kill, ptrace, ...) for the rest of
 * the run -- now aimed at a stranger.  The failure mode is
 * self-reinforcing, because the recycle is exactly what makes the
 * detector lie.
 *
 * An fd opened on /proc/<pid>/stat while the task existed is pinned to
 * that task rather than to the number, so it cannot be spoofed by a
 * recycle: procfs answers ESRCH once the task struct is released, no
 * matter who owns the pid now.  A zombie still reads fine (state Z) --
 * a task that has exited but not been waited for is not "gone" here,
 * which is what callers reaping via waitpid() want.
 *
 * Only that ESRCH counts as gone (proc_single_show() returns it, and
 * seq_read_iter() hands it back unchanged).  A read that fails any other
 * way, ENOMEM from the seq_file buffer or an LSM refusal, or returns no
 * bytes, says nothing about the task: reaping the slot of a live child
 * on it leaves the child running with nothing to track or kill it.  The
 * waitpid() drain still catches a real exit.  EINTR is retried.
 *
 * Returns false when there is no fd to ask, so a caller whose fd open
 * failed soft can fall back to whatever it did before rather than
 * treating an unopenable slot as dead.
 */
bool pidstat_task_gone(int fd)
{
	char buf[64];
	ssize_t n;

	if (fd < 0)
		return false;

	n = TEMP_FAILURE_RETRY(pread(fd, buf, sizeof(buf), 0));

	return (n < 0 && errno == ESRCH);
}

/*
 * Read /proc/<pid>/stat by pid number, for the callers that hold no fd
 * on the task: pid_alive() and pid_start_time().  Only ESRCH and an
 * ENOENT that kill(pid, 0) confirms say the task is gone: procfs answers
 * ESRCH once the task behind an entry it already holds is released, so
 * the open and the read can each say it.  ENOENT is its answer for a pid
 * it has no task for, but also what hidepid=2 gives a task the caller
 * may not read, and what a /proc mounted for another pid namespace gives
 * a pid that exists in the caller's.  kill() looks the pid up in the
 * caller's own namespace and sees both, so ESRCH from it is the proof.
 * Any other failure (EMFILE or ENFILE from a full fd table, ENOMEM,
 * EPERM under hidepid=1) says nothing about the task either, and reading
 * it as death releases a live holder's locks and skips the SIGKILL for a
 * running child.
 *
 * Raw open/read into the caller's stack buffer rather than
 * fopen/fread/fclose: this is the parent's hottest path (once per held
 * lock per check_all_locks tick and once per just-spawned child in
 * init_child) and stdio's per-call malloc of a FILE and its buffer is
 * heap traffic we don't need.  Under ASAN every one of those mallocs is
 * a candidate abort site; under normal builds it is just wasted work.
 */
enum pidstat_result pidstat_read(pid_t pid, char *buf, size_t size)
{
	char path[64];
	ssize_t n;
	int fd, err;

	/* No task has such a pid, and kill() would address a process group. */
	if (pid <= 0)
		return PIDSTAT_GONE;

	snprintf(path, sizeof(path), "/proc/%d/stat", pid);
	fd = TEMP_FAILURE_RETRY(open(path, O_RDONLY | O_CLOEXEC));
	if (fd < 0) {
		if (errno == ESRCH)
			return PIDSTAT_GONE;
		if (errno != ENOENT)
			return PIDSTAT_UNKNOWN;
		return (kill(pid, 0) == -1 && errno == ESRCH) ?
			PIDSTAT_GONE : PIDSTAT_UNKNOWN;
	}

	n = TEMP_FAILURE_RETRY(read(fd, buf, size - 1));
	err = errno;
	close(fd);
	if (n <= 0)
		return (n < 0 && err == ESRCH) ? PIDSTAT_GONE : PIDSTAT_UNKNOWN;

	buf[n] = '\0';
	return PIDSTAT_OK;
}

/*
 * Pick the fields the liveness callers need out of a stat line that
 * pidstat_read() returned: "pid (comm) state ppid ...".  The comm field
 * may contain ')' and spaces, so anchor on the LAST ')' and read the
 * state from the byte two after it.  After the closing ')' field 3
 * (state) starts; field 22 (start_time) is the 20th whitespace-separated
 * token after.  A field the line stops short of reads as '?' or
 * PID_START_TIME_UNKNOWN.
 */
struct pidstat_fields pidstat_parse(const char *buf)
{
	struct pidstat_fields f = { '?', PID_START_TIME_UNKNOWN };
	const char *p = strrchr(buf, ')');
	unsigned int field;

	if (p == NULL || p[1] != ' ' || p[2] == '\0')
		return f;

	f.state = p[2];

	p += 2;
	for (field = 3; field < 22; field++) {
		while (*p != '\0' && *p != ' ')
			p++;
		if (*p != ' ')
			return f;
		p++;
	}
	f.start_time = strtoull(p, NULL, 10);
	return f;
}

/*
 * Dead-owner fingerprint test used by all three lock recovery sites
 * (check_lock, try_release_dead_holder, force_bust_lock).  Returns true
 * when the task a lock recorded as (pid, start_time) is gone: the pid has
 * no task any more, the live start_time differs from the snapshot stored
 * at acquire time (pid recycled to a new process), or the task is a
 * zombie or dead (state Z or X).  A zombie still answers kill() and still
 * reads with the start_time it ran with, but it never runs again to
 * release anything, and the parent that spins in lock() on it cannot reap
 * it.
 *
 * A start_time of 0 or PID_START_TIME_UNKNOWN is what a lock holds when
 * its owner's /proc read failed as it stamped it.  No live task has that
 * start time, so comparing would call every live holder recycled; with no
 * fingerprint only the task decides, and one that is still there is taken
 * for the holder.
 *
 * When /proc cannot say (a full fd table, ENOMEM) the pid number decides:
 * ESRCH from kill(pid, 0) means no task holds it, so it is neither the
 * live holder nor a recycled pid.  The parent has to get that answer,
 * because lock() gives it no other way out of the spin on a holder that
 * is already reaped.  Returning false means the same holder is still
 * alive, or may be, and the caller must not release the lock.
 */
bool pidstat_identity_gone(pid_t pid, unsigned long long start_time)
{
	bool recorded = start_time != 0 && start_time != PID_START_TIME_UNKNOWN;
	char buf[512];
	enum pidstat_result res;

	res = pidstat_read(pid, buf, sizeof(buf));
	if (res == PIDSTAT_GONE)
		return true;

	if (res == PIDSTAT_OK) {
		struct pidstat_fields f = pidstat_parse(buf);

		if (f.state == 'Z' || f.state == 'X')
			return true;
		if (f.start_time != PID_START_TIME_UNKNOWN)
			return recorded && f.start_time != start_time;
	}
	return kill(pid, 0) == -1 && errno == ESRCH;
}
