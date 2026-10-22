/*
 * Self-checks for utils/pidstat-probe.c.
 *
 * pidstat_task_gone() replaced a kill(pid, 0) liveness probe in the
 * reap path, because kill() asks about a pid *number* and therefore
 * lies once the kernel recycles that number onto an unrelated
 * process.  The replacement is only sound because of a procfs
 * property that nothing in this tree controls: a read through an fd
 * opened on /proc/<pid>/stat fails once the task struct behind it is
 * released, and keeps succeeding while the task merely exited and is
 * waiting to be reaped.  If that ever changes, the reap path silently
 * goes back to leaking slots -- so pin the behaviour with a test
 * rather than trusting the comment that asserts it.
 *
 *   - probe_no_fd:      fd < 0 means "no oracle", not "task gone".
 *                       Callers whose open failed soft must keep
 *                       their old fallback instead of reaping a slot
 *                       whose child may well be running.
 *
 *   - probe_live_self:  an fd on our own /proc/self/stat reads, so a
 *                       live task is never reported gone.
 *
 *   - probe_zombie_then_gone: fork a child that exits immediately,
 *                       open its stat file, and prove the probe says
 *                       "not gone" while it is an unreaped zombie
 *                       (the waitpid(-1) drain owns those), then says
 *                       "gone" after the wait releases the task.
 *
 *   - probe_failed_read: only the released task's ESRCH counts as gone.
 *                       A read that fails any other way, or reads
 *                       nothing, says nothing about the task, and
 *                       reaping the slot of a live child on it leaves
 *                       the child running with nothing to track or
 *                       kill it.  pread() is wrapped so each failure
 *                       can be injected.
 *
 * The fork here is the only one in the test binary.  It is a bare
 * fork/_exit/waitpid with no shm and no trinity state, and the parent
 * waits for it before returning, so nothing outlives the check.
 *
 * pidstat_read() asks the same question by pid number, for pid_alive()
 * and pid_start_time().  Only a pid with no task reads as gone: a read
 * that fails for any other reason, a full fd table above all, must not,
 * or a live lock holder looks dead and a running child skips its SIGKILL.
 * ENOENT is one of those reasons unless kill(pid, 0) agrees: hidepid=2
 * and a /proc mounted for another pid namespace answer it for a task the
 * caller can signal.  The kill() wrapper in fake_parent.c stands in for
 * what kill() says.
 *
 * pidstat_parse() picks the state and start_time out of a stat line, and
 * pidstat_identity_gone() builds the lock recovery test on it: is the
 * task a lock recorded as (pid, start_time) gone.  The parse is checked
 * against lines of the test's own and against a stat line the kernel
 * wrote, and the test against tasks the test holds.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "debug.h"			/* BUG */
#include "fake_parent.h"
#include "pidstat-probe.h"
#include "utils.h"			/* waitpid_eintr */
#include "utils-macros.h"		/* ARRAY_SIZE */

/*
 * pread() failure injection (-Wl,--wrap=pread): while pread_fail_times is
 * non-zero, a pread of pread_fail_fd fails with pread_fail_errno, or reads
 * no bytes when that is 0, and counts down.  Every other call, and every
 * call of pread_fail_fd once it has run out, goes to the real pread().
 */
static int pread_fail_fd = -1;
static unsigned int pread_fail_times;
static int pread_fail_errno;
static unsigned int pread_calls;

ssize_t __real_pread(int fd, void *buf, size_t count, off_t offset);
ssize_t __wrap_pread(int fd, void *buf, size_t count, off_t offset);
ssize_t __wrap_pread(int fd, void *buf, size_t count, off_t offset)
{
	if (fd == pread_fail_fd) {
		pread_calls++;
		if (pread_fail_times > 0) {
			pread_fail_times--;
			if (pread_fail_errno == 0)
				return 0;
			errno = pread_fail_errno;
			return -1;
		}
	}
	return __real_pread(fd, buf, count, offset);
}

static int open_pidstat(pid_t pid)
{
	char path[64];

	snprintf(path, sizeof(path), "/proc/%d/stat", pid);

	return open(path, O_RDONLY | O_CLOEXEC);
}

static void selftest_no_fd(void)
{
	if (pidstat_task_gone(-1) != false)
		BUG("pidstat probe: fd -1 must not report the task gone");
}

static void selftest_live_self(void)
{
	int fd;

	fd = open_pidstat(getpid());
	if (fd < 0)
		BUG("pidstat probe: cannot open own /proc/<pid>/stat");

	if (pidstat_task_gone(fd) != false)
		BUG("pidstat probe: live task reported gone");

	close(fd);
}

static void selftest_zombie_then_gone(void)
{
	pid_t pid, waited;
	int fd, status;

	pid = fork();
	if (pid < 0)
		BUG("pidstat probe: fork failed");

	if (pid == 0)
		_exit(0);

	/* The child may be running or already a zombie by the time we
	 * get here; either way its stat file exists and reads, which is
	 * the point -- an exited-but-unreaped task is not "gone". */
	fd = open_pidstat(pid);
	if (fd < 0)
		BUG("pidstat probe: cannot open child /proc/<pid>/stat");

	if (pidstat_task_gone(fd) != false)
		BUG("pidstat probe: unreaped child reported gone");

	waited = waitpid_eintr(pid, &status, 0);
	if (waited != pid)
		BUG("pidstat probe: waitpid did not reap the child");

	if (pidstat_task_gone(fd) != true)
		BUG("pidstat probe: reaped child not reported gone");

	close(fd);
}

struct read_case {
	const char *what;
	int err;		/* 0: the read returns no bytes */
	bool gone;
	unsigned int calls;	/* preads of the fd the probe makes */
};

/*
 * The probe reads our own stat file, which never fails by itself, so what
 * the injected read does is the whole answer.  ESRCH is what procfs gives
 * once the task is released (proc_single_show(), handed back unchanged by
 * seq_read_iter()).  ENOMEM is what a live task's fd gives when the
 * seq_file buffer cannot be allocated.  EINTR is retried, so the second,
 * real read decides.
 */
static const struct read_case read_cases[] = {
	{ "ESRCH", ESRCH, true, 1 },
	{ "ENOMEM", ENOMEM, false, 1 },
	{ "EACCES", EACCES, false, 1 },
	{ "EIO", EIO, false, 1 },
	{ "no bytes", 0, false, 1 },
	{ "EINTR, then the real read", EINTR, false, 2 },
};

static void selftest_failed_read(void)
{
	unsigned int i;
	int fd;

	fd = open_pidstat(getpid());
	if (fd < 0)
		BUG("pidstat probe: cannot open own /proc/<pid>/stat");

	for (i = 0; i < ARRAY_SIZE(read_cases); i++) {
		const struct read_case *c = &read_cases[i];
		bool gone;

		pread_fail_fd = fd;
		pread_fail_times = 1;
		pread_fail_errno = c->err;
		pread_calls = 0;
		gone = pidstat_task_gone(fd);
		pread_fail_fd = -1;

		if (gone != c->gone) {
			fprintf(stderr, "pidstat probe: read case: %s\n", c->what);
			BUG("pidstat probe: a failed read decided the wrong way");
		}
		if (pread_calls != c->calls) {
			fprintf(stderr, "pidstat probe: read case: %s\n", c->what);
			BUG("pidstat probe: the read was not retried exactly when it was interrupted");
		}
	}

	close(fd);
}

static void selftest_read_live_and_gone(void)
{
	char buf[512], want[32];

	if (pidstat_read(getpid(), buf, sizeof(buf)) != PIDSTAT_OK)
		BUG("pidstat read: a live task did not read");
	snprintf(want, sizeof(want), "%d (", getpid());
	if (strncmp(buf, want, strlen(want)) != 0)
		BUG("pidstat read: the line read is not our own stat line");

	/* No pid reaches INT_MAX, so procfs has no task for it. */
	if (pidstat_read(INT_MAX, buf, sizeof(buf)) != PIDSTAT_GONE)
		BUG("pidstat read: a pid with no task did not read as gone");

	/* Nor is any task numbered 0 or below, and kill() would take those
	 * for a process group, which always has someone to signal. */
	if (pidstat_read(0, buf, sizeof(buf)) != PIDSTAT_GONE ||
	    pidstat_read(-1, buf, sizeof(buf)) != PIDSTAT_GONE)
		BUG("pidstat read: a pid that names no task did not read as gone");
}

/*
 * No pid reaches INT_MAX, so the open of its stat file always fails with
 * ENOENT; what kill() then says is the whole answer.  The real kill()
 * says ESRCH, which selftest_read_live_and_gone() covers.  EPERM is what
 * a caller without CAP_KILL over a task of another uid gets, and the
 * pair hidepid=2 makes of ENOENT and EPERM is the usual way a live task
 * reads as absent.  EACCES is what the security_task_kill hooks give.
 */
static const int enoent_kill_errnos[] = { EPERM, EACCES };

static void selftest_read_enoent_needs_kill(void)
{
	unsigned int i;
	char buf[512];

	for (i = 0; i < ARRAY_SIZE(enoent_kill_errnos); i++) {
		enum pidstat_result res;

		fake_kill_probe_pid = INT_MAX;
		fake_kill_probe_errno = enoent_kill_errnos[i];
		res = pidstat_read(INT_MAX, buf, sizeof(buf));
		fake_kill_probe_errno = 0;

		if (res != PIDSTAT_UNKNOWN) {
			fprintf(stderr, "pidstat read: kill() failed with %s\n",
				strerror(enoent_kill_errnos[i]));
			BUG("pidstat read: ENOENT read as gone though kill() still sees the pid");
		}
	}
}

/*
 * With the soft RLIMIT_NOFILE at the lowest free fd number the open of
 * the stat file fails with EMFILE, whatever the task is.  That says
 * nothing about it, so the pid number decides whether a lock holder is
 * gone: kill(pid, 0) finding the task keeps it, and ESRCH from kill()
 * ends it, whatever start time the lock recorded.
 */
static void selftest_read_out_of_fds(void)
{
	bool gone_alive, gone_esrch;
	struct rlimit orig, lim;
	enum pidstat_result res;
	char buf[512];
	int lowest_free;

	lowest_free = open("/dev/null", O_RDONLY | O_CLOEXEC);
	if (lowest_free < 0 || getrlimit(RLIMIT_NOFILE, &orig) != 0)
		BUG("pidstat read: cannot find the lowest free fd");
	close(lowest_free);

	lim = orig;
	lim.rlim_cur = lowest_free;
	if (setrlimit(RLIMIT_NOFILE, &lim) != 0)
		BUG("pidstat read: cannot lower RLIMIT_NOFILE");
	res = pidstat_read(getpid(), buf, sizeof(buf));
	gone_alive = pidstat_identity_gone(getpid(), 1);
	fake_kill_probe_pid = getpid();
	fake_kill_probe_errno = ESRCH;
	gone_esrch = pidstat_identity_gone(getpid(), 1);
	fake_kill_probe_errno = 0;
	if (setrlimit(RLIMIT_NOFILE, &orig) != 0)
		BUG("pidstat read: cannot restore RLIMIT_NOFILE");

	if (res != PIDSTAT_UNKNOWN)
		BUG("pidstat read: a full fd table did not read as unknown");
	if (gone_alive)
		BUG("pidstat identity: a full fd table read a live holder as gone");
	if (!gone_esrch)
		BUG("pidstat identity: ESRCH from kill() did not end a holder /proc could not read");
}

/* Fields 4 to 21 of a stat line, which the parser only walks past. */
#define STAT_TAIL "1 1234 1234 0 -1 4194560 1 0 0 0 1 2 0 0 20 0 1 0"

struct parse_case {
	const char *what;
	const char *line;
	char state;
	unsigned long long start_time;
};

static const struct parse_case parse_cases[] = {
	{ "plain line", "1234 (bash) S " STAT_TAIL " 987654 4096 1",
	  'S', 987654 },
	{ "comm holding ')' and spaces", "42 (a) b (c)) Z " STAT_TAIL " 555 0 0",
	  'Z', 555 },
	{ "no ')'", "1234 bash S 1", '?', PID_START_TIME_UNKNOWN },
	{ "no space after ')'", "1 (x)S 1", '?', PID_START_TIME_UNKNOWN },
	{ "empty line", "", '?', PID_START_TIME_UNKNOWN },
	{ "ends at the state", "1 (x) S", 'S', PID_START_TIME_UNKNOWN },
	{ "stops short of start_time", "1 (x) S " STAT_TAIL,
	  'S', PID_START_TIME_UNKNOWN },
};

static void selftest_parse(void)
{
	unsigned long long start = 0;
	struct pidstat_fields f;
	char buf[512], state = 0;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(parse_cases); i++) {
		const struct parse_case *c = &parse_cases[i];

		f = pidstat_parse(c->line);
		if (f.state != c->state || f.start_time != c->start_time) {
			fprintf(stderr, "pidstat parse: case: %s\n", c->what);
			BUG("pidstat parse: a line read as the wrong fields");
		}
	}

	/* A line the kernel wrote, with the fields picked out by a format
	 * that counts them on its own: the state and the 22nd field. */
	if (pidstat_read(getpid(), buf, sizeof(buf)) != PIDSTAT_OK)
		BUG("pidstat parse: cannot read our own stat line");
	if (sscanf(strrchr(buf, ')') + 2, "%c"
		   " %*s %*s %*s %*s %*s %*s %*s %*s %*s"
		   " %*s %*s %*s %*s %*s %*s %*s %*s %*s"
		   " %llu", &state, &start) != 2)
		BUG("pidstat parse: cannot pick fields out of our own stat line");
	f = pidstat_parse(buf);
	if (f.state != state || f.start_time != start)
		BUG("pidstat parse: a line from the kernel read as the wrong fields");
}

static unsigned long long start_time_of(pid_t pid)
{
	unsigned long long start;
	char buf[512];

	if (pidstat_read(pid, buf, sizeof(buf)) != PIDSTAT_OK)
		BUG("pidstat identity: cannot read the held task's stat line");
	start = pidstat_parse(buf).start_time;
	if (start == PID_START_TIME_UNKNOWN)
		BUG("pidstat identity: the held task's start time did not parse");
	return start;
}

static void end_task(pid_t pid)
{
	if (kill(pid, SIGKILL) != 0 || waitpid_eintr(pid, NULL, 0) != pid)
		BUG("pidstat identity: cannot end the held task");
}

static void selftest_identity_live_recycled_gone(void)
{
	unsigned long long start;
	pid_t pid;

	pid = fake_hold_task(0);
	start = start_time_of(pid);

	if (pidstat_identity_gone(pid, start))
		BUG("pidstat identity: a live task with its recorded start time read as gone");

	/* The pid reissued to a task that started later is not the holder. */
	if (!pidstat_identity_gone(pid, start + 1))
		BUG("pidstat identity: a pid with another start time did not read as recycled");

	end_task(pid);
	if (!pidstat_identity_gone(pid, start))
		BUG("pidstat identity: a reaped task did not read as gone");

	/* No task has pid 0 or below, however the start time compares. */
	if (!pidstat_identity_gone(0, start) || !pidstat_identity_gone(-1, start))
		BUG("pidstat identity: a pid that names no task did not read as gone");
}

/*
 * End a held task and leave it an unreaped zombie: waitid() with WNOWAIT
 * returns once the task has exited, and does not reap it.
 */
static void leave_zombie(pid_t pid)
{
	siginfo_t si;

	if (kill(pid, SIGKILL) != 0)
		BUG("pidstat identity: cannot kill the held task");
	while (waitid(P_PID, pid, &si, WEXITED | WNOWAIT) != 0) {
		if (errno != EINTR)
			BUG("pidstat identity: cannot wait for the held task to exit");
	}
}

/*
 * A zombie still answers kill() and still reads in /proc with the start
 * time it ran with, but it never runs again to release a lock, and a
 * parent spinning in lock() on it never gets to reap it.
 */
static void selftest_identity_zombie(void)
{
	unsigned long long start;
	struct pidstat_fields f;
	char buf[512];
	pid_t pid;

	pid = fake_hold_task(0);
	start = start_time_of(pid);
	leave_zombie(pid);

	if (kill(pid, 0) != 0 ||
	    pidstat_read(pid, buf, sizeof(buf)) != PIDSTAT_OK)
		BUG("pidstat identity: the zombie is not there to be seen");
	f = pidstat_parse(buf);
	if (f.state != 'Z' || f.start_time != start)
		BUG("pidstat identity: the zombie did not read as state Z with its start time");

	if (!pidstat_identity_gone(pid, start))
		BUG("pidstat identity: a zombie holder with its recorded start time read as alive");

	if (waitpid_eintr(pid, NULL, 0) != pid)
		BUG("pidstat identity: cannot reap the zombie");
}

void pidstat_probe_self_check(void);
void pidstat_probe_self_check(void)
{
	selftest_no_fd();
	selftest_live_self();
	selftest_zombie_then_gone();
	selftest_failed_read();
	selftest_read_live_and_gone();
	selftest_read_enoent_needs_kill();
	selftest_read_out_of_fds();
	selftest_parse();
	selftest_identity_live_recycled_gone();
	selftest_identity_zombie();
}
