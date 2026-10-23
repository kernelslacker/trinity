/*
 * Self-checks for utils/pidstat-probe.c.  pidstat_task_gone() is only sound
 * because of a procfs property nothing in this tree controls: a read through
 * an fd on /proc/<pid>/stat fails once the task struct is released and keeps
 * succeeding while the task is an unreaped zombie.  If that changed, the reap
 * path would silently leak slots, so the cases pin it and the helpers on it.
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

/* The child is a bare fork/_exit with no shm and no trinity state, and the
 * wait below reaps it, so nothing outlives the check. */
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
 * Put the soft RLIMIT_NOFILE at the lowest free fd number, so that every
 * open of a stat file fails with EMFILE, whatever the task is.  @orig gets
 * the limit to put back.
 */
static void limit_fds(struct rlimit *orig)
{
	struct rlimit lim;
	int lowest_free;

	lowest_free = open("/dev/null", O_RDONLY | O_CLOEXEC);
	if (lowest_free < 0 || getrlimit(RLIMIT_NOFILE, orig) != 0)
		BUG("pidstat read: cannot find the lowest free fd");
	close(lowest_free);

	lim = *orig;
	lim.rlim_cur = lowest_free;
	if (setrlimit(RLIMIT_NOFILE, &lim) != 0)
		BUG("pidstat read: cannot lower RLIMIT_NOFILE");
}

/*
 * With the fd table full the open of the stat file says nothing about
 * the task, so the pid number decides whether a lock holder is gone:
 * kill(pid, 0) finding the task keeps it, and ESRCH from kill() ends it,
 * whatever start time the lock recorded.
 */
static void selftest_read_out_of_fds(void)
{
	bool gone_alive, gone_esrch;
	enum pidstat_result res;
	struct rlimit orig;
	char buf[512];

	limit_fds(&orig);
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

/*
 * A lock stamped while its owner's /proc read failed records 0 or
 * PID_START_TIME_UNKNOWN, which no live start time equals.  There is no
 * fingerprint to compare then, so a live holder must not read as a
 * recycled pid: whether the task is still there decides, and a zombie is
 * not.
 */
static const unsigned long long unrecorded_starts[] = {
	0, PID_START_TIME_UNKNOWN,
};

static void selftest_identity_unrecorded_start(void)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(unrecorded_starts); i++) {
		unsigned long long recorded = unrecorded_starts[i];
		bool live_gone, zombie_gone, reaped_gone;
		pid_t pid = fake_hold_task(0);

		live_gone = pidstat_identity_gone(pid, recorded);
		leave_zombie(pid);
		zombie_gone = pidstat_identity_gone(pid, recorded);
		if (waitpid_eintr(pid, NULL, 0) != pid)
			BUG("pidstat identity: cannot reap the zombie");
		reaped_gone = pidstat_identity_gone(pid, recorded);

		if (live_gone || !zombie_gone || !reaped_gone) {
			fprintf(stderr, "pidstat identity: recorded start time %#llx: gone while live %d, as a zombie %d, reaped %d\n",
				recorded, live_gone, zombie_gone, reaped_gone);
			BUG("pidstat identity: a holder with no usable start time was judged by it");
		}
	}
}

/*
 * waitid() with WNOWAIT on a child of ours: one that still runs reads as
 * not exited, and one that has exited reads as exited however often it is
 * asked, since looking must not reap it, and the wait the reap path makes
 * afterwards still gets it.  A pid that is not our child, a reaped one
 * included, gets ECHILD, which says nothing about it, and so does a pid of
 * 0 or below.
 */
static void selftest_child_exited(void)
{
	pid_t pid = fake_hold_task(0);

	if (pidstat_child_exited(pid))
		BUG("pidstat child: a child that is still running read as exited");

	leave_zombie(pid);
	if (!pidstat_child_exited(pid))
		BUG("pidstat child: an exited child that was not waited for did not read as exited");
	if (!pidstat_child_exited(pid))
		BUG("pidstat child: asking about an exited child reaped it");
	if (waitpid_eintr(pid, NULL, 0) != pid)
		BUG("pidstat child: asking took the zombie from the reap path");

	if (pidstat_child_exited(pid))
		BUG("pidstat child: a reaped child read as exited");
	if (pidstat_child_exited(getpid()) || pidstat_child_exited(getppid()))
		BUG("pidstat child: a pid that is not our child read as exited");
	if (pidstat_child_exited(0) || pidstat_child_exited(-1))
		BUG("pidstat child: a pid that names no task read as exited");
}

/*
 * A zombie that /proc cannot show and kill() refuses is still a zombie,
 * and a parent spinning in lock() on one cannot reap it.  The fd table
 * stands in for the /proc that cannot say, and EPERM for the probe that is
 * refused.  The child that still runs says nothing, and keeps its verdict.
 */
static void selftest_identity_zombie_proc_cannot_say(void)
{
	bool zombie_gone, refused_gone, running_gone;
	unsigned long long start;
	pid_t zombie, running;
	struct rlimit orig;

	zombie = fake_hold_task(0);
	running = fake_hold_task(0);
	start = start_time_of(zombie);
	leave_zombie(zombie);

	limit_fds(&orig);
	zombie_gone = pidstat_identity_gone(zombie, start);
	fake_kill_probe_pid = zombie;
	fake_kill_probe_errno = EPERM;
	refused_gone = pidstat_identity_gone(zombie, start);
	fake_kill_probe_errno = 0;
	running_gone = pidstat_identity_gone(running, start);
	if (setrlimit(RLIMIT_NOFILE, &orig) != 0)
		BUG("pidstat identity: cannot restore RLIMIT_NOFILE");

	if (waitpid_eintr(zombie, NULL, 0) != zombie)
		BUG("pidstat identity: cannot reap the zombie");
	end_task(running);

	if (!zombie_gone || !refused_gone || running_gone) {
		fprintf(stderr, "pidstat identity: /proc cannot say: zombie gone %d, with kill() refused %d, running child gone %d\n",
			zombie_gone, refused_gone, running_gone);
		BUG("pidstat identity: a zombie child was not told from a running one by wait");
	}
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
	selftest_identity_unrecorded_start();
	selftest_child_exited();
	selftest_identity_zombie_proc_cannot_say();
}
