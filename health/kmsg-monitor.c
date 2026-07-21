/*
 * kmsg-monitor: live /dev/kmsg scraper for kernel diagnostic reports.
 *
 * Trinity already notices that the kernel went sideways via the taint
 * bit, but by the time taint flips we've lost the most useful piece of
 * evidence: the actual diagnostic dump (KASAN/KMSAN/KCSAN/UBSAN
 * report, lockdep splat, RCU stall, hung task warning, etc).  Those
 * land in the kernel printk ringbuffer as soon as the kernel notices
 * the bug, often *before* the taint bit gets set, and they roll out of
 * the buffer fast on busy systems.
 *
 * The monitor runs as a forked HELPER PROCESS (not a thread).  Doing
 * it in a parent-side pthread would force fork() to clone a multi-
 * threaded process every time the spawn loop carved a new fuzz child:
 * fork only inherits the calling thread, so if the spawn raced while
 * the monitor held glibc's stdio FILE lock the child would inherit the
 * lock held but ownerless and deadlock the first time it called into
 * fprintf.  Running the monitor as a separate process keeps the parent
 * single-threaded at fork time and gives the monitor its own glibc
 * stdio state.
 *
 * Lifecycle:
 *   - kmsg_monitor_start() fork()s once during early init (before the
 *     fuzz-child fork-storm).  Parent stashes the helper pid.
 *   - The helper installs a SIGTERM handler, requests
 *     PR_SET_PDEATHSIG=SIGTERM so it dies if the parent crashes, opens
 *     /dev/kmsg O_NONBLOCK, seeks to the end of the ringbuffer, and
 *     polls + reads records until SIGTERM.
 *   - kmsg_monitor_stop() SIGTERMs the helper and waitpids it.  ESRCH
 *     / ECHILD are tolerated: reap_dead_kids' generic waitpid(-1)
 *     drain may have already reaped the helper, and it calls
 *     kmsg_monitor_note_reaped() so the cached pid is cleared.
 *   - The helper is intentionally NOT registered in pids[]/
 *     running_childs/childdata — it is infrastructure, not a fuzz
 *     child, and the fuzz-side reap_child accounting does not apply.
 *
 * Scope is deliberately narrow: detect and log only.  Correlating
 * reports back to which child / which syscall provoked them is a
 * follow-up.
 */

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "kcov.h"		/* kcov_shm */
#include "kmsg-monitor.h"
#include "pre_crash_ring.h"
#include "stats.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/fcntl.h"
/*
 * Substrings that mark the start of an interesting kernel report.
 * Matched anywhere inside the printk record body so we tolerate any
 * "[ pid ]" prefix the kernel might prepend.
 */
static const char * const kmsg_triggers[] = {
	"BUG: KASAN",
	"BUG: KMSAN",
	"BUG: KCSAN",
	"UBSAN:",
	"WARNING: possible recursive locking",
	"WARNING: possible circular locking",
	"WARNING: CPU:",		/* generic WARN_ON()/WARN() splat banner from kernel/panic.c::__warn */
	"WARNING: suspicious RCU",	/* lockdep-RCU usage warning */
	"WARNING: bad unlock",		/* lockdep bad-unlock-balance */
	"WARNING: held lock",		/* lockdep held-lock-freed */
	"Oops:",			/* arch oops banner */
	"Kernel BUG",			/* BUG()/BUG_ON() banner */
	"kernel BUG",			/* alternate-case BUG banner emitted by some arches */
	"BUG:",				/* "BUG: sleeping function ...", "BUG: workqueue lockup", "BUG: scheduling while atomic", "BUG: unable to handle ..." */
	"refcount_t:",			/* lib/refcount.c overflow/underflow saturation */
	"INFO: rcu_sched self-detected stall",
	"INFO: rcu_preempt self-detected stall",
	"INFO: task ",			/* "INFO: task <name> blocked for more than ..." */
	"general protection fault",
	"Unable to handle kernel paging request",
};

/*
 * After a trigger line fires, copy this many subsequent records into
 * the output stream so the backtrace and supporting context get
 * captured.  Bounded so a misbehaving kernel logging a flood doesn't
 * drown out trinity's own progress output.
 */
#define KMSG_FOLLOW_MAX_RECORDS 200

/*
 * Largest single /dev/kmsg record we will read in one go.  The kernel
 * will return -EINVAL if the user buffer is smaller than the record,
 * so make this generously larger than CONSOLE_EXT_LOG_MAX (8192).
 */
#define KMSG_BUFSIZE 16384

/* Poll interval while idle.  Short enough that shutdown is responsive,
 * long enough that we don't burn CPU on an idle system. */
#define KMSG_POLL_TIMEOUT_MS 200

/*
 * Parent-side cache of the helper's pid.  Zero means no helper running
 * (either start hasn't run, fork failed, or reap_dead_kids already
 * picked it up via its waitpid(-1) drain).
 */
static pid_t kmsg_helper_pid;

/*
 * Helper-side stop flag.  Set by the SIGTERM handler; the poll loop
 * checks it on every iteration and exits when set.
 */
static volatile sig_atomic_t kmsg_stop_flag;

static bool line_matches_trigger(const char *body)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(kmsg_triggers); i++) {
		if (strstr(body, kmsg_triggers[i]) != NULL)
			return true;
	}
	return false;
}

/*
 * Coarse classification of a trigger-matched body.  Mirrors the
 * substrings in kmsg_triggers[] above; kept as a parallel ladder
 * rather than fused into the trigger table so this stays a pure
 * addition to the existing matcher.  More specific lockdep WARNs are
 * checked before the generic "WARNING:" arm so they don't get
 * swallowed by it.
 *
 * Returns KMSG_EVENT_UNKNOWN if a trigger matched but none of the
 * structured arms below recognise it — callers should still emit the
 * raw banner in that case.
 */
static enum kmsg_event_kind classify_kmsg_event(const char *body)
{
	if (strstr(body, "WARNING: possible recursive locking") != NULL)
		return KMSG_WARN_RECLOCK;
	if (strstr(body, "WARNING: possible circular locking") != NULL)
		return KMSG_WARN_CIRCULAR;
	if (strstr(body, "WARNING:") != NULL)
		return KMSG_WARN;
	if (strstr(body, "INFO: rcu_sched self-detected stall") != NULL ||
	    strstr(body, "INFO: rcu_preempt self-detected stall") != NULL)
		return KMSG_RCU;
	if (strstr(body, "Oops:") != NULL ||
	    strstr(body, "general protection fault") != NULL ||
	    strstr(body, "Unable to handle kernel paging request") != NULL)
		return KMSG_OOPS;
	if (strstr(body, "BUG:") != NULL ||
	    strstr(body, "Kernel BUG") != NULL ||
	    strstr(body, "kernel BUG") != NULL ||
	    strstr(body, "UBSAN:") != NULL ||
	    strstr(body, "refcount_t:") != NULL)
		return KMSG_BUG;
	if (strstr(body, "INFO: task ") != NULL)
		return KMSG_WARN;
	return KMSG_EVENT_UNKNOWN;
}

/*
 * /dev/kmsg record format is documented in the kernel's
 * Documentation/ABI/testing/dev-kmsg:
 *
 *   "<level>,<seqnum>,<timestamp_us>,<flag>[,...];<message>\n"
 *
 * Optional structured key=value lines may follow, each prefixed with a
 * single space.  We don't care about the structured data — return a
 * pointer to the start of the message body, or NULL if the record
 * doesn't have the expected ';' separator.  The returned pointer
 * aliases buf.
 */
static char *kmsg_record_body(char *buf)
{
	char *semi;

	semi = strchr(buf, ';');
	if (semi == NULL)
		return NULL;
	return semi + 1;
}

/*
 * Trim the message body in place: cut at the first newline so any
 * trailing structured-data lines don't get printed, and drop any
 * trailing whitespace.
 */
static void trim_body(char *body)
{
	char *nl;
	size_t len;

	nl = strchr(body, '\n');
	if (nl != NULL)
		*nl = '\0';

	len = strlen(body);
	while (len > 0 && (body[len - 1] == ' ' || body[len - 1] == '\t' ||
			   body[len - 1] == '\r')) {
		body[--len] = '\0';
	}
}

/*
 * Helper-side output: emit a "[kmsg] " prefixed line on the same
 * stdout/stderr fd the parent uses.  output() would dispatch via
 * find_childno() which returns CHILD_NOT_FOUND for the helper (it is
 * not in pids[]) and emit a misleading "[child-1:<pid>] " prefix; this
 * wrapper keeps the helper's lines self-identifying.  Helper has its
 * own glibc FILE* state since it is a separate process, so no shared
 * stdio lock with the parent.
 */
static void kmsg_emit(const char *fmt, ...)
{
	char buf[2048];
	va_list args;
	int n;

	va_start(args, fmt);
	n = vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);
	if (n < 0)
		return;
	fprintf(should_route_to_stdout() ? stdout : stderr, "[kmsg] %s", buf);
}

static void kmsg_sigterm_handler(int sig)
{
	(void)sig;
	kmsg_stop_flag = 1;
}

/*
 * Helper-process entry point.  Never returns; every exit goes through
 * _exit() so atexit handlers registered in the parent
 * (self_cgroup_cleanup, etc.) do not run a second time from here.
 */
static void __attribute__((noreturn)) kmsg_helper_main(void)
{
	int fd;
	char buf[KMSG_BUFSIZE];
	struct pollfd pfd;
	unsigned int follow_remaining = 0;
	unsigned int read_errors = 0;
	struct sigaction sa;
	const char taskname[13] = "trinity-kmsg";

	/*
	 * Drop the inherited stats-log fd before anything else.  stats.c
	 * opens it via fopen(path, "a") with no "e" flag, so the underlying
	 * fd lacks O_CLOEXEC and the fork-time clone landed it in our table
	 * too -- the fuzz-child path drops the same fd in
	 * stats_log_drop_in_child() to preserve the parent-only-writer
	 * invariant.  Without this the helper would silently hold a second
	 * fd-table reference to the operator's stats.log for the whole run.
	 */
	stats_log_drop_in_child();
	stats_timeseries_drop_in_child();

	/*
	 * Install the SIGTERM handler before anything else: the parent's
	 * stop signal could in principle land on us between fork and the
	 * first instruction of the helper, and the inherited disposition
	 * is whatever main had at the time of the fork (default = kill).
	 * No SA_RESTART so poll() returns EINTR and the loop re-checks
	 * kmsg_stop_flag promptly.
	 */
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = kmsg_sigterm_handler;
	(void)sigaction(SIGTERM, &sa, NULL);

	/* Parent handles ctrl-c; helper just exits with the parent. */
	(void)signal(SIGINT, SIG_IGN);
	/* No children to reap. */
	(void)signal(SIGCHLD, SIG_DFL);

	/*
	 * If the parent dies unexpectedly, get SIGTERM'd so we don't end
	 * up reparented to init burning CPU reading /dev/kmsg forever.
	 * Race: the parent might already be gone between fork() return
	 * and this prctl; detect that by re-checking getppid().
	 */
	(void)prctl(PR_SET_PDEATHSIG, SIGTERM);
	if (getppid() == 1)
		_exit(0);

	(void)prctl(PR_SET_NAME, (unsigned long)taskname);

	fd = open("/dev/kmsg", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0) {
		kmsg_emit("kmsg-monitor: open(/dev/kmsg) failed: %s\n",
			strerror(errno));
		_exit(0);
	}

	/*
	 * Skip everything that was already in the ringbuffer before we
	 * started; we only want reports the fuzzer is provoking.  If
	 * SEEK_END isn't supported (very old kernels) we'll harmlessly
	 * see boot-time messages too — log it and continue.
	 */
	if (lseek(fd, 0, SEEK_END) == (off_t)-1) {
		kmsg_emit("kmsg-monitor: lseek(SEEK_END) failed: %s\n",
			strerror(errno));
	}

	pfd.fd = fd;
	pfd.events = POLLIN;

	while (!kmsg_stop_flag) {
		ssize_t n;
		char *body;
		bool match;
		int rc;

		rc = poll(&pfd, 1, KMSG_POLL_TIMEOUT_MS);
		if (rc < 0) {
			if (errno == EINTR)
				continue;
			kmsg_emit("kmsg-monitor: poll failed: %s\n",
				strerror(errno));
			break;
		}
		if (rc == 0)
			continue;

		n = read(fd, buf, sizeof(buf) - 1);
		if (n < 0) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			if (errno == EPIPE) {
				/* Ringbuffer wrapped past us.  Resync. */
				(void)lseek(fd, 0, SEEK_END);
				continue;
			}
			/*
			 * Unexpected errno.  Do NOT bail: a single transient
			 * read error would otherwise silently end live
			 * kernel-log capture for the rest of the run, which
			 * is exactly the diagnostic stream we need when the
			 * kernel goes sideways.  Resync past whatever we
			 * tripped over (same recovery as the EPIPE arm) and
			 * keep polling.  Rate-limit the warning at 1, 2, 4,
			 * 8, ... consecutive failures so a persistent error
			 * (lost CAP_SYSLOG, /dev/kmsg pulled, etc.) does not
			 * flood the output.  The counter resets on the next
			 * successful read below.
			 */
			read_errors++;
			if ((read_errors & (read_errors - 1)) == 0) {
				kmsg_emit("kmsg-monitor: read failed: %s (count=%u)\n",
					strerror(errno), read_errors);
			}
			(void)lseek(fd, 0, SEEK_END);
			continue;
		}
		read_errors = 0;
		if (n == 0)
			continue;

		buf[n] = '\0';

		body = kmsg_record_body(buf);
		if (body == NULL)
			continue;

		trim_body(body);
		if (*body == '\0')
			continue;

		match = line_matches_trigger(body);

		if (match) {
			enum kmsg_event_kind kind = classify_kmsg_event(body);

			/* Flat WARN-fires bump for the chaos-mode V2 cohort
			 * attribution at bandit window close.  Any classified
			 * event counts -- the bucketing into chaos-on vs
			 * chaos-off cohorts happens in bandit_record_pull where
			 * the per-window delta lands.  UNKNOWN means the
			 * trigger ladder matched but the structured classifier
			 * did not recognise it, so it is not a real signal --
			 * leave the counter alone in that case.  kcov_shm is a
			 * MAP_SHARED region; the atomic from the helper process
			 * lands in the same memory the parent and fuzz children
			 * read. */
			if (kind != KMSG_EVENT_UNKNOWN && kcov_shm != NULL)
				__atomic_fetch_add(&kcov_shm->kmsg.kmsg_warn_fires,
						   1UL, __ATOMIC_RELAXED);

			kmsg_emit("KMSG: {event:%d, banner:\"%s\"}\n",
				(int)kind, body);
			/* dump pre-crash context for the event-detection
			 * postmortem.  Route through kmsg_emit so the per-slot
			 * dump lines land on the helper's own tagged stream
			 * alongside the KMSG: banner above; outputerr would
			 * split-stream them to raw stderr with no "[kmsg] "
			 * prefix, defeating the helper's single-stream
			 * self-identifying output. */
			if (kind != KMSG_EVENT_UNKNOWN && kind != KMSG_RCU)
				pre_crash_ring_dump_all(kmsg_emit);
			follow_remaining = KMSG_FOLLOW_MAX_RECORDS;
		} else if (follow_remaining > 0) {
			kmsg_emit("KMSG: %s\n", body);
			follow_remaining--;
		}
	}

	close(fd);
	_exit(0);
}

void kmsg_monitor_start(void)
{
	pid_t pid;

	pid = fork();
	if (pid < 0) {
		output(0, "kmsg-monitor: fork failed: %s\n", strerror(errno));
		return;
	}
	if (pid == 0)
		kmsg_helper_main();		/* noreturn */

	kmsg_helper_pid = pid;
	output(1, "kmsg-monitor: helper process pid %d started\n", (int)pid);
}

void kmsg_monitor_stop(void)
{
	pid_t pid = kmsg_helper_pid;

	if (pid == 0)
		return;

	/* Clear up front so a second call (or a reap_dead_kids untracked
	 * reap landing concurrently) doesn't double-signal. */
	kmsg_helper_pid = 0;

	if (kill(pid, SIGTERM) != 0 && errno != ESRCH) {
		output(0, "kmsg-monitor: kill(%d, SIGTERM) failed: %s\n",
			(int)pid, strerror(errno));
	}

	(void)waitpid_eintr(pid, NULL, 0);

	/*
	 * ECHILD just means reap_dead_kids' waitpid(-1) drain already
	 * picked the helper up; kmsg_monitor_note_reaped() would have
	 * cleared kmsg_helper_pid above, in which case we never got
	 * here.  Either way the helper is gone; no diagnostic needed.
	 */
}

void kmsg_monitor_note_reaped(pid_t pid, int status)
{
	if (pid <= 0 || pid != kmsg_helper_pid)
		return;

	kmsg_helper_pid = 0;
	output(0, "kmsg-monitor: helper process pid %d exited unexpectedly (status 0x%x)\n",
		(int)pid, status);
}
