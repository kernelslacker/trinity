/*
 * sysrq-lockup: opt-in (--sysrq-on-lockup) wedge diagnostic.  When a large
 * fraction of the fleet wedges at once it fires SysRq 'w' + 'l' and drains
 * the result from /dev/kmsg: the kernel's own blocked-task and all-CPU
 * backtrace dump, which the printk ring evicts fast under fuzz load.  The
 * check returns on !sysrq_on_lockup, so a default run is byte-identical.
 */

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "params.h"
#include "sysrq-lockup.h"
#include "trinity.h"		/* output, outputerr */
#include "utils.h"		/* max, ARRAY_SIZE */

#define SYSRQ_TRIGGER_PATH	"/proc/sysrq-trigger"
#define KMSG_PATH		"/dev/kmsg"

/* Post-mortem drain caps: after firing, read up to this many records
 * or wait up to this many milliseconds, whichever comes first.  The
 * record cap bounds output volume in the pathological case of a
 * kernel logging a flood in response to 'l'; the wall-clock cap keeps
 * the parent's reap tick from stalling if /dev/kmsg goes quiet. */
#define KMSG_DRAIN_MAX_RECORDS	200
#define KMSG_DRAIN_MAX_MS	500
#define KMSG_POLL_TIMEOUT_MS	50
#define KMSG_BUFSIZE		16384

/*
 * Set when a fire happens, cleared once stall_count drops back below the
 * threshold: one kernel dump per wedge event rather than one per watchdog
 * tick, while a later fleet wedge in the same run can still fire.
 */
static bool wedge_event_latched;

/*
 * Fire threshold: max(3, running_childs / 2).  The floor keeps a two-child
 * dev run, where "half wedged" is meaningless, from firing; above it the
 * ratio catches a fleet-wide event without arming on one sticky syscall.
 */
static unsigned int wedge_threshold(unsigned int running_childs)
{
	unsigned int half = running_childs / 2U;

	return max(3U, half);
}

/*
 * Write one sysrq character.  Each character goes as its own single-
 * byte write: the kernel's sysrq handler consumes one trigger char per
 * write() and multi-char writes get silently truncated on some
 * kernels.
 */
static bool sysrq_write_char(char c)
{
	int fd;
	ssize_t n;
	int e;

	fd = open(SYSRQ_TRIGGER_PATH, O_WRONLY | O_CLOEXEC);
	if (fd < 0) {
		output(0, "sysrq-on-lockup: open(%s) failed: %s\n",
			SYSRQ_TRIGGER_PATH, strerror(errno));
		return false;
	}
	n = write(fd, &c, 1);
	e = errno;
	close(fd);
	if (n != 1) {
		output(0, "sysrq-on-lockup: write(%s, '%c') failed: %s\n",
			SYSRQ_TRIGGER_PATH, c, strerror(e));
		return false;
	}
	return true;
}

/*
 * Extract the printk body (past the "level,seq,ts,flag;" header) and
 * trim its trailing newline in place.  Returns NULL if the record
 * has no ';' separator (very old kernels) so the caller can skip it.
 * Mirrors the parsing in health/kmsg-monitor.c but self-contained so
 * this file has no cross-file coupling to the live monitor's
 * (currently static) helpers.
 */
static char *record_body(char *buf)
{
	char *semi, *nl;

	semi = strchr(buf, ';');
	if (semi == NULL)
		return NULL;
	semi++;
	nl = strchr(semi, '\n');
	if (nl != NULL)
		*nl = '\0';
	return semi;
}

/*
 * Elapsed milliseconds since start_tp on CLOCK_MONOTONIC.  Returns a
 * huge value on clock_gettime failure so the drain loop bails on its
 * time cap rather than looping forever.
 */
static long long elapsed_ms(const struct timespec *start_tp)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
		return (long long)KMSG_DRAIN_MAX_MS * 2;
	return (long long)(now.tv_sec - start_tp->tv_sec) * 1000
		+ (long long)(now.tv_nsec - start_tp->tv_nsec) / 1000000;
}

/*
 * Drain up to KMSG_DRAIN_MAX_RECORDS records from an already-opened
 * /dev/kmsg fd, emitting each as a "sysrq-lockup:" tagged line.  Bails
 * on time cap, record cap, poll error, or persistent read error.
 */
static void drain_kmsg(int fd)
{
	char buf[KMSG_BUFSIZE];
	struct pollfd pfd = { .fd = fd, .events = POLLIN };
	struct timespec start_tp;
	unsigned int records = 0;

	if (clock_gettime(CLOCK_MONOTONIC, &start_tp) != 0) {
		output(0, "sysrq-on-lockup: clock_gettime failed, skipping drain\n");
		return;
	}

	while (records < KMSG_DRAIN_MAX_RECORDS) {
		ssize_t n;
		char *body;
		long long ms = elapsed_ms(&start_tp);
		int budget_ms;
		int rc;

		if (ms >= KMSG_DRAIN_MAX_MS)
			break;

		budget_ms = KMSG_POLL_TIMEOUT_MS;
		if (KMSG_DRAIN_MAX_MS - ms < budget_ms)
			budget_ms = (int)(KMSG_DRAIN_MAX_MS - ms);

		rc = poll(&pfd, 1, budget_ms);
		if (rc < 0) {
			if (errno == EINTR)
				continue;
			output(0, "sysrq-on-lockup: kmsg poll failed: %s\n",
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
				/* Ringbuffer wrapped past us mid-drain --
				 * the kernel is producing faster than we
				 * are reading.  Resync and keep going up to
				 * the caps; better than aborting the drain. */
				(void)lseek(fd, 0, SEEK_END);
				continue;
			}
			output(0, "sysrq-on-lockup: kmsg read failed: %s\n",
				strerror(errno));
			break;
		}
		if (n == 0)
			continue;

		buf[n] = '\0';
		body = record_body(buf);
		if (body == NULL || *body == '\0')
			continue;

		output(0, "sysrq-lockup: %s\n", body);
		records++;
	}

	if (records == KMSG_DRAIN_MAX_RECORDS)
		output(0, "sysrq-lockup: drain hit record cap (%u)\n", records);
}

/*
 * The actual fire path: pre-check, write w+l, drain kmsg.  Split out
 * of the polling wrapper so the hot-path caller stays a single flag
 * test + threshold compare + tail call.
 */
static void fire_sysrq_dump(unsigned int stall_count, unsigned int threshold)
{
	int kmsg_fd;

	output(0, "sysrq-lockup: fleet wedge detected (stall=%u threshold=%u), firing SysRq w+l\n",
		stall_count, threshold);

	/* Open a private kmsg fd BEFORE writing the trigger and seek to the
	 * end, so we only capture post-trigger output; a private fd also
	 * keeps the stream position independent of the kmsg-monitor
	 * helper's.  A failed open just skips the drain -- we still want
	 * the sysrq write to happen so the dump lands on the console /
	 * netconsole path even without us reading it back. */
	kmsg_fd = open(KMSG_PATH, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	if (kmsg_fd >= 0) {
		if (lseek(kmsg_fd, 0, SEEK_END) == (off_t)-1) {
			output(0, "sysrq-lockup: lseek(SEEK_END) failed: %s\n",
				strerror(errno));
		}
	} else {
		output(0, "sysrq-lockup: open(%s) failed: %s, no kmsg drain\n",
			KMSG_PATH, strerror(errno));
	}

	/* 'w' (blocked tasks, TASK_UNINTERRUPTIBLE) then 'l' (backtrace of all
	 * active CPUs).  Deliberately not 't': a dump of every task is far too
	 * noisy at fleet scale. */
	if (!sysrq_write_char('w')) {
		if (kmsg_fd >= 0)
			close(kmsg_fd);
		return;
	}
	if (!sysrq_write_char('l')) {
		if (kmsg_fd >= 0)
			close(kmsg_fd);
		return;
	}

	if (kmsg_fd >= 0) {
		drain_kmsg(kmsg_fd);
		close(kmsg_fd);
	}
}

void sysrq_lockup_check_and_fire(unsigned int stall_count,
				 unsigned int running_childs)
{
	unsigned int threshold;

	if (!sysrq_on_lockup)
		return;

	if (running_childs == 0) {
		wedge_event_latched = false;
		return;
	}

	threshold = wedge_threshold(running_childs);

	if (stall_count < threshold) {
		/* Re-arm once the fleet clears the threshold so a
		 * subsequent event in the same run can also fire. */
		wedge_event_latched = false;
		return;
	}

	if (wedge_event_latched)
		return;

	wedge_event_latched = true;
	fire_sysrq_dump(stall_count, threshold);
}
