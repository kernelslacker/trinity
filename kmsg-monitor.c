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
 * This file spawns a single pthread early in trinity startup that:
 *   - opens /dev/kmsg O_NONBLOCK
 *   - seeks to the end so we only see records produced after we
 *     started fuzzing
 *   - polls + reads records as the kernel emits them
 *   - pattern-matches each record body against a list of known
 *     report headers, and re-emits matches (plus a bounded run of
 *     follow-up records for the backtrace) into trinity's normal
 *     output() channel with a "KMSG:" prefix
 *
 * Scope is deliberately narrow: detect and log only.  Correlating
 * reports back to which child / which syscall provoked them is a
 * follow-up.
 */

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "kmsg-monitor.h"
#include "trinity.h"
#include "utils.h"

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

static pthread_t kmsg_thread;
static bool kmsg_thread_started;
static volatile int kmsg_thread_stop;

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

static void *kmsg_monitor_thread(void *arg)
{
	int fd;
	char buf[KMSG_BUFSIZE];
	struct pollfd pfd;
	unsigned int follow_remaining = 0;

	(void)arg;

	fd = open("/dev/kmsg", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0) {
		output(0, "kmsg-monitor: open(/dev/kmsg) failed: %s\n",
			strerror(errno));
		return NULL;
	}

	/*
	 * Skip everything that was already in the ringbuffer before we
	 * started; we only want reports the fuzzer is provoking.  If
	 * SEEK_END isn't supported (very old kernels) we'll harmlessly
	 * see boot-time messages too — log it and continue.
	 */
	if (lseek(fd, 0, SEEK_END) == (off_t)-1) {
		output(0, "kmsg-monitor: lseek(SEEK_END) failed: %s\n",
			strerror(errno));
	}

	pfd.fd = fd;
	pfd.events = POLLIN;

	while (__atomic_load_n(&kmsg_thread_stop, __ATOMIC_ACQUIRE) == 0) {
		ssize_t n;
		char *body;
		bool match;
		int rc;

		rc = poll(&pfd, 1, KMSG_POLL_TIMEOUT_MS);
		if (rc < 0) {
			if (errno == EINTR)
				continue;
			output(0, "kmsg-monitor: poll failed: %s\n",
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
			output(0, "kmsg-monitor: read failed: %s\n",
				strerror(errno));
			break;
		}
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
			output(0, "KMSG: %s\n", body);
			follow_remaining = KMSG_FOLLOW_MAX_RECORDS;
		} else if (follow_remaining > 0) {
			output(0, "KMSG: %s\n", body);
			follow_remaining--;
		}
	}

	close(fd);
	return NULL;
}

void kmsg_monitor_start(void)
{
	int rc;

	__atomic_store_n(&kmsg_thread_stop, 0, __ATOMIC_RELEASE);
	rc = pthread_create(&kmsg_thread, NULL, kmsg_monitor_thread, NULL);
	if (rc != 0) {
		output(0, "kmsg-monitor: pthread_create failed: %s\n",
			strerror(rc));
		return;
	}
	kmsg_thread_started = true;
}

void kmsg_monitor_stop(void)
{
	if (!kmsg_thread_started)
		return;
	/*
	 * Set the stop flag and wait for the thread to notice on its
	 * next poll wakeup (worst case KMSG_POLL_TIMEOUT_MS).
	 */
	__atomic_store_n(&kmsg_thread_stop, 1, __ATOMIC_RELEASE);
	pthread_join(kmsg_thread, NULL);
	kmsg_thread_started = false;
}
