#pragma once

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "utils.h"	/* waitpid_eintr() */

#include "kernel/fcntl.h"
/*
 * Best-effort `modprobe -q <mod>` invoked from a forked child.  stdio is
 * redirected to /dev/null so module-load chatter doesn't pollute trinity's
 * output, and the parent waits via waitpid_eintr() so the child is reaped
 * even under child.c's alarm(1).  Failure (fork/exec/missing module) is
 * silent; callers exercise the resulting interface afterwards and let it
 * fail naturally if the module isn't present.
 */
static inline void try_modprobe(const char *mod)
{
	pid_t pid = fork();
	int status;

	if (pid < 0)
		return;
	if (pid == 0) {
		int devnull = open("/dev/null", O_RDWR | O_CLOEXEC);
		if (devnull >= 0) {
			(void)dup2(devnull, 0);
			(void)dup2(devnull, 1);
			(void)dup2(devnull, 2);
			close(devnull);
		}
		execlp("modprobe", "modprobe", "-q", mod, (char *)NULL);
		_exit(127);
	}
	(void)waitpid_eintr(pid, &status, 0);
}

/*
 * Wall-clock budget check used by long-running childops to bound their
 * inner loops.  Returns true once `budget_ns` has elapsed since `start`
 * on CLOCK_MONOTONIC.  Each op picks its own ceiling (commonly 200-300 ms)
 * and passes it in; the helper just does the timespec arithmetic.
 */
static inline bool budget_elapsed_ns(const struct timespec *start, long budget_ns)
{
	struct timespec now;
	long elapsed_ns;

	clock_gettime(CLOCK_MONOTONIC, &now);
	elapsed_ns = (now.tv_sec  - start->tv_sec)  * 1000000000L
		   + (now.tv_nsec - start->tv_nsec);
	return elapsed_ns >= budget_ns;
}

/*
 * Read the kernel module reference count from /proc/modules.
 *
 * /proc/modules line format:
 *   name  size  refcount  used_by  state  address
 *
 * Returns the refcount (>= 0) on success, -1L if the module is not
 * listed in /proc/modules or if the file cannot be opened.  Reusable
 * by any childop that needs to observe live module-ref counts as an
 * oracle (e.g. to detect a per-bind module-ref leak across a loop).
 *
 * utils.h (transitively included via this header) already pulls in
 * <stdio.h> and <string.h>, so FILE, fopen, fgets, fclose, sscanf,
 * and memcmp are all available without additional includes.
 */
static inline long proc_module_refcount(const char *module_name)
{
	FILE *f;
	char line[512];
	long refcount = -1L;
	size_t namelen;

	if (!module_name)
		return -1L;
	namelen = strlen(module_name);

	f = fopen("/proc/modules", "r");
	if (!f)
		return -1L;

	while (fgets(line, sizeof(line), f)) {
		char name[64];
		unsigned long modsize;
		long rc;

		/* Scan the first three space-separated fields: name size refcount */
		if (sscanf(line, "%63s %lu %ld", name, &modsize, &rc) != 3)
			continue;
		if (strlen(name) == namelen &&
		    memcmp(name, module_name, namelen) == 0) {
			refcount = rc;
			break;
		}
	}
	fclose(f);
	return refcount;
}

/*
 * Reap an acceptor helper child forked by a churn op.  The acceptor exits
 * as soon as its peer closes, which the caller does before this call.
 * Bound the wait with a few WNOHANG polls separated by short sleeps; if
 * it still hasn't gone, send a SIGTERM and reap blocking.
 */
static inline void reap_acceptor(pid_t pid)
{
	int status;
	int waited = 0;

	if (pid <= 0)
		return;

	while (waited++ < 8) {
		pid_t r = waitpid_eintr(pid, &status, WNOHANG);
		if (r == pid || r < 0)
			return;
		{
			struct timespec ts = { 0, 1000000L };  /* 1 ms */
			(void)nanosleep(&ts, NULL);
		}
	}
	(void)kill(pid, SIGTERM);
	(void)waitpid_eintr(pid, &status, 0);
}
