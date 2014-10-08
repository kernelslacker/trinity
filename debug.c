/*
 * Various routines useful for debugging.
 */

#include "config.h"

#ifdef USE_BACKTRACE
#include <execinfo.h>
#endif
#include <stdio.h>
#include <stdarg.h>
#include "child.h"
#include "debug.h"
#include "log.h"
#include "params.h"
#include "shm.h"
#include "syscall.h"
#include "version.h"

#define BACKTRACE_SIZE 100

void show_backtrace(void)
{
#ifdef USE_BACKTRACE
	unsigned int j, nptrs;
	void *buffer[BACKTRACE_SIZE];
	char **strings;

	set_dontkillme(getpid(), FALSE);

	nptrs = backtrace(buffer, BACKTRACE_SIZE);

	strings = backtrace_symbols(buffer, nptrs);
	if (strings == NULL) {
		perror("backtrace_symbols");
		goto out;
	}

	for (j = 0; j < nptrs; j++)
		output(0, "%s\n", strings[j]);

	free(strings);
out:
	set_dontkillme(getpid(), TRUE);
#endif
}

void __BUG(const char *bugtxt, const char *filename, const char *funcname, unsigned int lineno)
{
	printf("BUG!: %s%s%s\n", ANSI_RED, bugtxt, ANSI_RESET);
	printf("BUG!: %s\n", VERSION);
	printf("BUG!: [%d] %s:%s:%d\n", getpid(), filename, funcname, lineno);

	show_backtrace();

	/* Now spin indefinitely (but allow ctrl-c) */

	set_dontkillme(getpid(), TRUE);

	while (1) {
		if (shm->exit_reason == EXIT_SIGINT) {
			set_dontkillme(getpid(), FALSE);
			exit(EXIT_FAILURE);
		}
		sleep(1);
	}
}

void dump_syscallrec(struct syscallrecord *rec)
{
	output(0, " tv.tvsec=%d tv.usec=%d\n", rec->tv.tv_sec, rec->tv.tv_usec);
	output(0, " nr:%d a1:%lx a2:%lx a3:%lx a4:%lx a5:%lx a6:%lx retval:%ld errno_post:%d\n",
		rec->nr, rec->a1, rec->a2, rec->a3, rec->a4, rec->a5, rec->a6, rec->retval, rec->errno_post);
	output(0, " op_nr:%lx do32bit:%d\n", rec->op_nr, rec->do32bit);
	output(0, " lock:%d {owner:%d contention:%ld)\n", rec->lock.lock, rec->lock.owner, rec->lock.contention);
	output(0, " state:%d\n", rec->state);
	output(0, " prebuffer : %p (len:%d)\n", rec->prebuffer, strlen(rec->prebuffer));
	output(0, " -> %s\n", rec->prebuffer);
	output(0, " postbuffer : %p (len:%d)\n", rec->postbuffer, strlen(rec->postbuffer));
	output(0, " -> %s\n", rec->postbuffer);
}

void dump_childdata(struct childdata *child)
{
	output(0, "child struct @%p\n", child);
	output(0, "syscall: %p\n", &child->syscall);
	dump_syscallrec(&child->syscall);
	output(0, "previous syscall: %p\n", &child->previous);
	dump_syscallrec(&child->previous);

	output(0, "logfile: %p (dirty:%d)\n", child->logfile, child->logdirty);

	output(0, "mappings: %p (num:%d)\n", child->mappings, child->num_mappings);

	output(0, "seed: %ld\n", child->seed);
	output(0, "pid: %d\n", child->pid);
	output(0, "childnum: %d\n", child->num);

	output(0, "killcount: %d\n", child->kill_count);
	output(0, "dontkillme: %d\n", child->dontkillme);
	output(0, "\n");
};

/*
 * debugging output.
 * This is just a convenience helper to avoid littering the code
 * with dozens of 'if debug == TRUE' comparisons causing unnecessary nesting.
 */
#define BUFSIZE 1024

void debugf(const char *fmt, ...)
{
	char debugbuf[BUFSIZE];
	va_list args;

	if (shm->debug == FALSE)
		return;

	va_start(args, fmt);
	vsprintf(debugbuf, fmt, args);
	va_end(args);
	output(0, debugbuf);
}
