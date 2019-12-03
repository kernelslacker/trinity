/*
 * Various routines useful for debugging.
 */


#ifdef USE_BACKTRACE
#include <execinfo.h>
#endif
#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include <unistd.h>
#include "child.h"
#include "debug.h"
#include "log.h"
#include "params.h"
#include "pids.h"
#include "shm.h"
#include "syscall.h"
#include "version.h"

#define BACKTRACE_SIZE 100

static void __show_backtrace(void)
{
#ifdef USE_BACKTRACE
	unsigned int j, nptrs;
	void *buffer[BACKTRACE_SIZE];
	char **strings;

	nptrs = backtrace(buffer, BACKTRACE_SIZE);

	strings = backtrace_symbols(buffer, nptrs);
	if (strings == NULL) {
		perror("backtrace_symbols");
		return;
	}

	for (j = 0; j < nptrs; j++)
		output(0, "%s\n", strings[j]);

	free(strings);
#endif
}

static void show_child_backtrace(void)
{
	struct childdata *child = this_child();

	set_dontkillme(child, FALSE);
	__show_backtrace();
	set_dontkillme(child, TRUE);
}

void show_backtrace(void)
{
	pid_t pid = getpid();

	if (pid == mainpid) {
		__show_backtrace();
		return;
	}

	show_child_backtrace();
}

void __BUG(const char *bugtxt, const char *filename, const char *funcname, unsigned int lineno)
{
	struct childdata *child = this_child();

	printf("BUG!: %s\n", bugtxt);
	printf("BUG!: %s\n", VERSION);
	printf("BUG!: [%d] %s:%s:%u\n", getpid(), filename, funcname, lineno);

	show_backtrace();

	/* Now spin indefinitely (but allow ctrl-c) */

	set_dontkillme(child, TRUE);

	while (1) {
		if (shm->exit_reason == EXIT_SIGINT) {
			set_dontkillme(child, FALSE);
			exit(EXIT_FAILURE);
		}
		sleep(1);
	}
}

void dump_syscallrec(struct syscallrecord *rec)
{
	output(0, " nr:%d a1:%lx a2:%lx a3:%lx a4:%lx a5:%lx a6:%lx retval:%ld errno_post:%d\n",
		rec->nr, rec->a1, rec->a2, rec->a3, rec->a4, rec->a5, rec->a6, rec->retval, rec->errno_post);
	output(0, " do32bit:%d\n", rec->do32bit);
	output(0, " lock:%d {owner:%d)\n", rec->lock.lock, rec->lock.owner);
	output(0, " state:%d\n", rec->state);
	output(0, " prebuffer : %p (len:%d)\n", rec->prebuffer, strlen(rec->prebuffer));
	output(0, " -> %s\n", rec->prebuffer);
	output(0, " postbuffer : %p (len:%ld)\n", rec->postbuffer, strlen(rec->postbuffer));
	output(0, " -> %s\n", rec->postbuffer);
}

void dump_childdata(struct childdata *child)
{
	output(0, "child struct @%p\n", child);

	output(0, " op_nr:%lx\n", child->op_nr);

	output(0, "syscall: %p\n", &child->syscall);
	dump_syscallrec(&child->syscall);

	if (logging == LOGGING_FILES)
		output(0, "logfile: %p (dirty:%d)\n", child->logfile, child->logdirty);

	output(0, "objects: %p\n", child->objects);
	//TODO: dump each objhead

	output(0, " tp.tv_sec=%ld tp.tv_nsec=%ld\n", child->tp.tv_sec, child->tp.tv_nsec);

	output(0, "seed: %u\n", child->seed);
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

/* This is a bit crappy, wrapping a varargs fn with another,
 * but this saves us having to do the openlog/closelog for every
 * case where we want to write a message.
 */
void syslogf(const char *fmt, ...)
{
	char debugbuf[BUFSIZE];
	va_list args;

	va_start(args, fmt);
	vsprintf(debugbuf, fmt, args);
	va_end(args);

	openlog("trinity", LOG_CONS|LOG_PERROR, LOG_USER);
	syslog(LOG_CRIT, "%s", debugbuf);
	closelog();
}
