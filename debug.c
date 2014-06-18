/*
 * Various routines useful for debugging.
 */

#include <execinfo.h>
#include <stdio.h>
#include "child.h"
#include "config.h"
#include "debug.h"
#include "log.h"
#include "shm.h"

#define BACKTRACE_SIZE 100

void show_backtrace(void)
{
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

void dump_childdata(struct childdata *child)
{
	output(0, "syscall: %p\n", child->syscall);
	output(0, "previous syscall: %p\n", child->previous);

	output(0, "logfile: %p (dirty:%d)\n", child->logfile, child->logdirty);

	output(0, "mappings: %p (num:%d)\n", child->mappings, child->num_mappings);

	output(0, "seed: %ld\n", child->seed);
	output(0, "pid: %d\n", child->pid);
	output(0, "childnum: %d\n", child->num);

	output(0, "killcount: %d\n", child->kill_count);
	output(0, "dontkillme: %d\n", child->dontkillme);
};
