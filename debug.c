/*
 * Various routines useful for debugging.
 */

#include <execinfo.h>
#include <stdio.h>
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
