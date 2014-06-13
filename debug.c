/*
 * Various routines useful for debugging.
 */

#include <stdio.h>
#include "config.h"
#include "log.h"
#include "shm.h"

void __BUG(const char *bugtxt, const char *filename, const char *funcname, unsigned int lineno)
{
	printf("BUG!: %s%s%s\n", ANSI_RED, bugtxt, ANSI_RESET);
	printf("BUG!: %s\n", VERSION);
	printf("BUG!: [%d] %s:%s:%d\n", getpid(), filename, funcname, lineno);

	show_backtrace();

	/* Now spin indefinitely (but allow ctrl-c) */
	while (1) {
		if (shm->exit_reason == EXIT_SIGINT)
			exit(EXIT_FAILURE);
		sleep(1);
	}
}
