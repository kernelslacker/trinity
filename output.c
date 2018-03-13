#include <errno.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include "arg-decoder.h"
#include "log.h"
#include "pids.h"
#include "params.h"	// quiet_level
#include "shm.h"

#define BUFSIZE 1024	// decoded syscall args are fprintf'd directly, this is for everything else.

/*
 * level defines whether it gets displayed to the screen with printf.
 * (it always logs).
 *   0 = everything, even all the registers
 *   1 = prints syscall count
 *   2 = Just the reseed values
 *
 */
void output(char level, const char *fmt, ...)
{
	va_list args;
	int n;
	FILE *handle;
	pid_t pid;
	char outputbuf[BUFSIZE];
	char *prefix = NULL;
	char main_prefix[]="[main] ";
	char continuationtxt[]="";
	char child_prefix[32];

	if (level >= quiet_level)
		return;

	if (level == CONT) {
		prefix = continuationtxt;
		goto skip_pid;
	}

	/* prefix preparation */
	pid = getpid();

	if (pid == mainpid)
		prefix = main_prefix;
	else if (prefix == NULL) {
		unsigned int childno;

		childno = find_childno(pid);
		snprintf(child_prefix, sizeof(child_prefix), "[child%u:%u] ", childno, pid);
		prefix = child_prefix;
		shm->children[childno]->logdirty = TRUE;
	}

skip_pid:

	/* formatting output */
	va_start(args, fmt);
	n = vsnprintf(outputbuf, sizeof(outputbuf), fmt, args);
	va_end(args);
	if (n < 0) {
		outputerr("## Something went wrong in output() [%d]\n", n);
		exit(EXIT_FAILURE);
	}

	/* stdout output if needed */
	if (quiet_level >= level) {
		printf("%s%s", prefix, outputbuf);
		(void)fflush(stdout);
	}

	/* go on with file logs only if enabled */
	if (logging == LOGGING_FILES) {
		handle = find_logfile_handle();
		if (!handle)
			return;

		fprintf(handle, "%s %s", prefix, outputbuf);

		(void)fflush(handle);
	}
}

/*
* Used as a way to consolidated all printf calls if someones one to redirect it to somewhere else.
* note: this function ignores quiet_level since it main purpose is error output.
*/
void outputerr(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
}

void outputstd(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vfprintf(stdout, fmt, args);
	va_end(args);
}


void output_rendered_buffer(char *buffer)
{
	FILE *log_handle;

	/* Output to stdout only if -q param is not specified */
	if (quiet_level == MAX_LOGLEVEL) {
		fprintf(stdout, "%s", buffer);
		fflush(stdout);
	}

	if (logging == LOGGING_DISABLED)
		return;

	log_handle = find_logfile_handle();
	if (log_handle != NULL) {
		fprintf(log_handle, "%s", buffer);
		fflush(log_handle);
	}
}
