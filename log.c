#include <stdio.h>
#include <stdarg.h>
#include "log.h"
#include "params.h"	// logging, monochrome, quiet_level
#include "pids.h"
#include "shm.h"
#include "trinity.h"

#define BUFSIZE 1024	// decoded syscall args are fprintf'd directly, this is for everything else.

char ANSI_RED[] = "[1;31m";
char ANSI_GREEN[] = "[1;32m";
char ANSI_YELLOW[] = "[1;33m";
char ANSI_BLUE[] = "[1;34m";
char ANSI_MAGENTA[] = "[1;35m";
char ANSI_CYAN[] = "[1;36m";
char ANSI_WHITE[] = "[1;37m";
char ANSI_RESET[] = "[0m";

void strip_ansi(char *ansibuf)
{
	char *from = ansibuf, *to = ansibuf;
	unsigned int len, i;

	/* If we've specified monochrome, we won't have any ANSI codes
	 * in the buffer to be stripped out. */
	if (monochrome == TRUE)
		return;

	/* because we look ahead two bytes as we scan the buffer,
	 * we only want to scan a maximum of buffer len - 2 bytes
	 * to avoid reading past the end.
	 */
	len = strlen(ansibuf) - 2;

	for (i = 0; i < len; i++) {
		*to = from[i];
		if (from[i] == '') {
			if (from[i + 2] == '1')
				i += 6;	// ANSI_COLOUR
			else
				i += 3;	// ANSI_RESET
		} else {
			to++;
		}
	}

	/* copy the trailing 2 bytes */
	*to++ = from[i++];
	*to++ = from[i];
	*to = 0;
}

/*
 * level defines whether it gets displayed to the screen with printf.
 * (it always logs).
 *   0 = everything, even all the registers
 *   1 = Watchdog prints syscall count
 *   2 = Just the reseed values
 *
 */
void output(unsigned char level, const char *fmt, ...)
{
	va_list args;
	int n;
	FILE *handle;
	pid_t pid;
	char outputbuf[BUFSIZE];
	char *prefix = NULL;
	char watchdog_prefix[]="[watchdog]";
	char init_prefix[]="[init]";
	char main_prefix[]="[main]";
	char child_prefix[32];

	if (logging == LOGGING_DISABLED && level >= quiet_level)
		return;

	/* prefix preparation */
	pid = getpid();
	if (pid == watchdog_pid)
		prefix = watchdog_prefix;

	if (pid == initpid)
		prefix = init_prefix;

	if (pid == shm->mainpid)
		prefix = main_prefix;

	if (prefix == NULL) {
		unsigned int childno;

		childno = find_childno(pid);
		snprintf(child_prefix, sizeof(child_prefix), "[child%u:%u]", childno, pid);
		prefix = child_prefix;
		shm->children[childno]->logdirty = TRUE;
	}

	/* formatting output */
	va_start(args, fmt);
	n = vsnprintf(outputbuf, sizeof(outputbuf), fmt, args);
	va_end(args);
	if (n < 0) {
		outputerr("## Something went wrong in output() [%d]\n", n);
		if (getpid() == shm->mainpid)
			exit_main_fail();
		else
			exit(EXIT_FAILURE);
	}

	/* stdout output if needed */
	if (quiet_level >= level) {
		printf("%s %s", prefix, outputbuf);
		(void)fflush(stdout);
	}

	/* go on with file logs only if enabled */
	if (logging == LOGGING_FILES)
		return;

	handle = find_logfile_handle();
	if (!handle)
		return;

	strip_ansi(outputbuf);

	fprintf(handle, "%s %s", prefix, outputbuf);

	(void)fflush(handle);
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


// TODO: combine the below with output()
void output_rendered_buffer(char *buffer)
{
	FILE *log_handle;

	/* Output to stdout only if -q param is not specified */
	if (quiet_level == MAX_LOGLEVEL) {
		fprintf(stdout, "%s", buffer);
		fflush(stdout);
	}

	/* Exit if should not continue at all. */
	if (logging == LOGGING_DISABLED)
		return;

	log_handle = find_logfile_handle();
	if (log_handle != NULL) {
		strip_ansi(buffer);
		fprintf(log_handle, "%s", buffer);
		fflush(log_handle);
	}
}
