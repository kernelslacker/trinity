#include <errno.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include "arg-decoder.h"
#include "pids.h"
#include "params.h"	// quiet_level
#include "shm.h"

#define BUFSIZE 1024	// decoded syscall args are fprintf'd directly, this is for everything else.

/*
 * level defines whether it gets displayed to the screen.
 * quiet_level defaults to 1 (only level 0 prints).
 * Each -v increases quiet_level: -v shows 0+1, -vv shows 0+1+2.
 *   0 = important (errors, taint, startup info, syscall counts)
 *   1 = operational (fd generation, socket cache, done parsing)
 *   2 = debug (device details, per-socket info, map details)
 */
void output(char level, const char *fmt, ...)
{
	va_list args;
	int n;
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

	printf("%s%s", prefix, outputbuf);
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
	if (quiet_level > 1)
		fprintf(stdout, "%s", buffer);
}
