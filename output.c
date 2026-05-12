#include <errno.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include "arg-decoder.h"
#include "pids.h"
#include "params.h"	// verbosity
#include "shm.h"

#define BUFSIZE 1024	// decoded syscall args are fprintf'd directly, this is for everything else.

/* Set once at child init to avoid repeated getpid() syscalls in the output hot path. */
static pid_t my_pid = 0;

void output_set_pid(pid_t pid)
{
	my_pid = pid;
}

/*
 * In --stats-json mode, stdout is reserved for the single JSON document
 * emitted by dump_stats_json() so consumers can pipe trinity directly into
 * jq / json.loads / serde_json without stripping a banner or status lines.
 * Every other human-readable line is routed to stderr instead.  Callers that
 * legitimately need to write to stdout (the startup banner, etc.) consult
 * this helper before deciding which stream to use.
 */
bool should_route_to_stdout(void)
{
	return !stats_json;
}

/*
 * level defines whether it gets displayed to the screen.
 * verbosity defaults to 1 (only level 0 prints).
 * Each -v increases verbosity: -v shows 0+1, -vv shows 0+1+2.
 *   0 = important (errors, taint, startup info, syscall counts)
 *   1 = operational (fd generation, socket cache, done parsing)
 *   2 = debug (device details, per-socket info, map details)
 */
void output(int level, const char *fmt, ...)
{
	va_list args;
	int n;
	pid_t pid;
	char outputbuf[BUFSIZE];
	char *prefix = NULL;
	char main_prefix[]="[main] ";
	char continuationtxt[]="";
	char child_prefix[32];

	if (level >= verbosity)
		return;

	if (level == CONT) {
		prefix = continuationtxt;
		goto skip_pid;
	}

	/* prefix preparation */
	pid = my_pid ? my_pid : getpid();

	if (pid == mainpid)
		prefix = main_prefix;
	else {
		int childno;

		childno = find_childno(pid);
		snprintf(child_prefix, sizeof(child_prefix), "[child%d:%d] ", childno, pid);
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

	fprintf(should_route_to_stdout() ? stdout : stderr,
		"%s%s", prefix, outputbuf);
}

/*
* Used as a way to consolidated all printf calls if someones one to redirect it to somewhere else.
* note: this function ignores verbosity since it main purpose is error output.
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
	if (verbosity > 1)
		fprintf(should_route_to_stdout() ? stdout : stderr, "%s", buffer);
}
