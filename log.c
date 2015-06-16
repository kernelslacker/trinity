#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "log.h"
#include "params.h"	// logging, monochrome, quiet_level
#include "pids.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#define BUFSIZE 1024	// decoded syscall args are fprintf'd directly, this is for everything else.

char ANSI_RED[] = "[1;31m";
char ANSI_GREEN[] = "[1;32m";
char ANSI_YELLOW[] = "[1;33m";
char ANSI_BLUE[] = "[1;34m";
char ANSI_MAGENTA[] = "[1;35m";
char ANSI_CYAN[] = "[1;36m";
char ANSI_WHITE[] = "[1;37m";
char ANSI_RESET[] = "[0m";

FILE *mainlogfile;

static bool logfiles_opened = FALSE;

static FILE *open_logfile(const char *logfilename)
{
	FILE *file;

	unlink(logfilename);

	file = fopen(logfilename, "w");
	if (!file)
		outputerr("## couldn't open logfile %s\n", logfilename);

	return file;
}

void open_main_logfile(void)
{
	mainlogfile = open_logfile("trinity.log");
	if (!mainlogfile)
		exit(EXIT_FAILURE);

	logfiles_opened = TRUE;	//FIXME: This is a bit crap
}

void open_child_logfile(struct childdata *child)
{
	char *logfilename;

	if (logging == FALSE)
		return;

	logfilename = zmalloc(64);
	sprintf(logfilename, "trinity-child%u.log", child->num);

	child->logfile = open_logfile(logfilename);
	if (!child->logfile) {
		shm->exit_reason = EXIT_LOGFILE_OPEN_ERROR;
		exit(EXIT_FAILURE);
	}

	free(logfilename);

	child->logdirty = FALSE;
}

void close_logfile(FILE **filehandle)
{
	if (*filehandle == NULL)
		return;

	fclose(*filehandle);
	*filehandle = NULL;
}

static FILE * find_child_logfile_handle(pid_t pid)
{
	int i;
	unsigned int j;
	FILE *log = NULL;

	i = find_childno(pid);
	if (i != CHILD_NOT_FOUND) {
		log = shm->children[i]->logfile;
	} else {
		/* This is pretty ugly, and should never happen,
		 * but try again a second later, in case we're racing setup/teardown.
		 * FIXME: We may not even need this now that we have proper locking; test it.
		 */
		sleep(1);
		i = find_childno(pid);
		if (i == CHILD_NOT_FOUND) {
			outputerr("Couldn't find child for pid %d\n", pid);
			return mainlogfile;
		}
		log = shm->children[i]->logfile;

	}

	if (log != NULL)
		return log;

	/* if the logfile hadn't been set, log to main. */
	shm->children[i]->logfile = mainlogfile;
	outputerr("## child %d logfile handle was null logging to main!\n", i);

	outputerr("## Couldn't find logfile for pid %d\n", pid);
	dump_childnos();
	outputerr("## Logfiles for pids: ");
	for_each_child(j)
		outputerr("%p ", shm->children[j]->logfile);
	outputerr("\n");

	(void)fflush(stdout);

	sleep(5);
	return mainlogfile;
}

FILE *find_logfile_handle(void)
{
	FILE *handle = NULL;

	if ((logging == TRUE) && (logfiles_opened)) {
		pid_t pid;

		pid = getpid();
		if (pid == initpid)
			return mainlogfile;

		if (pid == shm->mainpid)
			return mainlogfile;

		if (pid == watchdog_pid)
			return mainlogfile;

		handle = find_child_logfile_handle(pid);
	}
	return handle;
}

/*
 * Flush any pending log writes to disk.
 * Only to be called from child context.
 */
void synclogs(void)
{
	int fd;

	if (logging == FALSE)
		return;

	if (this_child->logdirty == FALSE)
		return;

	fflush(this_child->logfile);
	fd = fileno(this_child->logfile);
	if (fd != -1)
		(void) fsync(fd);

	this_child->logdirty = FALSE;

	/* If we're flushing the child log, may as well flush
	 * any other logs while we're writing to disk.
	 */
	(void)fflush(mainlogfile);
	fsync(fileno(mainlogfile));
}

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

	if (logging == FALSE && level >= quiet_level)
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
	if (logging == FALSE)
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
	/* Output to stdout only if -q param is not specified */
	if (quiet_level == MAX_LOGLEVEL) {
		fprintf(stdout, "%s", buffer);
		fflush(stdout);
	}

	/* Exit if should not continue at all. */
	if (logging == TRUE) {
		FILE *log_handle;

		log_handle = find_logfile_handle();
		if (log_handle != NULL) {
			strip_ansi(buffer);
			fprintf(log_handle, "%s", buffer);
			fflush(log_handle);
		}
	}
}
