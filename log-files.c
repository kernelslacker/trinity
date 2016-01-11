#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "log.h"
#include "params.h"	// logging, quiet_level
#include "pids.h"
#include "shm.h"

#define BUFSIZE 1024	// decoded syscall args are fprintf'd directly, this is for everything else.

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
	if (logging == LOGGING_DISABLED)
		return;

	mainlogfile = open_logfile("trinity.log");
	if (!mainlogfile)
		exit(EXIT_FAILURE);

	logfiles_opened = TRUE;	//FIXME: This is a bit crap
}

void open_child_logfile(struct childdata *child)
{
	char *logfilename;

	if (logging == LOGGING_DISABLED)
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
	if (logging == LOGGING_DISABLED)
		return;

	if (*filehandle == NULL)
		return;

	fclose(*filehandle);
	*filehandle = NULL;
}

FILE *find_logfile_handle(void)
{
	struct childdata *child;
	pid_t pid;

	if (logging == LOGGING_DISABLED)
		return NULL;

	if (!logfiles_opened)
		return NULL;

	pid = getpid();
	if (pid == mainpid)
		return mainlogfile;

	child = this_child();
	if (child != NULL)
		return child->logfile;

	return NULL;
}

/*
 * Flush any pending log writes to disk.
 * Only to be called from child context.
 */
void synclogs(void)
{
	struct childdata *child;
	int fd;

	if (logging == LOGGING_DISABLED)
		return;

	child = this_child();
	if (child->logdirty == FALSE)
		return;

	fflush(child->logfile);
	fd = fileno(child->logfile);
	if (fd != -1)
		(void) fsync(fd);

	child->logdirty = FALSE;

	/* If we're flushing the child log, may as well flush
	 * any other logs while we're writing to disk.
	 */
	(void)fflush(mainlogfile);
	fsync(fileno(mainlogfile));
}
