#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "log.h"
#include "logfile.h"
#include "params.h"	// logging, quiet_level
#include "pids.h"
#include "shm.h"

FILE *mainlogfile;

static FILE *open_logfile(const char *logfilename)
{
	FILE *file;
	char *fullpath, *p;
	int len = strlen(logfilename) + 2;

	if (logging_args)
		len += strlen(logging_args);

	p = fullpath = zmalloc(len);
	if (logging_args)
		p += snprintf(fullpath, strlen(logging_args) + 2, "%s/", logging_args);
	p += snprintf(p, strlen(logfilename) + 1, "%s", logfilename);

	unlink(fullpath);

	file = fopen(fullpath, "w");
	if (!file)
		outputerr("## couldn't open logfile %s\n", fullpath);

	free(fullpath);
	return file;
}

void open_main_logfile(void)
{
	mainlogfile = open_logfile("trinity.log");
	if (!mainlogfile)
		exit(EXIT_FAILURE);
}

void open_child_logfile(struct childdata *child)
{
	char *logfilename;

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

FILE *find_logfile_handle(void)
{
	struct childdata *child;
	pid_t pid;

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
