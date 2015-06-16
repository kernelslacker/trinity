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
	pid_t pid;

	if (logging == LOGGING_DISABLED)
		return NULL;

	if (!logfiles_opened)
		return NULL;

	pid = getpid();
	if (pid == initpid)
		return mainlogfile;

	if (pid == shm->mainpid)
		return mainlogfile;

	if (pid == watchdog_pid)
		return mainlogfile;

	handle = find_child_logfile_handle(pid);

	return handle;
}

/*
 * Flush any pending log writes to disk.
 * Only to be called from child context.
 */
void synclogs(void)
{
	int fd;

	if (logging == LOGGING_DISABLED)
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
