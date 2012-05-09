#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "trinity.h"
#include "shm.h"

static char outputbuf[1024];
FILE *parentlogfile;

void open_logfiles()
{
	unsigned int i;
	char *logfilename;

	logfilename = malloc(25);
	sprintf(logfilename, "trinity-%d.log", parentpid);
	unlink(logfilename);
	parentlogfile = fopen(logfilename, "a");
	if (!parentlogfile) {
		perror("couldn't open logfile\n");
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < shm->nr_childs; i++) {
		logfilename = malloc(25);
		sprintf(logfilename, "trinity-%d-child%d.log", parentpid, i);
		unlink(logfilename);
		shm->logfiles[i] = fopen(logfilename, "a");
		if (!shm->logfiles[i]) {
			printf("couldn't open logfile %s\n", logfilename);
			exit(EXIT_FAILURE);
		}
	}
	free(logfilename);
}

void close_logfiles()
{
	unsigned int i;

	for (i = 0; i < shm->nr_childs; i++)
		fclose(shm->logfiles[i]);
}

static FILE * find_logfile_handle()
{
	pid_t pid;
	unsigned int i;

	pid = getpid();
	if (pid == parentpid)
		return parentlogfile;

	for (i = 0; i < shm->nr_childs; i++) {
		if (shm->pids[i] == pid)
			return shm->logfiles[i];
	}
	return NULL;
}

void synclogs()
{
	unsigned int i;

	if (logging == 0)
		return;

	for (i = 0; i < shm->nr_childs; i++) {
		(void)fflush(shm->logfiles[i]);
		(void)fsync(fileno(shm->logfiles[i]));
	}

	(void)fflush(parentlogfile);
	fsync(fileno(parentlogfile));
}

void output(const char *fmt, ...)
{
	va_list args;
	int n;
	FILE *handle;

	va_start(args, fmt);
	n = vsnprintf(outputbuf, sizeof(outputbuf), fmt, args);
	va_end(args);

	if (n < 0) {
		printf("Something went wrong in output() [%d]\n", n);
		exit(EXIT_FAILURE);
	}

	if (!quiet)
		printf("%s", outputbuf);

	if (logging == 0)
		return;

	handle = find_logfile_handle();
	fprintf(handle, "%s", outputbuf);
}
