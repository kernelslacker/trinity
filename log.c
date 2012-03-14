#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "trinity.h"

static char outputbuf[1024];
FILE *parentlogfile;
static int parentpid;

void open_logfiles()
{
	unsigned int i;
	char *logfilename;

	parentpid = getpid();
	logfilename = strdup("trinity.log");
	unlink(logfilename);
	parentlogfile = fopen(logfilename, "a");
	if (!parentlogfile) {
		perror("couldn't open logfile\n");
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < shm->nr_childs; i++) {
		logfilename = malloc(20);
		sprintf(logfilename, "trinity-child%d.log", i);
		unlink(logfilename);
		shm->logfiles[i] = fopen(logfilename, "a");
		if (!shm->logfiles[i]) {
			printf("couldn't open logfile %s\n", logfilename);
			exit(EXIT_FAILURE);
		}
	}
}

void close_logfiles()
{
	unsigned int i;

	for (i = 0; i < shm->nr_childs; i++)
		fclose(shm->logfiles[i]);
}

FILE * find_logfile_handle()
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
	return (void *) -1;
}

void synclog()
{
	FILE *handle;

	if (logging == 0)
		return;

	handle = find_logfile_handle();
	(void)fflush(handle);
	fsync(fileno(handle));
}

void sync_output()
{
	(void)fflush(stdout);
	synclog();
}

void lock_logfile()
{
	struct flock logfilelock;
	FILE *handle;

	if (logging == 0)
		return;

	logfilelock.l_type = F_WRLCK;
	logfilelock.l_whence = SEEK_SET;
	logfilelock.l_start = 0;
	logfilelock.l_len = 0;
	logfilelock.l_pid = getpid();

	handle = find_logfile_handle();

	if (fcntl(fileno(handle), F_SETLKW, &logfilelock) == -1) {
		printf("[%d] ", getpid());
		perror("fcntl lock F_SETLKW");
		exit(EXIT_FAILURE);
	}
}

void unlock_logfile()
{
	struct flock logfilelock;
	FILE *handle;

	if (logging == 0)
		return;

	logfilelock.l_type = F_UNLCK;
	logfilelock.l_whence = SEEK_SET;
	logfilelock.l_start = 0;
	logfilelock.l_len = 0;
	logfilelock.l_pid = getpid();

	handle = find_logfile_handle();

	if (fcntl(fileno(handle), F_SETLKW, &logfilelock) == -1) {
		printf("[%d] ", getpid());
		perror("fcntl unlock F_SETLKW\n");
		exit(EXIT_FAILURE);
	}
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
